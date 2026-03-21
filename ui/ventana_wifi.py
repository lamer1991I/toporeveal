"""
ventana_wifi.py — WiFi Scope v2 para TopoReveal.

Tres pestañas:
  1. MAPA     — canvas visual de APs y clientes en tiempo real
  2. APs      — tabla completa con señal, cifrado, WPS, rogue detection
  3. CAPTURA  — handshakes WPA2 capturados pasivamente + exportar .pcap

Capacidades pasivas (sin deauth ni ataques activos):
  - Detección de todos los APs cercanos con airodump-ng
  - Captura de handshakes WPA2 que ocurren naturalmente
  - Detección de rogue APs (mismo SSID, BSSID diferente)
  - Detección de redes WEP (obsoleto/vulnerable)
  - Detección de WPS activo (vulnerable a Pixie Dust)
  - Detección de redes ocultas (hidden SSID)
  - Detección de deauth attacks en curso (alguien atacando la red)
  - Análisis de solapamiento de canales
  - Identificación de clientes y su AP asociado
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import math
import subprocess
import os
import re
from datetime import datetime

# ── Colores ───────────────────────────────────────────────────────────────────
C_FONDO   = "#0d1117"
C_PANEL   = "#161b22"
C_BORDE   = "#30363d"
C_TEXTO   = "#c9d1d9"
C_SUB     = "#6e7681"
C_ACENTO  = "#1f6feb"
C_VERDE   = "#3fb950"   # WPA3 / nuestra red
C_CYAN    = "#58d6ff"   # WPA2
C_NARANJA = "#f0883e"   # WPA / WPS activo
C_ROJO    = "#da3633"   # WEP / abierta / rogue
C_AMARILLO= "#e3b341"   # handshake capturado
C_MORADO  = "#a371f7"   # red oculta

RADIO_AP      = 28
RADIO_CLI     = 10
ORBITA_DIST   = 60

# Cifrado → color
def _color_cifrado(cifrado):
    c = (cifrado or "").upper()
    if "WPA3" in c:  return C_VERDE
    if "WPA2" in c:  return C_CYAN
    if "WPA" in c:   return C_NARANJA
    if "WEP" in c:   return C_ROJO
    if "OPN" in c or c == "OPEN": return C_ROJO
    return C_SUB


class VentanaWifi:
    def __init__(self, padre, bssid_propio=None):
        self.ventana = tk.Toplevel(padre)
        self.ventana.title("⚡ WiFi Scope v2")
        self.ventana.geometry("1000x660")
        self.ventana.configure(bg=C_FONDO)
        self.ventana.minsize(800, 500)

        self._lock        = threading.Lock()
        self._aps         = {}   # {bssid: {ssid, canal, cifrado, rssi, wps, clientes, ...}}
        self._clientes    = {}   # {mac_cli: {bssid_ap, rssi, pkts}}
        self._handshakes  = []   # [(ts, bssid, ssid, mac_cli, ruta_pcap)]
        self._rogues      = []   # [(bssid_rogue, ssid, bssid_legit)]
        self._deauths     = {}   # {bssid: n_deauths}
        self._bssid_propio = (bssid_propio or "").lower()
        self._nodo_sel    = None
        self._posiciones  = {}
        self._monitor_activo = False
        self._interfaz_monitor = None

        self._construir_ui()
        self._ciclo_render()

    def set_bssid_propio(self, bssid):
        self._bssid_propio = (bssid or "").lower()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _construir_ui(self):
        # Barra superior
        barra = tk.Frame(self.ventana, bg=C_PANEL, height=42)
        barra.pack(fill=tk.X)
        barra.pack_propagate(False)

        tk.Label(barra, text="⚡ WiFi SCOPE v2",
            bg=C_PANEL, fg=C_CYAN,
            font=("Monospace", 11, "bold")).pack(side=tk.LEFT, padx=12)

        self.lbl_monitor = tk.Label(barra,
            text="◌ Monitor inactivo",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8))
        self.lbl_monitor.pack(side=tk.LEFT, padx=8)

        self.lbl_stats = tk.Label(barra,
            text="APs: 0  |  Clientes: 0  |  HS: 0",
            bg=C_PANEL, fg=C_TEXTO,
            font=("Monospace", 8))
        self.lbl_stats.pack(side=tk.RIGHT, padx=12)

        # Leyenda
        leyenda_frame = tk.Frame(barra, bg=C_PANEL)
        leyenda_frame.pack(side=tk.RIGHT, padx=8)
        for color, texto in [(C_VERDE,"WPA3"),(C_CYAN,"WPA2"),
                              (C_NARANJA,"WPA/WPS"),(C_ROJO,"WEP/Abierta"),
                              (C_AMARILLO,"Handshake"),(C_MORADO,"Oculta")]:
            tk.Label(leyenda_frame, text=f"● {texto}",
                bg=C_PANEL, fg=color,
                font=("Monospace", 7)).pack(side=tk.LEFT, padx=3)

        # Notebook con 3 pestañas
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Wifi.TNotebook",
            background=C_FONDO, borderwidth=0)
        style.configure("Wifi.TNotebook.Tab",
            background=C_PANEL, foreground=C_SUB,
            font=("Monospace", 9, "bold"),
            padding=[12, 5])
        style.map("Wifi.TNotebook.Tab",
            background=[("selected", C_ACENTO)],
            foreground=[("selected", "white")])

        self.nb = ttk.Notebook(self.ventana, style="Wifi.TNotebook")
        self.nb.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        self._frame_mapa    = tk.Frame(self.nb, bg=C_FONDO)
        self._frame_tabla   = tk.Frame(self.nb, bg=C_FONDO)
        self._frame_captura = tk.Frame(self.nb, bg=C_FONDO)

        self.nb.add(self._frame_mapa,    text="  🗺 MAPA  ")
        self.nb.add(self._frame_tabla,   text="  📋 APs  ")
        self.nb.add(self._frame_captura, text="  🔑 CAPTURA  ")

        self._construir_mapa()
        self._construir_tabla()
        self._construir_captura()

    # ── PESTAÑA 1: MAPA ───────────────────────────────────────────────────────

    def _construir_mapa(self):
        f = self._frame_mapa

        # Canvas principal
        self.cv = tk.Canvas(f, bg=C_FONDO, highlightthickness=0)
        self.cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.cv.bind("<Button-1>", self._click_mapa)

        # Panel derecho del mapa
        panel = tk.Frame(f, bg=C_PANEL, width=260)
        panel.pack(side=tk.RIGHT, fill=tk.Y)
        panel.pack_propagate(False)

        tk.Label(panel, text="NODO SELECCIONADO",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 7, "bold")).pack(anchor="w", padx=10, pady=(10,4))

        self.lbl_ssid_sel = tk.Label(panel,
            text="— Click en un AP —",
            bg=C_PANEL, fg=C_CYAN,
            font=("Monospace", 10, "bold"),
            wraplength=230, justify="left")
        self.lbl_ssid_sel.pack(anchor="w", padx=10)

        self._lbl_campos = {}
        for campo in ["BSSID","Canal","Cifrado","Señal","WPS","Clientes","Vista"]:
            fila = tk.Frame(panel, bg=C_PANEL)
            fila.pack(fill=tk.X, padx=10, pady=1)
            tk.Label(fila, text=f"{campo}:",
                bg=C_PANEL, fg=C_SUB,
                font=("Monospace", 7), width=9, anchor="w").pack(side=tk.LEFT)
            lbl = tk.Label(fila, text="—",
                bg=C_PANEL, fg=C_TEXTO,
                font=("Monospace", 7), anchor="w")
            lbl.pack(side=tk.LEFT)
            self._lbl_campos[campo] = lbl

        tk.Frame(panel, bg=C_BORDE, height=1).pack(fill=tk.X, padx=8, pady=8)

        # Alertas del AP seleccionado
        tk.Label(panel, text="ALERTAS",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 7, "bold")).pack(anchor="w", padx=10)
        self.lbl_alertas_ap = tk.Label(panel,
            text="—",
            bg=C_PANEL, fg=C_NARANJA,
            font=("Monospace", 7),
            wraplength=230, justify="left")
        self.lbl_alertas_ap.pack(anchor="w", padx=10, pady=2)

        tk.Frame(panel, bg=C_BORDE, height=1).pack(fill=tk.X, padx=8, pady=8)

        # Clientes del AP seleccionado
        tk.Label(panel, text="CLIENTES ASOCIADOS",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 7, "bold")).pack(anchor="w", padx=10)
        self.lista_clientes_sel = tk.Listbox(panel,
            bg=C_FONDO, fg=C_TEXTO,
            font=("Monospace", 7),
            relief=tk.FLAT, borderwidth=0,
            highlightthickness=0, height=6,
            selectbackground=C_ACENTO)
        self.lista_clientes_sel.pack(fill=tk.X, padx=10, pady=2)

        tk.Frame(panel, bg=C_BORDE, height=1).pack(fill=tk.X, padx=8, pady=4)

        # Botón capturar handshake
        self.btn_capturar = tk.Button(panel,
            text="🎯 Esperar Handshake",
            bg="#21262d", fg=C_CYAN,
            font=("Monospace", 8, "bold"),
            relief=tk.FLAT, padx=8, pady=4,
            cursor="hand2",
            command=self._capturar_handshake_seleccionado)
        self.btn_capturar.pack(fill=tk.X, padx=10, pady=3)

        tk.Button(panel,
            text="📊 Canal Heatmap",
            bg="#21262d", fg=C_SUB,
            font=("Monospace", 8),
            relief=tk.FLAT, padx=8, pady=3,
            cursor="hand2",
            command=self._mostrar_heatmap_canales
        ).pack(fill=tk.X, padx=10, pady=2)

    # ── PESTAÑA 2: TABLA DE APs ───────────────────────────────────────────────

    def _construir_tabla(self):
        f = self._frame_tabla

        # Barra de herramientas
        toolbar = tk.Frame(f, bg=C_PANEL, height=36)
        toolbar.pack(fill=tk.X)
        toolbar.pack_propagate(False)

        tk.Label(toolbar, text="Filtrar:",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8)).pack(side=tk.LEFT, padx=8)
        self._filtro_var = tk.StringVar()
        self._filtro_var.trace("w", lambda *a: self._filtrar_tabla())
        tk.Entry(toolbar,
            textvariable=self._filtro_var,
            bg="#21262d", fg=C_TEXTO,
            font=("Monospace", 8),
            relief=tk.FLAT, insertbackground=C_CYAN,
            width=20).pack(side=tk.LEFT, padx=4)

        # Alertas rápidas en toolbar
        self.lbl_alertas_rapidas = tk.Label(toolbar,
            text="",
            bg=C_PANEL, fg=C_ROJO,
            font=("Monospace", 8, "bold"))
        self.lbl_alertas_rapidas.pack(side=tk.RIGHT, padx=12)

        # Treeview
        cols = ("SSID","BSSID","Canal","Señal","Cifrado","WPS","Clientes","Vista","Alertas")
        self.tree = ttk.Treeview(f, columns=cols, show="headings", height=22)

        # Estilo
        style = ttk.Style()
        style.configure("Wifi.Treeview",
            background=C_FONDO, foreground=C_TEXTO,
            fieldbackground=C_FONDO,
            rowheight=28,
            font=("Monospace", 8))
        style.configure("Wifi.Treeview.Heading",
            background=C_PANEL, foreground=C_SUB,
            font=("Monospace", 8, "bold"))
        style.map("Wifi.Treeview",
            background=[("selected", C_ACENTO)])
        self.tree.configure(style="Wifi.Treeview")

        anchos = {"SSID":180,"BSSID":140,"Canal":55,"Señal":60,
                  "Cifrado":80,"WPS":40,"Clientes":65,"Vista":55,"Alertas":200}
        for col in cols:
            self.tree.heading(col, text=col,
                command=lambda c=col: self._ordenar(c))
            self.tree.column(col, width=anchos.get(col,80),
                anchor="center" if col not in ("SSID","BSSID","Alertas") else "w",
                minwidth=40)

        # Tags de color
        self.tree.tag_configure("wpa3",    foreground=C_VERDE)
        self.tree.tag_configure("wpa2",    foreground=C_CYAN)
        self.tree.tag_configure("wpa",     foreground=C_NARANJA)
        self.tree.tag_configure("wep",     foreground=C_ROJO)
        self.tree.tag_configure("abierta", foreground=C_ROJO)
        self.tree.tag_configure("nuestra", foreground=C_VERDE, font=("Monospace",8,"bold"))
        self.tree.tag_configure("rogue",   foreground=C_ROJO,  font=("Monospace",8,"bold"))
        self.tree.tag_configure("oculta",  foreground=C_MORADO)

        sb = ttk.Scrollbar(f, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self._doble_click_tabla)

    # ── PESTAÑA 3: CAPTURA ────────────────────────────────────────────────────

    def _construir_captura(self):
        f = self._frame_captura

        # Cabecera
        cab = tk.Frame(f, bg=C_PANEL, height=48)
        cab.pack(fill=tk.X)
        cab.pack_propagate(False)

        tk.Label(cab, text="🔑 HANDSHAKES WPA2 CAPTURADOS",
            bg=C_PANEL, fg=C_AMARILLO,
            font=("Monospace", 10, "bold")).pack(side=tk.LEFT, padx=12, pady=8)

        tk.Label(cab,
            text="Captura pasiva — solo handshakes que ocurren naturalmente en la red",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 7)).pack(side=tk.LEFT)

        # Tabla de handshakes
        hs_cols = ("Hora","SSID","BSSID AP","MAC Cliente","¿Nuestra red?","Archivo .pcap")
        self.tree_hs = ttk.Treeview(f, columns=hs_cols, show="headings", height=8)
        style = ttk.Style()
        style.configure("HS.Treeview",
            background=C_FONDO, foreground=C_TEXTO,
            fieldbackground=C_FONDO, rowheight=30,
            font=("Monospace", 8))
        style.configure("HS.Treeview.Heading",
            background=C_PANEL, foreground=C_AMARILLO,
            font=("Monospace", 8, "bold"))
        self.tree_hs.configure(style="HS.Treeview")
        self.tree_hs.tag_configure("nuestra", foreground=C_VERDE)
        self.tree_hs.tag_configure("vecina",  foreground=C_CYAN)

        anc_hs = {"Hora":70,"SSID":160,"BSSID AP":140,
                  "MAC Cliente":140,"¿Nuestra red?":100,"Archivo .pcap":220}
        for col in hs_cols:
            self.tree_hs.heading(col, text=col)
            self.tree_hs.column(col, width=anc_hs.get(col,100), anchor="w")

        sb_hs = ttk.Scrollbar(f, orient=tk.VERTICAL, command=self.tree_hs.yview)
        self.tree_hs.configure(yscrollcommand=sb_hs.set)
        sb_hs.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.tree_hs.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        tk.Frame(f, bg=C_BORDE, height=1).pack(fill=tk.X, pady=4)

        # Panel de alertas WiFi
        alerta_frame = tk.Frame(f, bg=C_PANEL)
        alerta_frame.pack(fill=tk.X, padx=8, pady=4)

        tk.Label(alerta_frame, text="⚠ ALERTAS DE SEGURIDAD WiFi",
            bg=C_PANEL, fg=C_ROJO,
            font=("Monospace", 9, "bold")).pack(anchor="w", padx=8, pady=(6,2))

        self.txt_alertas_wifi = tk.Text(alerta_frame,
            bg=C_FONDO, fg=C_TEXTO,
            font=("Monospace", 8),
            height=7, relief=tk.FLAT,
            state=tk.DISABLED,
            wrap=tk.WORD)
        self.txt_alertas_wifi.pack(fill=tk.X, padx=8, pady=(0,6))

        # Tags de color para el text widget
        self.txt_alertas_wifi.tag_configure("rojo",    foreground=C_ROJO)
        self.txt_alertas_wifi.tag_configure("naranja", foreground=C_NARANJA)
        self.txt_alertas_wifi.tag_configure("verde",   foreground=C_VERDE)
        self.txt_alertas_wifi.tag_configure("sub",     foreground=C_SUB)

        # Botones
        btn_row = tk.Frame(f, bg=C_FONDO)
        btn_row.pack(fill=tk.X, padx=8, pady=4)

        tk.Button(btn_row, text="📁 Abrir carpeta exports",
            bg="#21262d", fg=C_SUB,
            font=("Monospace", 8), relief=tk.FLAT,
            cursor="hand2",
            command=self._abrir_carpeta_exports
        ).pack(side=tk.LEFT, padx=4)

        tk.Button(btn_row, text="🔍 Analizar .pcap con Wireshark",
            bg="#21262d", fg=C_CYAN,
            font=("Monospace", 8), relief=tk.FLAT,
            cursor="hand2",
            command=self._abrir_wireshark
        ).pack(side=tk.LEFT, padx=4)

    # ── PROCESAMIENTO DE EVENTOS ──────────────────────────────────────────────

    def procesar_evento(self, evento):
        """Punto de entrada desde el interceptor 802.11."""
        tipo = evento.get("tipo_wifi", "")
        with self._lock:
            if tipo in ("BEACON", "PROBE_RESP"):
                self._reg_ap(evento)
            elif tipo in ("HANDSHAKE_M1","HANDSHAKE_M2",
                          "HANDSHAKE_M3","HANDSHAKE_M4","EAPOL"):
                self._reg_handshake(evento)
            elif tipo == "DATA":
                self._reg_cliente(evento)
            elif tipo == "DEAUTH":
                self._reg_deauth(evento)

    def _reg_ap(self, ev):
        bssid = (ev.get("bssid") or "").lower().strip()
        if not bssid or bssid in ("ff:ff:ff:ff:ff:ff","00:00:00:00:00:00"):
            return
        es_nuestra = ev.get("es_nuestra_red", False) or (
            bool(self._bssid_propio) and bssid == self._bssid_propio)
        if es_nuestra:
            self._bssid_propio = bssid

        ssid     = ev.get("ssid") or ""
        cifrado  = ev.get("cifrado", "?")
        canal    = ev.get("canal", 0)
        rssi     = ev.get("rssi")
        wps      = ev.get("wps", False)
        oculta   = not bool(ssid)

        if bssid not in self._aps:
            self._aps[bssid] = {
                "ssid"       : ssid or "<oculta>",
                "canal"      : canal,
                "cifrado"    : cifrado,
                "rssi"       : rssi,
                "wps"        : wps,
                "oculta"     : oculta,
                "clientes"   : set(),
                "pkts"       : 0,
                "es_nuestra" : es_nuestra,
                "handshake"  : False,
                "primer_visto": datetime.now().strftime("%H:%M:%S"),
                "alertas"    : [],
            }
            # Detectar amenazas en el momento de registro
            self._detectar_amenazas_ap(bssid)
        else:
            ap = self._aps[bssid]
            if ssid: ap["ssid"] = ssid
            if rssi is not None: ap["rssi"] = rssi
            if canal: ap["canal"] = canal
            if wps: ap["wps"] = True
            if es_nuestra: ap["es_nuestra"] = True
        self._aps[bssid]["pkts"] = self._aps[bssid].get("pkts",0) + 1

    def _detectar_amenazas_ap(self, bssid):
        """Detecta amenazas en un AP recién registrado."""
        ap = self._aps.get(bssid)
        if not ap:
            return
        alertas = []
        cifrado = (ap.get("cifrado") or "").upper()

        # WEP — obsoleto y roto
        if "WEP" in cifrado:
            alertas.append("🔴 WEP: cifrado roto — trivialmente hackeable")

        # Red abierta
        if "OPN" in cifrado or cifrado in ("OPEN",""):
            alertas.append("🔴 Red ABIERTA — sin cifrado")

        # WPS activo — vulnerable a Pixie Dust y ataques de pin
        if ap.get("wps"):
            alertas.append("🟠 WPS activo — vulnerable a Pixie Dust")

        # Red oculta — no más segura, solo más molesta
        if ap.get("oculta"):
            alertas.append("🟣 SSID oculto detectado — no añade seguridad real")

        # Rogue AP — mismo SSID que nuestra red pero BSSID diferente
        if self._bssid_propio:
            ap_nuestro = self._aps.get(self._bssid_propio)
            if ap_nuestro and bssid != self._bssid_propio:
                ssid_nuestro = ap_nuestro.get("ssid","").lower()
                ssid_este    = ap.get("ssid","").lower()
                if ssid_nuestro and ssid_este == ssid_nuestro:
                    alertas.append(
                        f"🔴 ROGUE AP — mismo SSID que nuestra red ({ssid_nuestro})")
                    self._rogues.append((bssid, ssid_este, self._bssid_propio))

        ap["alertas"] = alertas

    def _reg_handshake(self, ev):
        bssid     = (ev.get("bssid") or "").lower()
        mac_cli   = (ev.get("cliente_mac") or "?").lower()
        es_nuestra = ev.get("es_nuestra_red", False) or (
            bool(self._bssid_propio) and bssid == self._bssid_propio)
        ts   = datetime.now().strftime("%H:%M:%S")
        ssid = ""
        if bssid in self._aps:
            self._aps[bssid]["handshake"] = True
            ssid = self._aps[bssid].get("ssid", "")

        # Guardar info del handshake
        # El pcap ya lo guarda el interceptor — aquí solo registramos el evento
        ruta_pcap = ev.get("pcap_ruta", "—")
        self._handshakes.append((ts, ssid, bssid, mac_cli, es_nuestra, ruta_pcap))

    def _reg_cliente(self, ev):
        mac_cli = (ev.get("mac_cliente") or ev.get("mac_origen") or "").lower()
        bssid   = (ev.get("bssid") or "").lower()
        rssi    = ev.get("rssi")
        if not mac_cli or mac_cli in ("ff:ff:ff:ff:ff:ff","00:00:00:00:00:00"):
            return
        self._clientes[mac_cli] = {
            "bssid" : bssid,
            "rssi"  : rssi,
            "pkts"  : self._clientes.get(mac_cli, {}).get("pkts", 0) + 1
        }
        if bssid in self._aps:
            self._aps[bssid]["clientes"].add(mac_cli)

    def _reg_deauth(self, ev):
        bssid = (ev.get("bssid") or "").lower()
        if bssid:
            self._deauths[bssid] = self._deauths.get(bssid, 0) + 1
            if self._deauths[bssid] == 5:  # Umbral: 5 deauths = ataque
                if bssid in self._aps:
                    self._aps[bssid]["alertas"].append(
                        "🔴 DEAUTH ATTACK detectado — alguien está desconectando clientes")

    # ── RENDER ────────────────────────────────────────────────────────────────

    def _ciclo_render(self):
        try:
            if self.ventana.winfo_exists():
                self._render_mapa()
                self._actualizar_tabla()
                self._actualizar_captura()
                self._actualizar_stats()
                self.ventana.after(1800, self._ciclo_render)
        except Exception:
            pass

    def _render_mapa(self):
        with self._lock:
            aps = dict(self._aps)
        if not aps:
            self.cv.delete("all")
            w = self.cv.winfo_width() or 700
            h = self.cv.winfo_height() or 500
            self.cv.create_text(w//2, h//2,
                text="⚡ Escaneando el aire...\n\nEl monitor 802.11 detecta\nredes WiFi automáticamente",
                fill=C_SUB, font=("Monospace", 11), justify=tk.CENTER)
            return

        self.cv.delete("all")
        w = self.cv.winfo_width() or 700
        h = self.cv.winfo_height() or 500

        # Grid sutil
        for x in range(0, w, 40):
            self.cv.create_line(x,0,x,h, fill="#161b22", width=1)
        for y in range(0, h, 40):
            self.cv.create_line(0,y,w,y, fill="#161b22", width=1)

        # Ordenar: nuestra red primero
        lista = sorted(aps.items(),
            key=lambda x: (0 if x[1].get("es_nuestra") else 1, x[0]))
        n = len(lista)
        cx, cy = w//2, h//2
        pos = {}

        if n == 1:
            pos[lista[0][0]] = (cx, cy)
        elif n <= 6:
            # Círculo amplio con buen espacio entre nodos
            r = min(w, h) // 2 - RADIO_AP - 90
            for i, (bssid, _) in enumerate(lista):
                ang = (2*math.pi*i/n) - math.pi/2
                pos[bssid] = (int(cx + r*math.cos(ang)),
                              int(cy + r*math.sin(ang)))
        else:
            # Espiral para muchos APs — mejor separación
            r_base = 90
            for i, (bssid, _) in enumerate(lista):
                nivel  = i // 6
                idx    = i % 6
                r      = r_base + nivel * 95
                ang    = (2*math.pi*idx/6) - math.pi/2 + nivel*0.3
                px     = int(cx + r*math.cos(ang))
                py     = int(cy + r*math.sin(ang))
                # Clamp para que no salga de la pantalla
                px = max(RADIO_AP+30, min(w-RADIO_AP-30, px))
                py = max(RADIO_AP+30, min(h-RADIO_AP-30, py))
                pos[bssid] = (px, py)

        self._posiciones = pos

        # Líneas de conexión tenues entre APs del mismo canal
        canales_a_aps = {}
        for bssid, ap in lista:
            c = ap.get("canal", 0)
            canales_a_aps.setdefault(c, []).append(bssid)
        for canal, bssids in canales_a_aps.items():
            if len(bssids) > 1 and canal > 0:
                for i in range(len(bssids)-1):
                    b1, b2 = bssids[i], bssids[i+1]
                    if b1 in pos and b2 in pos:
                        p1, p2 = pos[b1], pos[b2]
                        self.cv.create_line(p1[0],p1[1],p2[0],p2[1],
                            fill="#f0883e", width=1, dash=(3,8))

        # Nodos
        for bssid, ap in lista:
            if bssid not in pos:
                continue
            px, py   = pos[bssid]
            tiene_hs = ap.get("handshake", False)
            es_nuestra = ap.get("es_nuestra", False)
            seleccionado = (bssid == self._nodo_sel)
            cifrado  = ap.get("cifrado","")
            oculta   = ap.get("oculta", False)
            wps      = ap.get("wps", False)
            alertas  = ap.get("alertas", [])
            tiene_alerta = len(alertas) > 0 or wps

            # Color base por cifrado
            if tiene_hs:
                color = C_AMARILLO
            elif es_nuestra:
                color = C_VERDE
            else:
                color = _color_cifrado(cifrado)

            # Clientes en órbita
            clientes = list(ap.get("clientes", set()))
            nc = len(clientes)
            for i, mac in enumerate(clientes[:8]):
                ang  = (2*math.pi*i/max(nc,1)) - math.pi/2
                cxc2 = int(px + ORBITA_DIST*math.cos(ang))
                cyc2 = int(py + ORBITA_DIST*math.sin(ang))
                self.cv.create_line(px,py,cxc2,cyc2,
                    fill=C_BORDE, width=1)
                self.cv.create_oval(
                    cxc2-RADIO_CLI, cyc2-RADIO_CLI,
                    cxc2+RADIO_CLI, cyc2+RADIO_CLI,
                    fill=C_PANEL, outline=C_ACENTO, width=2)
                mac_short = mac[-5:].upper()
                self.cv.create_text(cxc2, cyc2,
                    text=mac_short, fill=C_SUB,
                    font=("Monospace", 5))

            # Anillo de selección
            if seleccionado:
                self.cv.create_oval(
                    px-RADIO_AP-8, py-RADIO_AP-8,
                    px+RADIO_AP+8, py+RADIO_AP+8,
                    outline=C_CYAN, width=2, dash=(4,4))

            # Anillo de alerta pulsante
            if tiene_alerta:
                self.cv.create_oval(
                    px-RADIO_AP-4, py-RADIO_AP-4,
                    px+RADIO_AP+4, py+RADIO_AP+4,
                    outline=C_ROJO, width=1)

            # Nodo AP
            self.cv.create_oval(
                px-RADIO_AP, py-RADIO_AP,
                px+RADIO_AP, py+RADIO_AP,
                fill=C_PANEL, outline=color, width=3)

            # Icono interior
            icono = "⭐" if es_nuestra else ("🔓" if "OPN" in cifrado.upper() else "📡")
            self.cv.create_text(px, py-4,
                text=icono, font=("Monospace",12))

            # Indicadores pequeños
            if tiene_hs:
                self.cv.create_text(px+RADIO_AP-2, py-RADIO_AP+2,
                    text="🔑", font=("Monospace",8))
            if wps:
                self.cv.create_text(px-RADIO_AP+2, py-RADIO_AP+2,
                    text="W", fill=C_NARANJA, font=("Monospace",7,"bold"))
            if oculta:
                self.cv.create_text(px, py+RADIO_AP+3,
                    text="●", fill=C_MORADO, font=("Monospace",6))

            # SSID
            ssid_txt = (ap.get("ssid","?"))[:16]
            self.cv.create_text(px, py+RADIO_AP+14,
                text=ssid_txt, fill=color,
                font=("Monospace",8,"bold"))

            # Canal y señal
            rssi = ap.get("rssi")
            info_txt = f"ch{ap.get('canal','?')}"
            if rssi:
                info_txt += f" {rssi}dBm"
            self.cv.create_text(px, py+RADIO_AP+26,
                text=info_txt, fill=C_SUB,
                font=("Monospace",7))

    def _actualizar_tabla(self):
        with self._lock:
            aps = dict(self._aps)
        filtro = self._filtro_var.get().lower()

        # Limpiar y recargar
        for item in self.tree.get_children():
            self.tree.delete(item)

        alertas_globales = []
        for bssid, ap in sorted(aps.items(),
                key=lambda x: x[1].get("rssi") or -100, reverse=True):
            ssid = ap.get("ssid","?")
            if filtro and filtro not in ssid.lower() and filtro not in bssid:
                continue

            rssi_val = ap.get("rssi")
            rssi_txt = f"{rssi_val}dBm" if rssi_val else "?"
            cifrado  = ap.get("cifrado","?")
            wps_txt  = "✓" if ap.get("wps") else "—"
            n_cli    = len(ap.get("clientes",set()))
            hs_txt   = "✓" if ap.get("handshake") else "—"
            alertas  = ap.get("alertas",[])
            alert_txt = " | ".join(alertas) if alertas else "✓ OK"

            # Tag de color
            if bssid == self._bssid_propio:
                tag = "nuestra"
            elif any("ROGUE" in a for a in alertas):
                tag = "rogue"
                alertas_globales.append(f"ROGUE: {ssid}")
            elif "WEP" in cifrado.upper():
                tag = "wep"
            elif "OPN" in cifrado.upper():
                tag = "abierta"
            elif ap.get("oculta"):
                tag = "oculta"
            elif "WPA3" in cifrado.upper():
                tag = "wpa3"
            elif "WPA2" in cifrado.upper():
                tag = "wpa2"
            else:
                tag = "wpa"

            self.tree.insert("", tk.END, iid=bssid,
                values=(ssid, bssid, ap.get("canal","?"), rssi_txt,
                        cifrado, wps_txt, n_cli, hs_txt, alert_txt),
                tags=(tag,))

            if alertas:
                alertas_globales.extend(alertas)

        # Alerta rápida en toolbar
        n_rog = len([a for a in alertas_globales if "ROGUE" in a])
        n_wep = sum(1 for ap in aps.values() if "WEP" in (ap.get("cifrado","")).upper())
        txt_al = ""
        if n_rog: txt_al += f"⚠ {n_rog} ROGUE AP  "
        if n_wep: txt_al += f"⚠ {n_wep} WEP  "
        self.lbl_alertas_rapidas.config(text=txt_al)

    def _actualizar_captura(self):
        # Tabla de handshakes
        for item in self.tree_hs.get_children():
            self.tree_hs.delete(item)
        with self._lock:
            hs_list = list(self._handshakes)

        for ts, ssid, bssid, mac_cli, es_nuestra, ruta_pcap in hs_list:
            tag = "nuestra" if es_nuestra else "vecina"
            self.tree_hs.insert("", tk.END,
                values=(ts, ssid or "?", bssid, mac_cli,
                        "✓ NUESTRA" if es_nuestra else "Vecina", ruta_pcap),
                tags=(tag,))

        # Panel de alertas WiFi
        with self._lock:
            aps = dict(self._aps)
            deauths = dict(self._deauths)
            rogues  = list(self._rogues)

        self.txt_alertas_wifi.config(state=tk.NORMAL)
        self.txt_alertas_wifi.delete("1.0", tk.END)

        if not aps:
            self.txt_alertas_wifi.insert(tk.END,
                "Sin datos — esperando tráfico 802.11...\n", "sub")
        else:
            # Rogues
            if rogues:
                for bssid_r, ssid_r, bssid_l in rogues:
                    self.txt_alertas_wifi.insert(tk.END,
                        f"🔴 ROGUE AP: '{ssid_r}' — {bssid_r} "
                        f"(legítimo: {bssid_l})\n", "rojo")
            # Deauth attacks
            for bssid, n in deauths.items():
                if n >= 5:
                    ssid_d = aps.get(bssid,{}).get("ssid","?")
                    self.txt_alertas_wifi.insert(tk.END,
                        f"🔴 DEAUTH ATTACK en '{ssid_d}' — "
                        f"{n} frames de desconexión\n", "rojo")
            # WEP y abiertas
            for bssid, ap in aps.items():
                cif = (ap.get("cifrado","")).upper()
                if "WEP" in cif:
                    self.txt_alertas_wifi.insert(tk.END,
                        f"🔴 WEP: '{ap.get('ssid','?')}' — cifrado roto\n", "rojo")
                elif "OPN" in cif:
                    self.txt_alertas_wifi.insert(tk.END,
                        f"🔴 ABIERTA: '{ap.get('ssid','?')}' — sin cifrado\n", "rojo")
                if ap.get("wps"):
                    self.txt_alertas_wifi.insert(tk.END,
                        f"🟠 WPS ACTIVO: '{ap.get('ssid','?')}' — "
                        f"vulnerable a Pixie Dust\n", "naranja")
            # Handshakes
            if hs_list:
                nuestros = sum(1 for h in hs_list if h[4])
                self.txt_alertas_wifi.insert(tk.END,
                    f"🔑 {len(hs_list)} handshake(s) capturado(s) "
                    f"({nuestros} de nuestra red)\n", "naranja")
            if not any([rogues, deauths]):
                all_ok = all(
                    "WPA2" in (ap.get("cifrado","")).upper() or
                    "WPA3" in (ap.get("cifrado","")).upper()
                    for ap in aps.values())
                if all_ok and not hs_list:
                    self.txt_alertas_wifi.insert(tk.END,
                        "✓ Sin amenazas detectadas\n", "verde")

        self.txt_alertas_wifi.config(state=tk.DISABLED)

    def _actualizar_stats(self):
        with self._lock:
            n_aps = len(self._aps)
            n_cli = len(self._clientes)
            n_hs  = len(self._handshakes)
        self.lbl_stats.config(
            text=f"APs: {n_aps}  |  Clientes: {n_cli}  |  HS: {n_hs}")

    # ── INTERACCIÓN ──────────────────────────────────────────────────────────

    def _click_mapa(self, event):
        """Selecciona AP al hacer click en el canvas."""
        for bssid, (px, py) in self._posiciones.items():
            if abs(event.x - px) < RADIO_AP+6 and abs(event.y - py) < RADIO_AP+6:
                self._nodo_sel = bssid
                self._actualizar_panel_ap(bssid)
                return
        self._nodo_sel = None

    def _actualizar_panel_ap(self, bssid):
        with self._lock:
            ap = dict(self._aps.get(bssid, {}))
        if not ap:
            return

        self.lbl_ssid_sel.config(text=ap.get("ssid","?"))
        rssi = ap.get("rssi")
        self._lbl_campos["BSSID"].config(text=bssid)
        self._lbl_campos["Canal"].config(text=str(ap.get("canal","?")))
        self._lbl_campos["Cifrado"].config(
            text=ap.get("cifrado","?"),
            fg=_color_cifrado(ap.get("cifrado","")))
        self._lbl_campos["Señal"].config(
            text=f"{rssi}dBm" if rssi else "?")
        self._lbl_campos["WPS"].config(
            text="✓ Activo" if ap.get("wps") else "No",
            fg=C_NARANJA if ap.get("wps") else C_VERDE)
        self._lbl_campos["Clientes"].config(
            text=str(len(ap.get("clientes",set()))))
        self._lbl_campos["Vista"].config(
            text=ap.get("primer_visto","?"))

        # Alertas
        alertas = ap.get("alertas",[])
        self.lbl_alertas_ap.config(
            text="\n".join(alertas) if alertas else "✓ Sin alertas",
            fg=C_ROJO if alertas else C_VERDE)

        # Clientes
        self.lista_clientes_sel.delete(0, tk.END)
        for mac in sorted(ap.get("clientes",set())):
            self.lista_clientes_sel.insert(tk.END, f"  {mac.upper()}")

    def _doble_click_tabla(self, event):
        """Al hacer doble click en la tabla, ir al mapa y seleccionar el AP."""
        sel = self.tree.selection()
        if sel:
            bssid = sel[0]
            self._nodo_sel = bssid
            self._actualizar_panel_ap(bssid)
            self.nb.select(0)  # Ir a la pestaña del mapa

    def _filtrar_tabla(self):
        self._actualizar_tabla()

    def _ordenar(self, columna):
        """Ordena la tabla por la columna clickeada."""
        pass  # Simple — se puede expandir

    def _capturar_handshake_seleccionado(self):
        """Inicia espera de handshake en el AP seleccionado."""
        if not self._nodo_sel:
            messagebox.showinfo("WiFi Scope",
                "Selecciona un AP en el mapa primero.")
            return
        with self._lock:
            ap = self._aps.get(self._nodo_sel, {})
        ssid  = ap.get("ssid","?")
        canal = ap.get("canal", 0)
        messagebox.showinfo("Esperando Handshake",
            f"Monitoreando '{ssid}' (canal {canal})\n\n"
            f"Cuando un cliente se autentique naturalmente,\n"
            f"el handshake WPA2 se capturará automáticamente\n"
            f"y aparecerá en la pestaña CAPTURA.\n\n"
            f"No se realizará ningún ataque de deautenticación.")

    def _mostrar_heatmap_canales(self):
        """Muestra un heatmap de uso de canales WiFi."""
        with self._lock:
            aps = dict(self._aps)

        if not aps:
            messagebox.showinfo("Canal Heatmap", "Sin APs detectados aún.")
            return

        win = tk.Toplevel(self.ventana)
        win.title("Canal Heatmap")
        win.geometry("600x280")
        win.configure(bg=C_FONDO)

        tk.Label(win, text="USO DE CANALES WiFi",
            bg=C_FONDO, fg=C_CYAN,
            font=("Monospace", 10, "bold")).pack(pady=8)

        cv = tk.Canvas(win, bg=C_FONDO,
            width=580, height=200, highlightthickness=0)
        cv.pack(padx=10)

        # Contar APs por canal
        canales = {}
        for ap in aps.values():
            c = ap.get("canal", 0)
            if c:
                canales[c] = canales.get(c, 0) + 1

        if not canales:
            cv.create_text(290, 100,
                text="Sin datos de canal", fill=C_SUB,
                font=("Monospace", 10))
            return

        max_n = max(canales.values())
        # Canales 1-14 (2.4GHz) + 36-165 (5GHz)
        canales_2g = [c for c in canales if c <= 14]
        canales_5g = [c for c in canales if c > 14]

        def _dibujar_canales(lista, x_start, titulo):
            if not lista:
                return
            cv.create_text(x_start + 100, 20,
                text=titulo, fill=C_SUB,
                font=("Monospace", 8, "bold"))
            bar_w = 16
            gap   = 6
            for i, canal in enumerate(sorted(lista)):
                n   = canales.get(canal, 0)
                h   = int((n / max_n) * 120)
                x   = x_start + i*(bar_w+gap)
                y_b = 160
                # Color: canales solapados en 2.4GHz (1,6,11 son los buenos)
                col = C_VERDE if canal in (1,6,11,36,40,44,48,149,153,157,161) else C_NARANJA
                if n > 1: col = C_ROJO   # saturado
                cv.create_rectangle(x, y_b-h, x+bar_w, y_b,
                    fill=col, outline="")
                cv.create_text(x+bar_w//2, y_b+10,
                    text=str(canal), fill=C_SUB,
                    font=("Monospace",6))
                cv.create_text(x+bar_w//2, y_b-h-8,
                    text=str(n), fill=col,
                    font=("Monospace",7))

        _dibujar_canales(canales_2g, 10,  "2.4 GHz")
        _dibujar_canales(canales_5g, 300, "5 GHz")

        tk.Label(win,
            text="Verde=canal limpio  |  Naranja=solapamiento  |  Rojo=saturado",
            bg=C_FONDO, fg=C_SUB,
            font=("Monospace",7)).pack(pady=4)

    def _abrir_carpeta_exports(self):
        try:
            import subprocess
            carpeta = os.path.expanduser("~/Proyectos/toporeveal/exports")
            os.makedirs(carpeta, exist_ok=True)
            subprocess.Popen(["xdg-open", carpeta])
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _abrir_wireshark(self):
        sel = self.tree_hs.selection()
        if not sel:
            messagebox.showinfo("Wireshark",
                "Selecciona un handshake de la tabla primero.")
            return
        vals = self.tree_hs.item(sel[0])["values"]
        ruta = vals[5] if vals else ""
        if ruta and ruta != "—" and os.path.exists(ruta):
            try:
                subprocess.Popen(["wireshark", ruta])
            except FileNotFoundError:
                messagebox.showerror("Error",
                    "Wireshark no está instalado.\n"
                    "sudo apt install wireshark")
        else:
            messagebox.showinfo("Wireshark",
                f"Archivo no encontrado: {ruta}\n"
                "El .pcap se guarda cuando se captura el handshake completo.")

    def marcar_monitor_activo(self, interfaz):
        self._monitor_activo = True
        self._interfaz_monitor = interfaz
        self.lbl_monitor.config(
            text=f"● Monitor: {interfaz}",
            fg=C_VERDE)

    def marcar_monitor_inactivo(self):
        self._monitor_activo = False
        self.lbl_monitor.config(
            text="◌ Monitor inactivo",
            fg=C_SUB)
