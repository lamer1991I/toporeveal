"""
ventana_trafico.py — Panel de Análisis de Tráfico en Tiempo Real
TopoReveal · con sistema de filtros completo

Filtros disponibles:
  - Búsqueda libre: IP, protocolo, país, organización, ASN, aplicación
  - Botones rápidos de protocolo (HTTPS, UDP, DNS, XMPP, TCP…)
  - Botones rápidos de país (click en barra de stats)
  - Toggle: Ocultar multicast/broadcast
  - Toggle: Solo con GeoIP (excluir desconocidos)
  - Toggle: Pausar/reanudar la lista
  - Rango de hora: desde/hasta HH:MM:SS
"""

import tkinter as tk
from datetime import datetime
from collections import defaultdict, deque
import threading
import time

# ── Paleta ────────────────────────────────────────────────────────
C_FONDO    = "#0d1117"
C_PANEL    = "#161b22"
C_BORDE    = "#30363d"
C_TEXTO    = "#e6edf3"
C_SUB      = "#8b949e"
C_VERDE    = "#3fb950"
C_CYAN     = "#58d6ff"
C_NARANJA  = "#f0883e"
C_ROJO     = "#da3633"
C_MORADO   = "#a371f7"
C_AZUL     = "#1f6feb"
C_AMARILLO = "#f0e040"
C_ACTIVO   = "#238636"   # fondo botón filtro activo

PROTO_COLOR = {
    "HTTPS": C_VERDE, "HTTP": C_NARANJA, "DNS": C_CYAN,
    "XMPP": C_MORADO, "QUIC": C_AZUL, "TCP": "#388bfd",
    "UDP": "#a371f7", "IGMP": "#8b949e", "ICMP": C_AMARILLO,
    "ICMP-Echo": C_AMARILLO, "SMTP": "#ffa657", "FTP": "#ff7b72",
    "SSH": C_VERDE, "RDP": C_ROJO, "SMB": "#f85149",
    "NTP": "#79c0ff", "SNMP": "#ffa657",
}

APP_MAP = {
    "alibaba": "Alibaba/WeChat", "bytedance": "TikTok",
    "facebook": "Facebook/Instagram", "google": "Google/YouTube",
    "microsoft": "Microsoft", "amazon": "Amazon/AWS",
    "akamai": "Akamai CDN", "fastly": "Fastly CDN",
    "cloudflare": "Cloudflare", "netflix": "Netflix",
    "apple": "Apple/iCloud", "twitter": "Twitter/X",
    "taboola": "Taboola Ads", "huawei": "Huawei Cloud",
    "colombia movil": "Tigo Colombia", "une epm": "UNE Colombia",
}

PROTOS_RAPIDOS = ["HTTPS","HTTP","UDP","TCP","DNS","XMPP","QUIC","ICMP","IGMP"]
MAX_FILAS = 1000
ANCHO_BARRA = 130


def _detectar_app(org):
    if not org: return "Desconocido"
    o = org.lower()
    for k, v in APP_MAP.items():
        if k in o: return v
    return org[:22] if org else "Desconocido"


def _es_local_multicast(ip):
    """True si la IP es multicast, broadcast o link-local."""
    return (ip.startswith("224.") or ip.startswith("239.") or
            ip.startswith("255.") or ip.startswith("169.254."))


class VentanaTrafico:

    def __init__(self, padre, topologia=None):
        self.ventana = tk.Toplevel(padre)
        self.ventana.title("TopoReveal — 📡 Análisis de Tráfico")
        self.ventana.configure(bg=C_FONDO)
        self.ventana.geometry("1280x740")
        self.ventana.minsize(1000, 560)

        self._topologia = topologia
        self._lock      = threading.Lock()

        # Datos
        self._flujos      = deque(maxlen=MAX_FILAS)
        self._stats_pais  = defaultdict(int)
        self._stats_org   = defaultdict(int)
        self._stats_proto = defaultdict(int)
        self._stats_app   = defaultdict(int)
        self._stats_host  = defaultdict(int)
        self._total_pkts  = 0
        self._total_bytes = 0
        self._inicio      = time.time()

        # Estado filtros
        self._filtro_texto  = tk.StringVar()
        self._filtro_proto  = tk.StringVar(value="")   # "" = todos
        self._filtro_pais   = tk.StringVar(value="")
        self._var_multicast = tk.BooleanVar(value=True)  # True = ocultar multicast
        self._var_solo_geo  = tk.BooleanVar(value=False)
        self._var_pausado   = tk.BooleanVar(value=False)
        self._filtro_desde  = tk.StringVar()
        self._filtro_hasta  = tk.StringVar()

        # Caché de filas visibles (resultado del filtro actual)
        self._filas_visibles = []
        self._ultimo_hash_filtro = None

        self._construir_ui()
        self._ciclo()
        self.ventana.protocol("WM_DELETE_WINDOW", self._cerrar)

    # ── UI ────────────────────────────────────────────────────────

    def _construir_ui(self):
        # ── Barra superior ────────────────────────────────────────
        barra = tk.Frame(self.ventana, bg=C_PANEL, height=44)
        barra.pack(fill=tk.X)
        barra.pack_propagate(False)

        tk.Label(barra, text="📡 ANÁLISIS DE TRÁFICO",
            bg=C_PANEL, fg=C_CYAN,
            font=("Monospace", 11, "bold")).pack(side=tk.LEFT, padx=14, pady=10)

        self.lbl_total = tk.Label(barra,
            text="Paquetes: 0  |  0 B  |  0 pps",
            bg=C_PANEL, fg=C_SUB, font=("Monospace", 9))
        self.lbl_total.pack(side=tk.LEFT, padx=12)

        # Pausa / Limpiar
        tk.Checkbutton(barra, text="⏸ Pausar",
            variable=self._var_pausado,
            bg=C_PANEL, fg=C_NARANJA,
            selectcolor=C_FONDO,
            font=("Monospace", 8),
            activebackground=C_PANEL
        ).pack(side=tk.RIGHT, padx=4)

        tk.Button(barra, text="⌫ Limpiar",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8), relief=tk.FLAT,
            cursor="hand2", command=self._limpiar
        ).pack(side=tk.RIGHT, padx=10)

        self.lbl_filtrados = tk.Label(barra, text="",
            bg=C_PANEL, fg=C_AMARILLO, font=("Monospace", 8))
        self.lbl_filtrados.pack(side=tk.RIGHT, padx=8)

        # ── Barra de filtros ──────────────────────────────────────
        fbar = tk.Frame(self.ventana, bg=C_PANEL, height=36)
        fbar.pack(fill=tk.X)
        fbar.pack_propagate(False)

        tk.Label(fbar, text="🔍",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 10)).pack(side=tk.LEFT, padx=(10, 2), pady=6)

        # Entrada de búsqueda libre
        self.entry_busq = tk.Entry(fbar,
            textvariable=self._filtro_texto,
            bg=C_FONDO, fg=C_TEXTO,
            insertbackground=C_CYAN,
            font=("Monospace", 9),
            relief=tk.FLAT, width=22,
            highlightthickness=1,
            highlightcolor=C_CYAN,
            highlightbackground=C_BORDE)
        self.entry_busq.pack(side=tk.LEFT, padx=4, ipady=3)
        self.entry_busq.bind("<Return>", lambda e: (self._aplicar_filtros(), self._actualizar_chips()))
        self.entry_busq.bind("<KeyRelease>", lambda e: (self._aplicar_filtros(), self._actualizar_chips()))

        tk.Label(fbar, text="País:",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8)).pack(side=tk.LEFT, padx=(8,2))
        self.entry_pais = tk.Entry(fbar,
            textvariable=self._filtro_pais,
            bg=C_FONDO, fg=C_CYAN,
            insertbackground=C_CYAN,
            font=("Monospace", 8), relief=tk.FLAT, width=4,
            highlightthickness=1,
            highlightcolor=C_CYAN,
            highlightbackground=C_BORDE)
        self.entry_pais.pack(side=tk.LEFT, padx=2, ipady=3)
        self.entry_pais.bind("<KeyRelease>", lambda e: (self._aplicar_filtros(), self._actualizar_chips()))

        tk.Label(fbar, text="Hora:",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8)).pack(side=tk.LEFT, padx=(8,2))
        tk.Entry(fbar, textvariable=self._filtro_desde,
            bg=C_FONDO, fg=C_TEXTO,
            insertbackground=C_CYAN,
            font=("Monospace", 8), relief=tk.FLAT, width=9,
            highlightthickness=1,
            highlightcolor=C_CYAN,
            highlightbackground=C_BORDE,
            ).pack(side=tk.LEFT, padx=1, ipady=3)
        tk.Label(fbar, text="→",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8)).pack(side=tk.LEFT)
        tk.Entry(fbar, textvariable=self._filtro_hasta,
            bg=C_FONDO, fg=C_TEXTO,
            insertbackground=C_CYAN,
            font=("Monospace", 8), relief=tk.FLAT, width=9,
            highlightthickness=1,
            highlightcolor=C_CYAN,
            highlightbackground=C_BORDE,
            ).pack(side=tk.LEFT, padx=1, ipady=3)
        self._filtro_desde.trace_add("write", lambda *a: self._aplicar_filtros())
        self._filtro_hasta.trace_add("write", lambda *a: self._aplicar_filtros())

        # Separador
        tk.Frame(fbar, bg=C_BORDE, width=1).pack(
            side=tk.LEFT, fill=tk.Y, pady=4, padx=8)

        # Toggles
        tk.Checkbutton(fbar, text="Sin multicast",
            variable=self._var_multicast,
            bg=C_PANEL, fg=C_SUB,
            selectcolor=C_FONDO,
            font=("Monospace", 8),
            command=self._aplicar_filtros,
            activebackground=C_PANEL
        ).pack(side=tk.LEFT, padx=4)

        tk.Checkbutton(fbar, text="Solo GeoIP",
            variable=self._var_solo_geo,
            bg=C_PANEL, fg=C_SUB,
            selectcolor=C_FONDO,
            font=("Monospace", 8),
            command=self._aplicar_filtros,
            activebackground=C_PANEL
        ).pack(side=tk.LEFT, padx=4)

        # Botón limpiar filtros
        tk.Button(fbar, text="✕ Quitar filtros",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8), relief=tk.FLAT,
            cursor="hand2",
            command=self._limpiar_filtros
        ).pack(side=tk.LEFT, padx=8)

        # ── Barra de protocolos rápidos ───────────────────────────
        pbar = tk.Frame(self.ventana, bg=C_FONDO, height=28)
        pbar.pack(fill=tk.X)
        pbar.pack_propagate(False)

        tk.Label(pbar, text="Proto:",
            bg=C_FONDO, fg=C_SUB,
            font=("Monospace", 8)).pack(side=tk.LEFT, padx=(12, 4))

        self._btns_proto = {}
        for proto in PROTOS_RAPIDOS:
            color = PROTO_COLOR.get(proto, C_SUB)
            btn = tk.Button(pbar,
                text=proto,
                bg=C_FONDO, fg=color,
                font=("Monospace", 8, "bold"),
                relief=tk.FLAT, padx=6, pady=1,
                cursor="hand2",
                command=lambda p=proto: self._toggle_proto(p))
            btn.pack(side=tk.LEFT, padx=2)
            self._btns_proto[proto] = btn

        # Botón "Todos"
        self.btn_proto_todos = tk.Button(pbar,
            text="TODOS",
            bg=C_ACTIVO, fg=C_VERDE,
            font=("Monospace", 8, "bold"),
            relief=tk.FLAT, padx=6, pady=1,
            cursor="hand2",
            command=lambda: self._toggle_proto(""))
        self.btn_proto_todos.pack(side=tk.LEFT, padx=4)

        # Separador
        tk.Frame(pbar, bg=C_BORDE, width=1).pack(
            side=tk.LEFT, fill=tk.Y, pady=3, padx=6)

        # Zona de chips — filtros activos con X para quitarlos
        # Se actualiza en _actualizar_chips()
        self._frame_chips = tk.Frame(pbar, bg=C_FONDO)
        self._frame_chips.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # ── Área principal ────────────────────────────────────────
        tk.Frame(self.ventana, bg=C_BORDE, height=1).pack(fill=tk.X)
        area = tk.Frame(self.ventana, bg=C_FONDO)
        area.pack(fill=tk.BOTH, expand=True)

        self._construir_lista(area)
        tk.Frame(area, bg=C_BORDE, width=1).pack(side=tk.LEFT, fill=tk.Y)
        self._construir_stats(area)
        tk.Frame(area, bg=C_BORDE, width=1).pack(side=tk.LEFT, fill=tk.Y)
        self._construir_detalle(area)

        # Barra de estado
        self.lbl_estado = tk.Label(self.ventana,
            text="● En vivo — esperando tráfico...",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8), anchor="w")
        self.lbl_estado.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=2)

    def _construir_lista(self, padre):
        frame = tk.Frame(padre, bg=C_FONDO)
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Cabecera fija
        cab = tk.Frame(frame, bg=C_PANEL)
        cab.pack(fill=tk.X)
        for texto, ancho in [
            ("Hora", 9), ("Origen", 15), ("Destino", 17),
            ("Proto", 7), ("País", 5), ("Organización", 22)
        ]:
            tk.Label(cab, text=texto,
                bg=C_PANEL, fg=C_SUB,
                font=("Monospace", 8, "bold"),
                width=ancho, anchor="w").pack(side=tk.LEFT, padx=2, pady=3)

        # Lista + scroll
        f2 = tk.Frame(frame, bg=C_FONDO)
        f2.pack(fill=tk.BOTH, expand=True)
        sb = tk.Scrollbar(f2, bg=C_PANEL, troughcolor=C_FONDO)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.lista = tk.Listbox(f2,
            bg=C_FONDO, fg=C_TEXTO,
            font=("Monospace", 8),
            relief=tk.FLAT, highlightthickness=0,
            selectbackground=C_AZUL,
            activestyle="none",
            yscrollcommand=sb.set)
        sb.config(command=self.lista.yview)
        self.lista.pack(fill=tk.BOTH, expand=True)
        self.lista.bind("<<ListboxSelect>>", self._on_select)

    def _construir_stats(self, padre):
        frame = tk.Frame(padre, bg=C_PANEL, width=295)
        frame.pack(side=tk.LEFT, fill=tk.Y)
        frame.pack_propagate(False)

        inner = tk.Frame(frame, bg=C_PANEL)
        inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        self._sec_pais  = self._crear_sec(inner, "TOP PAÍSES",       C_CYAN,    8)
        self._sec_app   = self._crear_sec(inner, "TOP APLICACIONES",  C_VERDE,   6)
        self._sec_proto = self._crear_sec(inner, "TOP PROTOCOLOS",    C_MORADO,  7)
        self._sec_host  = self._crear_sec(inner, "TOP ORÍGENES",      C_NARANJA, 5)

    def _crear_sec(self, padre, titulo, color, n):
        tk.Frame(padre, bg=C_BORDE, height=1).pack(fill=tk.X, pady=(5, 3))
        tk.Label(padre, text=titulo,
            bg=C_PANEL, fg=color,
            font=("Monospace", 8, "bold"), anchor="w"
        ).pack(fill=tk.X)
        barras = []
        for _ in range(n):
            fila = tk.Frame(padre, bg=C_PANEL)
            fila.pack(fill=tk.X, pady=1)
            ln = tk.Label(fila, text="",
                bg=C_PANEL, fg=C_TEXTO,
                font=("Monospace", 7), width=18, anchor="w",
                cursor="hand2")
            ln.pack(side=tk.LEFT)
            cv = tk.Canvas(fila, bg=C_PANEL, height=9,
                           width=ANCHO_BARRA, highlightthickness=0)
            cv.pack(side=tk.LEFT, padx=2)
            lc = tk.Label(fila, text="",
                bg=C_PANEL, fg=C_SUB,
                font=("Monospace", 7), width=4, anchor="e")
            lc.pack(side=tk.LEFT)
            barras.append((ln, cv, lc))
        return barras, color

    def _construir_detalle(self, padre):
        frame = tk.Frame(padre, bg=C_PANEL, width=275)
        frame.pack(side=tk.RIGHT, fill=tk.Y)
        frame.pack_propagate(False)

        tk.Label(frame, text="DETALLE DEL FLUJO",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8, "bold"), anchor="w"
        ).pack(fill=tk.X, padx=12, pady=(10, 4))

        # Cabecera con botón limpiar detalle
        cab_det = tk.Frame(frame, bg=C_PANEL)
        cab_det.pack(fill=tk.X, padx=8, pady=(0, 4))

        self.lbl_det_titulo = tk.Label(cab_det,
            text="— Selecciona un flujo —",
            bg=C_PANEL, fg=C_CYAN,
            font=("Monospace", 9, "bold"),
            anchor="w", wraplength=220)
        self.lbl_det_titulo.pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Button(cab_det, text="✕",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 9, "bold"),
            relief=tk.FLAT, padx=4, pady=0,
            cursor="hand2",
            command=self._limpiar_detalle
        ).pack(side=tk.RIGHT, padx=4)

        self._det = {}
        for etq, clave in [
            ("Hora",    "hora"),   ("IP Origen", "ip_src"),
            ("IP Dest", "ip_dst"), ("Protocolo", "proto"),
            ("País",    "pais"),   ("Ciudad",    "ciudad"),
            ("Org",     "org"),    ("ASN",       "asn"),
            ("App",     "app"),    ("Dirección", "dir"),
        ]:
            f = tk.Frame(frame, bg=C_PANEL)
            f.pack(fill=tk.X, padx=12, pady=1)
            tk.Label(f, text=f"{etq}:",
                bg=C_PANEL, fg=C_SUB,
                font=("Monospace", 8), width=10, anchor="w").pack(side=tk.LEFT)
            lbl = tk.Label(f, text="—",
                bg=C_PANEL, fg=C_TEXTO,
                font=("Monospace", 8), anchor="w", wraplength=155)
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self._det[clave] = lbl

        # Botones de acción sobre el flujo seleccionado
        fb = tk.Frame(frame, bg=C_PANEL)
        fb.pack(fill=tk.X, padx=12, pady=4)
        tk.Button(fb, text="🔍 Origen",
            bg=C_FONDO, fg=C_CYAN,
            font=("Monospace", 7), relief=tk.FLAT,
            cursor="hand2",
            command=self._filtrar_origen_sel
        ).pack(side=tk.LEFT, padx=2)
        tk.Button(fb, text="🌐 País",
            bg=C_FONDO, fg=C_CYAN,
            font=("Monospace", 7), relief=tk.FLAT,
            cursor="hand2",
            command=self._filtrar_pais_sel
        ).pack(side=tk.LEFT, padx=2)
        tk.Button(fb, text="📡 Proto",
            bg=C_FONDO, fg=C_CYAN,
            font=("Monospace", 7), relief=tk.FLAT,
            cursor="hand2",
            command=self._filtrar_proto_sel
        ).pack(side=tk.LEFT, padx=2)

        tk.Frame(frame, bg=C_BORDE, height=1).pack(fill=tk.X, padx=8, pady=6)

        tk.Label(frame, text="OTROS FLUJOS DEL HOST",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8, "bold"), anchor="w"
        ).pack(fill=tk.X, padx=12, pady=(0, 4))

        f3 = tk.Frame(frame, bg=C_PANEL)
        f3.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.lista_ctx = tk.Listbox(f3,
            bg=C_FONDO, fg=C_SUB,
            font=("Monospace", 7),
            relief=tk.FLAT, highlightthickness=0)
        self.lista_ctx.pack(fill=tk.BOTH, expand=True)

    # ── FILTROS ───────────────────────────────────────────────────

    def _pasa_filtro(self, fila):
        """Evalúa si una fila pasa todos los filtros activos."""
        # Ocultar multicast/broadcast
        if self._var_multicast.get():
            if _es_local_multicast(fila.get("ip_dst", "")):
                return False

        # Solo con GeoIP válido
        if self._var_solo_geo.get() and not fila.get("geo_ok"):
            return False

        # Filtro protocolo
        proto_f = self._filtro_proto.get()
        if proto_f and fila.get("proto") != proto_f:
            return False

        # Filtro país (ISO 2 letras)
        pais_f = self._filtro_pais.get().strip().upper()
        if pais_f and fila.get("pais", "").upper() != pais_f:
            return False

        # Filtro rango de hora
        desde = self._filtro_desde.get().strip()
        hasta = self._filtro_hasta.get().strip()
        if desde and fila.get("ts", "") < desde:
            return False
        if hasta and fila.get("ts", "") > hasta:
            return False

        # Búsqueda libre — busca en todos los campos de texto
        texto = self._filtro_texto.get().strip().lower()
        if texto:
            campos = [
                fila.get("ip_src",""), fila.get("ip_dst",""),
                fila.get("proto",""), fila.get("pais",""),
                fila.get("org",""),   fila.get("app",""),
                fila.get("ciudad",""),fila.get("asn",""),
            ]
            if not any(texto in str(c).lower() for c in campos):
                return False

        return True

    def _aplicar_filtros(self):
        """Recalcula _filas_visibles y fuerza redibujado de la lista."""
        with self._lock:
            todos = list(self._flujos)
        self._filas_visibles = [f for f in todos if self._pasa_filtro(f)]
        self._redibujar_lista()

    def _toggle_proto(self, proto):
        actual = self._filtro_proto.get()
        nuevo  = "" if actual == proto else proto
        self._filtro_proto.set(nuevo)
        self.btn_proto_todos.config(
            bg=C_ACTIVO if nuevo == "" else C_FONDO,
            fg=C_VERDE  if nuevo == "" else C_SUB)
        for p, btn in self._btns_proto.items():
            color = PROTO_COLOR.get(p, C_SUB)
            btn.config(bg=C_ACTIVO if p == nuevo else C_FONDO, fg=color)
        self._aplicar_filtros()
        self._actualizar_chips()

    def _limpiar_filtros(self):
        self._filtro_texto.set("")
        self._filtro_proto.set("")
        self._filtro_pais.set("")
        self._filtro_desde.set("")
        self._filtro_hasta.set("")
        self._var_multicast.set(True)
        self._var_solo_geo.set(False)
        self.btn_proto_todos.config(bg=C_ACTIVO, fg=C_VERDE)
        for p, btn in self._btns_proto.items():
            btn.config(bg=C_FONDO, fg=PROTO_COLOR.get(p, C_SUB))
        self._aplicar_filtros()
        self._actualizar_chips()

    def _filtrar_origen_sel(self):
        if self._fila_sel:
            self._filtro_texto.set(self._fila_sel.get("ip_src", ""))
            self._aplicar_filtros()
            self._actualizar_chips()

    def _filtrar_pais_sel(self):
        if self._fila_sel:
            self._filtro_pais.set(self._fila_sel.get("pais", ""))
            self._aplicar_filtros()
            self._actualizar_chips()

    def _filtrar_proto_sel(self):
        if self._fila_sel:
            self._toggle_proto(self._fila_sel.get("proto", ""))
            self._actualizar_chips()

    def _actualizar_chips(self):
        """
        Dibuja los chips de filtros activos en la barra de protocolos.
        Cada chip muestra el valor del filtro y una X para quitarlo.
        """
        # Limpiar chips anteriores
        for w in self._frame_chips.winfo_children():
            w.destroy()

        chips = []

        # Chip de búsqueda libre
        texto = self._filtro_texto.get().strip()
        if texto:
            chips.append(("🔍 " + texto[:18], lambda: (
                self._filtro_texto.set(""),
                self._aplicar_filtros(),
                self._actualizar_chips()
            )))

        # Chip de país
        pais = self._filtro_pais.get().strip().upper()
        if pais:
            chips.append(("🌐 " + pais, lambda: (
                self._filtro_pais.set(""),
                self._aplicar_filtros(),
                self._actualizar_chips()
            )))

        # Chip de protocolo
        proto = self._filtro_proto.get()
        if proto:
            color = PROTO_COLOR.get(proto, C_SUB)
            chips.append(("📡 " + proto, lambda: (
                self._toggle_proto(""),
                self._actualizar_chips()
            )))

        # Chip de rango de hora
        desde = self._filtro_desde.get().strip()
        hasta = self._filtro_hasta.get().strip()
        if desde or hasta:
            rango = f"⏱ {desde or '?'} → {hasta or '?'}"
            chips.append((rango, lambda: (
                self._filtro_desde.set(""),
                self._filtro_hasta.set(""),
                self._aplicar_filtros(),
                self._actualizar_chips()
            )))

        # Chip solo GeoIP
        if self._var_solo_geo.get():
            chips.append(("✓ Solo GeoIP", lambda: (
                self._var_solo_geo.set(False),
                self._aplicar_filtros(),
                self._actualizar_chips()
            )))

        # Dibujar los chips
        for label_texto, accion in chips:
            chip = tk.Frame(self._frame_chips,
                bg="#1f3a4a", relief=tk.FLAT,
                highlightthickness=1,
                highlightbackground=C_CYAN)
            chip.pack(side=tk.LEFT, padx=3, pady=2)

            tk.Label(chip,
                text=label_texto,
                bg="#1f3a4a", fg=C_CYAN,
                font=("Monospace", 7)
            ).pack(side=tk.LEFT, padx=(5, 1))

            # X para quitar este chip
            btn_x = tk.Button(chip,
                text="✕",
                bg="#1f3a4a", fg=C_NARANJA,
                font=("Monospace", 7, "bold"),
                relief=tk.FLAT, padx=2, pady=0,
                cursor="hand2",
                command=accion)
            btn_x.pack(side=tk.LEFT, padx=(0, 3))

    def _quitar_chip_texto(self):
        self._filtro_texto.set("")
        self._aplicar_filtros()
        self._actualizar_chips()

    # ── INGESTA ───────────────────────────────────────────────────

    def registrar_flujo(self, ip_src, ip_dst, protocolo, geo=None, bytes_n=0):
        if self._var_pausado.get():
            return

        ts  = datetime.now().strftime("%H:%M:%S")
        geo = geo or {}

        fila = {
            "ts"    : ts,
            "ip_src": ip_src,
            "ip_dst": ip_dst,
            "proto" : protocolo,
            "pais"  : geo.get("iso","") or "??",
            "ciudad": geo.get("ciudad","") or geo.get("pais","") or "?",
            "org"   : geo.get("org","") or "?",
            "asn"   : geo.get("asn","") or "",
            "app"   : _detectar_app(geo.get("org","")),
            "bytes" : bytes_n,
            "geo_ok": geo.get("ok", False)
        }

        with self._lock:
            self._flujos.appendleft(fila)
            self._total_pkts  += 1
            self._total_bytes += bytes_n

            # Stats — solo flujos con GeoIP para no contaminar
            if fila["geo_ok"]:
                nombre_pais = geo.get("pais", fila["pais"])
                self._stats_pais[f"[{fila['pais']}] {nombre_pais}"] += 1
                self._stats_org[fila["org"]] += 1
                self._stats_app[fila["app"]] += 1
            self._stats_proto[protocolo] += 1
            if not _es_local_multicast(ip_dst):
                self._stats_host[ip_src] += 1

    # ── CICLO ─────────────────────────────────────────────────────

    def _ciclo(self):
        try:
            if not self._var_pausado.get():
                self._aplicar_filtros()
                self._actualizar_stats()
                self._actualizar_contador()
        except Exception:
            pass
        try:
            self.ventana.after(1200, self._ciclo)
        except Exception:
            pass

    def _redibujar_lista(self):
        """Redibuja la lista con las filas visibles actuales."""
        self.lista.delete(0, tk.END)
        for f in self._filas_visibles:
            org_c = (f["org"][:20] if f["org"] and f["org"] != "?" else "")
            linea = (f"{f['ts']:<9}"
                     f"{f['ip_src']:<16}"
                     f"{f['ip_dst']:<17}"
                     f"{f['proto']:<8}"
                     f"[{f['pais']:<3}] "
                     f"{org_c}")
            self.lista.insert(tk.END, linea)
            color = PROTO_COLOR.get(f["proto"], C_TEXTO)
            self.lista.itemconfig(self.lista.size()-1, fg=color)

        # Actualizar contador de filas filtradas
        total = len(self._flujos)
        vis   = len(self._filas_visibles)
        if vis < total:
            self.lbl_filtrados.config(
                text=f"Mostrando {vis} de {total}",
                fg=C_AMARILLO)
        else:
            self.lbl_filtrados.config(text="")

    def _actualizar_stats(self):
        try:
            with self._lock:
                datos_pais  = dict(self._stats_pais)
                datos_app   = dict(self._stats_app)
                datos_proto = dict(self._stats_proto)
                datos_host  = dict(self._stats_host)

            self._render_sec(self._sec_pais,  datos_pais,  "pais")
            self._render_sec(self._sec_app,   datos_app,   "app")
            self._render_sec(self._sec_proto, datos_proto, "proto")
            self._render_sec(self._sec_host,  datos_host,  "host")
        except Exception:
            pass

    def _render_sec(self, sec, datos, tipo):
        """Renderiza una sección de barras con los datos dados."""
        barras, color = sec
        top     = sorted(datos.items(), key=lambda x: x[1], reverse=True)
        maximo  = top[0][1] if top else 1

        for i, (ln, cv, lc) in enumerate(barras):
            if i < len(top):
                nombre, val = top[i]
                nombre_corto = nombre[:18]
                ln.config(text=nombre_corto, fg=C_TEXTO)
                lc.config(text=str(val))
                cv.delete("all")
                w = int(ANCHO_BARRA * val / max(maximo, 1))
                if w > 0:
                    cv.create_rectangle(0, 1, w, 8, fill=color, outline="")
                cv.create_rectangle(w, 1, ANCHO_BARRA, 8,
                                    fill=C_BORDE, outline="")
                # Click en etiqueta → aplicar filtro correspondiente
                if tipo == "pais":
                    # Extraer código ISO del formato "[CO] Colombia"
                    iso = nombre[1:3] if nombre.startswith("[") else nombre[:2]
                    ln.config(cursor="hand2")
                    ln.bind("<Button-1>",
                        lambda e, v=iso: self._click_filtro_pais(v))
                elif tipo in ("app", "host"):
                    ln.config(cursor="hand2")
                    ln.bind("<Button-1>",
                        lambda e, v=nombre: self._click_filtro_texto(v))
                elif tipo == "proto":
                    ln.config(cursor="hand2")
                    ln.bind("<Button-1>",
                        lambda e, v=nombre: self._toggle_proto(v))
            else:
                ln.config(text="", cursor="")
                lc.config(text="")
                cv.delete("all")
                cv.create_rectangle(0, 1, ANCHO_BARRA, 8,
                                    fill=C_BORDE, outline="")

    def _click_filtro_pais(self, iso):
        self._filtro_pais.set(iso)
        self._aplicar_filtros()
        self._actualizar_chips()

    def _click_filtro_texto(self, valor):
        self._filtro_texto.set(valor)
        self._aplicar_filtros()
        self._actualizar_chips()

    def _actualizar_contador(self):
        with self._lock:
            pkts = self._total_pkts
            bts  = self._total_bytes
            t    = time.time() - self._inicio
        pps = pkts / max(t, 1)
        bs  = f"{bts/1024:.1f}KB" if bts > 1024 else f"{bts}B"
        self.lbl_total.config(
            text=f"Paquetes: {pkts}  |  {bs}  |  {pps:.1f} pps")
        estado = "⏸ Pausado" if self._var_pausado.get() else "● En vivo"
        color  = C_NARANJA   if self._var_pausado.get() else C_VERDE
        self.lbl_estado.config(text=estado, fg=color)

    # ── SELECCIÓN ─────────────────────────────────────────────────

    def _on_select(self, event):
        sel = self.lista.curselection()
        if not sel: return
        idx = sel[0]
        if idx >= len(self._filas_visibles): return
        fila = self._filas_visibles[idx]
        self._fila_sel = fila
        self._mostrar_detalle(fila)

    def _mostrar_detalle(self, fila):
        proto = fila.get("proto","?")
        color = PROTO_COLOR.get(proto, C_CYAN)
        self.lbl_det_titulo.config(
            text=f"{fila['ip_src']} → {fila['ip_dst']}", fg=color)
        self._det["hora"  ].config(text=fila.get("ts","—"),      fg=C_SUB)
        self._det["ip_src"].config(text=fila.get("ip_src","—"),   fg=C_TEXTO)
        self._det["ip_dst"].config(text=fila.get("ip_dst","—"),   fg=C_TEXTO)
        self._det["proto" ].config(text=proto,                    fg=color)
        self._det["pais"  ].config(
            text=f"[{fila.get('pais','?')}] {fila.get('ciudad','')}",
            fg=C_CYAN)
        self._det["ciudad"].config(text=fila.get("ciudad","—"),   fg=C_TEXTO)
        self._det["org"   ].config(text=fila.get("org","—"),      fg=C_TEXTO)
        self._det["asn"   ].config(text=fila.get("asn","—"),      fg=C_SUB)
        self._det["app"   ].config(text=fila.get("app","—"),      fg=C_VERDE)
        self._det["dir"   ].config(
            text="Saliente" if fila.get("geo_ok") else "Local/Multicast",
            fg=C_SUB)

        # Otros flujos del mismo origen
        self.lista_ctx.delete(0, tk.END)
        ip_src = fila.get("ip_src")
        with self._lock:
            otros = [f for f in self._flujos
                     if f.get("ip_src")==ip_src and f is not fila][:25]
        visto = set()
        for f in otros:
            k = f"{f['ip_dst']}:{f['proto']}"
            if k not in visto:
                visto.add(k)
                org_c = f["org"][:12] if f["org"] and f["org"] != "?" else "?"
                self.lista_ctx.insert(tk.END,
                    f"{f['ts']} {f['proto']:<7} {f['ip_dst']:<16} {org_c}")
        if not visto:
            self.lista_ctx.insert(tk.END, "  Sin otros flujos")

    # ── LIMPIAR / CERRAR ──────────────────────────────────────────

    def _limpiar(self):
        with self._lock:
            self._flujos.clear()
            self._stats_pais.clear()
            self._stats_org.clear()
            self._stats_proto.clear()
            self._stats_app.clear()
            self._stats_host.clear()
            self._total_pkts  = 0
            self._total_bytes = 0
            self._inicio      = time.time()
        self._filas_visibles = []
        self.lista.delete(0, tk.END)

    def _limpiar_detalle(self):
        """Limpia el panel de detalle derecho sin tocar la lista ni los filtros."""
        self._fila_sel = None
        self.lbl_det_titulo.config(
            text="— Selecciona un flujo —", fg=C_CYAN)
        for lbl in self._det.values():
            lbl.config(text="—", fg=C_TEXTO)
        self.lista_ctx.delete(0, tk.END)

    def _cerrar(self):
        try:
            self.ventana.destroy()
        except Exception:
            pass
        self.ventana = None
