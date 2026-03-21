"""
ventana_wifi.py — ⚡ WiFi Scope
Panel visual de entorno WiFi con canvas de nodos estilo Packet Tracer.
Cada AP es un nodo interactivo con ícono de router 3D neon.
"""

import tkinter as tk
from datetime import datetime
from collections import defaultdict
import math
import time

# ── Paleta ────────────────────────────────────────────────────────
C_FONDO    = "#0d1117"
C_PANEL    = "#161b22"
C_BORDE    = "#30363d"
C_TEXTO    = "#e6edf3"
C_SUB      = "#8b949e"
C_NUESTRA  = "#3fb950"
C_VECINA   = "#58d6ff"
C_ALERTA   = "#f0883e"
C_ACENTO   = "#1f6feb"
C_MORADO   = "#a371f7"
C_OSCURO   = "#010409"

RADIO_AP      = 30
RADIO_CLIENTE = 14
ORBITA_DIST   = 85


def _mezclar(hex1, hex2, t):
    try:
        r1,g1,b1 = int(hex1[1:3],16),int(hex1[3:5],16),int(hex1[5:7],16)
        r2,g2,b2 = int(hex2[1:3],16),int(hex2[3:5],16),int(hex2[5:7],16)
        return f"#{int(r1+(r2-r1)*t):02x}{int(g1+(g2-g1)*t):02x}{int(b1+(b2-b1)*t):02x}"
    except Exception:
        return hex1


def _dibujar_ap(canvas, cx, cy, radio, color, es_nuestra=False, seleccionado=False):
    """Dibuja un nodo router/AP estilo Cisco Packet Tracer en el canvas tkinter."""
    fill  = _mezclar(color, C_FONDO, 0.6)
    brill = _mezclar(color, "#ffffff", 0.3)

    # Anillo de selección
    if seleccionado:
        canvas.create_oval(
            cx-radio-10, cy-radio-10, cx+radio+10, cy+radio+10,
            outline=color, width=2, dash=(5,3))

    # Sombra
    canvas.create_oval(
        cx-radio+6, cy+radio//2,
        cx+radio-6, cy+radio//2+10,
        fill="#000000", outline="", stipple="gray12")

    # Cara lateral cilindro
    canvas.create_arc(
        cx-radio, cy-radio//3, cx+radio, cy+radio,
        start=180, extent=180,
        fill=fill, outline=color, width=1, style=tk.CHORD)

    # Rectángulo medio
    canvas.create_rectangle(
        cx-radio, cy-radio//3, cx+radio, cy+radio//2,
        fill=fill, outline="")

    # Borde lateral
    canvas.create_line(cx-radio, cy-radio//3, cx-radio, cy+radio//2, fill=color, width=1)
    canvas.create_line(cx+radio, cy-radio//3, cx+radio, cy+radio//2, fill=color, width=1)

    # Cara superior (elipse brillante)
    canvas.create_oval(
        cx-radio, cy-radio//2, cx+radio, cy+radio//3,
        fill=brill, outline=color, width=1.5)

    # Flechas en la cara superior
    for pts in [
        [cx-radio//2,cy-4, cx-radio//2-9,cy, cx-radio//2,cy+4],  # izq
        [cx+radio//2,cy-4, cx+radio//2+9,cy, cx+radio//2,cy+4],  # der
        [cx-4,cy-radio//3, cx,cy-radio//3-9, cx+4,cy-radio//3],  # arr
        [cx-4,cy+radio//4, cx,cy+radio//4+9, cx+4,cy+radio//4],  # abj
    ]:
        canvas.create_polygon(pts, fill="#ffffff", outline="")

    # LED
    canvas.create_oval(cx-3, cy-radio//2, cx+3, cy-radio//2+7,
                       fill=C_NUESTRA, outline="")

    # Ondas WiFi
    for i, (r, op) in enumerate([(10,1.0),(17,0.65),(24,0.35)]):
        canvas.create_arc(
            cx-r, cy-radio//2-r-2, cx+r, cy-radio//2+r-2,
            start=25, extent=130,
            outline=_mezclar(color,"#ffffff",0.2),
            width=max(1, 2-i*0.4), style=tk.ARC)

    # Corona estrella nuestra red
    if es_nuestra:
        canvas.create_text(cx, cy-radio-16,
            text="★ NUESTRA", fill=C_NUESTRA,
            font=("Monospace", 8, "bold"))


def _dibujar_cliente(canvas, cx, cy, radio, color):
    """Dibuja un nodo cliente (PC/dispositivo)."""
    fill = _mezclar(color, C_FONDO, 0.7)
    # Monitor
    canvas.create_rectangle(
        cx-radio, cy-radio, cx+radio, cy+radio//2,
        fill=C_PANEL, outline=color, width=1)
    # Pantalla
    canvas.create_rectangle(
        cx-radio+3, cy-radio+3, cx+radio-3, cy+radio//2-3,
        fill=C_OSCURO, outline="")
    # Líneas de actividad
    for y_off in [-radio//3+2, 2, radio//5+2]:
        canvas.create_line(
            cx-radio+5, cy+y_off, cx+radio-8, cy+y_off,
            fill=color, width=1)
    # Base
    canvas.create_rectangle(
        cx-radio//3, cy+radio//2,
        cx+radio//3, cy+radio//2+5,
        fill=C_BORDE, outline="")
    canvas.create_rectangle(
        cx-radio//2, cy+radio//2+5,
        cx+radio//2, cy+radio//2+9,
        fill=C_BORDE, outline="")


class VentanaWifi:
    """⚡ WiFi Scope — visualización de nodos WiFi estilo Packet Tracer."""

    def __init__(self, padre, bssid_propio=None):
        self.ventana = tk.Toplevel(padre)
        self.ventana.title("TopoReveal — ⚡ WiFi Scope")
        self.ventana.configure(bg=C_FONDO)
        self.ventana.geometry("1100x700")
        self.ventana.minsize(800, 500)

        self._aps          = {}
        self._handshakes   = []   # [(ts, bssid, cliente, es_nuestra, ssid, archivo)]
        self._bssid_propio = bssid_propio.lower() if bssid_propio else None
        self._nodo_sel     = None
        self._posiciones   = {}
        self._lock         = __import__("threading").Lock()
        # Zoom del canvas
        self._zoom         = 1.0
        self._offset_x     = 0
        self._offset_y     = 0
        self._drag_start   = None

        self._construir_ui()
        self._ciclo()
        self.ventana.protocol("WM_DELETE_WINDOW", self._cerrar)

    def set_bssid_propio(self, bssid):
        if bssid:
            with self._lock:
                self._bssid_propio = bssid.lower()

    # ── UI ────────────────────────────────────────────────────────

    def _construir_ui(self):
        # Barra
        barra = tk.Frame(self.ventana, bg=C_PANEL, height=44)
        barra.pack(fill=tk.X)
        barra.pack_propagate(False)

        tk.Label(barra, text="⚡ WiFi SCOPE",
            bg=C_PANEL, fg=C_MORADO,
            font=("Monospace", 12, "bold")).pack(side=tk.LEFT, padx=16, pady=10)

        self.lbl_monitor = tk.Label(barra, text="◌ Monitor inactivo",
            bg=C_PANEL, fg=C_SUB, font=("Monospace", 8))
        self.lbl_monitor.pack(side=tk.LEFT, padx=8)

        self.lbl_count = tk.Label(barra, text="",
            bg=C_PANEL, fg=C_VECINA, font=("Monospace", 9, "bold"))
        self.lbl_count.pack(side=tk.RIGHT, padx=16)

        # Área principal
        area = tk.Frame(self.ventana, bg=C_FONDO)
        area.pack(fill=tk.BOTH, expand=True)

        # Canvas
        self.cv = tk.Canvas(area, bg=C_FONDO,
                            highlightthickness=0, cursor="crosshair")
        self.cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.cv.bind("<Button-1>",   self._click)
        self.cv.bind("<ButtonPress-2>",   self._drag_start_ev)
        self.cv.bind("<B2-Motion>",       self._drag_move)
        self.cv.bind("<ButtonPress-3>",   self._drag_start_ev)
        self.cv.bind("<B3-Motion>",       self._drag_move)
        # Zoom con Ctrl+rueda
        self.cv.bind("<Control-MouseWheel>", self._zoom_wheel)
        self.cv.bind("<Control-Button-4>",   lambda e: self._zoom_step(1.1))
        self.cv.bind("<Control-Button-5>",   lambda e: self._zoom_step(0.9))
        # Rueda sin Ctrl: scroll vertical
        self.cv.bind("<MouseWheel>", lambda e: self._scroll(e.delta))
        self.cv.bind("<Button-4>",   lambda e: self._scroll(120))
        self.cv.bind("<Button-5>",   lambda e: self._scroll(-120))

        # Separador
        tk.Frame(area, bg=C_BORDE, width=1).pack(side=tk.LEFT, fill=tk.Y)

        # Panel lateral
        self.panel = tk.Frame(area, bg=C_PANEL, width=290)
        self.panel.pack(side=tk.RIGHT, fill=tk.Y)
        self.panel.pack_propagate(False)
        self._build_panel()

        # Estado
        self.lbl_estado = tk.Label(self.ventana,
            text="Esperando datos del monitor 802.11...",
            bg=C_PANEL, fg=C_SUB, font=("Monospace", 8), anchor="w")
        self.lbl_estado.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=3)

    def _build_panel(self):
        p = self.panel

        tk.Label(p, text="NODO SELECCIONADO",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8, "bold"), anchor="w"
        ).pack(fill=tk.X, padx=12, pady=(12,4))

        self.lbl_ssid = tk.Label(p,
            text="— Haz clic en un nodo —",
            bg=C_PANEL, fg=C_VECINA,
            font=("Monospace", 10, "bold"),
            anchor="w", wraplength=260)
        self.lbl_ssid.pack(fill=tk.X, padx=12, pady=(0,8))

        self._campos = {}
        for etq, clave in [
            ("BSSID","bssid"),("Canal","canal"),("Cifrado","cifrado"),
            ("Señal","rssi"),("Clientes","n_cli"),("Paquetes","pkts"),
            ("Visto","primer_visto"),("Estado","estado"),
        ]:
            f = tk.Frame(p, bg=C_PANEL)
            f.pack(fill=tk.X, padx=12, pady=1)
            tk.Label(f, text=f"{etq}:",
                bg=C_PANEL, fg=C_SUB,
                font=("Monospace", 8), width=9, anchor="w").pack(side=tk.LEFT)
            lbl = tk.Label(f, text="—",
                bg=C_PANEL, fg=C_TEXTO,
                font=("Monospace", 8), anchor="w", wraplength=160)
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self._campos[clave] = lbl

        tk.Frame(p, bg=C_BORDE, height=1).pack(fill=tk.X, padx=8, pady=8)

        tk.Label(p, text="CLIENTES ASOCIADOS",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8, "bold"), anchor="w"
        ).pack(fill=tk.X, padx=12, pady=(0,4))

        f2 = tk.Frame(p, bg=C_PANEL)
        f2.pack(fill=tk.X, padx=8)
        sb = tk.Scrollbar(f2, bg=C_PANEL)
        self.lista_cli = tk.Listbox(f2,
            bg=C_FONDO, fg=C_NUESTRA,
            font=("Monospace", 8), height=5,
            relief=tk.FLAT, highlightthickness=0,
            yscrollcommand=sb.set)
        sb.config(command=self.lista_cli.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.lista_cli.pack(fill=tk.X, expand=True)

        tk.Frame(p, bg=C_BORDE, height=1).pack(fill=tk.X, padx=8, pady=8)

        # Handshakes — con info de archivo .pcap
        hdr_hs = tk.Frame(p, bg=C_PANEL)
        hdr_hs.pack(fill=tk.X, padx=12, pady=(0,4))
        tk.Label(hdr_hs, text="HANDSHAKES WPA2",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 8, "bold"), anchor="w"
        ).pack(side=tk.LEFT)
        tk.Button(hdr_hs, text="📂",
            bg=C_PANEL, fg=C_ALERTA,
            font=("Monospace", 9), relief=tk.FLAT,
            cursor="hand2",
            command=self._abrir_carpeta_exports
        ).pack(side=tk.RIGHT)

        f3 = tk.Frame(p, bg=C_PANEL)
        f3.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0,8))
        self.lista_hs = tk.Listbox(f3,
            bg=C_FONDO, fg=C_ALERTA,
            font=("Monospace", 8),
            relief=tk.FLAT, highlightthickness=0,
            selectbackground=C_ACENTO)
        sb_hs = tk.Scrollbar(f3, command=self.lista_hs.yview, bg=C_PANEL)
        self.lista_hs.config(yscrollcommand=sb_hs.set)
        sb_hs.pack(side=tk.RIGHT, fill=tk.Y)
        self.lista_hs.pack(fill=tk.BOTH, expand=True)

    # ── EVENTOS ───────────────────────────────────────────────────

    def procesar_evento(self, evento):
        tipo = evento.get("tipo")
        with self._lock:
            if tipo == "ap_detectado":
                self._reg_ap(evento)
            elif tipo == "handshake_wpa2":
                self._reg_hs(evento)
            elif tipo == "trafico_externo":
                b = (evento.get("bssid") or "").lower()
                if b in self._aps:
                    self._aps[b]["pkts"] += 1
        try:
            self.ventana.after(0, lambda: self.lbl_monitor.config(
                text="● Monitor activo", fg=C_NUESTRA))
        except Exception:
            pass

    def _reg_ap(self, ev):
        bssid = (ev.get("bssid") or "").lower().strip()
        if not bssid or bssid in ("ff:ff:ff:ff:ff:ff","00:00:00:00:00:00"):
            return
        es_nuestra = ev.get("es_nuestra_red", False)
        if not es_nuestra and self._bssid_propio:
            es_nuestra = (bssid == self._bssid_propio)
        if es_nuestra:
            self._bssid_propio = bssid
        if bssid not in self._aps:
            self._aps[bssid] = {
                "ssid": ev.get("ssid") or "<oculto>",
                "canal": ev.get("canal", 0),
                "cifrado": ev.get("cifrado","?"),
                "rssi": ev.get("rssi"),
                "clientes": set(),
                "pkts": 0,
                "es_nuestra": es_nuestra,
                "primer_visto": datetime.now().strftime("%H:%M:%S"),
                "handshake": False,
            }
        else:
            ap = self._aps[bssid]
            if ev.get("ssid"): ap["ssid"] = ev["ssid"]
            if ev.get("rssi") is not None: ap["rssi"] = ev["rssi"]
            if ev.get("canal"): ap["canal"] = ev["canal"]
            if es_nuestra: ap["es_nuestra"] = True

    def _reg_hs(self, ev):
        ts     = datetime.now().strftime("%H:%M:%S")
        bssid  = (ev.get("bssid") or "").lower()
        cliente = ev.get("cliente_mac","?")
        es_n   = ev.get("es_nuestra_red", False)
        ssid   = ev.get("ssid","?")
        archivo = ev.get("archivo","")  # nombre del .pcap si se guardó
        n_f    = ev.get("n_frames", 0)
        self._handshakes.append((ts, bssid, cliente, es_n, ssid, archivo, n_f))
        if bssid in self._aps:
            self._aps[bssid]["handshake"] = True

    def _abrir_carpeta_exports(self):
        """Abre la carpeta exports/ en el gestor de archivos."""
        try:
            import os, subprocess as sp
            usuario = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
            import pwd
            home = pwd.getpwnam(usuario).pw_dir
            carpeta = os.path.join(home, "Proyectos", "toporeveal", "exports")
            os.makedirs(carpeta, exist_ok=True)
            sp.Popen(["xdg-open", carpeta])
        except Exception:
            pass

    # ── ZOOM Y DRAG ───────────────────────────────────────────────

    def _zoom_wheel(self, event):
        factor = 1.1 if event.delta > 0 else 0.9
        self._zoom_step(factor)

    def _zoom_step(self, factor):
        self._zoom = max(0.3, min(3.0, self._zoom * factor))

    def _scroll(self, delta):
        self._offset_y += int(delta * 0.3)

    def _drag_start_ev(self, event):
        self._drag_start = (event.x, event.y)

    def _drag_move(self, event):
        if self._drag_start:
            dx = event.x - self._drag_start[0]
            dy = event.y - self._drag_start[1]
            self._offset_x += dx
            self._offset_y += dy
            self._drag_start = (event.x, event.y)

    # ── CANVAS ────────────────────────────────────────────────────

    def _ciclo(self):
        try:
            self._render()
            self._actualizar_panel()
        except Exception:
            pass
        try:
            self.ventana.after(1500, self._ciclo)
        except Exception:
            pass

    def _render(self):
        with self._lock:
            aps = dict(self._aps)

        self.cv.delete("all")
        w = self.cv.winfo_width() or 740
        h = self.cv.winfo_height() or 500

        # Grid de fondo
        for x in range(0, w, 38):
            self.cv.create_line(x,0,x,h, fill=C_PANEL, width=1)
        for y in range(0, h, 38):
            self.cv.create_line(0,y,w,y, fill=C_PANEL, width=1)

        # Hint de zoom
        self.cv.create_text(8, h-12,
            text=f"Ctrl+rueda: zoom {self._zoom:.1f}x | drag clic derecho",
            fill=C_SUB, font=("Monospace",7), anchor="w")

        if not aps:
            self.cv.create_text(w//2, h//2,
                text="⚡ Escaneando el aire...\n\nEl monitor 802.11 está buscando\nredes WiFi cercanas",
                fill=C_SUB, font=("Monospace", 12), justify=tk.CENTER)
            self.lbl_count.config(text="APs: 0")
            return

        # Centro con offset (drag) y zoom
        z   = self._zoom
        cxc = w//2 + self._offset_x
        cyc = h//2 + self._offset_y

        lista = sorted(aps.items(),
                       key=lambda x:(0 if x[1].get("es_nuestra") else 1, x[0]))
        n = len(lista)

        # Radio del layout — más grande con zoom, mínimo separación legible
        # Con muchos APs usar radio mayor para que no se encimen
        radio_min  = max(150, n * 18)
        r_layout   = int(min(min(w,h)//2 - RADIO_AP*2 - 40, radio_min) * z)
        pos = {}

        if n == 1:
            pos[lista[0][0]] = (cxc, cyc)
        else:
            for i,(bssid,_) in enumerate(lista):
                ang = (2*math.pi*i/n) - math.pi/2
                pos[bssid] = (int(cxc + r_layout*math.cos(ang)),
                              int(cyc + r_layout*math.sin(ang)))

        self._posiciones = pos

        # Radio visual del nodo escalado con zoom
        radio_nodo = int(RADIO_AP * z)
        radio_nodo = max(12, min(40, radio_nodo))

        # Líneas entre APs
        blist = [b for b,_ in lista]
        for i,b1 in enumerate(blist):
            for b2 in blist[i+1:]:
                p1,p2 = pos[b1], pos[b2]
                self.cv.create_line(p1[0],p1[1],p2[0],p2[1],
                    fill=C_BORDE, width=1, dash=(4,12))

        # Nodos
        for bssid, ap in lista:
            px, py = pos[bssid]
            tiene_hs   = ap.get("handshake", False)
            es_nuestra = ap.get("es_nuestra", False)
            sel        = (bssid == self._nodo_sel)

            color = C_ALERTA if tiene_hs else (C_NUESTRA if es_nuestra else C_VECINA)

            # Clientes
            clientes = list(ap.get("clientes", set()))
            nc = len(clientes)
            orbita = int(ORBITA_DIST * z)
            for i, mac in enumerate(clientes[:6]):
                ang    = (2*math.pi*i/max(nc,1)) - math.pi/2
                cxc2   = int(px + orbita*math.cos(ang))
                cyc2   = int(py + orbita*math.sin(ang))
                rc     = int(RADIO_CLIENTE * z)
                rc     = max(8, min(20, rc))
                self.cv.create_line(px, py+radio_nodo//3, cxc2, cyc2,
                    fill=_mezclar(color,C_FONDO,0.55), width=1, dash=(3,6))
                _dibujar_cliente(self.cv, cxc2, cyc2, rc, color)
                if z > 0.6:
                    self.cv.create_text(cxc2, cyc2+rc+8,
                        text=mac[-8:].upper(), fill=C_SUB,
                        font=("Monospace", max(5,int(6*z))))

            # Nodo AP
            _dibujar_ap(self.cv, px, py, radio_nodo, color,
                        es_nuestra=es_nuestra, seleccionado=sel)

            # Etiquetas — solo si hay espacio suficiente
            ssid = ap.get("ssid","?")
            # Truncar según zoom: más zoom = más texto visible
            max_chars = max(8, int(14 * z))
            if len(ssid) > max_chars:
                ssid = ssid[:max_chars-1]+"…"

            fs_ssid = max(7, int(9 * z))
            fs_bssid = max(6, int(7 * z))

            self.cv.create_text(px, py+radio_nodo+int(12*z),
                text=ssid, fill=color,
                font=("Monospace", fs_ssid, "bold"))

            if z > 0.5:
                self.cv.create_text(px, py+radio_nodo+int(22*z),
                    text=bssid.upper()[:17], fill=C_SUB,
                    font=("Monospace", fs_bssid))

            rssi = ap.get("rssi")
            if rssi is not None and z > 0.6:
                self.cv.create_text(px, py+radio_nodo+int(32*z),
                    text=f"{self._barras(rssi)} {rssi}dBm",
                    fill=color, font=("Monospace", fs_bssid))

            if tiene_hs:
                self.cv.create_text(px+radio_nodo+4, py-radio_nodo+2,
                    text="⚠HS", fill=C_ALERTA,
                    font=("Monospace", max(6, int(7*z)), "bold"))

            # Área clickeable
            tag = f"ap_{bssid.replace(':','_')}"
            self.cv.create_rectangle(
                px-radio_nodo-4, py-radio_nodo-int(20*z),
                px+radio_nodo+4, py+radio_nodo+int(45*z),
                outline="", fill="", tags=(tag,))
            self.cv.tag_bind(tag, "<Button-1>",
                lambda e, b=bssid: self._sel(b))
            self.cv.tag_bind(tag, "<Enter>",
                lambda e: self.cv.config(cursor="hand2"))
            self.cv.tag_bind(tag, "<Leave>",
                lambda e: self.cv.config(cursor="crosshair"))

        n_nuestra = sum(1 for a in aps.values() if a.get("es_nuestra"))
        self.lbl_count.config(
            text=f"APs: {n}  |  ★ propia: {n_nuestra}  |  vecinas: {n-n_nuestra}")

    def _barras(self, rssi):
        if rssi is None: return "?"
        if rssi >= -50:  return "▂▄▆█"
        if rssi >= -65:  return "▂▄▆░"
        if rssi >= -75:  return "▂▄░░"
        if rssi >= -85:  return "▂░░░"
        return "░░░░"

    def _click(self, ev):
        x, y = ev.x, ev.y
        mejor, dist_min = None, float("inf")
        for bssid,(px,py) in self._posiciones.items():
            d = math.sqrt((x-px)**2+(y-py)**2)
            if d < dist_min and d < RADIO_AP+50:
                dist_min, mejor = d, bssid
        self._sel(mejor) if mejor else setattr(self, "_nodo_sel", None)

    def _sel(self, bssid):
        self._nodo_sel = bssid
        self._det(bssid)

    def _det(self, bssid):
        with self._lock:
            ap = dict(self._aps.get(bssid, {}))
        if not ap:
            return

        es_nuestra = ap.get("es_nuestra", False)
        tiene_hs   = ap.get("handshake", False)
        color = C_ALERTA if tiene_hs else (C_NUESTRA if es_nuestra else C_VECINA)

        ssid = ap.get("ssid","?")
        pref = "★ " if es_nuestra else ""
        self.lbl_ssid.config(text=f"{pref}{ssid}", fg=color)

        rssi = ap.get("rssi")
        rssi_str = f"{self._barras(rssi)} {rssi} dBm" if rssi else "—"
        estado = ("NUESTRA RED" if es_nuestra else "Red vecina")
        if tiene_hs: estado += " | ⚠ HANDSHAKE"

        vals = {
            "bssid": bssid.upper(),
            "canal": str(ap.get("canal","?")),
            "cifrado": ap.get("cifrado","?"),
            "rssi": rssi_str,
            "n_cli": str(len(ap.get("clientes",set()))),
            "pkts": str(ap.get("pkts",0)),
            "primer_visto": ap.get("primer_visto","—"),
            "estado": estado,
        }
        for k, v in vals.items():
            c = color if k=="estado" else (C_SUB if k=="bssid" else C_TEXTO)
            self._campos[k].config(text=v, fg=c)

        self.lista_cli.delete(0, tk.END)
        clientes = sorted(ap.get("clientes",set()))
        if clientes:
            for m in clientes:
                self.lista_cli.insert(tk.END, f"  {m.upper()}")
        else:
            self.lista_cli.insert(tk.END, "  Sin clientes detectados")

    def _actualizar_panel(self):
        with self._lock:
            hs = list(self._handshakes[-20:])
            n  = len(self._aps)
            nn = sum(1 for a in self._aps.values() if a.get("es_nuestra"))

        self.lista_hs.delete(0, tk.END)
        for item in reversed(hs):
            ts, bssid, cli, es_n, ssid, archivo, n_f = item
            pfx = "🔴" if es_n else "🟡"
            nombre = ssid if ssid and ssid != "?" else bssid[:11]
            pcap_info = f" 💾{archivo[:12]}" if archivo else ""
            self.lista_hs.insert(tk.END,
                f"{ts} {pfx} {nombre[:14]} ({n_f}f){pcap_info}")

        self.lbl_estado.config(
            text=f"APs: {n} | propia: {nn} | vecinas: {n-nn} | "
                 f"handshakes: {len(hs)} | {datetime.now().strftime('%H:%M:%S')}")

        if self._nodo_sel:
            self._det(self._nodo_sel)

    # ── CIERRE ────────────────────────────────────────────────────

    def _cerrar(self):
        try:
            self.ventana.destroy()
        except Exception:
            pass
        self.ventana = None
