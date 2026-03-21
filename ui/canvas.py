import tkinter as tk
import math
import os
try:
    from PIL import Image, ImageTk
    _PIL_OK = True
except ImportError:
    _PIL_OK = False

COLOR_FONDO        = "#0d1117"
COLOR_NODO_CONF    = "#3fb950"
COLOR_NODO_SOSP    = "#f0883e"
COLOR_NODO_FANT    = "#da3633"
COLOR_NODO_SCAN    = "#ffa657"  # Naranja brillante — ARP scanner
COLOR_LINEA        = "#30363d"
COLOR_TRAFICO_LAT  = "#8957e5"
COLOR_TEXTO        = "#e6edf3"
COLOR_TEXTO_SUB    = "#8b949e"
COLOR_INTERNET     = "#388bfd"

# Colores por severidad de hallazgos
COLOR_SEV_INFO    = "#58d6ff"   # cyan  — borde punteado
COLOR_SEV_MEDIO   = "#f0e040"   # amarillo — borde sólido
COLOR_SEV_ALTO    = "#f0883e"   # naranja — nodo completo
COLOR_SEV_CRITICO = "#da3633"   # rojo — nodo + pulso

BADGE_SEV = {
    "info":    ("🔵", COLOR_SEV_INFO),
    "medio":   ("🟡", COLOR_SEV_MEDIO),
    "alto":    ("🟠", COLOR_SEV_ALTO),
    "critico": ("🔴", COLOR_SEV_CRITICO),
}

# Color por protocolo
PROTO_COLOR = {
    "ARP":  "#f0883e",
    "TCP":  "#1f6feb",
    "UDP":  "#a371f7",
    "ICMP": "#3fb950",
    "IP":   "#8b949e",
}

# Iconos emoji (fallback si no hay PNG)
ICONOS_TEXTO = {
    "router":        "⬡",
    "switch":        "◈",
    "arp-scanner":   "⚠",
    "pc":            "□",
    "laptop":        "⊓",
    "servidor":      "▣",
    "smartphone":    "▭",
    "camara":        "◉",
    "impresora":     "⊟",
    "smart_tv":      "▬",
    "tablet":        "▭",
    "iot":           "◌",
    "ap":            "⊕",
    "firewall":      "⬡",
    "voip":          "☎",
    "sniffer":       "◎",
    "historian":     "▤",
    "controller":    "⊞",
    "wired_generic": "⊡",
    "desconocido":   "○",
    "internet":      "☁",
}

# Caché de imágenes PNG cargadas (se llena en tiempo de ejecución)
_ICON_CACHE = {}

def _cargar_icono(tipo, size):
    """Carga el PNG del tipo dado, escalado a size×size. Retorna PhotoImage o None."""
    if not _PIL_OK:
        return None
    clave = (tipo, size)
    if clave in _ICON_CACHE:
        return _ICON_CACHE[clave]
    # Buscar en assets/icons/ relativo al directorio del archivo
    base = os.path.dirname(os.path.abspath(__file__))
    # Subir un nivel si estamos en ui/
    for ruta in [
        os.path.join(base, "assets", "icons", f"{tipo}.png"),
        os.path.join(base, "..", "assets", "icons", f"{tipo}.png"),
    ]:
        if os.path.exists(ruta):
            img = Image.open(ruta).convert("RGBA").resize((size, size), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            _ICON_CACHE[clave] = photo
            return photo
    _ICON_CACHE[clave] = None
    return None

RADIO_NODO   = 28
RADIO_GRANDE = 34

def _radio_adaptativo(n_nodos):
    """Reduce el radio según cuántos nodos hay."""
    if n_nodos <= 10:  return 28
    if n_nodos <= 25:  return 22
    if n_nodos <= 50:  return 16
    if n_nodos <= 100: return 11
    return 8


class Canvas:
    def __init__(self, padre, topologia):
        self.topologia       = topologia
        self.mostrar_lateral = False
        self.ip_local        = None   # IP propia — se resalta en canvas

        self.frame = tk.Frame(padre, bg=COLOR_FONDO)
        # Scrollbar vertical para redes grandes (100+ nodos)
        self._scrollbar = tk.Scrollbar(self.frame, orient=tk.VERTICAL,
                                       bg=COLOR_FONDO, troughcolor="#161b22",
                                       activebackground="#30363d")
        self._scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.c = tk.Canvas(self.frame, bg=COLOR_FONDO, highlightthickness=0,
                           yscrollcommand=self._scrollbar.set)
        self.c.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._scrollbar.config(command=self.c.yview)
        # Scroll con rueda del mouse
        self.c.bind("<MouseWheel>", lambda e: self.c.yview_scroll(-1*(e.delta//120), "units"))
        self.c.bind("<Button-4>",   lambda e: self.c.yview_scroll(-1, "units"))
        self.c.bind("<Button-5>",   lambda e: self.c.yview_scroll( 1, "units"))

        self._tooltip_ventana  = None
        self._tooltip_label    = None
        self._nodo_bajo_cursor = None

        self.c.bind("<Motion>",         self._on_mouse_move)
        self.c.bind("<Leave>",          self._on_mouse_leave)
        self.c.bind("<Button-1>",       self._on_click)
        self.c.bind("<Double-1>",       self._on_doble_click)
        self.c.bind("<Button-3>",       self._on_click_derecho)
        self.c.bind("<Configure>",      self._on_resize)

        self._posiciones           = {}
        self._nodo_seleccionado_ip = None
        self.on_nodo_seleccionado  = None
        self.arsenal               = None
        self._ventanas_arsenal     = {}
        self.tipo_resaltado        = None   # filtro tipo → resalta en rojo
        self.subredes_secundarias  = []     # list[SubredSecundaria] desde app.py

    # ─────────────────────────────────────────
    # DIBUJO
    # ─────────────────────────────────────────

    def redibujar(self):
        self.c.delete("all")
        ancho = self.c.winfo_width()
        alto  = self.c.winfo_height()
        if ancho < 10 or alto < 10: return

        nodos = self.topologia.todos_los_nodos_visibles()
        if not nodos:
            self._dibujar_vacio(ancho, alto)
            return

        subredes = getattr(self, "subredes_secundarias", [])

        # Reservar columna derecha si hay subredes secundarias
        ancho_islas = min(200, ancho // 3) if subredes else 0
        ancho_principal = ancho - ancho_islas

        self._calcular_posiciones(nodos, ancho_principal, alto)

        cx = ancho_principal // 2
        cy = 55   # WAN más arriba
        self._dibujar_internet(cx, cy)
        self._dibujar_lineas(cx, cy)
        if self.mostrar_lateral:
            self._dibujar_trafico_lateral()
        for nodo in nodos:
            if nodo.ip in self._posiciones:
                x, y = self._posiciones[nodo.ip]
                self._dibujar_nodo(nodo, x, y)

        # Islas de subredes secundarias en columna derecha
        if subredes:
            self._dibujar_islas(subredes, ancho_principal, alto)

    def seleccionar_nodo(self, ip):
        """Marca el nodo con esta IP como seleccionado para mostrar el anillo."""
        self._nodo_seleccionado_ip = ip

    def _dibujar_vacio(self, ancho, alto):
        self.c.create_text(
            ancho // 2, alto // 2,
            text="⬡  Presiona Escanear para descubrir la red",
            fill=COLOR_TEXTO_SUB, font=("Monospace", 12)
        )

    # ─────────────────────────────────────────
    # POSICIONES
    # ─────────────────────────────────────────

    def _calcular_posiciones(self, nodos, ancho, alto):
        self._posiciones = {}
        routers  = [n for n in nodos if n.tipo == "router"]
        switches = [n for n in nodos if n.tipo == "switch"]
        arp_scan = [n for n in nodos if n.tipo == "arp-scanner"]
        hosts    = [n for n in nodos if n.tipo not in ("router", "switch", "arp-scanner")]

        total = len(nodos)
        self._radio = _radio_adaptativo(total)
        sep = max(self._radio * 2.8, 36)
        max_por_fila = max(1, int(ancho / sep))

        def _colocar_grupo(grupo, y_base):
            if not grupo: return y_base
            filas = [grupo[i:i+max_por_fila] for i in range(0, len(grupo), max_por_fila)]
            for f_idx, fila in enumerate(filas):
                y = y_base + f_idx * sep
                espaciado = ancho / (len(fila) + 1)
                for i, nodo in enumerate(fila):
                    self._posiciones[nodo.ip] = (espaciado * (i+1), y)
            return y_base + len(filas) * sep

        y = _colocar_grupo(routers, 175)   # antes 130 — más espacio bajo el WAN
        y = max(y + sep, 250)              # antes 200
        y = _colocar_grupo(switches, y)
        y = _colocar_grupo(arp_scan, y)
        y = max(y + sep, 320)              # antes 260
        y_fin = _colocar_grupo(hosts, y)

        # Canvas virtual scrollable si el contenido no cabe en pantalla
        altura_necesaria = y_fin + sep
        if altura_necesaria > alto:
            self.c.configure(scrollregion=(0, 0, ancho, altura_necesaria))
        else:
            self.c.configure(scrollregion=(0, 0, ancho, alto))

    # ─────────────────────────────────────────
    # ELEMENTOS
    # ─────────────────────────────────────────

    def _dibujar_internet(self, x, y):
        r = RADIO_GRANDE + 4   # un poco más grande que los nodos normales
        # Halo exterior sutil
        self.c.create_oval(x-r-6, y-r-6, x+r+6, y+r+6,
            fill="", outline=COLOR_INTERNET, width=1,
            dash=(4, 4))
        self.c.create_oval(x-r, y-r, x+r, y+r,
            fill="#0d2137", outline=COLOR_INTERNET, width=2)
        foto_inet = _cargar_icono("internet", int(r * 1.1))
        if foto_inet:
            self.c.create_image(x, y, image=foto_inet)
        else:
            self.c.create_text(x, y-4, text=ICONOS_TEXTO.get("internet","☁"),
                fill=COLOR_INTERNET, font=("Monospace", 14, "bold"))
        self.c.create_text(x, y, text="WAN",
            fill=COLOR_INTERNET, font=("Monospace", 7))
        # Etiqueta debajo con más separación
        self.c.create_text(x, y + r + 16, text="Internet",
            fill=COLOR_TEXTO_SUB, font=("Monospace", 8))

    def _dibujar_nodo(self, nodo, x, y):
        from core.nodes import CONFIRMADO, SOSPECHOSO

        sev = getattr(nodo, "severidad_max", None)

        # ── FILTRO POR TIPO ─────────────────────────────────────────
        tipo_activo  = getattr(self, "tipo_resaltado", None)
        es_resaltado = tipo_activo and (str(nodo.tipo or "") == tipo_activo)
        es_atenuado  = tipo_activo and not es_resaltado

        # Color base según estado
        if nodo.tipo == "arp-scanner":
            cb, cf = COLOR_NODO_SCAN, "#1f1200"
        elif nodo.estado == CONFIRMADO:
            cb, cf = COLOR_NODO_CONF, "#0d2117"
        elif nodo.estado == SOSPECHOSO:
            cb, cf = COLOR_NODO_SOSP, "#1f1608"
        else:
            cb, cf = COLOR_NODO_FANT, "#1f0808"

        # Severidad sobreescribe color si es alto o crítico
        if sev == "alto":
            cb, cf = COLOR_SEV_ALTO, "#1f0e00"
        elif sev == "critico":
            cb, cf = COLOR_SEV_CRITICO, "#1f0000"

        # Resaltado por tipo: override total
        if es_resaltado:
            cb, cf = "#ff3333", "#2a0000"
        elif es_atenuado:
            cb, cf = "#2a2a2a", "#161616"

        r   = getattr(self, "_radio", RADIO_NODO)
        if nodo.tipo == "router":
            r = min(RADIO_GRANDE, r + 6)
        tag = f"nodo_{nodo.ip}"

        fs_oct   = max(5,  int(r * 0.28))
        fs_label = max(5,  int(r * 0.30))
        fs_icono = max(6,  int(r * 0.45))

        es_local = (self.ip_local and nodo.ip == self.ip_local)

        # Anillo rojo para nodos resaltados por tipo
        if es_resaltado:
            self.c.create_oval(x-r-7, y-r-7, x+r+7, y+r+7,
                fill="", outline="#ff3333", width=2,
                tags=(tag, "nodo"))

        # Anillo de selección — nodo elegido en panel/canvas
        if getattr(self, "_nodo_seleccionado_ip", None) == nodo.ip:
            self.c.create_oval(x-r-8, y-r-8, x+r+8, y+r+8,
                fill="", outline="#ffffff", width=1,
                dash=(2, 2), tags=(tag, "nodo", "seleccionado"))
            self.c.create_oval(x-r-5, y-r-5, x+r+5, y+r+5,
                fill="", outline="#58d6ff", width=3,
                tags=(tag, "nodo", "seleccionado"))

        # Borde exterior para nodo propio
        if es_local:
            self.c.create_oval(x-r-4, y-r-4, x+r+4, y+r+4,
                fill="", outline="#58d6ff", width=2,
                dash=(3, 3), tags=(tag, "nodo"))

        # Borde de severidad INFO/MEDIO (antes del círculo para que quede debajo)
        if sev == "info" and not es_local:
            self.c.create_oval(x-r-3, y-r-3, x+r+3, y+r+3,
                fill="", outline=COLOR_SEV_INFO, width=1,
                dash=(4,4), tags=(tag, "nodo"))
        elif sev == "medio" and not es_local:
            self.c.create_oval(x-r-3, y-r-3, x+r+3, y+r+3,
                fill="", outline=COLOR_SEV_MEDIO, width=2,
                tags=(tag, "nodo"))

        # Círculo base del nodo
        self.c.create_oval(x-r, y-r, x+r, y+r,
            fill=cf, outline="#58d6ff" if es_local else cb,
            width=3 if es_local else 2, tags=(tag, "nodo"))

        # Pulso rojo extra para CRÍTICO
        if sev == "critico" and not es_local:
            self.c.create_oval(x-r-5, y-r-5, x+r+5, y+r+5,
                fill="", outline=COLOR_SEV_CRITICO, width=1,
                dash=(2,3), tags=(tag, "nodo"))

        # Anillo de selección — nodo elegido en panel/canvas
        if getattr(self, "_nodo_seleccionado_ip", None) == nodo.ip:
            # Anillo exterior brillante
            self.c.create_oval(x-r-8, y-r-8, x+r+8, y+r+8,
                fill="", outline="#ffffff", width=1,
                dash=(2,2), tags=(tag, "nodo", "seleccionado"))
            self.c.create_oval(x-r-5, y-r-5, x+r+5, y+r+5,
                fill="", outline="#58d6ff", width=3,
                tags=(tag, "nodo", "seleccionado"))

        # Intentar dibujar ícono PNG
        tipo_icono = nodo.tipo if nodo.tipo != "arp-scanner" else "arp-scanner"
        icon_size  = max(10, int(r * 1.1))   # ligeramente más pequeño que el círculo
        foto = _cargar_icono(tipo_icono, icon_size)

        if foto:
            # PNG disponible — centrado en el nodo
            self.c.create_image(x, y, image=foto, tags=(tag, "nodo"))
        else:
            # Fallback: emoji de texto
            self.c.create_text(x, y - int(r*0.15),
                text=ICONOS_TEXTO.get(nodo.tipo, "○"),
                fill="#58d6ff" if es_local else cb,
                font=("Monospace", fs_icono, "bold"), tags=(tag, "nodo"))

        # Badges de hallazgos — arriba del nodo
        hallazgos = getattr(nodo, "hallazgos", [])
        if hallazgos and r >= 14:
            # Mostrar hasta 3 badges, ordenados por severidad
            orden = {"critico":3,"alto":2,"medio":1,"info":0}
            tops = sorted(hallazgos, key=lambda h: orden.get(h.severidad,0), reverse=True)[:3]
            bx = x - (len(tops)-1) * 8
            for h in tops:
                _, bcol = BADGE_SEV.get(h.severidad, ("●", COLOR_TEXTO_SUB))
                self.c.create_oval(bx-5, y-r-14, bx+5, y-r-4,
                    fill=bcol, outline="", tags=(tag,"nodo"))
                bx += 12

        # Último octeto siempre visible si hay espacio
        if r >= 12:
            self.c.create_text(x, y + r + 9,
                text=("▶ TÚ" if es_local else nodo.ip),
                fill="#58d6ff" if es_local else COLOR_TEXTO_SUB,
                font=("Monospace", fs_label, "bold" if es_local else "normal"))
        if r >= 18:
            etiqueta_tipo = nodo.ip if es_local else nodo.tipo
            self.c.create_text(x, y + r + 19,
                text=etiqueta_tipo,
                fill=COLOR_TEXTO_SUB,
                font=("Monospace", max(5, fs_label - 1)))
                
        # Badge "NUEVO" parpadeante (primeros 30s)
        import time
        if not es_local and hasattr(nodo, 'visto_en') and (time.time() - nodo.visto_en < 30):
            # Usar segundos para parpadeo sincrónico (par cada segundo = visible)
            if int(time.time() * 2) % 2 == 0:
                bx_nuevo = x + r * 0.7
                by_nuevo = y - r * 0.7
                self.c.create_oval(bx_nuevo-6, by_nuevo-6, bx_nuevo+6, by_nuevo+6, fill="#238636", outline="", tags=(tag, "nodo"))
                self.c.create_text(bx_nuevo, by_nuevo, text="N", fill="#ffffff", font=("Monospace", 7, "bold"), tags=(tag, "nodo"))

        # Badge de conexiones externas — globo naranja esquina inferior derecha
        if r >= 14:
            externos = self.topologia.obtener_externos(nodo.ip)
            if externos:
                bx_ext = x + r * 0.72
                by_ext = y + r * 0.72
                self.c.create_oval(bx_ext-6, by_ext-6, bx_ext+6, by_ext+6,
                    fill="#f0883e", outline="#0d1117", width=1,
                    tags=(tag, "nodo"))
                self.c.create_text(bx_ext, by_ext, text="\u2197",
                    fill="#ffffff", font=("Monospace", 6, "bold"),
                    tags=(tag, "nodo"))

    def _dibujar_lineas(self, cx_internet, cy_internet):
        nodos    = self.topologia.todos_los_nodos()
        routers  = [n for n in nodos if n.tipo == "router"]
        switches = [n for n in nodos if n.tipo == "switch"]
        hosts    = [n for n in nodos if n.tipo not in ("router", "switch")]

        def linea_jerarquia(x1, y1, x2, y2):
            self.c.create_line(x1, y1, x2, y2,
                fill=COLOR_LINEA, width=1, dash=(4, 4))

        for n in routers:
            if n.ip in self._posiciones:
                x, y = self._posiciones[n.ip]
                linea_jerarquia(cx_internet, cy_internet+getattr(self,'_radio',RADIO_GRANDE), x, y-getattr(self,'_radio',RADIO_GRANDE))

        for n in switches:
            if n.ip not in self._posiciones: continue
            x, y = self._posiciones[n.ip]
            if routers:
                for r in routers:
                    if r.ip in self._posiciones:
                        rx, ry = self._posiciones[r.ip]
                        linea_jerarquia(rx, ry+getattr(self,'_radio',RADIO_GRANDE), x, y-getattr(self,'_radio',RADIO_NODO))
            else:
                linea_jerarquia(cx_internet, cy_internet+getattr(self,'_radio',RADIO_GRANDE), x, y-getattr(self,'_radio',RADIO_NODO))

        padres = switches if switches else routers
        for n in hosts:
            if n.ip not in self._posiciones: continue
            x, y = self._posiciones[n.ip]
            if padres and padres[0].ip in self._posiciones:
                px, py = self._posiciones[padres[0].ip]
                linea_jerarquia(px, py+getattr(self,'_radio',RADIO_NODO), x, y-getattr(self,'_radio',RADIO_NODO))
            else:
                linea_jerarquia(cx_internet, cy_internet+getattr(self,'_radio',RADIO_GRANDE), x, y-getattr(self,'_radio',RADIO_NODO))

    def _dibujar_trafico_lateral(self):
        """Líneas de tráfico con protocolo visible encima."""
        for origen, destino, protocolo in self.topologia.obtener_enlaces():
            if origen not in self._posiciones or destino not in self._posiciones:
                continue
            x1, y1 = self._posiciones[origen]
            x2, y2 = self._posiciones[destino]

            color = PROTO_COLOR.get(protocolo, COLOR_TRAFICO_LAT)

            self.c.create_line(x1, y1, x2, y2,
                fill=color, width=1, dash=(2, 6))

            # Texto del protocolo — solo si es el más reciente del par
            if protocolo:
                mx = (x1 + x2) / 2
                my = (y1 + y2) / 2
                # Fondo pequeño para evitar superposición visual
                self.c.create_rectangle(
                    mx - 14, my - 16, mx + 14, my - 4,
                    fill=COLOR_FONDO, outline="", width=0)
                self.c.create_text(mx, my - 10,
                    text=protocolo,
                    fill=color,
                    font=("Monospace", 7, "bold"))

    # ─────────────────────────────────────────
    # SUBREDES SECUNDARIAS — ISLAS
    # ─────────────────────────────────────────

    def _dibujar_islas(self, subredes, x_inicio, alto):
        """Dibuja las subredes secundarias como islas en la columna derecha."""
        ISLA_ANCHO  = 180
        ISLA_MARGEN = 14
        ISLA_RADIO  = 10   # radio de los nodos dentro de la isla

        # Buscar posición del router principal para trazar la línea de conexión
        router_pos = None
        for ip, pos in self._posiciones.items():
            nodo = self.topologia.nodos.get(ip)
            if nodo and nodo.tipo == "router":
                router_pos = pos
                break

        y_cursor = 50  # posición vertical de la primera isla

        for subred in subredes:
            n_nodos   = len(subred.nodos)
            filas     = max(1, (n_nodos + 1) // 2)
            isla_alto = 56 + filas * (ISLA_RADIO * 2 + 10)

            x0 = x_inicio + ISLA_MARGEN
            y0 = y_cursor
            x1 = x0 + ISLA_ANCHO
            y1 = y0 + isla_alto

            # Fondo de la isla — rectángulo punteado con color del tipo
            self.c.create_rectangle(
                x0, y0, x1, y1,
                fill="#0d1117", outline=subred.color,
                width=1, dash=(5, 4),
                tags=("isla",)
            )

            # Etiqueta del tipo (HOTSPOT / VLAN / etc)
            self.c.create_rectangle(
                x0, y0, x1, y0 + 18,
                fill=subred.color, outline="",
                tags=("isla",)
            )
            self.c.create_text(
                (x0 + x1) // 2, y0 + 9,
                text=f"{subred.tipo}  {subred.prefijo}.x",
                fill="#0d1117",
                font=("Monospace", 7, "bold"),
                tags=("isla",)
            )

            # Badge con número de hosts
            bx = x1 - 2
            by = y0 + 2
            self.c.create_oval(bx - 10, by - 8, bx + 10, by + 8,
                fill=subred.color, outline="", tags=("isla",))
            self.c.create_text(bx, by,
                text=str(n_nodos),
                fill="#0d1117",
                font=("Monospace", 7, "bold"),
                tags=("isla",)
            )

            # Nodos dentro de la isla
            nodos_lista = list(subred.nodos.values())
            for idx, nodo_isla in enumerate(nodos_lista):
                col_i = idx % 2
                fila_i = idx // 2
                nx = x0 + 30 + col_i * (ISLA_RADIO * 2 + 55)
                ny = y0 + 30 + fila_i * (ISLA_RADIO * 2 + 14)

                # Círculo del nodo
                self.c.create_oval(
                    nx - ISLA_RADIO, ny - ISLA_RADIO,
                    nx + ISLA_RADIO, ny + ISLA_RADIO,
                    fill="#161b22", outline=subred.color,
                    width=1, tags=("isla",)
                )

                # Último octeto de la IP
                octeto = nodo_isla.ip.split(".")[-1]
                self.c.create_text(
                    nx, ny,
                    text=octeto,
                    fill=subred.color,
                    font=("Monospace", 6, "bold"),
                    tags=("isla",)
                )

                # IP completa debajo
                self.c.create_text(
                    nx, ny + ISLA_RADIO + 7,
                    text=nodo_isla.ip,
                    fill=COLOR_TEXTO_SUB,
                    font=("Monospace", 5),
                    tags=("isla",)
                )

            # Línea de conexión desde el router al centro-izquierda de la isla
            isla_cx = x0
            isla_cy = (y0 + y1) // 2
            if router_pos:
                rx, ry = router_pos
                self.c.create_line(
                    rx, ry, isla_cx, isla_cy,
                    fill=subred.color, width=1,
                    dash=(3, 6), arrow=tk.LAST,
                    tags=("isla",)
                )
                # Etiqueta en el punto medio de la línea
                mx = (rx + isla_cx) // 2
                my = (ry + isla_cy) // 2
                self.c.create_text(
                    mx, my - 8,
                    text=subred.desc,
                    fill=subred.color,
                    font=("Monospace", 6),
                    tags=("isla",)
                )

            y_cursor = y1 + ISLA_MARGEN

    # ─────────────────────────────────────────
    # TOOLTIP
    # ─────────────────────────────────────────

    def _nodo_en_posicion(self, x, y):
        for nodo in self.topologia.todos_los_nodos():
            if nodo.ip not in self._posiciones: continue
            nx, ny = self._posiciones[nodo.ip]
            # Usar el radio adaptativo real del último dibujo
            r = getattr(self, '_radio', RADIO_NODO)
            if nodo.tipo == "router":
                r = min(RADIO_GRANDE, r + 6)
            # Área de click un poco más generosa que el radio visual
            zona = max(r + 6, 18)
            if math.sqrt((x-nx)**2 + (y-ny)**2) <= zona:
                return nodo
        return None

    def _mostrar_tooltip(self, nodo, rx, ry):
        externos = self.topologia.obtener_externos(nodo.ip)
        n_ext = len(externos) if externos else 0
        rs = getattr(nodo, 'risk_score', 0)
        sev = getattr(nodo, 'severidad_max', None)
        n_hallazgos = len(getattr(nodo, 'hallazgos', []))
        texto = (
            f"IP:       {nodo.ip}\n"
            f"MAC:      {nodo.mac or '—'}\n"
            f"Tipo:     {nodo.tipo}\n"
            f"Fabric.:  {nodo.fabricante}\n"
            f"OS:       {nodo.sistema_op}\n"
            f"Paquetes: {nodo.paquetes}\n"
            f"Estado:   {nodo.estado}\n"
            f"Risk:     {rs}/100  [{sev or 'ok'}]\n"
            f"Alertas:  {n_hallazgos}\n"
            f"Externos: {n_ext} IPs"
        )
        if self._tooltip_ventana is None:
            self._tooltip_ventana = tk.Toplevel(self.c)
            self._tooltip_ventana.wm_overrideredirect(True)
            self._tooltip_label = tk.Label(
                self._tooltip_ventana,
                bg="#1c2128", fg=COLOR_TEXTO,
                font=("Monospace", 8),
                justify=tk.LEFT, padx=10, pady=6, relief=tk.FLAT
            )
            self._tooltip_label.pack()
        self._tooltip_label.config(text=texto)
        self._tooltip_ventana.wm_geometry(f"+{rx+15}+{ry+10}")

    def _ocultar_tooltip(self):
        if self._tooltip_ventana:
            self._tooltip_ventana.destroy()
            self._tooltip_ventana = None
            self._tooltip_label   = None
        self._nodo_bajo_cursor = None

    # ─────────────────────────────────────────
    # EVENTOS
    # ─────────────────────────────────────────

    def _on_mouse_move(self, evento):
        nodo = self._nodo_en_posicion(evento.x, evento.y)
        if nodo:
            if self._nodo_bajo_cursor != nodo.ip:
                self._nodo_bajo_cursor = nodo.ip
            rx = self.c.winfo_rootx() + evento.x
            ry = self.c.winfo_rooty() + evento.y
            self._mostrar_tooltip(nodo, rx, ry)
        else:
            self._ocultar_tooltip()

    def _on_mouse_leave(self, evento):
        self._ocultar_tooltip()

    def _on_click(self, evento):
        nodo = self._nodo_en_posicion(evento.x, evento.y)
        if nodo and self.on_nodo_seleccionado:
            self.on_nodo_seleccionado(nodo)

    def _on_doble_click(self, evento):
        """Doble click — Lanza directamente Quick Ports."""
        nodo = self._nodo_en_posicion(evento.x, evento.y)
        if nodo:
            log(f"[CANVAS] Doble click en {nodo.ip} -> Lanzando Quick Ports")
            self._lanzar_escaneo(nodo.ip, "quick")

    def _on_click_derecho(self, evento):
        """Click derecho — muestra menú contextual con arsenal nmap."""
        nodo = self._nodo_en_posicion(evento.x, evento.y)
        if not nodo:
            return
        self._mostrar_menu_arsenal(nodo, evento.x_root, evento.y_root)

    def _mostrar_menu_arsenal(self, nodo, rx, ry):
        """Construye y muestra el menú contextual sobre el nodo."""
        from tools.arsenal import ESCANEOS

        menu = tk.Menu(
            self.c, tearoff=0,
            bg="#161b22", fg="#e6edf3",
            activebackground="#1f6feb", activeforeground="#ffffff",
            font=("Monospace", 9),
            relief=tk.FLAT,
            bd=1,
        )

        # Cabecera — no clickeable
        menu.add_command(
            label=f"  ⚔  Arsenal — {nodo.ip}",
            state=tk.DISABLED,
            font=("Monospace", 9, "bold"),
        )
        menu.add_separator()

        # Información del nodo
        info_tipo = f"  {nodo.tipo}  |  {nodo.fabricante or '—'}"
        menu.add_command(label=info_tipo, state=tk.DISABLED,
                         font=("Monospace", 8))
        if nodo.puertos_abiertos:
            puertos_str = ", ".join(str(p) for p in sorted(nodo.puertos_abiertos)[:8])
            if len(nodo.puertos_abiertos) > 8:
                puertos_str += f" +{len(nodo.puertos_abiertos)-8}"
            menu.add_command(label=f"  Puertos: {puertos_str}",
                             state=tk.DISABLED, font=("Monospace", 8))
        menu.add_separator()

        # Escaneos del arsenal
        for escaneo in ESCANEOS:
            corriendo = (self.arsenal and
                         self.arsenal.esta_corriendo(nodo.ip, escaneo["id"]))
            if corriendo:
                label = f"  ⏳ {escaneo['nombre']} (corriendo...)"
                estado = tk.DISABLED
            else:
                label = f"  {escaneo['nombre']}   {escaneo['desc']}"
                estado = tk.NORMAL

            menu.add_command(
                label=label,
                state=estado,
                command=lambda ip=nodo.ip, eid=escaneo["id"],
                               nombre=escaneo["nombre"]: (
                    self._lanzar_escaneo(ip, eid, nombre)
                )
            )

        menu.add_separator()

        # Copiar IP
        menu.add_command(
            label=f"  📋 Copiar IP ({nodo.ip})",
            command=lambda: self._copiar_ip(nodo.ip)
        )

        # Mostrar el menú
        try:
            menu.tk_popup(rx, ry)
        finally:
            menu.grab_release()

    def _lanzar_escaneo(self, ip, escaneo_id, nombre):
        """Abre la ventana de resultado y lanza el escaneo."""
        if self.arsenal is None:
            return

        from ui.ventana_arsenal import VentanaArsenal

        key = f"{ip}:{escaneo_id}"

        # Si ya hay una ventana abierta para este escaneo, traerla al frente
        if key in self._ventanas_arsenal:
            ven = self._ventanas_arsenal[key]
            try:
                ven.lift()
                ven.focus_set()
                return
            except tk.TclError:
                pass  # ventana ya cerrada

        # Crear nueva ventana
        ventana_raiz = self.c.winfo_toplevel()

        def _lanzar_siguiente(ip2, eid2, nombre2):
            """Callback para que la ventana pueda lanzar el siguiente escaneo."""
            self._lanzar_escaneo(ip2, eid2, nombre2)

        ven = VentanaArsenal(ventana_raiz, ip, nombre,
                             callback_lanzar=_lanzar_siguiente)
        self._ventanas_arsenal[key] = ven

        # Callback específico para esta ventana
        def on_resultado(ip, escaneo_id, titulo, texto, puertos):
            k = f"{ip}:{escaneo_id}"
            if k != key:
                return   # no es para esta ventana
            def _actualizar():
                if k in self._ventanas_arsenal:
                    try:
                        self._ventanas_arsenal[k].mostrar_resultado(texto, puertos)
                    except tk.TclError:
                        self._ventanas_arsenal.pop(k, None)
            self.c.after(0, _actualizar)

        self.arsenal.añadir_listener(on_resultado)
        self.arsenal.lanzar(ip, escaneo_id)

    def _copiar_ip(self, ip):
        try:
            root = self.c.winfo_toplevel()
            root.clipboard_clear()
            root.clipboard_append(ip)
            root.update()  # Necesario para que el portapapeles persista
        except Exception:
            self.c.clipboard_clear()
            self.c.clipboard_append(ip)

    def _on_resize(self, evento):
        self.redibujar()

    def seleccionar_nodo(self, ip):
        """Marca el nodo con esta IP como seleccionado y redibuja para mostrar el anillo."""
        self._nodo_seleccionado_ip = ip
