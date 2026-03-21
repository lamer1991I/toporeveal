"""
splash.py — Pantalla de bienvenida de TopoReveal
Diseño: Cyber-operacional · Red neuronal animada · Terminal boot sequence
"""

import tkinter as tk
import math
import random
import threading
import time


# ── Paleta ────────────────────────────────────────────────────────────────────
C_BG       = "#020810"   # negro profundo con tinte azul
C_GRID     = "#0a1628"   # cuadrícula sutil
C_CYAN     = "#00d4ff"   # cian eléctrico — color principal
C_CYAN2    = "#0097b8"   # cian oscuro
C_GREEN    = "#00ff88"   # verde neón — acento
C_ORANGE   = "#ff6b35"   # naranja — alerta
C_DIM      = "#1a3a5c"   # azul apagado
C_TEXT     = "#e0f0ff"   # texto principal
C_SUB      = "#4a7fa5"   # texto secundario
C_PULSE    = "#00d4ff"   # color de pulso


class SplashScreen:
    """
    Pantalla de bienvenida animada de TopoReveal.
    Muestra:
    - Red de nodos animada de fondo (topología fantasma)
    - Hexágono central pulsante con logo
    - Secuencia de boot tipo terminal
    - Barra de progreso con texto de estado
    - Auto-cierre cuando termine la inicialización
    """

    def __init__(self, parent, callback_listo=None):
        """
        parent          — ventana principal (se oculta mientras splash corre)
        callback_listo  — función a llamar cuando el splash termina
        """
        self.parent         = parent
        self.callback_listo = callback_listo
        self._corriendo     = True
        self._progreso      = 0.0
        self._fase          = 0

        # Crear ventana splash sin bordes — pantalla completa
        self.win = tk.Toplevel(parent)
        self.win.overrideredirect(True)
        self.win.configure(bg=C_BG)
        self.win.attributes("-topmost", True)

        # Pantalla completa real
        sw = self.win.winfo_screenwidth()
        sh = self.win.winfo_screenheight()
        self.win.geometry(f"{sw}x{sh}+0+0")

        self.W = sw
        self.H = sh

        # Canvas principal — ocupa toda la pantalla
        self.cv = tk.Canvas(self.win,
            width=self.W, height=self.H,
            bg=C_BG, highlightthickness=0)
        self.cv.pack(fill=tk.BOTH, expand=True)

        # Estado de animación
        self._t        = 0.0      # tiempo interno
        self._nodos    = []       # nodos de la red de fondo
        self._pulsos   = []       # pulsos viajando por las aristas
        self._mensajes = []       # mensajes del boot ya mostrados
        self._msg_idx  = 0        # índice del próximo mensaje

        # Generación de topología de fondo
        self._generar_red()

        # Mensajes de boot
        self._boot_msgs = [
            ("Inicializando motor de captura...",       C_CYAN,   0.08),
            ("Cargando base GeoIP — 71MB...",           C_CYAN,   0.16),
            ("Verificando interfaces de red...",         C_CYAN,   0.24),
            ("Activando modo promiscuo...",              C_GREEN,  0.32),
            ("Pipeline de scanner — 5 hilos OK",        C_GREEN,  0.42),
            ("Módulos DHCP · mDNS · SSDP activos",     C_CYAN,   0.52),
            ("Motor de fingerprinting cargado",          C_CYAN,   0.62),
            ("Interceptor ARP en espera...",             C_CYAN,   0.72),
            ("Sistema de scoring compuesto activo",      C_GREEN,  0.82),
            ("TopoReveal listo — iniciando UI...",       C_GREEN,  1.00),
        ]

        # Dibujo inicial
        self._dibujar()

        # Iniciar animación
        self._animar()

        # Click para cerrar anticipado
        self.cv.bind("<Button-1>", lambda e: self._cerrar_si_listo())
        self.win.bind("<Escape>",  lambda e: self._cerrar())

    # ── GENERACIÓN DE RED DE FONDO ─────────────────────────────────────────

    def _generar_red(self):
        """Genera nodos y aristas para la topología animada de fondo."""
        self._nodos = []
        # Nodos periféricos — distribuidos en zona exterior
        posiciones = [
            (90,  80),  (200, 45),  (350, 60),  (500, 40),  (650, 75),
            (730, 160), (760, 280), (720, 420), (580, 500), (420, 520),
            (260, 510), (110, 450), (50,  320), (45,  190),
            # Nodos medios
            (160, 200), (300, 150), (460, 170), (600, 200),
            (680, 340), (540, 420), (370, 430), (200, 380),
            # Nodo central — gateway
            (self.W // 2, self.H // 2),
        ]
        for i, (x, y) in enumerate(posiciones):
            es_central = (i == len(posiciones) - 1)
            self._nodos.append({
                "x"   : x, "y": y,
                "r"   : 6 if es_central else random.choice([3, 4, 5]),
                "fase": random.uniform(0, math.pi * 2),
                "vel" : random.uniform(0.5, 1.5),
                "tipo": "gateway" if es_central else random.choice(
                    ["router","smartphone","server","iot","pc"]),
                "central": es_central,
            })

        # Aristas — conectar nodo central con todos los medios
        # y los medios entre sí
        self._aristas = []
        central_idx = len(self._nodos) - 1
        # Conectar central con nodos medios
        for i in range(14, len(self._nodos) - 1):
            self._aristas.append((central_idx, i))
        # Conectar medios con periféricos
        medios = list(range(14, len(self._nodos) - 1))
        periferia = list(range(0, 14))
        for j, p in enumerate(periferia):
            m = medios[j % len(medios)]
            self._aristas.append((m, p))
        # Algunas aristas adicionales aleatorias
        for _ in range(8):
            a = random.randint(0, len(self._nodos) - 2)
            b = random.randint(0, len(self._nodos) - 2)
            if a != b:
                self._aristas.append((a, b))

        # Pulsos iniciales
        self._pulsos = []
        for _ in range(12):
            arista = random.choice(self._aristas)
            self._pulsos.append({
                "arista": arista,
                "t"     : random.uniform(0, 1),
                "vel"   : random.uniform(0.008, 0.02),
                "color" : random.choice([C_CYAN, C_GREEN, C_CYAN2]),
            })

    # ── DIBUJO PRINCIPAL ───────────────────────────────────────────────────

    def _dibujar(self):
        """Dibuja un frame completo."""
        cv = self.cv
        cv.delete("all")

        t = self._t

        # ── Fondo con cuadrícula sutil ──────────────────────────────
        self._dibujar_grid()

        # ── Red de nodos de fondo ───────────────────────────────────
        self._dibujar_red(t)

        # ── Marco exterior ──────────────────────────────────────────
        self._dibujar_marco()

        # ── Hexágono central animado ────────────────────────────────
        cx, cy = self.W // 2, self.H // 2 - 80
        self._dibujar_hexagono(cx, cy, t)

        # ── Título ──────────────────────────────────────────────────
        self._dibujar_titulo(cx, cy)

        # ── Terminal de boot ────────────────────────────────────────
        self._dibujar_terminal()

        # ── Barra de progreso ───────────────────────────────────────
        self._dibujar_progreso()

        # ── Esquinas decorativas ────────────────────────────────────
        self._dibujar_esquinas()

    def _dibujar_grid(self):
        """Cuadrícula de fondo — perspectiva sutil."""
        cv = self.cv
        paso = 40
        for x in range(0, self.W + paso, paso):
            alpha = 0.3 if x % 120 == 0 else 0.15
            col = self._hex_alpha(C_DIM, alpha)
            cv.create_line(x, 0, x, self.H, fill=col, width=1)
        for y in range(0, self.H + paso, paso):
            alpha = 0.3 if y % 120 == 0 else 0.15
            col = self._hex_alpha(C_DIM, alpha)
            cv.create_line(0, y, self.W, y, fill=col, width=1)

    def _dibujar_red(self, t):
        """Dibuja la topología animada de fondo."""
        cv = self.cv
        nodos = self._nodos

        # Aristas con pulsos
        for i, (a_idx, b_idx) in enumerate(self._aristas):
            a = nodos[a_idx]
            b = nodos[b_idx]
            # Línea base muy tenue
            cv.create_line(a["x"], a["y"], b["x"], b["y"],
                fill=self._hex_alpha(C_CYAN, 0.08), width=1)

        # Pulsos viajando
        for p in self._pulsos:
            a_idx, b_idx = p["arista"]
            a = nodos[a_idx]
            b = nodos[b_idx]
            frac = p["t"]
            px = a["x"] + (b["x"] - a["x"]) * frac
            py = a["y"] + (b["y"] - a["y"]) * frac
            r = 3
            cv.create_oval(px-r, py-r, px+r, py+r,
                fill=p["color"], outline="", tags="pulse")
            # Estela del pulso
            for k in range(1, 4):
                frac2 = max(0, frac - k * 0.04)
                px2 = a["x"] + (b["x"] - a["x"]) * frac2
                py2 = a["y"] + (b["y"] - a["y"]) * frac2
                r2 = max(1, r - k)
                alpha = 0.4 - k * 0.1
                col2 = self._hex_alpha(p["color"], alpha)
                cv.create_oval(px2-r2, py2-r2, px2+r2, py2+r2,
                    fill=col2, outline="")

        # Nodos
        for n in nodos:
            if n["central"]:
                continue  # el central se dibuja en hexágono
            pulso = math.sin(t * n["vel"] + n["fase"]) * 0.5 + 0.5
            r = n["r"] + pulso * 2
            col = C_GREEN if n["tipo"] == "server" else \
                  C_ORANGE if n["tipo"] == "iot" else C_CYAN
            cv.create_oval(n["x"]-r, n["y"]-r, n["x"]+r, n["y"]+r,
                fill=self._hex_alpha(col, 0.15), outline=self._hex_alpha(col, 0.5),
                width=1)
            # Punto central
            cv.create_oval(n["x"]-1, n["y"]-1, n["x"]+1, n["y"]+1,
                fill=col, outline="")

    def _dibujar_hexagono(self, cx, cy, t):
        """Hexágono central con múltiples capas y animación de pulso."""
        cv = self.cv

        # Anillos externos pulsantes — más grandes
        for i in range(4, 0, -1):
            radio = 80 + i * 24 + math.sin(t * 1.2 + i) * 5
            alpha = 0.05 + (4 - i) * 0.025
            puntos = self._hex_puntos(cx, cy, radio, t * 0.08 * i)
            cv.create_polygon(*puntos,
                fill="", outline=self._hex_alpha(C_CYAN, alpha), width=1)

        # Hexágono principal
        radio_main = 75
        puntos_main = self._hex_puntos(cx, cy, radio_main, 0)
        cv.create_polygon(*puntos_main,
            fill=self._hex_alpha(C_CYAN, 0.07),
            outline=C_CYAN, width=2)

        # Líneas internas
        for i in range(6):
            angle = math.pi / 3 * i
            px = cx + radio_main * 0.6 * math.cos(angle)
            py = cy + radio_main * 0.6 * math.sin(angle)
            cv.create_line(cx, cy, px, py,
                fill=self._hex_alpha(C_CYAN, 0.25), width=1)

        # Círculos interiores con halo
        pulso_r = math.sin(t * 2) * 4
        for r, alpha in [
            (44 + pulso_r, 0.07),
            (32, 0.12),
            (22, 0.20),
        ]:
            cv.create_oval(cx-r, cy-r, cx+r, cy+r,
                fill=self._hex_alpha(C_CYAN, alpha), outline="")

        # Icono central
        cv.create_oval(cx-7, cy-7, cx+7, cy+7,
            fill=C_CYAN, outline="")
        for i in range(6):
            angle = math.pi / 3 * i + t * 0.3
            x1 = cx + 11 * math.cos(angle)
            y1 = cy + 11 * math.sin(angle)
            x2 = cx + 22 * math.cos(angle)
            y2 = cy + 22 * math.sin(angle)
            cv.create_line(x1, y1, x2, y2,
                fill=self._hex_alpha(C_CYAN, 0.7), width=1)

    def _dibujar_titulo(self, cx, cy):
        """Título principal y subtítulo — centrados en pantalla."""
        cv = self.cv

        # TopoReveal — título principal grande
        cv.create_text(cx, cy + 110,
            text="TopoReveal",
            font=("Courier", 42, "bold"),
            fill=C_CYAN)

        # Línea decorativa bajo el título
        lw = 300
        cv.create_line(cx - lw, cy + 135, cx + lw, cy + 135,
            fill=self._hex_alpha(C_CYAN, 0.4), width=1)
        for dx in [-lw, lw]:
            sign = -1 if dx < 0 else 1
            cv.create_polygon(
                cx + dx,          cy + 131,
                cx + dx + sign*10, cy + 135,
                cx + dx,          cy + 139,
                fill=C_CYAN, outline="")

        # Subtítulo
        cv.create_text(cx, cy + 158,
            text="Network Topology Viewer  ·  v2.0",
            font=("Courier", 14),
            fill=C_SUB)

        # Tag línea bajo subtítulo
        cv.create_text(cx, cy + 182,
            text="ARP  ·  MITM  ·  GeoIP  ·  SSL  ·  Fingerprinting  ·  WiFi Monitor",
            font=("Courier", 10),
            fill=self._hex_alpha(C_CYAN, 0.35))

    def _dibujar_terminal(self):
        """Líneas del boot type terminal — posición dinámica."""
        cv = self.cv

        # Posición relativa al tamaño de pantalla
        tx = self.W // 2 - 400
        ty = self.H - 240
        tw = 800
        th = 150

        # Marco del terminal
        cv.create_rectangle(tx, ty, tx + tw, ty + th,
            fill=self._hex_alpha(C_BG, 0.9),
            outline=self._hex_alpha(C_CYAN, 0.3), width=1)

        # Cabecera del terminal
        cv.create_rectangle(tx, ty, tx + tw, ty + 24,
            fill=self._hex_alpha(C_CYAN, 0.08), outline="")
        cv.create_text(tx + 12, ty + 12,
            text="SYSTEM BOOT  ─────────────────────────────────────────────────────",
            font=("Courier", 9),
            fill=self._hex_alpha(C_CYAN, 0.5),
            anchor="w")

        # Mensajes mostrados
        y_base = ty + 34
        max_visible = 5
        mensajes_vis = self._mensajes[-max_visible:]
        for i, (msg, color) in enumerate(mensajes_vis):
            cv.create_text(tx + 14, y_base + i * 22,
                text="▶",
                font=("Courier", 9),
                fill=self._hex_alpha(C_GREEN, 0.7),
                anchor="w")
            cv.create_text(tx + 30, y_base + i * 22,
                text=msg,
                font=("Courier", 10),
                fill=color,
                anchor="w")

        # Cursor parpadeante
        n = len(mensajes_vis)
        if n < max_visible and self._progreso < 1.0:
            cursor_x = tx + 30
            cursor_y = y_base + n * 22
            if int(time.time() * 2) % 2 == 0:
                cv.create_text(cursor_x, cursor_y,
                    text="█",
                    font=("Courier", 10),
                    fill=C_CYAN, anchor="w")

    def _dibujar_progreso(self):
        """Barra de progreso con porcentaje — posición dinámica."""
        cv = self.cv

        bx = self.W // 2 - 400
        by = self.H - 72
        bw = 800
        bh = 14

        # Fondo
        cv.create_rectangle(bx, by, bx + bw, by + bh,
            fill=self._hex_alpha(C_DIM, 0.4),
            outline=self._hex_alpha(C_CYAN, 0.3), width=1)

        # Relleno con gradiente simulado
        if self._progreso > 0:
            fill_w = int(bw * self._progreso)
            segmentos = 30
            for i in range(segmentos):
                seg_x = bx + int(fill_w * i / segmentos)
                seg_w = max(1, int(fill_w / segmentos))
                alpha = 0.4 + 0.6 * (i / segmentos)
                col = C_GREEN if self._progreso >= 1.0 else C_CYAN
                cv.create_rectangle(seg_x, by + 1,
                    seg_x + seg_w, by + bh - 1,
                    fill=self._hex_alpha(col, alpha), outline="")
            if self._progreso < 1.0:
                fx = bx + fill_w
                cv.create_line(fx, by + 1, fx, by + bh - 1,
                    fill=C_CYAN, width=2)

        # Porcentaje
        pct = int(self._progreso * 100)
        col_pct = C_GREEN if pct >= 100 else C_CYAN
        cv.create_text(bx + bw + 40, by + bh // 2,
            text=f"{pct:3d}%",
            font=("Courier", 12, "bold"),
            fill=col_pct, anchor="w")

        # Estado
        estado = "SISTEMA LISTO" if self._progreso >= 1.0 else "Inicializando..."
        col_est = C_GREEN if self._progreso >= 1.0 else C_SUB
        cv.create_text(bx, by + bh + 16,
            text=estado,
            font=("Courier", 9),
            fill=col_est, anchor="w")

        cv.create_text(bx + bw, by + bh + 16,
            text="kali · wlan0 ready",
            font=("Courier", 9),
            fill=self._hex_alpha(C_SUB, 0.5),
            anchor="e")

    def _dibujar_marco(self):
        """Marco exterior con detalles decorativos."""
        cv = self.cv
        m = 12
        cv.create_rectangle(m, m, self.W - m, self.H - m,
            fill="", outline=self._hex_alpha(C_CYAN, 0.25), width=1)
        cv.create_rectangle(m + 4, m + 4, self.W - m - 4, self.H - m - 4,
            fill="", outline=self._hex_alpha(C_CYAN, 0.1), width=1)

        # Línea superior
        cv.create_line(m, 44, self.W - m, 44,
            fill=self._hex_alpha(C_CYAN, 0.15), width=1)

        cv.create_text(26, 26,
            text="TOPOREVEAL SECURITY SUITE  ─  NETWORK INTELLIGENCE PLATFORM",
            font=("Courier", 9),
            fill=self._hex_alpha(C_CYAN, 0.35),
            anchor="w")

        # Indicador ONLINE
        cv.create_oval(self.W - 34, 18, self.W - 22, 30,
            fill=C_GREEN, outline="")
        cv.create_text(self.W - 38, 24,
            text="ONLINE",
            font=("Courier", 8),
            fill=C_GREEN,
            anchor="e")

    def _dibujar_esquinas(self):
        """Esquinas decorativas estilo HUD."""
        cv = self.cv
        L = 35
        m = 12
        grosor = 2

        esquinas = [
            [(m, m + L, m, m, m + L, m)],
            [(self.W - m - L, m, self.W - m, m, self.W - m, m + L)],
            [(m, self.H - m - L, m, self.H - m, m + L, self.H - m)],
            [(self.W - m - L, self.H - m, self.W - m, self.H - m,
              self.W - m, self.H - m - L)],
        ]
        for coords_list in esquinas:
            for coords in coords_list:
                cv.create_line(*coords,
                    fill=C_CYAN, width=grosor, joinstyle=tk.MITER)

    # ── ANIMACIÓN ─────────────────────────────────────────────────────────

    def _animar(self):
        """Loop de animación — 30 fps."""
        if not self._corriendo:
            return

        self._t += 0.05

        # Actualizar pulsos
        for p in self._pulsos:
            p["t"] += p["vel"]
            if p["t"] >= 1.0:
                p["t"] = 0.0
                p["arista"] = random.choice(self._aristas)
                p["color"] = random.choice([C_CYAN, C_GREEN, C_CYAN2])

        # Añadir nuevos pulsos ocasionalmente
        if len(self._pulsos) < 18 and random.random() < 0.05:
            self._pulsos.append({
                "arista": random.choice(self._aristas),
                "t"     : 0.0,
                "vel"   : random.uniform(0.008, 0.025),
                "color" : random.choice([C_CYAN, C_GREEN]),
            })

        # Actualizar mensajes de boot
        if self._msg_idx < len(self._boot_msgs):
            msg, color, umbral = self._boot_msgs[self._msg_idx]
            if self._progreso >= umbral - 0.01:
                self._mensajes.append((msg, color))
                self._msg_idx += 1

        self._dibujar()

        if self._corriendo:
            self.win.after(33, self._animar)  # ~30 fps

    def set_progreso(self, valor, cerrar_al_terminar=True):
        """
        Actualiza la barra de progreso (0.0 a 1.0).
        Llamado desde app.py durante la inicialización.
        """
        self._progreso = min(1.0, max(0.0, valor))
        if self._progreso >= 1.0 and cerrar_al_terminar:
            self.win.after(800, self._cerrar)

    def _cerrar_si_listo(self):
        if self._progreso >= 0.5:
            self._cerrar()

    def _cerrar(self):
        self._corriendo = False
        try:
            self.win.destroy()
        except Exception:
            pass
        if self.callback_listo:
            try:
                self.callback_listo()
            except Exception:
                pass

    # ── UTILIDADES ────────────────────────────────────────────────────────

    def _hex_puntos(self, cx, cy, r, offset=0):
        """Genera los 6 vértices de un hexágono."""
        puntos = []
        for i in range(6):
            angle = math.pi / 3 * i + offset
            puntos.append(cx + r * math.cos(angle))
            puntos.append(cy + r * math.sin(angle))
        return puntos

    @staticmethod
    def _hex_alpha(color_hex, alpha):
        """
        Mezcla color_hex con el fondo oscuro según alpha (0..1).
        Retorna string #RRGGBB compatible con tkinter.
        """
        # Parsear color
        h = color_hex.lstrip("#")
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        r = int(h[0:2], 16)
        g = int(h[2:4], 16)
        b = int(h[4:6], 16)
        # Fondo de referencia
        br, bg, bb = 2, 8, 16
        # Mezcla
        nr = int(br + (r - br) * alpha)
        ng = int(bg + (g - bg) * alpha)
        nb = int(bb + (b - bb) * alpha)
        # Clamp
        nr = max(0, min(255, nr))
        ng = max(0, min(255, ng))
        nb = max(0, min(255, nb))
        return f"#{nr:02x}{ng:02x}{nb:02x}"


# ── INTEGRACIÓN RÁPIDA ────────────────────────────────────────────────────────

def mostrar_splash(ventana_principal, callback_listo):
    """
    Función de entrada — crear y mostrar el splash.
    La ventana principal se mantiene oculta durante el splash.
    """
    ventana_principal.withdraw()
    splash = SplashScreen(ventana_principal, callback_listo)
    return splash


# ── TEST STANDALONE ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    root.title("TopoReveal")
    root.geometry("900x600")
    root.configure(bg="#020810")

    def on_listo():
        root.deiconify()
        print("[SPLASH] Animación terminada — app lista")

    splash = mostrar_splash(root, on_listo)

    # Simular progreso de carga
    def simular_carga():
        for i in range(101):
            time.sleep(0.04)
            try:
                root.after(0, lambda v=i/100: splash.set_progreso(
                    v, cerrar_al_terminar=(v >= 1.0)))
            except Exception:
                break

    threading.Thread(target=simular_carga, daemon=True).start()
    root.mainloop()
