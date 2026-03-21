"""
toast.py — Sistema de notificaciones toast para TopoReveal.

Muestra popups flotantes no intrusivos en la esquina superior derecha
cuando ocurren eventos importantes en la red:
  - Nuevo host detectado con riesgo alto/critico
  - Vulnerabilidad critica encontrada por el arsenal
  - ARP scanner detectado
  - Host reactivado desde lobby
"""

import tkinter as tk
import threading
import queue
import time

# Colores por nivel
NIVELES = {
    "critico": {"bg": "#3d0000", "borde": "#da3633", "icono": "🔴", "fg": "#ffaaaa"},
    "alto":    {"bg": "#2d1800", "borde": "#f0883e", "icono": "🟠", "fg": "#ffcc88"},
    "medio":   {"bg": "#2d2800", "borde": "#f0e040", "icono": "🟡", "fg": "#ffffaa"},
    "info":    {"bg": "#001830", "borde": "#58d6ff", "icono": "🔵", "fg": "#88ddff"},
    "ok":      {"bg": "#002800", "borde": "#3fb950", "icono": "🟢", "fg": "#aaffaa"},
}

COLOR_FONDO    = "#0d1117"
COLOR_TEXTO    = "#e6edf3"
COLOR_TEXTO_SUB = "#8b949e"

# Cola global para encolar toasts desde hilos secundarios
_cola_toasts = queue.Queue()
_ventana_raiz = None
_toasts_activos = []   # lista de ventanas Toast abiertas
_lock = threading.Lock()


def inicializar(ventana_raiz):
    """Llamar desde app.py al iniciar — registra la ventana raíz."""
    global _ventana_raiz
    _ventana_raiz = ventana_raiz
    _procesar_cola()


def notificar(titulo, mensaje, nivel="info"):
    """
    Encola una notificación toast. Seguro de llamar desde cualquier hilo.
    nivel: "critico" | "alto" | "medio" | "info" | "ok"
    """
    _cola_toasts.put((titulo, mensaje, nivel))


def _procesar_cola():
    """Polling de la cola de toasts desde el hilo principal de tkinter."""
    if _ventana_raiz is None:
        return
    try:
        while True:
            titulo, mensaje, nivel = _cola_toasts.get_nowait()
            _mostrar_toast(titulo, mensaje, nivel)
    except queue.Empty:
        pass
    # Volver a llamar en 500ms
    _ventana_raiz.after(500, _procesar_cola)


def _mostrar_toast(titulo, mensaje, nivel):
    """Crea y muestra la ventana toast."""
    global _toasts_activos
    if _ventana_raiz is None:
        return

    # Limpiar referencias a ventanas ya cerradas
    with _lock:
        _toasts_activos = [t for t in _toasts_activos if t.winfo_exists()]

    try:
        toast = _Toast(_ventana_raiz, titulo, mensaje, nivel,
                       offset_y=len(_toasts_activos))
        with _lock:
            _toasts_activos.append(toast)
    except Exception:
        pass


class _Toast(tk.Toplevel):
    """Ventana toast individual."""

    ANCHO    = 320
    ALTO     = 72
    MARGEN   = 10
    DURACION = 5000   # ms antes de empezar a desvanecerse

    def __init__(self, parent, titulo, mensaje, nivel, offset_y=0):
        super().__init__(parent)
        self._nivel  = nivel
        self._alpha  = 1.0
        self._alive  = True

        cfg = NIVELES.get(nivel, NIVELES["info"])

        # Sin decoraciones de ventana
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        try:
            self.attributes("-alpha", 1.0)
        except Exception:
            pass

        self.configure(bg=cfg["borde"])

        # Posicionar esquina superior derecha
        sw = self.winfo_screenwidth()
        x  = sw - self.ANCHO - self.MARGEN
        y  = self.MARGEN + offset_y * (self.ALTO + 8)
        self.geometry(f"{self.ANCHO}x{self.ALTO}+{x}+{y}")

        # Marco interior
        inner = tk.Frame(self, bg=cfg["bg"],
                         padx=10, pady=8)
        inner.pack(fill=tk.BOTH, expand=True,
                   padx=1, pady=1)

        # Fila superior: icono + título
        fila1 = tk.Frame(inner, bg=cfg["bg"])
        fila1.pack(fill=tk.X)

        tk.Label(fila1, text=cfg["icono"],
                 bg=cfg["bg"], fg=cfg["borde"],
                 font=("Monospace", 11)).pack(side=tk.LEFT)

        tk.Label(fila1, text=f"  {titulo}",
                 bg=cfg["bg"], fg=cfg["fg"],
                 font=("Monospace", 9, "bold"),
                 anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Botón cerrar
        tk.Button(fila1, text="✕",
                  bg=cfg["bg"], fg=COLOR_TEXTO_SUB,
                  font=("Monospace", 8), relief=tk.FLAT,
                  cursor="hand2", padx=2,
                  command=self._cerrar_inmediato
                  ).pack(side=tk.RIGHT)

        # Fila mensaje
        tk.Label(inner, text=mensaje,
                 bg=cfg["bg"], fg=COLOR_TEXTO_SUB,
                 font=("Monospace", 8), anchor="w",
                 wraplength=280, justify=tk.LEFT
                 ).pack(fill=tk.X, pady=(2, 0))

        # Barra de progreso (se va vaciando)
        self._barra_cont = tk.Frame(inner, bg=cfg["borde"], height=2)
        self._barra_cont.pack(fill=tk.X, side=tk.BOTTOM)
        self._barra = tk.Frame(self._barra_cont, bg=cfg["borde"], height=2)
        self._barra.pack(fill=tk.X, side=tk.LEFT)

        # Click en el toast lo cierra
        for widget in [inner, fila1]:
            widget.bind("<Button-1>", lambda e: self._cerrar_inmediato())

        # Temporizador: iniciar fade después de DURACION ms
        self.after(self.DURACION, self._iniciar_fade)
        # Actualizar barra de progreso
        self._inicio = time.time()
        self._actualizar_barra()

    def _actualizar_barra(self):
        if not self._alive or not self.winfo_exists():
            return
        elapsed = (time.time() - self._inicio) * 1000
        rel = max(0.0, 1.0 - elapsed / self.DURACION)
        try:
            self._barra.place(relwidth=rel, relheight=1.0)
        except Exception:
            pass
        if rel > 0:
            self.after(50, self._actualizar_barra)

    def _iniciar_fade(self):
        if not self._alive or not self.winfo_exists():
            return
        self._fade()

    def _fade(self):
        if not self._alive or not self.winfo_exists():
            return
        self._alpha -= 0.08
        if self._alpha <= 0:
            self._cerrar_inmediato()
            return
        try:
            self.attributes("-alpha", self._alpha)
        except Exception:
            pass
        self.after(40, self._fade)

    def _cerrar_inmediato(self):
        self._alive = False
        try:
            self.destroy()
        except Exception:
            pass
