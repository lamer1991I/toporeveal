"""
ventana_stats.py — Dashboard gráfico para TopoReveal usando Matplotlib.

Muestra analíticas en tiempo real sobre la red:
  - Distribución de tipos de dispositivos.
  - Histograma de niveles de riesgo.
  - Top puertos abiertos.
  - Nodos activos vs inactivos.
"""

import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib
from datetime import datetime

# Configuración estética oscura
plt.style.use('dark_background')
matplotlib.rcParams['font.size'] = 8
matplotlib.rcParams['axes.titlesize'] = 9
matplotlib.rcParams['text.color'] = '#e6edf3'
matplotlib.rcParams['axes.labelcolor'] = '#8b949e'
matplotlib.rcParams['xtick.color'] = '#8b949e'
matplotlib.rcParams['ytick.color'] = '#8b949e'

COLOR_BG = "#0d1117"

class VentanaStats(tk.Toplevel):
    def __init__(self, parent, topologia):
        super().__init__(parent)
        self.title("TopoReveal — Dashboard de Analíticas")
        self.geometry("900x650")
        self.configure(bg=COLOR_BG)
        self.topologia = topologia
        self.protocol("WM_DELETE_WINDOW", self._cerrar)
        self._alive = True
        
        self._construir_ui()
        self._actualizar_graficas()

    def _construir_ui(self):
        # Header
        header = tk.Frame(self, bg=COLOR_BG, padx=20, pady=10)
        header.pack(fill=tk.X)
        
        tk.Label(header, text="DASHBOARD DE RED", 
                 bg=COLOR_BG, fg="#58d6ff", 
                 font=("Monospace", 12, "bold")).pack(side=tk.LEFT)
        
        self.lbl_info = tk.Label(header, text="Actualizando cada 10s...", 
                                bg=COLOR_BG, fg="#8b949e", font=("Monospace", 8))
        self.lbl_info.pack(side=tk.RIGHT)

        # Contenedor de gráficas (Grid 2x2)
        self.container = tk.Frame(self, bg=COLOR_BG)
        self.container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Figura de Matplotlib con 4 subplots
        self.fig, self.axs = plt.subplots(2, 2, figsize=(10, 7), facecolor=COLOR_BG)
        self.fig.tight_layout(pad=4.0)
        
        self.canvas_plot = FigureCanvasTkAgg(self.fig, master=self.container)
        self.canvas_plot.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def _actualizar_graficas(self):
        if not self._alive: return
        
        nodos = self.topologia.todos_los_nodos()
        if not nodos:
            self.after(5000, self._actualizar_graficas)
            return

        # 1. Pie Chart: Tipos de dispositivos
        tipos = {}
        for n in nodos:
            t = n.tipo or "desconocido"
            tipos[t] = tipos.get(t, 0) + 1
        
        ax1 = self.axs[0, 0]
        ax1.clear()
        if tipos:
            ax1.pie(tipos.values(), labels=list(tipos.keys()), autopct='%1.1f%%', 
                   startangle=140, colors=['#1f6feb', '#238636', '#d29922', '#da3633', '#8957e5'])
        ax1.set_title("Distribución por Tipo")

        # 2. Bar Chart: Risk Score
        scores = [getattr(n, 'risk_score', 0) for n in nodos]
        ax2 = self.axs[0, 1]
        ax2.clear()
        ax2.hist(scores, bins=[0, 20, 40, 60, 80, 100], color='#d29922', rwidth=0.8)
        ax2.set_title("Niveles de Riesgo")
        ax2.set_xlabel("Score")
        ax2.set_ylabel("Hosts")

        # 3. Horizontal Bar: Top Puertos
        puertos_count = {}
        for n in nodos:
            for p in n.puertos_abiertos:
                puertos_count[p] = puertos_count.get(p, 0) + 1
        
        ax3 = self.axs[1, 0]
        ax3.clear()
        if puertos_count:
            # Top 10
            top = sorted(puertos_count.items(), key=lambda x: x[1], reverse=True)[:10]
            labels = [str(p[0]) for p in top]
            values = [p[1] for p in top]
            ax3.barh(labels, values, color='#1f6feb')
        ax3.set_title("Top 10 Puertos Abiertos")
        ax3.invert_yaxis()

        # 4. Estadísticas Generales (Texto/Info)
        ax4 = self.axs[1, 1]
        ax4.clear()
        ax4.axis('off')
        
        vivos = len([n for n in nodos if not n.en_lobby])
        lobby = len([n for n in nodos if n.en_lobby])
        alertas = len(getattr(self.topologia, 'alertas', []))
        sev_max = "OK"
        if alertas:
            orden_sev = {"critico":3,"alto":2,"medio":1,"info":0}
            max_h = max(self.topologia.alertas, key=lambda h: orden_sev.get(h.severidad, 0))
            sev_max = max_h.severidad.upper()

        txt = (f"Resumen de Red\n"
               f"───────────────────\n"
               f"Total de Hosts:   {len(nodos)}\n"
               f"Activos ahora:    {vivos}\n"
               f"En Lobby:         {lobby}\n"
               f"Total Alertas:    {alertas}\n"
               f"Gravedad Máx:     {sev_max}\n"
               f"Generado: {datetime.now().strftime('%H:%M:%S')}")
        
        ax4.text(0.1, 0.5, txt, transform=ax4.transAxes, 
                fontfamily='monospace', fontsize=10, 
                verticalalignment='center', color='#e6edf3')

        self.fig.tight_layout(pad=3.0)
        self.canvas_plot.draw()
        
        # Volver a llamar en 10 segundos
        self.after(10000, self._actualizar_graficas)

    def _cerrar(self):
        self._alive = False
        self.destroy()
