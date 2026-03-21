"""
panel_alertas.py — Panel izquierdo de alertas priorizadas.
Versión mejorada: tarjetas expandibles, filtros por severidad,
botones de acción directa al arsenal.
"""

import tkinter as tk

COLOR_FONDO       = "#0d1117"
COLOR_PANEL       = "#161b22"
COLOR_BORDE       = "#30363d"
COLOR_TEXTO       = "#e6edf3"
COLOR_TEXTO_SUB   = "#8b949e"
COLOR_ACENTO      = "#1f6feb"
COLOR_CONF        = "#3fb950"
COLOR_SOSP        = "#f0883e"
COLOR_FANT        = "#da3633"
COLOR_LOBBY       = "#6e7681"
COLOR_SEV_INFO    = "#58d6ff"
COLOR_SEV_MEDIO   = "#f0e040"
COLOR_SEV_ALTO    = "#f0883e"
COLOR_SEV_CRITICO = "#da3633"
COLOR_LOBBY       = "#6e7681"

SEV_COLOR = {
    "info"   : COLOR_SEV_INFO,
    "medio"  : COLOR_SEV_MEDIO,
    "alto"   : COLOR_SEV_ALTO,
    "critico": COLOR_SEV_CRITICO,
}
SEV_ORDEN = {"critico": 3, "alto": 2, "medio": 1, "info": 0}
SEV_ICONO = {"critico": "🔴", "alto": "🟠", "medio": "🟡", "info": "🔵"}

ANCHO_PANEL = 240


class PanelAlertas:
    """
    Panel izquierdo — muestra alertas priorizadas como tarjetas expandibles.
    Cada tarjeta se puede expandir para ver detalles y lanzar acciones del arsenal.
    """

    def __init__(self, padre):
        self.frame = tk.Frame(padre, bg=COLOR_PANEL, width=ANCHO_PANEL)
        self.frame.pack_propagate(False)

        self._topologia      = None
        self._on_nodo_click  = None
        self._on_arsenal     = None   # callback para lanzar arsenal
        self._alerta_expand  = None   # key de la tarjeta expandida
        self._tarjetas       = {}     # key → frame detalle
        self._filtro_sev     = None
        self._n_alertas_prev = -1     # para detectar cambios y no redibujar siempre

        self._construir()

    def set_topologia(self, topologia):
        self._topologia = topologia

    # ── CONSTRUCCIÓN ──────────────────────────────────────────────

    def _construir(self):
        # ── Cabecera con riesgo máximo ────────────────────────────
        cab = tk.Frame(self.frame, bg=COLOR_PANEL)
        cab.pack(fill=tk.X, padx=10, pady=(10, 2))

        self.lbl_riesgo = tk.Label(cab,
            text="● RIESGO", bg=COLOR_PANEL,
            fg=COLOR_SEV_CRITICO, font=("Monospace", 9, "bold"))
        self.lbl_riesgo.pack(side=tk.LEFT)

        self.lbl_score = tk.Label(cab,
            text="0", bg=COLOR_PANEL,
            fg=COLOR_SEV_CRITICO, font=("Monospace", 18, "bold"))
        self.lbl_score.pack(side=tk.RIGHT)

        # Barra de riesgo
        barra_bg = tk.Frame(self.frame, bg=COLOR_BORDE, height=3)
        barra_bg.pack(fill=tk.X, padx=10, pady=(0, 4))
        self.barra_riesgo = tk.Frame(barra_bg, bg=COLOR_SEV_CRITICO, height=3)
        self.barra_riesgo.place(x=0, y=0, relwidth=0, height=3)

        tk.Label(self.frame, text="risk máx. (avg)",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 7)).pack(anchor="e", padx=10)

        tk.Frame(self.frame, bg=COLOR_BORDE, height=1).pack(fill=tk.X, pady=3)

        # ── Estadísticas de red ───────────────────────────────────
        tk.Label(self.frame, text="ESTADÍSTICAS DE RED",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 7, "bold")).pack(anchor="w", padx=10, pady=(4, 2))

        # ── Total de sesión (todos incluyendo lobby) ──────────────
        total_frame = tk.Frame(self.frame, bg=COLOR_PANEL)
        total_frame.pack(fill=tk.X, padx=10, pady=(0, 2))
        tk.Label(total_frame, text="Sesión:",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 7), anchor="w").pack(side=tk.LEFT)
        self.lbl_total_sesion = tk.Label(total_frame,
            text="0 dispositivos",
            bg=COLOR_PANEL, fg=COLOR_TEXTO,
            font=("Monospace", 7, "bold"), anchor="w")
        self.lbl_total_sesion.pack(side=tk.LEFT, padx=4)
        self.lbl_en_lobby = tk.Label(total_frame,
            text="",
            bg=COLOR_PANEL, fg=COLOR_LOBBY,
            font=("Monospace", 7), anchor="e")
        self.lbl_en_lobby.pack(side=tk.RIGHT)

        stats = tk.Frame(self.frame, bg=COLOR_PANEL)
        stats.pack(fill=tk.X, padx=10)
        self.lbl_hosts    = self._stat(stats, "0", "activos",  COLOR_CONF)
        self.lbl_criticos = self._stat(stats, "0", "críticos", COLOR_SEV_CRITICO)
        self.lbl_altos    = self._stat(stats, "0", "altos",    COLOR_SEV_ALTO)
        self.lbl_alertas  = self._stat(stats, "0", "alertas",  COLOR_SEV_MEDIO)

        tk.Frame(self.frame, bg=COLOR_BORDE, height=1).pack(fill=tk.X, pady=4)

        # ── Tipos de dispositivo ──────────────────────────────────
        tk.Label(self.frame, text="TIPOS DE DISPOSITIVO",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 7, "bold")).pack(anchor="w", padx=10, pady=(0, 2))
        self._frame_tipos = tk.Frame(self.frame, bg=COLOR_PANEL)
        self._frame_tipos.pack(fill=tk.X, padx=10)

        tk.Frame(self.frame, bg=COLOR_BORDE, height=1).pack(fill=tk.X, pady=3)

        # ── Distribución de riesgo ────────────────────────────────
        tk.Label(self.frame, text="DISTRIBUCIÓN DE RIESGO",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 7, "bold")).pack(anchor="w", padx=10, pady=(0, 2))
        self._frame_dist = tk.Frame(self.frame, bg=COLOR_PANEL)
        self._frame_dist.pack(fill=tk.X, padx=10)

        tk.Frame(self.frame, bg=COLOR_BORDE, height=1).pack(fill=tk.X, pady=3)

        # ── Subredes detectadas ───────────────────────────────────
        tk.Label(self.frame, text="SUBREDES DETECTADAS",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 7, "bold")).pack(anchor="w", padx=10, pady=(0, 2))
        self.lbl_subredes = tk.Label(self.frame,
            text="Sin subredes secundarias",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 7), anchor="w")
        self.lbl_subredes.pack(fill=tk.X, padx=10)

        tk.Frame(self.frame, bg=COLOR_BORDE, height=1).pack(fill=tk.X, pady=3)

        # ── ALERTAS PRIORIZADAS — cabecera ────────────────────────
        hdr = tk.Frame(self.frame, bg=COLOR_PANEL)
        hdr.pack(fill=tk.X, padx=8, pady=(2, 1))

        self.lbl_alertas_titulo = tk.Label(hdr,
            text="ALERTAS PRIORIZADAS",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 7, "bold"), anchor="w")
        self.lbl_alertas_titulo.pack(side=tk.LEFT)

        # Botón limpiar INFO
        tk.Button(hdr, text="✕ info",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 6), relief=tk.FLAT, padx=2,
            cursor="hand2",
            command=self._limpiar_info
        ).pack(side=tk.RIGHT)

        # Contador resumen
        self.lbl_resumen_alertas = tk.Label(self.frame,
            text="0 total  •  0 críticas  •  0 altas",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 6), anchor="w")
        self.lbl_resumen_alertas.pack(fill=tk.X, padx=10, pady=(0, 2))

        # Filtros de severidad
        self._filtro_sev = tk.StringVar(value="todas")
        frow = tk.Frame(self.frame, bg=COLOR_PANEL)
        frow.pack(fill=tk.X, padx=8, pady=(0, 3))
        for sev, col in [("todas", COLOR_TEXTO_SUB),
                         ("critico", COLOR_SEV_CRITICO),
                         ("alto",    COLOR_SEV_ALTO),
                         ("medio",   COLOR_SEV_MEDIO),
                         ("info",    COLOR_SEV_INFO)]:
            tk.Radiobutton(frow, text=sev[:4],
                variable=self._filtro_sev, value=sev,
                bg=COLOR_PANEL, fg=col,
                selectcolor=COLOR_FONDO,
                activebackground=COLOR_PANEL,
                font=("Monospace", 6), relief=tk.FLAT,
                command=self._forzar_rebuild
            ).pack(side=tk.LEFT, padx=1)

        # ── Área scrollable de tarjetas ───────────────────────────
        wrap = tk.Frame(self.frame, bg=COLOR_FONDO)
        wrap.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

        sb = tk.Scrollbar(wrap, orient=tk.VERTICAL,
            bg=COLOR_PANEL, troughcolor=COLOR_FONDO, width=6)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self._cv = tk.Canvas(wrap, bg=COLOR_FONDO,
            highlightthickness=0,
            yscrollcommand=sb.set)
        self._cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.config(command=self._cv.yview)

        self._frame_tarjetas = tk.Frame(self._cv, bg=COLOR_FONDO)
        self._win_tarjetas = self._cv.create_window(
            (0, 0), window=self._frame_tarjetas, anchor="nw")

        self._frame_tarjetas.bind("<Configure>",
            lambda e: self._cv.configure(
                scrollregion=self._cv.bbox("all")))
        self._cv.bind("<Configure>",
            lambda e: self._cv.itemconfig(
                self._win_tarjetas, width=e.width))

        for w in (self._cv, self._frame_tarjetas):
            w.bind("<Button-4>",
                lambda e: self._cv.yview_scroll(-1, "units"))
            w.bind("<Button-5>",
                lambda e: self._cv.yview_scroll(1, "units"))

    def _stat(self, padre, val, lbl, col):
        bloque = tk.Frame(padre, bg=COLOR_PANEL)
        bloque.pack(side=tk.LEFT, expand=True)
        lv = tk.Label(bloque, text=val, bg=COLOR_PANEL,
            fg=col, font=("Monospace", 14, "bold"))
        lv.pack()
        tk.Label(bloque, text=lbl, bg=COLOR_PANEL,
            fg=COLOR_TEXTO_SUB, font=("Monospace", 6)).pack()
        return lv

    # ── ACTUALIZACIÓN ──────────────────────────────────────────────

    def actualizar(self):
        if not self._topologia:
            return

        nodos = self._topologia.todos_los_nodos()
        alertas_raw = list(getattr(self._topologia, 'alertas', []))

        activos   = [n for n in nodos if not n.en_lobby]
        en_lobby  = [n for n in nodos if n.en_lobby]
        total_ses = len(nodos)   # TODOS incluyendo lobby

        criticos  = sum(1 for n in activos if n.severidad_max == "critico")
        altos     = sum(1 for n in activos if n.severidad_max == "alto")
        n_alertas = len(alertas_raw)

        # Total de sesión
        self.lbl_total_sesion.config(
            text=f"{total_ses} dispositivo{'s' if total_ses != 1 else ''}")
        self.lbl_en_lobby.config(
            text=f"💤 {len(en_lobby)} lobby" if en_lobby else "",
            fg=COLOR_LOBBY)

        self.lbl_hosts.config(text=str(len(activos)))
        self.lbl_criticos.config(text=str(criticos))
        self.lbl_altos.config(text=str(altos))
        self.lbl_alertas.config(text=str(n_alertas))

        # ── Risk score máximo ─────────────────────────────────────
        scores = [getattr(n, 'risk_score', 0) or 0 for n in activos]
        score_max = max(scores) if scores else 0
        score_avg = int(sum(scores) / max(len(scores), 1))
        col_score = (COLOR_SEV_CRITICO if score_max >= 70 else
                     COLOR_SEV_ALTO    if score_max >= 40 else
                     COLOR_SEV_MEDIO   if score_max >= 20 else COLOR_CONF)
        self.lbl_score.config(text=str(score_max), fg=col_score)
        self.lbl_riesgo.config(fg=col_score)
        try:
            ancho = self.barra_riesgo.master.winfo_width()
            self.barra_riesgo.place(x=0, y=0,
                width=int(ancho * score_max / 100), height=3)
            self.barra_riesgo.config(bg=col_score)
        except Exception:
            pass

        # ── Tipos de dispositivo ──────────────────────────────────
        for w in self._frame_tipos.winfo_children():
            w.destroy()
        tipos = {}
        for n in activos:
            t = n.tipo or "desconocido"
            tipos[t] = tipos.get(t, 0) + 1
        for tipo, cnt in sorted(tipos.items(), key=lambda x: x[1], reverse=True):
            fila = tk.Frame(self._frame_tipos, bg=COLOR_PANEL)
            fila.pack(fill=tk.X)
            tk.Label(fila, text=f"  {tipo}", bg=COLOR_PANEL,
                fg=COLOR_TEXTO_SUB, font=("Monospace", 7),
                anchor="w").pack(side=tk.LEFT)
            tk.Label(fila, text=str(cnt), bg=COLOR_PANEL,
                fg=COLOR_TEXTO, font=("Monospace", 7, "bold"),
                anchor="e").pack(side=tk.RIGHT)

        # ── Distribución de riesgo ────────────────────────────────
        for w in self._frame_dist.winfo_children():
            w.destroy()
        dist = {"alto": 0, "medio": 0, "info": 0}
        for n in activos:
            s = getattr(n, 'severidad_max', None)
            if s and s in dist:
                dist[s] += 1
        for sev, cnt in dist.items():
            if cnt == 0:
                continue
            fila = tk.Frame(self._frame_dist, bg=COLOR_PANEL)
            fila.pack(fill=tk.X, pady=1)
            col = SEV_COLOR.get(sev, COLOR_TEXTO_SUB)
            tk.Label(fila, text=sev.upper(), bg=COLOR_PANEL,
                fg=col, font=("Monospace", 7, "bold"),
                width=8, anchor="w").pack(side=tk.LEFT)
            # Mini barra
            bar_bg = tk.Frame(fila, bg=COLOR_BORDE, height=6, width=100)
            bar_bg.pack(side=tk.LEFT, padx=4)
            bar_bg.pack_propagate(False)
            fill_w = min(100, cnt * 30)
            tk.Frame(bar_bg, bg=col, height=6, width=fill_w).place(x=0, y=0)
            tk.Label(fila, text=str(cnt), bg=COLOR_PANEL,
                fg=col, font=("Monospace", 7)).pack(side=tk.LEFT)

        # ── Subredes ──────────────────────────────────────────────
        subredes = getattr(self._topologia, 'subredes_secundarias', {})
        if subredes:
            txt = ", ".join(f"{s}.x" for s in list(subredes.keys())[:3])
            self.lbl_subredes.config(text=txt, fg=COLOR_SEV_INFO)
        else:
            self.lbl_subredes.config(
                text="Sin subredes secundarias", fg=COLOR_TEXTO_SUB)

        # ── Tarjetas de alerta ────────────────────────────────────
        sev_activa = self._filtro_sev.get() if self._filtro_sev else "todas"
        alertas_sorted = sorted(alertas_raw,
            key=lambda h: SEV_ORDEN.get(h.severidad, 0), reverse=True)
        if sev_activa != "todas":
            alertas_filtradas = [h for h in alertas_sorted
                                 if h.severidad == sev_activa]
        else:
            alertas_filtradas = alertas_sorted

        # Resumen
        n_crit = sum(1 for h in alertas_raw if h.severidad == "critico")
        n_alto = sum(1 for h in alertas_raw if h.severidad == "alto")
        self.lbl_resumen_alertas.config(
            text=f"{n_alertas} total  •  {n_crit} críticas  •  {n_alto} altas",
            fg=COLOR_SEV_CRITICO if n_crit else
               COLOR_SEV_ALTO    if n_alto else COLOR_TEXTO_SUB)
        self.lbl_alertas_titulo.config(
            fg=COLOR_SEV_CRITICO if n_crit else COLOR_TEXTO_SUB)

        # Hash de contenido real — reconstruir SOLO si cambió algo
        alertas_lim = alertas_filtradas[:60]
        hash_nuevo  = hash(tuple(
            (h.ip, h.servicio, h.puerto, h.severidad)
            for h in alertas_lim))
        if hash_nuevo != getattr(self, '_hash_alertas', None):
            self._hash_alertas = hash_nuevo
            self._rebuild_tarjetas_incremental(alertas_lim)

    def _rebuild_tarjetas_incremental(self, alertas):
        """
        Actualización incremental — solo agrega tarjetas nuevas.
        No destruye las existentes → sin parpadeo.
        Si el orden cambió o hay eliminaciones, hace rebuild completo.
        """
        claves_nuevas  = [f"{h.ip}_{h.servicio}_{h.puerto}" for h in alertas]
        claves_actuales = list(self._tarjetas.keys())

        # Si el orden es idéntico excepto por adiciones al final → incremental
        if (claves_actuales == claves_nuevas[:len(claves_actuales)] and
                len(claves_nuevas) >= len(claves_actuales)):
            # Solo agregar las nuevas al final
            for h in alertas[len(claves_actuales):]:
                self._hacer_tarjeta(h)
        else:
            # Cambio de orden o eliminación → rebuild completo pero rápido
            self._rebuild_tarjetas(alertas)

        self._cv.update_idletasks()
        self._cv.configure(scrollregion=self._cv.bbox("all"))

    def _rebuild_tarjetas(self, alertas):
        """Reconstruye todas las tarjetas desde cero."""
        for w in self._frame_tarjetas.winfo_children():
            w.destroy()
        self._tarjetas     = {}
        self._alerta_expand = None

        for h in alertas:
            self._hacer_tarjeta(h)

        self._cv.update_idletasks()
        self._cv.configure(scrollregion=self._cv.bbox("all"))

    def _hacer_tarjeta(self, h):
        """Crea una tarjeta expandible para un hallazgo."""
        sev  = h.severidad or "info"
        col  = SEV_COLOR.get(sev, COLOR_TEXTO)
        ico  = SEV_ICONO.get(sev, "●")
        key  = f"{h.ip}_{h.servicio}_{h.puerto}"

        tarjeta = tk.Frame(self._frame_tarjetas, bg=COLOR_PANEL,
            highlightbackground=col, highlightthickness=1)
        tarjeta.pack(fill=tk.X, padx=3, pady=1)

        # ── Fila compacta siempre visible ─────────────────────────
        fila = tk.Frame(tarjeta, bg=COLOR_PANEL, cursor="hand2")
        fila.pack(fill=tk.X, padx=3, pady=2)

        tk.Label(fila, text=ico, bg=COLOR_PANEL,
            font=("Monospace", 8)).pack(side=tk.LEFT)

        # IP
        tk.Label(fila, text=h.ip,
            bg=COLOR_PANEL, fg=COLOR_SEV_INFO,
            font=("Monospace", 8), width=12, anchor="w"
        ).pack(side=tk.LEFT)

        # Servicio (truncado)
        svc = (h.servicio or "?")[:12]
        lbl_svc = tk.Label(fila, text=svc,
            bg=COLOR_PANEL, fg=col,
            font=("Monospace", 8, "bold"), anchor="w")
        lbl_svc.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Timestamp
        ts = (getattr(h, 'timestamp', '') or '')[-5:]
        tk.Label(fila, text=ts,
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 7)).pack(side=tk.RIGHT)

        # ── Frame de detalle (oculto) ─────────────────────────────
        detalle_frame = tk.Frame(tarjeta, bg="#0a0f16")

        def _toggle(event=None, k=key, df=detalle_frame, h=h, col=col):
            if self._alerta_expand == k:
                df.pack_forget()
                self._alerta_expand = None
            else:
                # Cerrar anterior
                if self._alerta_expand and self._alerta_expand in self._tarjetas:
                    old = self._tarjetas[self._alerta_expand]
                    if old:
                        try:
                            old.pack_forget()
                        except Exception:
                            pass
                self._alerta_expand = k
                self._tarjetas[k] = df
                self._rellenar_detalle(df, h, col)
                df.pack(fill=tk.X, padx=3, pady=(0, 3))
            self._cv.update_idletasks()
            self._cv.configure(scrollregion=self._cv.bbox("all"))

        # Bind a toda la fila
        for widget in (tarjeta, fila):
            widget.bind("<Button-1>", _toggle)
        for child in fila.winfo_children():
            child.bind("<Button-1>", _toggle)

        self._tarjetas[key] = None

    def _rellenar_detalle(self, frame, h, col):
        """Rellena el frame de detalle con info completa y botones."""
        for w in frame.winfo_children():
            w.destroy()

        detalle = getattr(h, 'detalle', getattr(h, 'desc', '')) or '—'
        puerto  = h.puerto if h.puerto else '—'

        # Texto de detalle
        info = (
            f"  Puerto  : {puerto}\n"
            f"  Svc     : {h.servicio or '—'}\n"
            f"  Hora    : {getattr(h,'timestamp','—')}\n"
            f"  Detalle : {detalle[:60]}"
        )
        tk.Label(frame, text=info,
            bg="#0a0f16", fg=COLOR_TEXTO,
            font=("Monospace", 7), anchor="w", justify=tk.LEFT,
            wraplength=210, padx=4, pady=3
        ).pack(fill=tk.X)

        # ── Botones de acción ─────────────────────────────────────
        btns = tk.Frame(frame, bg="#0a0f16")
        btns.pack(fill=tk.X, padx=4, pady=(0, 4))

        def _btn(txt, cmd):
            tk.Button(btns, text=txt, command=cmd,
                bg=COLOR_BORDE, fg=COLOR_TEXTO,
                font=("Monospace", 7), relief=tk.FLAT,
                padx=4, pady=1, cursor="hand2",
                activebackground=COLOR_ACENTO
            ).pack(side=tk.LEFT, padx=2)

        # Copiar
        def _copiar():
            txt = f"{h.ip} | {h.servicio}:{puerto} [{h.severidad}] {detalle}"
            try:
                frame.clipboard_clear()
                frame.clipboard_append(txt)
            except Exception:
                pass
        _btn("📋", _copiar)

        # Ir al nodo
        def _ir():
            if self._on_nodo_click:
                self._on_nodo_click(h.ip)
        _btn("🎯 Nodo", _ir)

        # Arsenal sugerido
        eid, etq = self._sugerir_arsenal(h)
        def _arsenal(e=eid, ip=h.ip):
            if self._on_arsenal:
                self._on_arsenal(ip, e)
        _btn(f"⚡ {etq}", _arsenal)

    def _sugerir_arsenal(self, h):
        """Retorna (escaneo_id, etiqueta) según el tipo de hallazgo."""
        svc = (h.servicio or "").lower()
        if any(k in svc for k in ("vuln","cve")):
            return "vuln", "Vuln"
        if any(k in svc for k in ("ssl","tls","cert")):
            return "versions", "Vers."
        if any(k in svc for k in ("rtsp","hikvision","cámara","camera")):
            return "scripts", "Scripts"
        if any(k in svc for k in ("smb","share","ldap")):
            return "scripts", "Scripts"
        if h.puerto and h.puerto > 0:
            return "versions", "Vers."
        return "os", "OS"

    def _limpiar_info(self):
        """Elimina alertas INFO de la topología."""
        if self._topologia and hasattr(self._topologia, 'alertas'):
            self._topologia.alertas = [
                h for h in self._topologia.alertas
                if h.severidad != "info"]
            self._forzar_rebuild()

    def _forzar_rebuild(self):
        """Fuerza reconstrucción de tarjetas en el próximo ciclo."""
        self._n_alertas_prev = -1
