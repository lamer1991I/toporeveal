import tkinter as tk

COLOR_FONDO      = "#0d1117"
COLOR_PANEL      = "#161b22"
COLOR_BORDE      = "#30363d"
COLOR_TEXTO      = "#e6edf3"
COLOR_TEXTO_SUB  = "#8b949e"
COLOR_CONF       = "#3fb950"
COLOR_SOSP       = "#f0883e"
COLOR_FANT       = "#da3633"
COLOR_ACENTO     = "#1f6feb"
COLOR_EXT        = "#8957e5"
COLOR_LOBBY      = "#6e7681"
COLOR_SEV_INFO    = "#58d6ff"
COLOR_SEV_MEDIO   = "#f0e040"
COLOR_SEV_ALTO    = "#f0883e"
COLOR_SEV_CRITICO = "#da3633"

SEV_COLOR = {
    "info":    COLOR_SEV_INFO,
    "medio":   COLOR_SEV_MEDIO,
    "alto":    COLOR_SEV_ALTO,
    "critico": COLOR_SEV_CRITICO,
}

ANCHO_PANEL = 240


class Panel:
    def __init__(self, padre):
        self.frame = tk.Frame(padre, bg=COLOR_PANEL, width=ANCHO_PANEL)
        self.frame.pack_propagate(False)
        self._nodo_actual  = None
        self._topologia    = None
        self._lobby_visible = False
        self._var_busq = None
        self._lista_nodos_orden = []
        self._on_seleccion_en_lista = None

        # ── Scroll global del panel derecho ──────────────────────────
        self._sb = tk.Scrollbar(self.frame, orient=tk.VERTICAL,
            bg=COLOR_PANEL, troughcolor=COLOR_FONDO,
            activebackground=COLOR_BORDE, width=8)
        self._sb.pack(side=tk.RIGHT, fill=tk.Y)

        self._cv = tk.Canvas(self.frame, bg=COLOR_PANEL,
            highlightthickness=0,
            yscrollcommand=self._sb.set)
        self._cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._sb.config(command=self._cv.yview)

        # Frame interior donde va todo el contenido
        self._inner = tk.Frame(self._cv, bg=COLOR_PANEL)
        self._win = self._cv.create_window((0, 0), window=self._inner,
            anchor="nw", tags="inner")

        # Actualizar scrollregion cuando cambia el tamaño del inner
        self._inner.bind("<Configure>", self._on_inner_configure)
        self._cv.bind("<Configure>", self._on_cv_configure)

        # Scroll con rueda del mouse
        self._cv.bind("<MouseWheel>",
            lambda e: self._cv.yview_scroll(-1*(e.delta//120), "units"))
        self._cv.bind("<Button-4>",
            lambda e: self._cv.yview_scroll(-1, "units"))
        self._cv.bind("<Button-5>",
            lambda e: self._cv.yview_scroll(1, "units"))
        self._inner.bind("<MouseWheel>",
            lambda e: self._cv.yview_scroll(-1*(e.delta//120), "units"))
        self._inner.bind("<Button-4>",
            lambda e: self._cv.yview_scroll(-1, "units"))
        self._inner.bind("<Button-5>",
            lambda e: self._cv.yview_scroll(1, "units"))

        self._construir()

    def _on_inner_configure(self, event=None):
        self._cv.configure(scrollregion=self._cv.bbox("all"))

    def _on_cv_configure(self, event=None):
        # Mantener el inner al ancho del canvas
        self._cv.itemconfig(self._win, width=event.width if event else self._cv.winfo_width())


    def _bind_scroll(self, widget):
        """Conecta la rueda del mouse de un widget al scroll del panel."""
        widget.bind('<MouseWheel>',
            lambda e: self._cv.yview_scroll(-1*(e.delta//120), 'units'))
        widget.bind('<Button-4>',
            lambda e: self._cv.yview_scroll(-1, 'units'))
        widget.bind('<Button-5>',
            lambda e: self._cv.yview_scroll(1, 'units'))

    def set_topologia(self, topologia):
        self._topologia = topologia

    # ─────────────────────────────────────────
    # CONSTRUCCIÓN
    # ─────────────────────────────────────────

    def _construir(self):
        self._construir_titulo()
        self._construir_resumen()
        self._separador()
        self._construir_detalle()
        self._separador()
        # Las alertas van en el panel izquierdo (panel_alertas.py)
        self._construir_externos()
        self._separador()
        self._construir_busqueda()
        self._construir_lista_nodos()
        self._separador()
        self._construir_lobby()

    def _construir_titulo(self):
        tk.Label(self._inner, text="RED LOCAL",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 8, "bold"), anchor="w"
        ).pack(fill=tk.X, padx=12, pady=(12, 0))

        self.lbl_ip_local = tk.Label(self._inner,
            text="Tu IP: —",
            bg=COLOR_PANEL, fg="#58d6ff",
            font=("Monospace", 8), anchor="w"
        )
        self.lbl_ip_local.pack(fill=tk.X, padx=12, pady=(0, 4))

    def _construir_resumen(self):
        resumen = tk.Frame(self._inner, bg=COLOR_PANEL)
        resumen.pack(fill=tk.X, padx=12, pady=4)
        self.lbl_total = self._contador(resumen, "0", "total", COLOR_TEXTO)
        self.lbl_conf  = self._contador(resumen, "0", "conf",  COLOR_CONF)
        self.lbl_sosp  = self._contador(resumen, "0", "sosp",  COLOR_SOSP)
        self.lbl_fant  = self._contador(resumen, "0", "ghost", COLOR_FANT)

    def _contador(self, padre, numero, etiqueta, color):
        bloque = tk.Frame(padre, bg=COLOR_PANEL)
        bloque.pack(side=tk.LEFT, expand=True)
        lbl = tk.Label(bloque, text=numero,
            bg=COLOR_PANEL, fg=color, font=("Monospace", 16, "bold"))
        lbl.pack()
        tk.Label(bloque, text=etiqueta,
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB, font=("Monospace", 7)).pack()
        return lbl

    def _separador(self):
        tk.Frame(self._inner, bg=COLOR_BORDE, height=1).pack(fill=tk.X, pady=4)

    def _construir_alertas(self):
        # ── Cabecera con filtros rápidos ──────────────────────────────
        hdr = tk.Frame(self._inner, bg=COLOR_PANEL)
        hdr.pack(fill=tk.X, padx=8, pady=(6, 2))

        self.lbl_alertas_titulo = tk.Label(hdr, text="ALERTAS (0)",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 8, "bold"), anchor="w")
        self.lbl_alertas_titulo.pack(side=tk.LEFT)

        # Botón limpiar alertas INFO
        tk.Button(hdr, text="✕ info", bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 6), relief=tk.FLAT, padx=2, cursor="hand2",
            command=self._limpiar_alertas_info
        ).pack(side=tk.RIGHT)

        # Filtros rápidos de severidad
        self._filtro_sev = tk.StringVar(value="todas")
        filtros = tk.Frame(self._inner, bg=COLOR_PANEL)
        filtros.pack(fill=tk.X, padx=8, pady=(0, 3))
        for sev, col in [("todas", COLOR_TEXTO_SUB), ("critico", COLOR_SEV_CRITICO),
                         ("alto", COLOR_SEV_ALTO), ("medio", COLOR_SEV_MEDIO)]:
            rb = tk.Radiobutton(filtros, text=sev, variable=self._filtro_sev,
                value=sev, bg=COLOR_PANEL, fg=col,
                selectcolor=COLOR_FONDO, activebackground=COLOR_PANEL,
                font=("Monospace", 7), relief=tk.FLAT,
                command=self._refrescar_alertas_panel)
            rb.pack(side=tk.LEFT, padx=1)

        # ── Contenedor scrollable de tarjetas de alerta ───────────────
        wrap = tk.Frame(self._inner, bg=COLOR_FONDO,
            highlightbackground=COLOR_BORDE, highlightthickness=1)
        wrap.pack(fill=tk.X, padx=8, pady=(0, 4))

        sb_a = tk.Scrollbar(wrap, orient=tk.VERTICAL,
            bg=COLOR_PANEL, troughcolor=COLOR_FONDO, width=6)
        sb_a.pack(side=tk.RIGHT, fill=tk.Y)

        self._cv_alertas = tk.Canvas(wrap, bg=COLOR_FONDO,
            highlightthickness=0, height=160,
            yscrollcommand=sb_a.set)
        self._cv_alertas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_a.config(command=self._cv_alertas.yview)

        self._frame_alertas = tk.Frame(self._cv_alertas, bg=COLOR_FONDO)
        self._win_alertas = self._cv_alertas.create_window(
            (0, 0), window=self._frame_alertas, anchor="nw")

        self._frame_alertas.bind("<Configure>",
            lambda e: self._cv_alertas.configure(
                scrollregion=self._cv_alertas.bbox("all")))
        self._cv_alertas.bind("<Configure>",
            lambda e: self._cv_alertas.itemconfig(
                self._win_alertas, width=e.width))

        # Scroll con rueda
        for w in (self._cv_alertas, self._frame_alertas):
            w.bind("<Button-4>", lambda e: self._cv_alertas.yview_scroll(-1,"units"))
            w.bind("<Button-5>", lambda e: self._cv_alertas.yview_scroll(1,"units"))

        self._alertas_data      = []
        self._alerta_expandida  = None   # ip+servicio de la que está abierta
        self._tarjetas_alertas  = {}     # key → frame de tarjeta

    def _limpiar_alertas_info(self):
        """Elimina de la vista las alertas de severidad INFO."""
        if self._topologia and hasattr(self._topologia, 'alertas'):
            self._topologia.alertas = [
                h for h in self._topologia.alertas if h.severidad != "info"]

    def _refrescar_alertas_panel(self):
        """Redibuja las tarjetas de alerta con el filtro actual."""
        # Se llama automáticamente desde actualizar()
        pass

    def _construir_tarjeta_alerta(self, h, idx):
        """Construye una tarjeta de alerta expandible."""
        sev   = h.severidad or "info"
        col   = SEV_COLOR.get(sev, COLOR_TEXTO)
        prefijo = {"critico":"🔴","alto":"🟠","medio":"🟡","info":"🔵"}.get(sev,"●")
        key   = f"{h.ip}_{h.servicio}_{h.puerto}"

        # Frame de tarjeta
        tarjeta = tk.Frame(self._frame_alertas, bg=COLOR_PANEL,
            highlightbackground=col, highlightthickness=1)
        tarjeta.pack(fill=tk.X, padx=2, pady=1)

        # ── Fila principal (siempre visible) ─────────────────────────
        fila = tk.Frame(tarjeta, bg=COLOR_PANEL, cursor="hand2")
        fila.pack(fill=tk.X, padx=4, pady=2)

        tk.Label(fila, text=prefijo, bg=COLOR_PANEL,
            font=("Monospace", 8), width=2).pack(side=tk.LEFT)

        tk.Label(fila, text=h.ip, bg=COLOR_PANEL, fg="#58d6ff",
            font=("Monospace", 8), width=13, anchor="w").pack(side=tk.LEFT)

        # Servicio truncado
        svc_txt = (h.servicio or "?")[:14]
        tk.Label(fila, text=svc_txt, bg=COLOR_PANEL, fg=col,
            font=("Monospace", 8, "bold"), anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Timestamp pequeño
        ts = getattr(h, 'timestamp', '') or ''
        tk.Label(fila, text=ts[-5:] if ts else "", bg=COLOR_PANEL,
            fg=COLOR_TEXTO_SUB, font=("Monospace", 7)).pack(side=tk.RIGHT)

        # ── Frame expandido (oculto por defecto) ─────────────────────
        detalle_frame = tk.Frame(tarjeta, bg="#0d1117")

        def _toggle(event=None, k=key, df=detalle_frame, h=h, col=col):
            if self._alerta_expandida == k:
                df.pack_forget()
                self._alerta_expandida = None
            else:
                if self._alerta_expandida and self._alerta_expandida in self._tarjetas_alertas:
                    old_df = self._tarjetas_alertas[self._alerta_expandida]
                    if old_df:
                        old_df.pack_forget()
                self._alerta_expandida = k
                self._tarjetas_alertas[k] = df
                self._construir_detalle_alerta(df, h, col)
                df.pack(fill=tk.X, padx=4, pady=(0, 4))
            self._cv_alertas.update_idletasks()
            self._cv_alertas.configure(scrollregion=self._cv_alertas.bbox("all"))

        # Bind click en toda la fila
        for widget in (fila, tarjeta):
            widget.bind("<Button-1>", _toggle)
        for child in fila.winfo_children():
            child.bind("<Button-1>", _toggle)

        self._tarjetas_alertas[key] = None
        return tarjeta

    def _construir_detalle_alerta(self, frame, h, col):
        """Rellena el frame de detalle con info completa + botones de acción."""
        for w in frame.winfo_children():
            w.destroy()

        detalle = getattr(h, 'detalle', getattr(h, 'desc', '')) or '—'
        puerto  = h.puerto if h.puerto else '—'

        # Info completa
        info_txt = (
            f"Puerto : {puerto}\n"
            f"Servicio: {h.servicio or '—'}\n"
            f"Hora    : {getattr(h,'timestamp','—')}\n"
            f"Detalle : {detalle}"
        )
        lbl = tk.Label(frame, text=info_txt,
            bg="#0d1117", fg=COLOR_TEXTO,
            font=("Monospace", 7), anchor="w", justify=tk.LEFT,
            wraplength=195, padx=6, pady=4)
        lbl.pack(fill=tk.X)

        # ── Botones de acción ─────────────────────────────────────────
        btn_frame = tk.Frame(frame, bg="#0d1117")
        btn_frame.pack(fill=tk.X, padx=4, pady=(0, 4))

        def _btn(texto, cmd):
            tk.Button(btn_frame, text=texto, command=cmd,
                bg=COLOR_BORDE, fg=COLOR_TEXTO,
                font=("Monospace", 7), relief=tk.FLAT,
                padx=4, pady=1, cursor="hand2",
                activebackground=COLOR_ACENTO
            ).pack(side=tk.LEFT, padx=2)

        # Copiar al portapapeles
        def _copiar():
            txt = f"{h.ip} | {h.servicio}:{puerto} [{h.severidad}] {detalle}"
            try:
                frame.clipboard_clear()
                frame.clipboard_append(txt)
            except Exception:
                pass
        _btn("📋 Copiar", _copiar)

        # Ir al nodo
        def _ir():
            if hasattr(self, '_on_alerta_seleccionada') and self._on_alerta_seleccionada:
                self._on_alerta_seleccionada(h.ip)
        _btn("🎯 Ir al nodo", _ir)

        # Acción de Arsenal sugerida según el hallazgo
        accion_arsenal = self._sugerir_arsenal(h)
        if accion_arsenal:
            escaneo_id, etiqueta = accion_arsenal
            def _lanzar_arsenal(eid=escaneo_id, ip=h.ip):
                if hasattr(self, '_on_arsenal_desde_alerta') and self._on_arsenal_desde_alerta:
                    self._on_arsenal_desde_alerta(ip, eid)
            _btn(f"⚡ {etiqueta}", _lanzar_arsenal)

    def _sugerir_arsenal(self, h):
        """Devuelve (escaneo_id, etiqueta) según el tipo de hallazgo."""
        svc = (h.servicio or "").lower()
        if "vuln" in svc or "cve" in svc:
            return ("vuln", "Vuln Scan")
        if "ssl" in svc or "tls" in svc or "cert" in svc:
            return ("versions", "Versiones")
        if "rtsp" in svc or "hikvision" in svc or "cámara" in svc:
            return ("scripts", "Safe Scripts")
        if "smb" in svc or "shares" in svc or "ldap" in svc:
            return ("scripts", "Safe Scripts")
        if h.puerto and h.puerto > 0:
            return ("versions", "Versiones")
        return ("os", "OS Detect")

    def _on_alerta_click(self, event):
        """Legacy — mantenido por compatibilidad."""
        pass

    def _construir_detalle(self):
        tk.Label(self._inner, text="NODO SELECCIONADO",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 8, "bold"), anchor="w"
        ).pack(fill=tk.X, padx=12, pady=(0, 4))

        self.frame_detalle = tk.Frame(self._inner, bg=COLOR_PANEL)
        self.frame_detalle.pack(fill=tk.X, padx=12)

        self.campos = {}
        for etiqueta, clave in [
            ("IP",         "ip"),
            ("MAC",        "mac"),
            ("Tipo",       "tipo"),
            ("Fabricante", "fabricante"),
            ("Sistema",    "sistema_op"),
            ("Estado",     "estado"),
            ("Paquetes",   "paquetes"),
            ("Puertos",    "puertos"),
            ("Cambios",    "delta"),
        ]:
            fila = tk.Frame(self.frame_detalle, bg=COLOR_PANEL)
            fila.pack(fill=tk.X, pady=1)
            tk.Label(fila, text=f"{etiqueta}:",
                bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
                font=("Monospace", 8), width=10, anchor="w").pack(side=tk.LEFT)
            lbl = tk.Label(fila, text="—",
                bg=COLOR_PANEL, fg=COLOR_TEXTO,
                font=("Monospace", 8), anchor="w", wraplength=130)
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.campos[clave] = lbl

    def _construir_externos(self):
        tk.Label(self._inner, text="CONEXIONES EXTERNAS",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 8, "bold"), anchor="w"
        ).pack(fill=tk.X, padx=12, pady=(0, 4))

        contenedor = tk.Frame(self._inner, bg=COLOR_PANEL)
        contenedor.pack(fill=tk.X, padx=4)

        sb = tk.Scrollbar(contenedor, bg=COLOR_PANEL)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.lista_externos = tk.Listbox(
            contenedor,
            bg=COLOR_FONDO, fg=COLOR_EXT,
            font=("Monospace", 7),
            selectbackground=COLOR_ACENTO,
            relief=tk.FLAT, borderwidth=0,
            highlightthickness=0,
            height=4,
            yscrollcommand=sb.set
        )
        self.lista_externos.pack(side=tk.LEFT, fill=tk.X, expand=True)
        sb.config(command=self.lista_externos.yview)

    def _construir_busqueda(self):
        f = tk.Frame(self._inner, bg=COLOR_PANEL)
        f.pack(fill=tk.X, padx=8, pady=(4,2))
        tk.Label(f, text="🔍", bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace",9)).pack(side=tk.LEFT)
        self._var_busq = tk.StringVar()
        self._var_busq.trace_add("write", self._filtrar_lista)
        entry = tk.Entry(f, textvariable=self._var_busq,
            bg="#0d1117", fg=COLOR_TEXTO,
            insertbackground=COLOR_TEXTO,
            font=("Monospace",8), relief=tk.FLAT,
            highlightbackground=COLOR_BORDE,
            highlightthickness=1)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tk.Button(f, text="✕", bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace",8), relief=tk.FLAT, padx=2,
            command=lambda: self._var_busq.set("")
        ).pack(side=tk.RIGHT)

    def _filtrar_lista(self, *args):
        # Refrescar lista con filtro activo
        if hasattr(self, 'lista') and self._topologia:
            self._actualizar_lista_filtrada()

    def _on_lista_dispositivos_seleccion(self, event=None):
        """Al elegir un dispositivo de la lista, mostrar detalle y sincronizar canvas."""
        sel = self.lista.curselection()
        if not sel or not self._lista_nodos_orden:
            return
        idx = sel[0]
        if idx < len(self._lista_nodos_orden):
            nodo = self._lista_nodos_orden[idx]
            self.mostrar_nodo(nodo)
            if self._on_seleccion_en_lista:
                self._on_seleccion_en_lista(nodo.ip)

    def _actualizar_lista_filtrada(self):
        filtro = self._var_busq.get().lower().strip()
        self.lista.delete(0, tk.END)
        self._lista_nodos_orden = []
        if not self._topologia:
            return
        nodos = [n for n in self._topologia.todos_los_nodos() if not n.en_lobby]
        for nodo in sorted(nodos, key=lambda n: [int(x) for x in (n.ip or "0.0.0.0").split(".")]):
            # Filtrar por IP, MAC, tipo o fabricante
            if filtro and not any(filtro in campo.lower() for campo in
                [nodo.ip, nodo.mac or "", nodo.tipo, nodo.fabricante]):
                continue
            from core.nodes import CONFIRMADO, SOSPECHOSO
            if nodo.tipo == "arp-scanner":
                prefijo = "⚠"
            elif nodo.estado == CONFIRMADO:
                prefijo = "●"
            elif nodo.estado == SOSPECHOSO:
                prefijo = "◌"
            else:
                prefijo = "○"
            # Añadir indicador de riesgo
            rs = getattr(nodo, "risk_score", 0)
            riesgo = " 🔴" if rs >= 60 else " 🟠" if rs >= 30 else ""
            
            # Añadir indicador de delta (historial)
            deltas = getattr(nodo, "delta", [])
            tag_delta = ""
            if "NUEVO" in deltas:
                tag_delta = " ✨"  # Sparkles para nuevo
            elif deltas:
                tag_delta = " 🛠"   # Hammer para cambios técnicos
            
            self.lista.insert(tk.END, f"{prefijo} {nodo.ip:<15} {nodo.tipo}{tag_delta}{riesgo}")
            self._lista_nodos_orden.append(nodo)

    def _construir_lista_nodos(self):
        tk.Label(self._inner, text="DISPOSITIVOS",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 8, "bold"), anchor="w"
        ).pack(fill=tk.X, padx=12, pady=(0, 4))

        contenedor = tk.Frame(self._inner, bg=COLOR_PANEL)
        contenedor.pack(fill=tk.X, padx=4)

        sb = tk.Scrollbar(contenedor, bg=COLOR_PANEL)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.lista = tk.Listbox(
            contenedor,
            bg=COLOR_FONDO, fg=COLOR_TEXTO,
            font=("Monospace", 8),
            selectbackground=COLOR_ACENTO,
            relief=tk.FLAT, borderwidth=0,
            highlightthickness=0,
            height=5,
            yscrollcommand=sb.set
        )
        self.lista.pack(side=tk.LEFT, fill=tk.X, expand=True)
        sb.config(command=self.lista.yview)
        self.lista.bind("<<ListboxSelect>>", self._on_lista_dispositivos_seleccion)

    def _construir_lobby(self):
        """Sección colapsable del lobby con botón verificar todos."""
        self.frame_lobby_titulo = tk.Frame(self._inner, bg=COLOR_PANEL, cursor="hand2")
        self.frame_lobby_titulo.pack(fill=tk.X, padx=12, pady=(0, 2))
        self.frame_lobby_titulo.bind("<Button-1>", self._toggle_lobby)

        self.lbl_lobby_titulo = tk.Label(
            self.frame_lobby_titulo,
            text="▶ INACTIVOS (0)",
            bg=COLOR_PANEL, fg=COLOR_LOBBY,
            font=("Monospace", 8, "bold"), anchor="w",
            cursor="hand2")
        self.lbl_lobby_titulo.pack(side=tk.LEFT)
        self.lbl_lobby_titulo.bind("<Button-1>", self._toggle_lobby)

        # Botón verificar todos — lanza ping a todos los del lobby
        self.btn_verificar_lobby = tk.Button(
            self.frame_lobby_titulo,
            text="🔍 Ver.",
            bg=COLOR_PANEL, fg=COLOR_LOBBY,
            font=("Monospace", 7), relief=tk.FLAT,
            padx=3, cursor="hand2",
            command=self._verificar_lobby)
        self.btn_verificar_lobby.pack(side=tk.RIGHT, padx=(0, 4))

        tk.Label(self.frame_lobby_titulo,
            text="5min → auto-borrado",
            bg=COLOR_PANEL, fg=COLOR_LOBBY,
            font=("Monospace", 6), anchor="e",
            cursor="hand2").pack(side=tk.RIGHT)

        self.frame_lobby_contenido = tk.Frame(self._inner, bg=COLOR_PANEL)

        contenedor = tk.Frame(self.frame_lobby_contenido, bg=COLOR_PANEL)
        contenedor.pack(fill=tk.X, padx=4)

        self.lista_lobby = tk.Listbox(
            contenedor,
            bg=COLOR_FONDO, fg=COLOR_LOBBY,
            font=("Monospace", 7),
            selectbackground=COLOR_ACENTO,
            relief=tk.FLAT, borderwidth=0,
            highlightthickness=0,
            height=4)
        self.lista_lobby.pack(fill=tk.X, expand=True)

    def _verificar_lobby(self):
        """Lanza verificación manual de todos los nodos en lobby."""
        if hasattr(self, '_on_verificar_lobby') and self._on_verificar_lobby:
            self._on_verificar_lobby()

    def _toggle_lobby(self, evento=None):
        """Abre o cierra el lobby."""
        self._lobby_visible = not self._lobby_visible
        if self._lobby_visible:
            self.frame_lobby_contenido.pack(fill=tk.X, padx=4, pady=(0, 6))
            flecha = "▼"
        else:
            self.frame_lobby_contenido.pack_forget()
            flecha = "▶"
        # Actualizar flecha en título
        texto_actual = self.lbl_lobby_titulo.cget("text")
        partes = texto_actual.split(" ", 1)
        if len(partes) == 2:
            self.lbl_lobby_titulo.config(text=f"{flecha} {partes[1]}")

    # ─────────────────────────────────────────
    # ACTUALIZACIÓN
    # ─────────────────────────────────────────

    def actualizar(self, nodos_visibles):
        from core.nodes import CONFIRMADO, SOSPECHOSO, FANTASMA

        total = len(nodos_visibles)
        conf  = sum(1 for n in nodos_visibles if n.estado == CONFIRMADO)
        sosp  = sum(1 for n in nodos_visibles if n.estado == SOSPECHOSO)
        fant  = sum(1 for n in nodos_visibles if n.estado == FANTASMA)

        self.lbl_total.config(text=str(total))
        self.lbl_conf.config(text=str(conf))
        self.lbl_sosp.config(text=str(sosp))
        self.lbl_fant.config(text=str(fant))

        # Mostrar ip_local siempre en el panel
        if self._topologia and self._topologia.ip_local:
            self.lbl_ip_local.config(text=f"Tu IP: {self._topologia.ip_local}")

        # Lista de dispositivos (con filtro de búsqueda)
        self._actualizar_lista_filtrada()

        # Lobby — nodos inactivos
        if self._topologia:
            en_lobby = [n for n in self._topologia.todos_los_nodos() if n.en_lobby]
            flecha = "▼" if self._lobby_visible else "▶"
            self.lbl_lobby_titulo.config(
                text=f"{flecha} INACTIVOS ({len(en_lobby)})",
                fg=COLOR_LOBBY if not en_lobby else COLOR_SOSP
            )
            self.lista_lobby.delete(0, tk.END)
            for nodo in en_lobby:
                self.lista_lobby.insert(
                    tk.END,
                    f"💤 {nodo.ip:<16} {nodo.mac or '—'}"
                )

        # Las alertas se muestran en panel_alertas (izquierdo) — no aquí

        # Refrescar externos si hay nodo seleccionado
        if self._nodo_actual and self._topologia:
            self._actualizar_externos(self._nodo_actual)

    def mostrar_nodo(self, nodo):
        from core.nodes import CONFIRMADO, SOSPECHOSO
        self._nodo_actual = nodo.ip

        color_estado = (COLOR_CONF if nodo.estado == CONFIRMADO
                       else COLOR_SOSP if nodo.estado == SOSPECHOSO
                       else COLOR_FANT)
        puertos = ", ".join(str(p) for p in nodo.puertos_abiertos) or "—"

        for clave, valor in [
            ("ip",         nodo.ip),
            ("mac",        nodo.mac or "—"),
            ("tipo",       nodo.tipo),
            ("fabricante", nodo.fabricante),
            ("sistema_op", nodo.sistema_op),
            ("estado",     nodo.estado),
            ("paquetes",   str(nodo.paquetes)),
            ("puertos",    puertos),
            ("delta",      ", ".join(nodo.delta) if nodo.delta else "—"),
        ]:
            color = color_estado if clave == "estado" else COLOR_TEXTO
            self.campos[clave].config(text=valor, fg=color)

        self._actualizar_externos(nodo.ip)

    def _actualizar_externos(self, ip):
        self.lista_externos.delete(0, tk.END)
        if not self._topologia: return

        externos = self._topologia.obtener_externos(ip)
        if not externos:
            self.lista_externos.insert(tk.END, "  Sin conexiones externas")
            return

        for ip_ext, protocolo in externos[:20]:
            self.lista_externos.insert(
                tk.END, f"→ {ip_ext:<20} {protocolo}")
