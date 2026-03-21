"""
ventana_arsenal.py — Ventana de resultado del Arsenal mejorada.
- Output formateado línea a línea con colores por tipo
- Parser inteligente según tipo de escaneo
- Botones de acción directa desde el resultado
- Resumen ejecutivo arriba del output
"""

import tkinter as tk
import re

# ── Paleta ────────────────────────────────────────────────────────────────────
C_BG      = "#0d1117"
C_PANEL   = "#161b22"
C_BORDE   = "#30363d"
C_TEXTO   = "#e6edf3"
C_SUB     = "#8b949e"
C_CYAN    = "#58d6ff"
C_VERDE   = "#3fb950"
C_NARANJA = "#f0883e"
C_ROJO    = "#da3633"
C_AMARILLO= "#f0e040"
C_ACENTO  = "#1f6feb"
C_GRIS    = "#30363d"

# Colores por tipo de línea
COLORES_LINEA = {
    "open"    : C_VERDE,
    "closed"  : C_GRIS,
    "filtered": C_NARANJA,
    "error"   : C_ROJO,
    "warn"    : C_NARANJA,
    "vuln"    : C_ROJO,
    "info"    : C_CYAN,
    "os"      : C_CYAN,
    "version" : "#8957e5",
    "script"  : C_AMARILLO,
    "normal"  : C_TEXTO,
    "titulo"  : C_CYAN,
    "sep"     : C_GRIS,
}

# Íconos por tipo de escaneo
ICONOS_ESCANEO = {
    "ping"    : "🟢",
    "quick"   : "⚡",
    "standard": "🔍",
    "versions": "🏷",
    "os"      : "💻",
    "scripts" : "📜",
    "vuln"    : "🔴",
    "udp"     : "📡",
}


class VentanaArsenal(tk.Toplevel):
    """
    Ventana flotante de resultado del Arsenal.
    Se crea una por escaneo. Muestra output formateado
    con resumen ejecutivo y acciones directas.
    """

    def __init__(self, padre, ip, titulo_escaneo, callback_lanzar=None):
        super().__init__(padre)
        self.ip               = ip
        self.titulo_escaneo   = titulo_escaneo
        self.callback_lanzar  = callback_lanzar  # para lanzar escaneo siguiente
        self._texto_raw       = ""

        # Detectar escaneo_id desde el título
        self._escaneo_id = self._inferir_id(titulo_escaneo)

        self.title(f"Arsenal — {ip}")
        self.configure(bg=C_BG)
        self.resizable(True, True)
        self.geometry("660x500")
        self.minsize(500, 350)

        # Centrar sobre la ventana padre
        try:
            px = padre.winfo_x() + padre.winfo_width() // 2 - 330
            py = padre.winfo_y() + padre.winfo_height() // 2 - 250
            self.geometry(f"660x500+{px}+{py}")
        except Exception:
            pass

        self._construir()

    def _inferir_id(self, titulo):
        t = titulo.lower()
        if "ping" in t:      return "ping"
        if "quick" in t:     return "quick"
        if "standard" in t:  return "standard"
        if "version" in t:   return "versions"
        if "os" in t or "detec" in t: return "os"
        if "script" in t or "safe" in t: return "scripts"
        if "vuln" in t:      return "vuln"
        if "udp" in t:       return "udp"
        return "standard"

    def _construir(self):
        # ── Cabecera ──────────────────────────────────────────────────
        cab = tk.Frame(self, bg=C_PANEL, pady=6)
        cab.pack(fill=tk.X)

        icono = ICONOS_ESCANEO.get(self._escaneo_id, "🔧")
        tk.Label(cab, text=f"{icono} {self.titulo_escaneo}",
            bg=C_PANEL, fg=C_CYAN,
            font=("Monospace", 11, "bold")).pack(side=tk.LEFT, padx=12)

        tk.Label(cab, text=f"Target: {self.ip}",
            bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 9)).pack(side=tk.LEFT, padx=8)

        tk.Button(cab, text="✕", bg=C_PANEL, fg=C_SUB,
            font=("Monospace", 10), relief=tk.FLAT,
            command=self.destroy).pack(side=tk.RIGHT, padx=8)

        tk.Frame(self, bg=C_BORDE, height=1).pack(fill=tk.X)

        # ── Resumen ejecutivo (se llena cuando llega el resultado) ────
        self._frame_resumen = tk.Frame(self, bg="#0d1f2d", pady=4)
        self._frame_resumen.pack(fill=tk.X)
        self._lbl_resumen = tk.Label(self._frame_resumen,
            text="⏳  Escaneando...",
            bg="#0d1f2d", fg=C_SUB,
            font=("Monospace", 8), anchor="w", padx=12)
        self._lbl_resumen.pack(fill=tk.X)

        tk.Frame(self, bg=C_BORDE, height=1).pack(fill=tk.X)

        # ── Área de texto formateada ──────────────────────────────────
        txt_frame = tk.Frame(self, bg=C_BG)
        txt_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        sb = tk.Scrollbar(txt_frame, bg=C_PANEL, troughcolor=C_BG)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self._txt = tk.Text(txt_frame,
            bg=C_BG, fg=C_TEXTO,
            font=("Courier", 9),
            relief=tk.FLAT, bd=0,
            wrap=tk.NONE,
            yscrollcommand=sb.set,
            state=tk.DISABLED,
            insertbackground=C_TEXTO,
            selectbackground=C_ACENTO)
        self._txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        sb.config(command=self._txt.yview)

        # Scrollbar horizontal
        sbx = tk.Scrollbar(self, orient=tk.HORIZONTAL,
            bg=C_PANEL, troughcolor=C_BG)
        sbx.pack(fill=tk.X)
        self._txt.config(xscrollcommand=sbx.set)
        sbx.config(command=self._txt.xview)

        # Tags de color para el Text
        for tag, color in COLORES_LINEA.items():
            self._txt.tag_configure(tag, foreground=color)
        self._txt.tag_configure("bold", font=("Courier", 9, "bold"))
        self._txt.tag_configure("titulo",
            foreground=C_CYAN, font=("Courier", 10, "bold"))

        # ── Botones de acción ─────────────────────────────────────────
        tk.Frame(self, bg=C_BORDE, height=1).pack(fill=tk.X)
        pie = tk.Frame(self, bg=C_PANEL, pady=4)
        pie.pack(fill=tk.X)

        self._frame_acciones = tk.Frame(pie, bg=C_PANEL)
        self._frame_acciones.pack(side=tk.LEFT, padx=8)

        # Botón copiar siempre presente
        tk.Button(pie, text="📋 Copiar todo", bg=C_GRIS, fg=C_TEXTO,
            font=("Monospace", 8), relief=tk.FLAT, padx=6, cursor="hand2",
            command=self._copiar_todo).pack(side=tk.RIGHT, padx=8)

    def mostrar_resultado(self, texto, puertos=None):
        """Llamado desde app.py con el output de nmap."""
        self._texto_raw = texto
        self._txt.config(state=tk.NORMAL)
        self._txt.delete("1.0", tk.END)

        # Formatear y colorear línea a línea
        lineas = self._formatear_texto(texto)
        for linea, tag in lineas:
            self._txt.insert(tk.END, linea + "\n", tag)

        self._txt.config(state=tk.DISABLED)
        self._txt.see(tk.END)

        # Resumen ejecutivo
        resumen = self._generar_resumen(texto, puertos)
        self._lbl_resumen.config(text=resumen,
            fg=C_VERDE if "✓" in resumen else C_NARANJA if "⚠" in resumen else C_SUB)

        # Botones de acción sugeridos
        self._construir_botones_accion(texto, puertos)

    def _formatear_texto(self, texto):
        """
        Convierte el output crudo de nmap en lista de (línea, tag).
        Cada tipo de línea recibe un color diferente.
        """
        resultado = []

        for linea in texto.splitlines():
            linea_strip = linea.strip()

            # Línea vacía
            if not linea_strip:
                resultado.append(("", "normal"))
                continue

            # Cabecera de Nmap
            if linea_strip.startswith("Starting Nmap") or \
               linea_strip.startswith("Nmap scan report") or \
               linea_strip.startswith("Nmap done"):
                resultado.append((linea_strip, "titulo"))
                continue

            # Separador
            if set(linea_strip) <= set("-=_"):
                resultado.append((linea_strip, "sep"))
                continue

            # Puerto abierto
            if re.match(r'^\d+/(tcp|udp)\s+open', linea_strip):
                resultado.append((linea_strip, "open"))
                continue

            # Puerto cerrado
            if re.match(r'^\d+/(tcp|udp)\s+closed', linea_strip):
                resultado.append((linea_strip, "closed"))
                continue

            # Puerto filtrado
            if re.match(r'^\d+/(tcp|udp)\s+filtered', linea_strip):
                resultado.append((linea_strip, "filtered"))
                continue

            # OS detection
            if linea_strip.startswith("OS") or \
               linea_strip.startswith("Running:") or \
               "OS details" in linea_strip:
                resultado.append((linea_strip, "os"))
                continue

            # Versiones de servicio
            if "Service Info" in linea_strip or \
               linea_strip.startswith("Service detection"):
                resultado.append((linea_strip, "version"))
                continue

            # Vulnerabilidades
            if "VULNERABLE" in linea_strip.upper() or \
               "CVE-" in linea_strip:
                resultado.append((linea_strip, "vuln"))
                continue

            # Scripts nmap (líneas con |)
            if linea_strip.startswith("|") or linea_strip.startswith("|_"):
                # Sub-clasificar
                if "ERROR" in linea_strip or "FAILED" in linea_strip.upper():
                    resultado.append((linea_strip, "error"))
                elif any(kw in linea_strip for kw in
                         ["UPnP","uuid","usn","location","server","Server",
                          "DHCP","IP Offered","hostname","commonName","Issuer"]):
                    resultado.append((linea_strip, "script"))
                else:
                    resultado.append((linea_strip, "info"))
                continue

            # MAC Address
            if linea_strip.startswith("MAC Address"):
                resultado.append((linea_strip, "info"))
                continue

            # Host is up/down
            if "Host is up" in linea_strip:
                resultado.append((linea_strip, "open"))
                continue
            if "Host seems down" in linea_strip or "0 hosts up" in linea_strip:
                resultado.append((linea_strip, "warn"))
                continue

            # Default
            resultado.append((linea_strip, "normal"))

        return resultado

    def _generar_resumen(self, texto, puertos):
        """Genera una línea de resumen ejecutivo del resultado."""
        eid = self._escaneo_id

        if eid == "ping":
            if "Host is up" in texto:
                latencia = re.search(r'\((\d+\.\d+)s latency\)', texto)
                lat = f" · latencia {latencia.group(1)}s" if latencia else ""
                return f"✓  Host ACTIVO{lat}"
            return "⚠  Host sin respuesta (puede filtrar ICMP)"

        if eid in ("quick", "standard"):
            n_open = len(re.findall(r'\d+/(tcp|udp)\s+open', texto))
            n_closed = len(re.findall(r'\d+/(tcp|udp)\s+closed', texto))
            if n_open:
                puertos_str = ", ".join(re.findall(r'(\d+)/tcp\s+open', texto)[:5])
                return f"✓  {n_open} puerto(s) abierto(s): {puertos_str}"
            return f"ℹ  Sin puertos abiertos detectados ({n_closed} cerrados)"

        if eid == "versions":
            servicios = re.findall(r'\d+/tcp\s+open\s+\S+\s+(.+)', texto)
            if servicios:
                return f"✓  {len(servicios)} servicio(s): {servicios[0][:40]}"
            return "ℹ  Sin versiones detectadas"

        if eid == "os":
            os_m = re.search(r'OS details?:\s*(.+)', texto)
            run_m = re.search(r'Running:\s*(.+)', texto)
            if os_m:
                return f"✓  OS: {os_m.group(1).strip()[:50]}"
            if run_m:
                return f"✓  Running: {run_m.group(1).strip()[:50]}"
            # MAC puede dar fabricante
            mac_m = re.search(r'MAC Address: .+\((.+)\)', texto)
            if mac_m:
                return f"ℹ  Fabricante: {mac_m.group(1)} — OS no determinado"
            return "⚠  OS no identificado (demasiados candidatos)"

        if eid == "scripts":
            # Buscar hallazgos interesantes
            items = []
            if "UPnP" in texto or "usn:" in texto:
                srv = re.search(r'server:\s*(.+)', texto)
                items.append(f"UPnP: {srv.group(1)[:30] if srv else 'activo'}")
            if "IP Offered" in texto:
                ip_m = re.search(r'IP Offered:\s*(\S+)', texto)
                items.append(f"DHCP: ofrece {ip_m.group(1) if ip_m else '?'}")
            if "EAP" in texto:
                items.append("802.1X/EAP detectado")
            if items:
                return f"⚠  {' · '.join(items)}"
            return "ℹ  Scripts completados — sin hallazgos críticos"

        if eid == "vuln":
            n_vuln = len(re.findall(r'VULNERABLE', texto, re.IGNORECASE))
            if n_vuln:
                return f"🔴  {n_vuln} VULNERABILIDAD(ES) ENCONTRADA(S)"
            return "✓  Vuln scan completado sin vulnerabilidades críticas"

        if eid == "udp":
            n_udp = len(re.findall(r'\d+/udp\s+open', texto))
            if n_udp:
                return f"⚠  {n_udp} puerto(s) UDP abierto(s)"
            return "ℹ  Sin puertos UDP abiertos"

        return "ℹ  Escaneo completado"

    def _construir_botones_accion(self, texto, puertos):
        """Añade botones de acción sugeridos según el resultado."""
        for w in self._frame_acciones.winfo_children():
            w.destroy()

        if not self.callback_lanzar:
            return

        sugeridos = self._sugerir_siguientes(texto)
        for eid, etiqueta in sugeridos:
            def _lanzar(e=eid, et=etiqueta, ip=self.ip):
                if self.callback_lanzar:
                    self.callback_lanzar(ip, e, et)
            tk.Button(self._frame_acciones,
                text=f"→ {etiqueta}",
                bg=C_ACENTO, fg="white",
                font=("Monospace", 8), relief=tk.FLAT,
                padx=6, pady=2, cursor="hand2",
                command=_lanzar
            ).pack(side=tk.LEFT, padx=2)

    def _sugerir_siguientes(self, texto):
        """Sugiere los siguientes escaneos útiles según el resultado actual."""
        eid = self._escaneo_id
        sugeridos = []

        if eid == "ping":
            if "Host is up" in texto:
                sugeridos += [("quick", "⚡ Quick Ports"),
                              ("os",    "💻 OS Detect")]

        elif eid in ("quick", "standard"):
            n_open = len(re.findall(r'\d+/tcp\s+open', texto))
            if n_open:
                sugeridos += [("versions", "🏷 Versiones"),
                              ("scripts",  "📜 Safe Scripts")]
                if any(p in texto for p in ["445/tcp", "139/tcp"]):
                    sugeridos.append(("vuln", "🔴 Vuln Scan"))

        elif eid == "versions":
            sugeridos += [("scripts", "📜 Safe Scripts"),
                          ("vuln",    "🔴 Vuln Scan")]

        elif eid == "os":
            sugeridos += [("versions", "🏷 Versiones"),
                          ("scripts",  "📜 Safe Scripts")]

        elif eid == "scripts":
            # Si encontró algo interesante, sugerir vuln
            if any(kw in texto for kw in ["UPnP","open","DHCP","EAP"]):
                sugeridos.append(("vuln", "🔴 Vuln Scan"))
            sugeridos.append(("udp", "📡 UDP Ports"))

        return sugeridos[:3]  # máx 3 sugerencias

    def _copiar_todo(self):
        try:
            self.clipboard_clear()
            self.clipboard_append(self._texto_raw)
            self.update()
        except Exception:
            pass
