"""
scanner.py — Escáner de red con arquitectura multi-hilo Pipeline (3 Fases)
Fase 1: Escaneo de superficie (ARP/Nbtscan) hiper rápido.
Fase 2: Escaneo profundo multihilo (Nmap -sV -O).
Fase 3: Zoom / Herramientas especializadas (Whatweb, scripts Nmap, etc).
"""

import subprocess
import re
import threading
import time
import queue
from datetime import datetime

# Log interno — puede ser reemplazado por set_log_callback()
_log_fn = None  # Función externa para redirigir logs a la UI (se inyecta desde ui/app.py)

def log(msg):
    """Escribe un mensaje en consola y, si existe, en el callback de log externo."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    if _log_fn is not None:
        try:
            _log_fn(msg)
        except Exception as e:
            print(f"[SCANNER LOG ERROR] Fallo al invocar callback: {e}")

def set_log_callback(fn):
    """Permite que la UI registre una función para recibir todos los logs del scanner."""
    global _log_fn
    _log_fn = fn

INTERVALO_ARP      = 5  * 60
INTERVALO_PROFUNDO = 5  * 60  # 5 min — observable en prueba
TIMEOUT_NODO       = 15
TIMEOUT_RED        = 300
PUERTOS = "21,22,23,25,80,88,123,389,443,445,554,623,636,664,1433,1883,2049,3268,3269,3306,3389,5432,5900,8000,8080,8443,8554,9010,9100"


class Scanner:
    def __init__(self, callback):
        """
        callback: función que recibe un dict con información de cada host detectado.
        """
        self.callback  = callback
        self.corriendo = False
        self._red      = None
        self._interfaz = None
        self._lock     = threading.Lock()
        
        self._cola_fase2 = queue.Queue() # Recibe IPs vivas para escanear SO/Puertos
        self._cola_fase3 = queue.Queue() # Recibe tareas específicas
        
        self._escaneados_f2 = set()
        self._escaneados_f3 = set()
        self._stop_event  = threading.Event()

    # ── ARRANQUE ──────────────────────────────────────────────────

    def escanear(self, interfaz):
        """
        Arranca el escaneo en segundo plano sobre una interfaz de red concreta.
        """
        if self.corriendo:
            log("[SCANNER] Ya en curso")
            return
        self._interfaz = interfaz
        self._stop_event.clear()
        self.corriendo = True

        threading.Thread(target=self._loop_fase1, daemon=True, name="scanner-fase1").start()

        # Pool de hilos para Fase 2 (OS y Puertos)
        for i in range(3):
            threading.Thread(target=self._worker_fase2, daemon=True, name=f"scanner-fase2-{i}").start()

        # Pool de hilos para Fase 3 (Especializadas)
        for i in range(2):
            threading.Thread(target=self._worker_fase3, daemon=True, name=f"scanner-fase3-{i}").start()

        threading.Thread(target=self._loop_profundo, daemon=True, name="scanner-profundo").start()
        log(f"[SCANNER] Pipeline de 3 Fases activo en {interfaz} (5 hilos workers)")

    def detener(self):
        """
        Señala a todos los hilos para que terminen.
        """
        self._stop_event.set()
        self.corriendo = False
        log("[SCANNER] Hilos detenidos")

    # ── FASE 1 — SUPERFICIE ────────────────────────────────────────

    def _loop_fase1(self):
        """
        Hilo Fase 1: hace un ARP sweep periódico + Nbtscan sobre la red local.
        """
        fallos_consecutivos = 0
        while not self._stop_event.is_set():
            try:
                red = self.obtener_red_local(self._interfaz)
                if red:
                    self._red = red
                    fallos_consecutivos = 0
                    self._fase1_arp(red)
                    self._fase1_nbtscan(red)
                else:
                    fallos_consecutivos += 1
                    espera = min(30 * fallos_consecutivos, 300)
                    log(f"[SCANNER] Sin red ({fallos_consecutivos}), reintento en {espera}s")
                    self._stop_event.wait(espera)
                    continue
            except Exception as e:
                log(f"[SCANNER] Error inesperado en loop Fase 1: {type(e).__name__}: {e}")
                fallos_consecutivos += 1
            self._stop_event.wait(INTERVALO_ARP)

    def _fase1_arp(self, red):
        try:
            t = datetime.now()
            res = subprocess.run(
                ["nmap", "-sn", "-PR", "--host-timeout", "5s", red],
                capture_output=True, text=True, timeout=60)
            self._parsear_resultado_fase1(res.stdout, encolar_fase2=True)
            log(f"[SCANNER] Fase 1 (ARP) completado en {(datetime.now()-t).seconds}s")
        except subprocess.TimeoutExpired:
            log("[SCANNER] Fase 1 (ARP) timeout")
        except Exception as e:
            log(f"[SCANNER] Error Fase 1 (ARP): {e}")

    def _fase1_nbtscan(self, red):
        try:
            res = subprocess.run(["nbtscan", "-q", red], 
                                 capture_output=True, text=True, timeout=15)
            for linea in res.stdout.splitlines():
                partes = linea.split()
                if len(partes) >= 2:
                    ip = partes[0]
                    nombre = partes[1]
                    if self._es_ip_valida(ip):
                        # Enviar delta por callback
                        self.callback({"ip": ip, "sistema_op": f"Windows ({nombre})", "fase": 1})
        except Exception:
            pass # Ignorar si no está instalado o falla

    def _es_ip_valida(self, ip):
        # Validador básico de IP
        m = re.match(r'^(\d+)\.(\d+)\.(\d+)\.(\d+)$', ip)
        if not m: return False
        return all(0 <= int(x) <= 255 for x in m.groups())


    def _parsear_resultado_fase1(self, texto, encolar_fase2=True):
        """
        Extrae IPs y MACs del ARP scan para iniciar la vista súper rápido.
        """
        ip_actual  = None
        mac_actual = None

        for linea in texto.splitlines():
            m_ip = re.search(
                r'Nmap scan report for (?:.+ \()?(\d+\.\d+\.\d+\.\d+)', linea)
            if m_ip:
                if ip_actual:
                    self.callback({"ip": ip_actual, "mac": mac_actual, "fase": 1})
                    if encolar_fase2: self.encolar_nodo(ip_actual)
                ip_actual  = m_ip.group(1)
                mac_actual = None
                continue

            m_mac = re.search(r'MAC Address: ([0-9A-Fa-f:]{17})', linea)
            if m_mac:
                mac_actual = m_mac.group(1).upper()

        if ip_actual:
            self.callback({"ip": ip_actual, "mac": mac_actual, "fase": 1})
            if encolar_fase2: self.encolar_nodo(ip_actual)


    # ── FASE 2 — PROFUNDIDAD ───────────────────────────────────────

    def encolar_nodo(self, ip):
        """
        Encola una IP para Fase 2 (usado también por app.py al detectar tráfico nuevo).
        """
        with self._lock:
            if ip not in self._escaneados_f2:
                self._escaneados_f2.add(ip)
                self._cola_fase2.put(ip)

    def _worker_fase2(self):
        """
        Hilo Fase 2: Ejecuta Nmap agresivo para un host 
        (OS, Versiones, Topología si es necesario).
        """
        while not self._stop_event.is_set():
            try:
                ip = self._cola_fase2.get(timeout=2)
                self._ejecutar_fase2(ip)
                self._cola_fase2.task_done()
            except queue.Empty:
                pass
            except Exception as e:
                log(f"[SCANNER] Error en worker_fase2: {e}")

    def _ejecutar_fase2(self, ip):
        log(f"[SCANNER] Fase 2: Perfilando OS y puertos de {ip}...")
        try:
            # ── PASO A: escaneo de puertos rápido (sin -sV ni -O) ──────────
            # Separamos la detección de versiones del escaneo de puertos para
            # evitar que el timeout de -sV/-O impida detectar los puertos abiertos.
            res = subprocess.run(
                ["nmap", "-Pn", "-p", PUERTOS,
                 "--host-timeout", f"{TIMEOUT_NODO}s", "--open", ip],
                capture_output=True, text=True, timeout=TIMEOUT_NODO + 5)

            puertos_abiertos = []
            for linea in res.stdout.splitlines():
                m_port = re.search(r'^(\d+)/tcp\s+open', linea)
                if m_port:
                    puertos_abiertos.append(int(m_port.group(1)))

            # ── PASO B: OS detection ligera (solo si hay puertos abiertos) ──
            os_info = None
            if puertos_abiertos:
                try:
                    res_os = subprocess.run(
                        ["nmap", "-Pn", "-O", "--osscan-guess",
                         "--host-timeout", "8s",
                         "-p", ",".join(str(p) for p in puertos_abiertos[:3]),
                         ip],
                        capture_output=True, text=True, timeout=15)
                    os_match = re.search(r'OS details?:\s*(.+)', res_os.stdout)
                    if os_match:
                        os_info = os_match.group(1).split(",")[0].strip()[:40]
                    elif re.search(r'Running:\s*(.+)', res_os.stdout):
                        m = re.search(r'Running:\s*(.+)', res_os.stdout)
                        os_info = m.group(1).strip()[:40]
                except Exception:
                    pass  # OS detection es opcional — no crashear

            # ── Callback con resultados ────────────────────────────────────
            datos = {"ip": ip, "puertos": puertos_abiertos, "fase": 2}
            if os_info:
                datos["os_version"] = os_info
                datos["sistema_op"] = os_info.split()[0]

            self.callback(datos)

            # Enrutamiento a Fase 3 si hay puertos web/smb/db
            if puertos_abiertos:
                self._rutear_a_fase3(ip, puertos_abiertos)

        except subprocess.TimeoutExpired:
            log(f"[SCANNER] Fase 2 timeout en {ip}")
        except Exception as e:
            log(f"[SCANNER] Fase 2 error en {ip}: {e}")

    def _rutear_a_fase3(self, ip, puertos):
        """Lanza tareas específicas a la cola de Fase 3 según los puertos."""
        pw = [p for p in puertos if p in (80, 443, 8080, 8443)]
        if pw:
            self._cola_fase3.put({"ip": ip, "tipo": "web", "puertos": pw})

        if 445 in puertos or 139 in puertos:
            self._cola_fase3.put({"ip": ip, "tipo": "smb"})
            # Network Shares discovery si tiene SMB
            self._cola_fase3.put({"ip": ip, "tipo": "shares"})

        pdb = [p for p in puertos if p in (3306, 1433, 5432)]
        if pdb:
            self._cola_fase3.put({"ip": ip, "tipo": "db", "puertos": pdb})

        # ── DC / Active Directory ─────────────────────────────────
        # Kerberos (88) + LDAP (389/636) + GC (3268/3269) → casi seguro un DC
        puertos_dc = set(puertos) & {88, 389, 445, 636, 3268, 3269}
        if len(puertos_dc) >= 2:
            self._cola_fase3.put({"ip": ip, "tipo": "dc_detect", "puertos": list(puertos_dc)})

        # LDAP anónimo — si tiene 389 o 636
        if 389 in puertos or 636 in puertos:
            self._cola_fase3.put({"ip": ip, "tipo": "ldap"})

        # SSL/TLS certificado — si tiene 443, 636, 3269, 8443
        puertos_ssl = [p for p in puertos if p in (443, 636, 3269, 8443, 8000)]
        if puertos_ssl:
            self._cola_fase3.put({"ip": ip, "tipo": "ssl_cert", "puertos": puertos_ssl})

        # FTP anonymous — puerto 21
        if 21 in puertos:
            self._cola_fase3.put({"ip": ip, "tipo": "ftp_anon"})

        # NFS showmount — puerto 2049
        if 2049 in puertos or 111 in puertos:
            self._cola_fase3.put({"ip": ip, "tipo": "nfs"})

        # NTP drift — puerto 123
        if 123 in puertos:
            self._cola_fase3.put({"ip": ip, "tipo": "ntp_drift"})

        # Kerberos SPN enumeration — solo si hay DC detectado (puerto 88)
        if 88 in puertos:
            self._cola_fase3.put({"ip": ip, "tipo": "kerberos_spn"})

        # IPMI/iDRAC/iLO — puertos 623 (IPMI) y 664 (IPMI sobre SSL)
        if 623 in puertos or 664 in puertos:
            self._cola_fase3.put({"ip": ip, "tipo": "ipmi"})

        # Credenciales por defecto — HTTP/HTTPS con paneles web conocidos
        if pw or 8000 in puertos or 9010 in puertos:
            self._cola_fase3.put({"ip": ip, "tipo": "default_creds",
                                  "puertos": pw or [8000]})


    # ── FASE 3 — ZOOM (ESPECIALIZADO) ──────────────────────────────

    def _worker_fase3(self):
        """
        Hilo Fase 3: Procesa tareas específicas de análisis profundo.
        """
        while not self._stop_event.is_set():
            try:
                tarea = self._cola_fase3.get(timeout=2)
                ip = tarea["ip"]
                tipo = tarea["tipo"]
                
                # Deduplicar tareas idénticas
                clave = f"{ip}_{tipo}"
                with self._lock:
                    if clave in self._escaneados_f3:
                        self._cola_fase3.task_done()
                        continue
                    self._escaneados_f3.add(clave)

                if tipo == "web":
                    self._fase3_web(ip, tarea.get("puertos", []))
                elif tipo == "smb":
                    self._fase3_smb(ip)
                elif tipo == "db":
                    self._fase3_db(ip, tarea.get("puertos", []))
                elif tipo == "shares":
                    self._fase3_shares(ip)
                elif tipo == "dc_detect":
                    self._fase3_dc_detect(ip, tarea.get("puertos", []))
                elif tipo == "ldap":
                    self._fase3_ldap(ip)
                elif tipo == "ssl_cert":
                    self._fase3_ssl_cert(ip, tarea.get("puertos", []))
                elif tipo == "ftp_anon":
                    self._fase3_ftp_anon(ip)
                elif tipo == "nfs":
                    self._fase3_nfs(ip)
                elif tipo == "ntp_drift":
                    self._fase3_ntp_drift(ip)
                elif tipo == "kerberos_spn":
                    self._fase3_kerberos_spn(ip)
                elif tipo == "default_creds":
                    self._fase3_default_creds(ip, tarea.get("puertos", [80]))
                elif tipo == "ipmi":
                    self._fase3_ipmi(ip)

                self._cola_fase3.task_done()
            except queue.Empty:
                pass
            except Exception as e:
                log(f"[SCANNER] Error en worker_fase3: {e}")

    def _fase3_web(self, ip, puertos_web):
        log(f"[SCANNER] Fase 3: Analizando web en {ip}")
        try:
            # Analizamos el primer puerto web detectado para no saturar
            p = puertos_web[0]
            url = f"http://{ip}:{p}" if p not in (443, 8443) else f"https://{ip}:{p}"
            res = subprocess.run(["whatweb", "-a", "1", "--color=never", "--no-errors", url], 
                                 capture_output=True, text=True, timeout=12)
            
            info = None
            if res.returncode == 0 and res.stdout:
                partes = res.stdout.split("[200 OK]")
                if len(partes) > 1:
                    info = partes[1].strip()[:60]
                elif "Title[" in res.stdout:
                    m = re.search(r'Title\[(.*?)\]', res.stdout)
                    info = m.group(1) if m else "Web activa"
            
            if info:
                self.callback({"ip": ip, "web_info": info, "fase": 3})
        except FileNotFoundError:
            pass # whatweb no instalado
        except Exception:
            pass

    def _fase3_smb(self, ip):
        log(f"[SCANNER] Fase 3: SMB-OS-Discovery en {ip}")
        try:
            res = subprocess.run(
                ["nmap", "-Pn", "-p", "445,139", "--script", "smb-os-discovery", ip],
                capture_output=True, text=True, timeout=20)
            
            os_match = re.search(r'OS: (.+)', res.stdout)
            
            if os_match:
                smb_info = os_match.group(1).strip()
                self.callback({"ip": ip, "smb_info": smb_info[:50], "fase": 3})
        except Exception:
            pass

    def _fase3_db(self, ip, puertos_db):
        log(f"[SCANNER] Fase 3: Revisando Bases de datos en {ip}")
        try:
            p_str = ",".join(map(str, puertos_db))
            res = subprocess.run(
                ["nmap", "-Pn", "-p", p_str, "-sV", "--version-intensity", "5", ip],
                capture_output=True, text=True, timeout=20)
            
            db_info = []
            for linea in res.stdout.splitlines():
                if "/tcp" in linea and "open" in linea:
                    partes = linea.split("open", 1)
                    if len(partes) > 1:
                        db_info.append(partes[1].strip())
            
            if db_info:
                # Usaremos la web_info campo libremente como info especializada extra
                info_texto = " | ".join(db_info)[:50]
                self.callback({"ip": ip, "web_info": f"DB: {info_texto}", "fase": 3})
        except Exception:
            pass


    # ── FASE 3 — SSL/TLS CERTIFICADO ─────────────────────────────

    def _fase3_ssl_cert(self, ip, puertos_ssl):
        """
        Inspecciona el certificado SSL/TLS:
        - Emisor, sujeto (CN), fecha de vencimiento
        - Detecta: caducado, autofirmado, hostname incorrecto
        - Detecta cifrados débiles (SSLv2, SSLv3, RC4)
        """
        puerto = puertos_ssl[0]
        log(f"[SCANNER] Fase 3: SSL/TLS en {ip}:{puerto}")
        try:
            res = subprocess.run([
                "nmap", "-Pn", f"-p{puerto}",
                "--script", "ssl-cert,ssl-enum-ciphers",
                "--script-timeout", "10s",
                ip],
                capture_output=True, text=True, timeout=25)

            stdout = res.stdout
            hallazgos = []

            # Extraer emisor y CN
            cn_match      = re.search(r'commonName=([^\n/,]+)', stdout)
            issuer_match  = re.search(r'Issuer:.*?commonName=([^\n/,]+)', stdout)
            expiry_match  = re.search(r'Not valid after:\s+(.+)', stdout)

            cn     = cn_match.group(1).strip()     if cn_match     else "?"
            issuer = issuer_match.group(1).strip() if issuer_match else "?"
            expiry = expiry_match.group(1).strip() if expiry_match else "?"

            # Detectar caducado
            caducado = False
            if expiry and expiry != "?":
                try:
                    from datetime import datetime as dt
                    # Formato: 2024-01-01T00:00:00
                    fecha_exp = dt.strptime(expiry[:10], "%Y-%m-%d")
                    if fecha_exp < dt.now():
                        caducado = True
                        hallazgos.append(("CERT CADUCADO", "alto",
                            f"SSL caducó: {expiry[:10]} — CN:{cn}"))
                except Exception:
                    pass

            # Detectar autofirmado (emisor == sujeto)
            if issuer and cn and issuer.lower() in cn.lower():
                hallazgos.append(("SSL Autofirmado", "medio",
                    f"Cert autofirmado — emisor: {issuer[:30]}"))

            # Detectar cifrados débiles
            cifrados_debiles = []
            for debil in ("sslv2", "sslv3", "rc4", "export", "null", "anon"):
                if debil in stdout.lower():
                    cifrados_debiles.append(debil.upper())
            if cifrados_debiles:
                hallazgos.append(("Cifrado Débil", "alto",
                    f"Cifrados inseguros: {', '.join(cifrados_debiles)}"))

            # Si no hay problemas, notificar el cert OK
            if not hallazgos:
                info = f"OK — CN:{cn} | Emisor:{issuer[:20]} | Exp:{expiry[:10]}"
                log(f"[SCANNER] SSL {ip}:{puerto}: {info}")
                self.callback({
                    "ip": ip, "fase": 3,
                    "hallazgo_directo": {
                        "puerto":     puerto,
                        "servicio":   "SSL/TLS",
                        "severidad":  "info",
                        "descripcion": info[:80]
                    }
                })
            else:
                for servicio, sev, detalle in hallazgos:
                    log(f"[SCANNER] SSL {ip}:{puerto} [{sev.upper()}] {detalle}")
                    self.callback({
                        "ip": ip, "fase": 3,
                        "hallazgo_directo": {
                            "puerto":     puerto,
                            "servicio":   servicio,
                            "severidad":  sev,
                            "descripcion": detalle[:80]
                        }
                    })
        except Exception as e:
            log(f"[SCANNER] SSL error en {ip}: {e}")

    # ── FASE 3 — DC / ACTIVE DIRECTORY ───────────────────────────

    def _fase3_dc_detect(self, ip, puertos_dc):
        """
        Detección de Domain Controller / Active Directory.
        Puertos clave: 88 (Kerberos), 389 (LDAP), 445 (SMB), 636 (LDAPS),
                       3268 (GC), 3269 (GC-SSL)
        También intenta dual-homed / jump box detection.
        """
        log(f"[SCANNER] Fase 3: DC/AD Detection en {ip}")
        try:
            # smb-security-mode + smb2-security-mode revelan si es un DC
            res = subprocess.run([
                "nmap", "-Pn",
                "-p", "88,389,445,636,3268,3269",
                "--script", "smb-security-mode,smb2-security-mode,"
                            "ldap-rootdse,krb5-enum-users",
                "--script-timeout", "12s",
                ip],
                capture_output=True, text=True, timeout=30)

            stdout = res.stdout
            es_dc = False
            dominio = None
            dc_info = []

            # Indicadores de DC
            if "kerberos" in stdout.lower() or \
               "88/tcp" in stdout and "open" in stdout:
                es_dc = True
                dc_info.append("Kerberos activo")

            if "defaultNamingContext" in stdout or \
               "domainFunctionality" in stdout:
                es_dc = True
                dc_info.append("LDAP rootDSE responde")
                m = re.search(r'defaultNamingContext:\s*(DC=[^\n]+)', stdout)
                if m:
                    dominio = m.group(1).replace("DC=", "").replace(",", ".").strip(".")

            if "Domain Controller" in stdout or \
               "PDC" in stdout or "domainFunctionality" in stdout:
                es_dc = True
                dc_info.append("SMB confirma DC")

            if es_dc:
                detalle = f"DC detectado | {', '.join(dc_info)}"
                if dominio:
                    detalle += f" | Dominio: {dominio}"
                log(f"[SCANNER] ⚠ {ip}: {detalle}")
                self.callback({
                    "ip": ip, "fase": 3,
                    "hallazgo_directo": {
                        "puerto":     88,
                        "servicio":   "DC/Active Directory",
                        "severidad":  "alto",
                        "descripcion": detalle[:80]
                    },
                    "tipo_dispositivo": "servidor",
                    "perfil": "Domain Controller"
                })

            # Dual-homed / Jump Box detection
            # Si tiene puertos de admin (22/3389/5900) + puertos de AD → posible jump box
            puertos_admin = set(puertos_dc) & {22, 3389, 5900, 23}
            puertos_ad    = set(puertos_dc) & {88, 389, 445, 636, 3268}
            if puertos_admin and puertos_ad:
                log(f"[SCANNER] ⚠ {ip}: posible Jump Box / Dual-Homed host")
                self.callback({
                    "ip": ip, "fase": 3,
                    "hallazgo_directo": {
                        "puerto":     0,
                        "servicio":   "Jump Box",
                        "severidad":  "alto",
                        "descripcion": f"Admin remoto + servicios AD — posible pivote"
                    }
                })

        except Exception as e:
            log(f"[SCANNER] DC detection error en {ip}: {e}")

    # ── FASE 3 — LDAP ENUMERATION ─────────────────────────────────

    def _fase3_ldap(self, ip):
        """
        LDAP enumeration básica — consulta anónima al rootDSE.
        Sin credenciales. Solo metadatos públicos:
        namingContexts, domainFunctionality, forestFunctionality.
        También intenta Domain Trust Discovery pasiva.
        """
        log(f"[SCANNER] Fase 3: LDAP enumeration en {ip}")
        try:
            res = subprocess.run([
                "nmap", "-Pn", "-p", "389,636",
                "--script", "ldap-rootdse,ldap-search",
                "--script-args", "ldap.base='',ldap.filter='(objectClass=*)',"
                                 "ldap.attribs='namingContexts,defaultNamingContext,"
                                 "domainFunctionality,forestFunctionality'",
                "--script-timeout", "15s",
                ip],
                capture_output=True, text=True, timeout=30)

            stdout = res.stdout
            info_ldap = []

            # Extraer naming context → nombre del dominio
            nc = re.search(r'defaultNamingContext:\s*(DC=[^\n]+)', stdout)
            if nc:
                dominio = nc.group(1).replace("DC=","").replace(",",".").strip(".")
                info_ldap.append(f"Dominio: {dominio}")

            # Forest functionality level → versión de Windows Server
            ff = re.search(r'forestFunctionality:\s*(\d+)', stdout)
            if ff:
                niveles = {"0":"2000","1":"2003 Interim","2":"2003",
                           "3":"2008","4":"2008 R2","5":"2012","6":"2012 R2","7":"2016+"}
                nivel = niveles.get(ff.group(1), ff.group(1))
                info_ldap.append(f"Forest: Windows Server {nivel}")

            # Domain trusts (nltest equivalente pasivo)
            trusts = re.findall(r'trustPartner:\s*([^\n]+)', stdout)
            if trusts:
                info_ldap.append(f"Trusts: {', '.join(trusts[:3])}")

            if info_ldap:
                detalle = " | ".join(info_ldap)
                log(f"[SCANNER] LDAP {ip}: {detalle}")
                self.callback({
                    "ip": ip, "fase": 3,
                    "hallazgo_directo": {
                        "puerto":     389,
                        "servicio":   "LDAP",
                        "severidad":  "medio",
                        "descripcion": detalle[:80]
                    }
                })
            else:
                log(f"[SCANNER] LDAP {ip}: sin datos anónimos (esperado en DCs bien configurados)")

        except Exception as e:
            log(f"[SCANNER] LDAP error en {ip}: {e}")

    # ── FASE 3 — NETWORK SHARES ───────────────────────────────────

    def _fase3_shares(self, ip):
        """
        Network Share discovery profunda.
        1) nmap smb-enum-shares — sin credenciales
        2) smbclient -L (listado anónimo)
        Detecta: shares públicos, shares admin ($), acceso anónimo.
        """
        log(f"[SCANNER] Fase 3: Network Shares en {ip}")
        try:
            # Intentar con nmap primero (más silencioso)
            res = subprocess.run([
                "nmap", "-Pn", "-p", "445,139",
                "--script", "smb-enum-shares,smb-enum-users",
                "--script-timeout", "15s",
                ip],
                capture_output=True, text=True, timeout=30)

            stdout = res.stdout
            shares = []
            share_anonimo = False

            # Parsear shares del output de nmap
            for linea in stdout.splitlines():
                linea = linea.strip()
                # Formato: \\IP\SHARE
                m = re.search(r'\\\\[^\s]+\\([A-Za-z0-9_$\-]+)', linea)
                if m:
                    share = m.group(1)
                    if share not in shares:
                        shares.append(share)
                # Detectar acceso anónimo
                if "Anonymous access" in linea and "READ" in linea:
                    share_anonimo = True

            # Si nmap no da nada, intentar smbclient
            if not shares:
                try:
                    res2 = subprocess.run([
                        "smbclient", "-L", ip,
                        "-N",  # sin contraseña (anónimo)
                        "--no-pass"],
                        capture_output=True, text=True, timeout=15)
                    for linea in res2.stdout.splitlines():
                        m = re.match(r'\s+(\S+)\s+Disk', linea)
                        if m:
                            share = m.group(1)
                            if share not in shares:
                                shares.append(share)
                        if "IPC$" in linea:
                            share_anonimo = True
                except FileNotFoundError:
                    pass  # smbclient no instalado

            if shares:
                shares_str = ", ".join(shares[:8])
                sev = "alto" if share_anonimo else "medio"
                detalle = f"Shares: {shares_str}"
                if share_anonimo:
                    detalle += " — ACCESO ANÓNIMO"
                log(f"[SCANNER] Shares {ip}: {detalle}")
                self.callback({
                    "ip": ip, "fase": 3,
                    "hallazgo_directo": {
                        "puerto":     445,
                        "servicio":   "Network Shares",
                        "severidad":  sev,
                        "descripcion": detalle[:80]
                    }
                })

        except Exception as e:
            log(f"[SCANNER] Shares error en {ip}: {e}")

    # ── FASE 3 — FTP ANONYMOUS ────────────────────────────────────

    def _fase3_ftp_anon(self, ip):
        """Intenta login FTP anónimo y lista directorios si tiene acceso."""
        log(f"[SCANNER] Fase 3: FTP Anonymous en {ip}")
        try:
            import ftplib
            ftp = ftplib.FTP(timeout=8)
            ftp.connect(ip, 21, timeout=8)
            banner = ftp.getwelcome()

            try:
                ftp.login("anonymous", "anonymous@example.com")
                # Login exitoso — listar directorio raíz
                archivos = []
                try:
                    ftp.dir(lambda l: archivos.append(l))
                except Exception:
                    pass
                ftp.quit()

                detalle = f"FTP Anonymous: acceso ABIERTO | Banner: {banner[:40]}"
                if archivos:
                    detalle += f" | {len(archivos)} entradas en raíz"
                log(f"[SCANNER] ⚠ FTP Anonymous {ip}: ACCESO ABIERTO")
                self.callback({
                    "ip": ip, "fase": 3,
                    "hallazgo_directo": {
                        "puerto"    : 21,
                        "servicio"  : "FTP Anonymous",
                        "severidad" : "alto",
                        "descripcion": detalle[:80]
                    }
                })
            except ftplib.error_perm:
                # Login rechazado — solo reportar banner si es interesante
                log(f"[SCANNER] FTP {ip}: anonymous rechazado — {banner[:40]}")
                if any(kw in banner.lower() for kw in
                       ["vsftpd", "filezilla", "proftpd", "pure-ftpd"]):
                    self.callback({
                        "ip": ip, "fase": 3,
                        "hallazgo_directo": {
                            "puerto"    : 21,
                            "servicio"  : "FTP Banner",
                            "severidad" : "info",
                            "descripcion": f"FTP: {banner[:60]}"
                        }
                    })
        except Exception as e:
            log(f"[SCANNER] FTP {ip}: {e}")

    # ── FASE 3 — NFS SHOWMOUNT ────────────────────────────────────

    def _fase3_nfs(self, ip):
        """Enumera exportaciones NFS con showmount -e."""
        log(f"[SCANNER] Fase 3: NFS showmount en {ip}")
        try:
            res = subprocess.run(
                ["showmount", "-e", "--no-headers", ip],
                capture_output=True, text=True, timeout=15)

            if res.returncode == 0 and res.stdout.strip():
                exportaciones = []
                for linea in res.stdout.strip().splitlines():
                    partes = linea.split()
                    if partes:
                        ruta = partes[0]
                        acceso = partes[1] if len(partes) > 1 else "*"
                        exportaciones.append(f"{ruta}({acceso})")

                if exportaciones:
                    sev = "alto" if any("*" in e or "0.0.0.0" in e
                                       for e in exportaciones) else "medio"
                    detalle = f"NFS exports: {', '.join(exportaciones[:4])}"
                    acceso_libre = any("*" in e for e in exportaciones)
                    if acceso_libre:
                        detalle += " — ACCESO LIBRE"
                    log(f"[SCANNER] NFS {ip}: {detalle}")
                    self.callback({
                        "ip": ip, "fase": 3,
                        "hallazgo_directo": {
                            "puerto"    : 2049,
                            "servicio"  : "NFS Export",
                            "severidad" : sev,
                            "descripcion": detalle[:80]
                        }
                    })
            else:
                log(f"[SCANNER] NFS {ip}: sin exportaciones o acceso denegado")
        except FileNotFoundError:
            log(f"[SCANNER] NFS {ip}: showmount no disponible")
        except Exception as e:
            log(f"[SCANNER] NFS {ip}: {e}")

    # ── FASE 3 — NTP DRIFT ────────────────────────────────────────

    def _fase3_ntp_drift(self, ip):
        """
        Compara el tiempo del servidor NTP con el tiempo local.
        Una desviación grande puede indicar manipulación de logs o ataque.
        """
        log(f"[SCANNER] Fase 3: NTP drift en {ip}")
        try:
            res = subprocess.run(
                ["ntpdate", "-q", ip],
                capture_output=True, text=True, timeout=10)

            # Parsear offset del output de ntpdate
            m = re.search(r'offset\s+([-\d.]+)\s+sec', res.stdout)
            if m:
                offset = float(m.group(1))
                offset_abs = abs(offset)
                if offset_abs > 300:       # 5+ minutos
                    sev = "alto"
                    alerta = f"CRÍTICO: desviación de {offset:.1f}s"
                elif offset_abs > 60:      # 1+ minuto
                    sev = "medio"
                    alerta = f"Desviación significativa: {offset:.1f}s"
                else:
                    sev = "info"
                    alerta = f"Tiempo OK — offset: {offset:.3f}s"

                log(f"[SCANNER] NTP {ip}: offset={offset:.3f}s [{sev.upper()}]")
                self.callback({
                    "ip": ip, "fase": 3,
                    "hallazgo_directo": {
                        "puerto"    : 123,
                        "servicio"  : "NTP Drift",
                        "severidad" : sev,
                        "descripcion": alerta
                    }
                })
            else:
                # ntpdate sin output útil — intentar con nmap
                res2 = subprocess.run(
                    ["nmap", "-Pn", "-sU", "-p", "123",
                     "--script", "ntp-info", ip],
                    capture_output=True, text=True, timeout=20)
                if "receive time" in res2.stdout:
                    log(f"[SCANNER] NTP {ip}: servidor NTP activo")
                    self.callback({
                        "ip": ip, "fase": 3,
                        "hallazgo_directo": {
                            "puerto"    : 123,
                            "servicio"  : "NTP Server",
                            "severidad" : "info",
                            "descripcion": "Servidor NTP activo — offset no medible"
                        }
                    })
        except FileNotFoundError:
            # ntpdate no disponible — usar nmap directamente
            try:
                res = subprocess.run(
                    ["nmap", "-Pn", "-sU", "-p", "123",
                     "--script", "ntp-info", ip],
                    capture_output=True, text=True, timeout=20)
                if "stratum" in res.stdout:
                    stratum_m = re.search(r'stratum:\s*(\d+)', res.stdout)
                    stratum = stratum_m.group(1) if stratum_m else "?"
                    log(f"[SCANNER] NTP {ip}: stratum={stratum}")
                    self.callback({
                        "ip": ip, "fase": 3,
                        "hallazgo_directo": {
                            "puerto"    : 123,
                            "servicio"  : "NTP Server",
                            "severidad" : "info",
                            "descripcion": f"Servidor NTP activo — stratum {stratum}"
                        }
                    })
            except Exception:
                pass
        except Exception as e:
            log(f"[SCANNER] NTP {ip}: {e}")

    # ── FASE 3 — KERBEROS SPN ENUMERATION ────────────────────────

    def _fase3_kerberos_spn(self, ip):
        """
        Enumera usuarios y SPNs Kerberos sin credenciales.
        Usa nmap krb5-enum-users con wordlist básica.
        Detecta: pre-autenticación deshabilitada (AS-REP Roasting posible).
        """
        log(f"[SCANNER] Fase 3: Kerberos enum en {ip}")
        try:
            # Paso 1: Detectar realm del DC
            res = subprocess.run([
                "nmap", "-Pn", "-p", "88",
                "--script", "krb5-enum-users",
                "--script-args",
                "krb5-enum-users.realm='',"
                "userdb=/usr/share/nmap/nselib/data/usernames.lst",
                "--script-timeout", "20s",
                ip],
                capture_output=True, text=True, timeout=35)

            stdout = res.stdout
            usuarios = re.findall(r'Valid username:\s*(\S+)', stdout)
            realm_m  = re.search(r'realm:\s*(\S+)', stdout, re.IGNORECASE)
            realm    = realm_m.group(1) if realm_m else "?"

            if usuarios:
                detalle = (f"Kerberos realm: {realm} | "
                           f"Usuarios válidos: {', '.join(usuarios[:5])}")
                log(f"[SCANNER] Kerberos {ip}: {len(usuarios)} usuario(s) — {detalle[:60]}")
                self.callback({
                    "ip": ip, "fase": 3,
                    "hallazgo_directo": {
                        "puerto"    : 88,
                        "servicio"  : "Kerberos SPN",
                        "severidad" : "medio",
                        "descripcion": detalle[:80]
                    }
                })
            elif "88/tcp open" in stdout or "kerberos" in stdout.lower():
                log(f"[SCANNER] Kerberos {ip}: activo, realm={realm}, "
                    f"sin usuarios enumerados (protegido)")
                self.callback({
                    "ip": ip, "fase": 3,
                    "hallazgo_directo": {
                        "puerto"    : 88,
                        "servicio"  : "Kerberos",
                        "severidad" : "info",
                        "descripcion": f"Kerberos activo — realm: {realm}"
                    }
                })
        except Exception as e:
            log(f"[SCANNER] Kerberos {ip}: {e}")

    # ── FASE 3 — CREDENCIALES POR DEFECTO ────────────────────────

    def _fase3_default_creds(self, ip, puertos_web):
        """
        Prueba credenciales por defecto en paneles web conocidos.
        Detecta fabricante por el banner HTTP y usa la lista correspondiente.
        No usa fuerza bruta — solo las credenciales más comunes por fabricante.
        """
        log(f"[SCANNER] Fase 3: Credenciales por defecto en {ip}")

        # Tabla de credenciales por defecto por fabricante/producto
        # Formato: {identificador_en_banner: [(user, pass), ...]}
        CREDS_DEFAULT = {
            "hikvision" : [("admin","12345"), ("admin","admin"),
                           ("admin",""), ("admin","Admin1234!")],
            "dahua"     : [("admin","admin"), ("admin","Admin1234"),
                           ("888888","888888"), ("666666","666666")],
            "tenda"     : [("admin","admin"), ("admin",""),
                           ("admin","tenda"), ("guest","guest")],
            "tp-link"   : [("admin","admin"), ("admin",""),
                           ("admin","tp-link"), ("user","user")],
            "mikrotik"  : [("admin",""), ("admin","admin")],
            "ubiquiti"  : [("ubnt","ubnt"), ("admin","ubnt"),
                           ("admin","admin")],
            "cisco"     : [("admin","admin"), ("cisco","cisco"),
                           ("admin","cisco"), ("", "cisco")],
            "d-link"    : [("admin",""), ("admin","admin"),
                           ("Admin",""), ("user","user")],
            "netgear"   : [("admin","password"), ("admin","admin"),
                           ("admin","1234")],
            "asus"      : [("admin","admin"), ("admin","")],
            "axis"      : [("root","pass"), ("admin","admin")],
            "foscam"    : [("admin",""), ("admin","admin")],
            "lighttpd"  : [("admin","admin"), ("root","root")],
            "default"   : [("admin","admin"), ("admin","password"),
                           ("admin","12345"), ("root","root"),
                           ("admin",""), ("user","user")],
        }

        import urllib.request
        import urllib.error
        import base64

        for puerto in puertos_web[:2]:   # máx 2 puertos para no saturar
            esquema = "https" if puerto in (443, 8443) else "http"
            url_base = f"{esquema}://{ip}:{puerto}"

            # Paso 1: Detectar fabricante por banner HTTP
            fabricante_key = "default"
            try:
                req = urllib.request.Request(
                    url_base,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                ctx = __import__("ssl").create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = __import__("ssl").CERT_NONE
                resp = urllib.request.urlopen(req, timeout=6, context=ctx
                          if esquema == "https" else None)
                server = resp.headers.get("Server", "").lower()
                body   = resp.read(2048).decode("utf-8", errors="replace").lower()

                for fab in CREDS_DEFAULT:
                    if fab in server or fab in body:
                        fabricante_key = fab
                        break
            except Exception:
                pass

            # Paso 1b: Hacer request SIN credenciales para baseline
            code_sin_creds = None
            body_sin_creds = ""
            try:
                req_base = urllib.request.Request(
                    url_base, headers={"User-Agent": "Mozilla/5.0"})
                ctx0 = __import__("ssl").create_default_context()
                ctx0.check_hostname = False
                ctx0.verify_mode = __import__("ssl").CERT_NONE
                try:
                    r0 = urllib.request.urlopen(
                        req_base, timeout=5,
                        context=ctx0 if esquema == "https" else None)
                    code_sin_creds = r0.status
                    body_sin_creds = r0.read(512).decode("utf-8", errors="replace")
                except urllib.error.HTTPError as he:
                    code_sin_creds = he.code  # 401 = pide auth → buena señal
            except Exception:
                pass

            # Si sin credenciales ya da 200 → no usa Basic Auth → saltar
            if code_sin_creds == 200:
                log(f"[SCANNER] Default creds {ip}:{puerto}: "
                    f"sin autenticación Basic (200 sin creds) — omitiendo")
                continue

            creds = CREDS_DEFAULT.get(fabricante_key, CREDS_DEFAULT["default"])

            # Paso 2: Probar credenciales con HTTP Basic Auth
            for usuario, password in creds[:6]:   # máx 6 intentos
                try:
                    cred_b64 = base64.b64encode(
                        f"{usuario}:{password}".encode()).decode()
                    req = urllib.request.Request(
                        url_base,
                        headers={
                            "Authorization": f"Basic {cred_b64}",
                            "User-Agent": "Mozilla/5.0"
                        }
                    )
                    ctx = __import__("ssl").create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = __import__("ssl").CERT_NONE
                    try:
                        resp = urllib.request.urlopen(
                            req, timeout=5,
                            context=ctx if esquema == "https" else None)
                        code = resp.status
                        body_con_creds = resp.read(512).decode("utf-8", errors="replace")
                    except urllib.error.HTTPError as he:
                        code = he.code
                        body_con_creds = ""

                    # Válido SOLO si:
                    # 1) Responde 200 con creds Y antes respondía 401/403
                    # 2) O si el body con creds es claramente diferente al sin creds
                    es_valido = (
                        code == 200 and code_sin_creds in (401, 403, None)
                    )

                    if es_valido:
                        detalle = (f"Credencial por defecto válida: "
                                   f"{usuario}:{password} en {url_base} "
                                   f"[{fabricante_key}]")
                        log(f"[SCANNER] 🔴 DEFAULT CREDS {ip}:{puerto} "
                            f"→ {usuario}:{password}")
                        self.callback({
                            "ip": ip, "fase": 3,
                            "hallazgo_directo": {
                                "puerto"    : puerto,
                                "servicio"  : "Cred. por Defecto",
                                "severidad" : "critico",
                                "descripcion": detalle[:80]
                            }
                        })
                        return  # Encontrado — no seguir probando
                except Exception:
                    continue

        log(f"[SCANNER] Default creds {ip}: sin acceso con credenciales comunes")

    # ── FASE 3 — IPMI / iDRAC / iLO ──────────────────────────────

    def _fase3_ipmi(self, ip):
        """
        Detecta interfaces de gestión fuera de banda.
        IPMI (puerto 623 UDP), iDRAC (Dell), iLO (HP), IPMI-over-LAN.
        Prueba: versión IPMI, canal de autenticación, cipher suite 0
        (vulnerabilidad conocida que permite auth sin contraseña).
        """
        log(f"[SCANNER] Fase 3: IPMI/BMC en {ip}")
        try:
            res = subprocess.run([
                "nmap", "-Pn", "-sU", "-p", "623",
                "--script", "ipmi-version,ipmi-cipher-zero",
                "--script-timeout", "15s", ip],
                capture_output=True, text=True, timeout=25)

            stdout = res.stdout
            hallazgos = []

            # Detectar versión IPMI
            if "IPMI" in stdout or "623/udp open" in stdout:
                version_m = re.search(r'IPMI[- ]v?([\d.]+)', stdout)
                version = version_m.group(0) if version_m else "IPMI detectado"

                # Detectar fabricante (iDRAC=Dell, iLO=HP, BMC genérico)
                if "iDRAC" in stdout or "Dell" in stdout:
                    fabricante = "Dell iDRAC"
                elif "iLO" in stdout or "Hewlett" in stdout or "HP " in stdout:
                    fabricante = "HP iLO"
                elif "Supermicro" in stdout:
                    fabricante = "Supermicro IPMI"
                else:
                    fabricante = "BMC/IPMI genérico"

                hallazgos.append((
                    "IPMI Detectado", "medio",
                    f"{fabricante} | {version} | "
                    f"Gestión fuera de banda expuesta en LAN"
                ))

            # Cipher Suite 0 — vulnerabilidad crítica
            # Permite autenticación sin contraseña válida
            if "cipher suite 0" in stdout.lower() or "VULNERABLE" in stdout:
                hallazgos.append((
                    "IPMI Cipher Zero", "critico",
                    f"IPMI Cipher Suite 0 vulnerable — "
                    f"auth sin contraseña posible en {ip}"
                ))
                log(f"[SCANNER] 🔴 IPMI Cipher Zero en {ip}: CRÍTICO")

            for servicio, sev, detalle in hallazgos:
                self.callback({
                    "ip": ip, "fase": 3,
                    "hallazgo_directo": {
                        "puerto"     : 623,
                        "servicio"   : servicio,
                        "severidad"  : sev,
                        "descripcion": detalle[:80]
                    }
                })

            if not hallazgos:
                log(f"[SCANNER] IPMI {ip}: sin respuesta en UDP 623")

        except Exception as e:
            log(f"[SCANNER] IPMI {ip}: {e}")

    # ── HILO 3 — RE-ESCANEO PROFUNDO PERIÓDICO ───────────────────

    def _loop_profundo(self):
        """
        Hilo 4 (auxiliar): re-escaneo profundo de toda la red cada cierto intervalo.
        """
        self._stop_event.wait(30)   # esperar al ARP inicial
        while not self._stop_event.is_set():
            if self._red:
                log(f"[SCANNER] Re-escaneo profundo masivo de {self._red}...")
                with self._lock:
                    self._escaneados_f2.clear()
                    self._escaneados_f3.clear()
                    
                # Hacemos nmap agresivo a toda la subred para capturar cambios
                try:
                    res = subprocess.run(
                        ["nmap", "-Pn", "-p", PUERTOS,
                         "--host-timeout", "10s", "--open", self._red],
                        capture_output=True, text=True, timeout=TIMEOUT_RED)
                    self._parsear_resultado_fase1(res.stdout, encolar_fase2=True)
                    log("[SCANNER] Re-escaneo masivo completado")
                except subprocess.TimeoutExpired:
                    log("[SCANNER] Re-escaneo masivo cancelado por timeout")
                except Exception as e:
                    log(f"[SCANNER] Error re-escaneo: {e}")

            self._stop_event.wait(INTERVALO_PROFUNDO)

    # ── UTILIDADES ────────────────────────────────────────────────

    def obtener_red_local(self, interfaz):
        try:
            res = subprocess.run(
                ["ip", "-o", "-f", "inet", "addr", "show", interfaz],
                capture_output=True, text=True, timeout=5)
            m = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', res.stdout)
            if m: return m.group(1)
        except Exception as e:
            log(f"[SCANNER] Error red: {e}")
        return None

    def obtener_gateway(self, interfaz):
        try:
            res = subprocess.run(
                ["ip", "route"],
                capture_output=True, text=True, timeout=5)
            for linea in res.stdout.splitlines():
                if "default" in linea and interfaz in linea:
                    partes = linea.split()
                    if "via" in partes:
                        return partes[partes.index("via") + 1]
        except Exception as e:
            log(f"[SCANNER] Error gateway: {e}")
        return None
