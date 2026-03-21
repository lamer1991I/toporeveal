# ─────────────────────────────────────────────────────────
# fingerprint.py — Identificación de dispositivos en red
# ─────────────────────────────────────────────────────────

OUI_DB = {
    # Cisco
    "00:00:0C": ("Cisco",      "router"),
    "00:1A:A1": ("Cisco",      "router"),
    "F8:72:EA": ("Cisco",      "router"),
    "00:17:DF": ("Cisco",      "switch"),
    "00:1C:57": ("Cisco",      "switch"),
    # MikroTik
    "00:0C:42": ("MikroTik",   "router"),
    "D4:CA:6D": ("MikroTik",   "router"),
    "B8:69:F4": ("MikroTik",   "router"),
    # TP-Link
    "50:C7:BF": ("TP-Link",    "router"),
    "C0:25:E9": ("TP-Link",    "router"),
    "00:27:19": ("TP-Link",    "switch"),
    # Ubiquiti
    "00:15:6D": ("Ubiquiti",   "router"),
    "04:18:D6": ("Ubiquiti",   "router"),
    "78:8A:20": ("Ubiquiti",   "router"),
    # Apple
    "00:03:93": ("Apple",      "pc"),
    "00:0A:95": ("Apple",      "pc"),
    "00:1B:63": ("Apple",      "pc"),
    "AC:BC:32": ("Apple",      "smartphone"),
    "F0:D1:A9": ("Apple",      "smartphone"),
    "A8:BE:27": ("Apple",      "smartphone"),
    "3C:CD:5D": ("Apple",      "smartphone"),
    "78:4F:43": ("Apple",      "smartphone"),
    "34:C0:59": ("Apple",      "smartphone"),
    "BC:D0:74": ("Apple",      "smartphone"),
    # Samsung
    "00:12:47": ("Samsung",    "smartphone"),
    "8C:77:12": ("Samsung",    "smartphone"),
    "F4:7B:5E": ("Samsung",    "smart_tv"),
    "00:E0:64": ("Samsung",    "smart_tv"),
    "EC:9B:F3": ("Samsung",    "smartphone"),
    "A8:57:4E": ("Samsung",    "smartphone"),
    "BC:44:86": ("Samsung",    "smartphone"),
    "F8:04:2E": ("Samsung",    "smartphone"),
    "94:08:53": ("Samsung",    "pc"),        # ← tu PC/laptop
    # Xiaomi (muy comunes en Latinoamérica)
    "04:CF:8C": ("Xiaomi",     "smartphone"),
    "28:6C:07": ("Xiaomi",     "smartphone"),
    "34:80:B3": ("Xiaomi",     "smartphone"),
    "50:64:2B": ("Xiaomi",     "smartphone"),
    "64:B4:73": ("Xiaomi",     "smartphone"),
    "74:51:BA": ("Xiaomi",     "smartphone"),
    "88:63:DF": ("Xiaomi",     "smartphone"),
    "AC:37:43": ("Xiaomi",     "smartphone"),
    "F8:A4:5F": ("Xiaomi",     "smartphone"),
    "00:9E:C8": ("Xiaomi",     "smartphone"),
    "E4:46:DA": ("Xiaomi",     "smartphone"),
    # Huawei
    "00:9A:CD": ("Huawei",     "smartphone"),
    "00:E0:FC": ("Huawei",     "smartphone"),
    "04:C0:6F": ("Huawei",     "smartphone"),
    "18:CE:D2": ("Huawei",     "smartphone"),
    "2C:AB:00": ("Huawei",     "smartphone"),
    "40:4D:8E": ("Huawei",     "smartphone"),
    "58:1F:28": ("Huawei",     "smartphone"),
    "70:72:3C": ("Huawei",     "smartphone"),
    "88:E3:AB": ("Huawei",     "smartphone"),
    "B4:CD:27": ("Huawei",     "smartphone"),
    # Motorola
    "00:22:A4": ("Motorola",   "smartphone"),
    "B8:E8:56": ("Motorola",   "smartphone"),
    "DC:2B:61": ("Motorola",   "smartphone"),
    "E8:DE:27": ("Motorola",   "smartphone"),
    "E8:DF:70": ("Motorola",   "smartphone"),
    # OPPO / OnePlus
    "00:1A:4E": ("OPPO",       "smartphone"),
    "08:F4:AB": ("OPPO",       "smartphone"),
    "14:2D:27": ("OPPO",       "smartphone"),
    "1C:77:F6": ("OPPO",       "smartphone"),
    # LG
    "30:19:66": ("LG",         "smartphone"),
    "AC:36:13": ("LG",         "smartphone"),
    "C8:02:10": ("LG",         "smartphone"),
    # Dell
    "00:06:5B": ("Dell",       "pc"),
    "00:14:22": ("Dell",       "pc"),
    "F8:DB:88": ("Dell",       "pc"),
    # HP
    "00:1C:C4": ("HP",         "pc"),
    "3C:D9:2B": ("HP",         "pc"),
    "00:25:B3": ("HP",         "impresora"),
    "A0:B3:CC": ("HP",         "impresora"),
    # Lenovo
    "00:1A:6B": ("Lenovo",     "pc"),
    "54:EE:75": ("Lenovo",     "pc"),
    "10:63:C8": ("Lenovo",     "pc"),   # ← .43 en tu red
    # Intel (laptops)
    "00:1B:21": ("Intel",      "pc"),
    "D0:3C:1F": ("Intel",      "pc"),   # ← .41 en tu red
    "EC:53:82": ("Intel",      "pc"),   # ← .109 en tu red
    "9C:2F:9D": ("Intel",      "pc"),   # ← .178 en tu red
    "60:45:2E": ("Intel",      "pc"),   # ← .174 en tu red
    "80:30:49": ("Intel",      "pc"),   # ← .99 en tu red
    "30:D1:6B": ("Intel",      "pc"),   # ← .31 en tu red
    "9C:B6:D0": ("Intel",      "pc"),
    "A4:C3:F0": ("Intel",      "pc"),
    # Realtek (laptops/PCs)
    "80:38:FB": ("Realtek",    "pc"),   # ← .94 en tu red
    # MediaTek / WiFi adapters
    "28:39:26": ("MediaTek",   "pc"),
    # Tenda / routers genéricos
    "60:D2:48": ("Tenda",       "router"),
    "60:d2:48": ("Tenda",       "router"),
    # Attachmate / interfaces virtuales conocidas
    "00:00:CA": ("Attachmate",  "wired_generic"),
    # Hikvision
    "44:19:B6": ("Hikvision",  "camara"),
    "C0:56:E3": ("Hikvision",  "camara"),
    "68:6D:BC": ("Hikvision",  "camara"),   # ← tu cámara en casa
    # Dahua
    "90:02:A9": ("Dahua",      "camara"),
    "E0:50:8B": ("Dahua",      "camara"),
    # Raspberry Pi / IoT
    "B8:27:EB": ("Raspberry",  "iot"),
    "DC:A6:32": ("Raspberry",  "iot"),
    "E4:5F:01": ("Raspberry",  "iot"),
    # Espressif IoT
    "24:6F:28": ("Espressif",  "iot"),
    "30:AE:A4": ("Espressif",  "iot"),
}

# TTL → OS  (los TTL se degradan en tránsito, usar rangos amplios)
# TTL original 64  → Linux/Android/Mac → llega ~60-64
# TTL original 128 → Windows           → llega ~120-128
# TTL original 255 → equipos de red    → llega ~240-255
# La clave: NO marcar 253-255 como RouterOS si hay otras señales
TTL_OS = {
    range(1,   33):  "Android",          # TTL muy bajo = muchos saltos o Android
    range(33,  65):  "Linux/Mac",
    range(65, 100):  "Linux/Mac",        # rango ampliado
    range(100, 130): "Windows",
    range(130, 200): "Desconocido",      # zona gris — no asumir
    range(200, 256): "Equipo de red",    # routers/switches reales
}

PUERTO_TIPO = {
    22:   "servidor",
    23:   "router",
    80:   "servidor",
    443:  "servidor",
    445:  "pc",        # SMB Windows
    3389: "pc",        # RDP Windows
    8080: "servidor",
    554:  "camara",    # RTSP stream
    8000: "camara",    # Hikvision control
    8554: "camara",    # RTSP alternativo
    9010: "camara",    # Hikvision SDR
    5353: "iot",       # mDNS
    9100: "impresora",
    631:  "impresora",
}


def _mac_es_local(mac):
    """
    MACs localmente administradas (bit U/L = 1) son aleatorias —
    no se pueden identificar por OUI. Ejemplo: xx:xx:xx donde
    el segundo nibble del primer byte es 2,6,A o E.
    """
    if not mac or len(mac) < 2:
        return False
    try:
        primer_byte = int(mac.replace(":", "").replace("-", "")[:2], 16)
        return bool(primer_byte & 0x02)
    except:
        return False


def identificar_fabricante(mac):
    if not mac:
        return ("Desconocido", None)
    mac_upper = mac.upper()

    # MACs locales/aleatorias — no buscar OUI
    if _mac_es_local(mac_upper):
        return ("Privada/Aleatoria", None)

    oui = mac_upper[:8]
    if oui in OUI_DB:
        return OUI_DB[oui]

    return ("Desconocido", None)


def identificar_os_por_ttl(ttl):
    if not ttl:
        return "Desconocido"
    for rango, sistema in TTL_OS.items():
        if ttl in rango:
            return sistema
    return "Desconocido"


def identificar_tipo_por_puerto(puertos):
    if not puertos:
        return None
    for puerto in puertos:
        if puerto in PUERTO_TIPO:
            return PUERTO_TIPO[puerto]
    return None


def fingerprint(nodo):
    """
    Prioridad:
    1. No tocar router/switch/arp-scanner
    2. Fabricante por MAC (solo si MAC no es aleatoria)
    3. OS por TTL — con rangos más precisos
    4. Tipo por puertos (máxima prioridad de tipo)
    5. Si MAC aleatoria → intentar clasificar por TTL
       - TTL 64 (Linux/Mac) en red doméstica → preferir smartphone
         porque la mayoría de PCs en WIFI doméstico son móviles
       - TTL 128 (Windows) → PC
    """
    if nodo.tipo in ("router", "switch", "arp-scanner"):
        return

    fabricante, tipo_por_mac = identificar_fabricante(nodo.mac)
    nodo.fabricante = fabricante

    # Tipo por MAC (solo si es real, no aleatoria)
    es_mac_local = _mac_es_local(nodo.mac or "")
    if tipo_por_mac and not es_mac_local:
        nodo.tipo = tipo_por_mac

    # OS por TTL
    ttl = getattr(nodo, 'ttl', None)
    os_detectado = identificar_os_por_ttl(ttl)
    if nodo.sistema_op in ("Desconocido", "RouterOS / Network Device", "Equipo de red"):
        nodo.sistema_op = os_detectado

    # Si MAC aleatoria — intentar clasificar por TTL y heurísticas
    if es_mac_local and nodo.tipo in ("desconocido", "pc"):
        if "Android" in nodo.sistema_op or "android" in nodo.sistema_op:
            nodo.tipo = "smartphone"
        elif "Windows" in nodo.sistema_op:
            nodo.tipo = "pc"
        elif nodo.sistema_op in ("Linux/Mac",) and ttl:
            if not nodo.puertos_abiertos:
                nodo.tipo = "smartphone"
            else:
                nodo.tipo = "pc"
        elif not nodo.puertos_abiertos and nodo.paquetes > 0:
            # MAC aleatoria + sin puertos + con tráfico → casi seguro móvil
            nodo.tipo = "smartphone"

    # Corrección de coherencia tipo ↔ OS
    if nodo.sistema_op == "Android" and nodo.tipo == "pc":
        nodo.tipo = "smartphone"
    if nodo.tipo == "smartphone" and nodo.sistema_op in ("Windows",):
        nodo.tipo = "pc"

    # Tipo por puertos (prioridad máxima — si tiene puertos sabemos qué es)
    tipo_por_puerto = identificar_tipo_por_puerto(nodo.puertos_abiertos)
    if tipo_por_puerto:
        nodo.tipo = tipo_por_puerto

    if not nodo.tipo:
        nodo.tipo = "desconocido"

# ─────────────────────────────────────────────────────────
# SISTEMA DE SCORING AVANZADO
# ─────────────────────────────────────────────────────────

# Dominios DNS → sistema operativo / fabricante (comportamiento)
DNS_OS_MAP = {
    # Apple / iOS / macOS
    "apple.com":              ("Apple",    "smartphone", 40),
    "icloud.com":             ("Apple",    "smartphone", 45),
    "itunes.apple.com":       ("Apple",    "smartphone", 60),
    "gateway.icloud.com":     ("Apple",    "smartphone", 55),
    "captive.apple.com":      ("Apple",    "smartphone", 50),
    "time.apple.com":         ("Apple",    "smartphone", 30),
    "push.apple.com":         ("Apple",    "smartphone", 50),
    # Android / Google
    "play.googleapis.com":    ("Google",   "smartphone", 60),
    "android.clients.google": ("Google",   "smartphone", 65),
    "connectivitycheck.gstatic.com": ("Google", "smartphone", 55),
    "clients1.google.com":    ("Google",   "smartphone", 40),
    "googleapis.com":         ("Google",   "smartphone", 30),
    # Microsoft / Windows
    "telemetry.microsoft.com":("Microsoft","pc",         60),
    "windowsupdate.com":      ("Microsoft","pc",         65),
    "microsoft.com":          ("Microsoft","pc",         35),
    "live.com":               ("Microsoft","pc",         30),
    "msftconnecttest.com":    ("Microsoft","pc",         55),
    # Xiaomi
    "miui.com":               ("Xiaomi",   "smartphone", 65),
    "xiaomi.com":             ("Xiaomi",   "smartphone", 60),
    "mi.com":                 ("Xiaomi",   "smartphone", 55),
    # Samsung
    "samsungdm.com":          ("Samsung",  "smartphone", 60),
    "samsung.com":            ("Samsung",  "smartphone", 40),
    # Huawei
    "hicloud.com":            ("Huawei",   "smartphone", 65),
    "huaweicloud.com":        ("Huawei",   "smartphone", 55),
    # TikTok / ByteDance
    "bytedance.com":          ("ByteDance","smartphone", 40),
    "tiktok.com":             ("ByteDance","smartphone", 45),
    "musical.ly":             ("ByteDance","smartphone", 50),
    # WeChat / Alibaba
    "wechat.com":             ("Alibaba",  "smartphone", 50),
    "alicdn.com":             ("Alibaba",  "smartphone", 40),
    # Netflix
    "netflix.com":            ("Netflix",  "smart_tv",   40),
    "nflxso.net":             ("Netflix",  "smart_tv",   45),
    # Hikvision / cámaras
    "hik-connect.com":        ("Hikvision","camara",     70),
    "ezvizlife.com":          ("Hikvision","camara",     65),
    "dahuasecurity.com":      ("Dahua",    "camara",     70),
}

# DHCP Option 55 fingerprints — Parameter Request List
# Orden y valores identifican el OS con alta precisión
DHCP_FINGERPRINTS = {
    # iOS (iPhone/iPad) — muy estables entre versiones
    (1,121,3,6,15,119,252,95,44,46): ("Apple",    "smartphone", "iOS",     80),
    (1,121,3,6,15,119,252,95,44):    ("Apple",    "smartphone", "iOS",     75),
    (1,3,6,15,119,252):              ("Apple",    "smartphone", "iOS",     60),
    # Android (AOSP) — varía más entre fabricantes
    (1,33,3,6,15,28,51,58,59):       ("Google",   "smartphone", "Android", 75),
    (1,3,6,15,26,28,51,58,59):       ("Google",   "smartphone", "Android", 70),
    (1,3,6,15,28,51,58,59,43):       ("Google",   "smartphone", "Android", 68),
    # Windows 10/11
    (1,3,6,15,31,33,43,44,46,47,119,121,249,252): ("Microsoft","pc","Windows",85),
    (1,3,6,15,31,33,43,44,46,47,119,121,249):     ("Microsoft","pc","Windows",80),
    # Linux (Ubuntu/Debian)
    (1,3,6,12,15,17,28,40,41,42):   ("Linux",    "pc",         "Linux",   70),
    (1,3,6,15,28,51,58,59):         ("Linux",    "pc",         "Linux",   60),
    # macOS
    (1,121,3,6,15,119,252,95,44,46,47): ("Apple","pc",         "macOS",   80),
    # Hikvision cameras
    (1,3,28,6):                      ("Hikvision","camara",    "embedded",75),
    (1,28,3,15,6):                   ("Hikvision","camara",    "embedded",65),
}

# Reglas de riesgo compuesto — combinaciones que elevan el score
# Formato: (set_de_servicios, score_adicional, razon)
REGLAS_RIESGO_COMPUESTO = [
    # Cámara IP con credenciales por defecto posibles
    ({"Hikvision", "RTSP"},     25, "Cámara expuesta con stream abierto"),
    ({"Hikvision-SDR", "RTSP"}, 20, "Cámara SDR con acceso remoto"),
    ({"Dahua", "RTSP"},         25, "Cámara Dahua expuesta"),
    # Servicios administrativos abiertos
    ({"HTTP", "Telnet"},        30, "Administración en texto plano"),
    ({"HTTP", "SSH"},           10, "Web + SSH expuestos"),
    ({"RDP", "SMB"},            35, "Windows con RDP y SMB expuestos"),
    # Servicios de BD expuestos
    ({"MySQL"},                 25, "Base de datos accesible"),
    ({"MSSQL"},                 30, "SQL Server accesible"),
    ({"PostgreSQL"},            25, "PostgreSQL accesible"),
    ({"Redis"},                 30, "Redis sin autenticación probable"),
    # IoT peligroso
    ({"MQTT"},                  15, "Broker MQTT sin cifrado"),
    ({"MQTT-TLS"},               5, "Broker MQTT (cifrado)"),
    ({"Telnet"},                40, "Telnet activo — texto plano"),
    ({"FTP"},                   20, "FTP activo — posible texto plano"),
    ({"VNC"},                   35, "VNC expuesto"),
    ({"SIP"},                   15, "VoIP expuesto"),
]


def _calcular_riesgo_compuesto(nodo):
    """
    Calcula el risk_score basado en combinaciones de servicios,
    no en suma lineal de puertos.
    """
    servicios = set(h.servicio for h in getattr(nodo, 'hallazgos', []))
    score_base = getattr(nodo, 'risk_score', 0)
    score_extra = 0
    razones = []

    for servicios_regla, bonus, razon in REGLAS_RIESGO_COMPUESTO:
        if servicios_regla.issubset(servicios):
            score_extra += bonus
            razones.append(razon)

    # Penalizar puertos de administración sin cifrado
    puertos = set(getattr(nodo, 'puertos_abiertos', []))
    if 23 in puertos:    score_extra += 40   # Telnet
    if 21 in puertos:    score_extra += 20   # FTP
    if 5900 in puertos:  score_extra += 35   # VNC

    nuevo_score = min(100, score_base + score_extra)
    return nuevo_score, razones


def registrar_dns_comportamiento(nodo, dominio):
    """
    Acumula evidencia DNS para el scoring.
    Llamado desde capture.py cuando se ve una consulta DNS.
    """
    if not dominio or not nodo:
        return

    dominio_l = dominio.lower().rstrip(".")
    for patron, (fab, tipo, puntos) in DNS_OS_MAP.items():
        if patron in dominio_l:
            # Inicializar scoring acumulado
            if not hasattr(nodo, '_score_fab'):
                nodo._score_fab  = {}
                nodo._score_tipo = {}

            nodo._score_fab[fab]   = nodo._score_fab.get(fab, 0)   + puntos
            nodo._score_tipo[tipo] = nodo._score_tipo.get(tipo, 0) + puntos

            # Actualizar fabricante y tipo si hay suficiente evidencia
            fab_top  = max(nodo._score_fab,  key=nodo._score_fab.get)
            tipo_top = max(nodo._score_tipo, key=nodo._score_tipo.get)

            score_fab  = nodo._score_fab[fab_top]
            score_tipo = nodo._score_tipo[tipo_top]

            # Solo actualizar si la evidencia es significativa
            if score_fab >= 50 and nodo.fabricante in ("Desconocido", "Privada/Aleatoria"):
                nodo.fabricante = fab_top
            if score_tipo >= 50 and nodo.tipo in ("desconocido", "pc", "smartphone"):
                nodo.tipo = tipo_top

            # OS desde comportamiento DNS
            if score_fab >= 60:
                if fab_top == "Apple" and "iOS" not in nodo.sistema_op:
                    nodo.sistema_op = "iOS/macOS"
                elif fab_top == "Google" and "Android" not in nodo.sistema_op:
                    nodo.sistema_op = "Android"
                elif fab_top == "Microsoft" and "Windows" not in nodo.sistema_op:
                    nodo.sistema_op = "Windows"
                elif fab_top == "Xiaomi":
                    nodo.sistema_op = "Android/MIUI"
            break


def registrar_dhcp_fingerprint(nodo, option_list):
    """
    Procesa la Option 55 del DHCP Request para identificar el OS.
    option_list: tupla de ints con los códigos de opción solicitados.
    """
    if not option_list or not nodo:
        return

    clave = tuple(option_list[:12])  # primeros 12 para tolerancia

    # Buscar match exacto primero
    if clave in DHCP_FINGERPRINTS:
        fab, tipo, os_str, confianza = DHCP_FINGERPRINTS[clave]
        _aplicar_dhcp_resultado(nodo, fab, tipo, os_str, confianza)
        return

    # Buscar match parcial (prefijo)
    mejor_match = None
    mejor_len   = 0
    for patron, resultado in DHCP_FINGERPRINTS.items():
        patron_t = patron[:min(len(patron), len(clave))]
        clave_t  = clave[:len(patron_t)]
        if patron_t == clave_t and len(patron_t) > mejor_len:
            mejor_len   = len(patron_t)
            mejor_match = resultado

    if mejor_match and mejor_len >= 4:
        fab, tipo, os_str, confianza = mejor_match
        # Reducir confianza por match parcial
        confianza = max(40, confianza - 20)
        _aplicar_dhcp_resultado(nodo, fab, tipo, os_str, confianza)


def _aplicar_dhcp_resultado(nodo, fab, tipo, os_str, confianza):
    """Aplica el resultado de DHCP fingerprint al nodo."""
    # DHCP es muy confiable — aplicar aunque haya otro dato
    if confianza >= 60:
        if nodo.fabricante in ("Desconocido", "Privada/Aleatoria", ""):
            nodo.fabricante = fab
        if nodo.tipo in ("desconocido", ""):
            nodo.tipo = tipo
        if nodo.sistema_op in ("Desconocido", ""):
            nodo.sistema_op = os_str
    elif confianza >= 40:
        # Confianza media — solo si no hay otro dato
        if nodo.sistema_op in ("Desconocido", ""):
            nodo.sistema_op = os_str


def registrar_user_agent(nodo, user_agent):
    """
    Parsea User-Agent HTTP para obtener OS y fabricante exactos.
    Es la fuente más precisa disponible sin escaneo activo.
    """
    if not user_agent or not nodo:
        return

    ua = user_agent.lower()

    # iPhone / iOS
    if "iphone" in ua or "ipad" in ua:
        nodo.tipo = "smartphone"
        nodo.fabricante = "Apple"
        import re
        m = re.search(r'os (\d+[_\d]*)', ua)
        if m:
            version = m.group(1).replace("_", ".")
            nodo.sistema_op = f"iOS {version}"
        else:
            nodo.sistema_op = "iOS"
        return

    # Android — con modelo si está disponible
    if "android" in ua:
        nodo.tipo = "smartphone"
        import re
        # Extraer versión Android
        m_ver = re.search(r'android (\d+[\.\d]*)', ua)
        version = m_ver.group(1) if m_ver else ""
        # Extraer modelo
        m_mod = re.search(r';\s*([^;)]+build)', ua)
        modelo = m_mod.group(1).strip() if m_mod else ""
        if modelo:
            nodo.sistema_op = f"Android {version} ({modelo[:25]})"
        else:
            nodo.sistema_op = f"Android {version}".strip()
        # Fabricante por modelo
        for marca in ("samsung", "xiaomi", "huawei", "motorola",
                      "oppo", "vivo", "realme", "nokia"):
            if marca in ua:
                nodo.fabricante = marca.capitalize()
                break
        return

    # Windows — versión exacta
    if "windows nt" in ua:
        import re
        m = re.search(r'windows nt (\d+\.\d+)', ua)
        if m:
            nt_map = {"10.0": "Windows 10/11", "6.3": "Windows 8.1",
                      "6.2": "Windows 8",      "6.1": "Windows 7"}
            ver = nt_map.get(m.group(1), f"Windows NT {m.group(1)}")
            nodo.sistema_op = ver
        nodo.tipo = "pc"
        return

    # macOS
    if "macintosh" in ua or "mac os x" in ua:
        nodo.tipo = "pc"
        nodo.fabricante = "Apple"
        import re
        m = re.search(r'mac os x (\d+[_\d]*)', ua)
        if m:
            ver = m.group(1).replace("_", ".")
            nodo.sistema_op = f"macOS {ver}"
        else:
            nodo.sistema_op = "macOS"
        return

    # Linux desktop
    if "linux" in ua and "android" not in ua:
        nodo.tipo = "pc"
        nodo.sistema_op = "Linux"


def fingerprint_completo(nodo):
    """
    Ejecuta fingerprint() original + calcula riesgo compuesto.
    Llamar esto en lugar de fingerprint() para scoring completo.
    """
    fingerprint(nodo)
    nuevo_score, razones = _calcular_riesgo_compuesto(nodo)
    if nuevo_score > getattr(nodo, 'risk_score', 0):
        nodo.risk_score = nuevo_score
        # Actualizar severidad máxima según nuevo score
        from core.nodes import severidad_maxima
        if razones and not getattr(nodo, 'hallazgos', []):
            pass  # sin hallazgos no actualizar
        # Recalcular severidad
        if nodo.risk_score >= 70:
            nodo.severidad_max = "alto"
        elif nodo.risk_score >= 40:
            if nodo.severidad_max not in ("alto", "critico"):
                nodo.severidad_max = "medio"
