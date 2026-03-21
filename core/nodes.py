import time
from datetime import datetime

CONFIRMADO = "confirmado"
SOSPECHOSO = "sospechoso"
FANTASMA   = "fantasma"

# Tiempos de inactividad: red doméstica — respuesta rápida
T_CONFIRMADO = 30       # segundos activo mínimo para confirmar
T_SOSPECHOSO = 60       # 60s sin actividad → sospechoso
T_FANTASMA   = 2  * 60  # 2 minutos → fantasma
T_LOBBY      = 4  * 60  # 4 minutos → lobby (desaparece del canvas)


class Nodo:
    def __init__(self, ip):
        self.ip         = ip
        self.mac        = None
        self.fabricante = "Desconocido"
        self.tipo       = "desconocido"
        self.sistema_op = "Desconocido"
        self.os_version = None
        self.web_info   = None
        self.smb_info   = None
        self.fase       = 0
        self.ttl        = None

        self.estado       = SOSPECHOSO
        self.visto_en     = time.time()
        self.ultimo_visto = time.time()
        self.veces_visto  = 0

        self.bytes_enviados  = 0
        self.bytes_recibidos = 0
        self.paquetes        = 0
        self.puertos_abiertos = []

        self.en_lobby   = False
        self.protegido  = False  # True para la IP local — nunca va a lobby
        self.x = 0
        self.y = 0
        self.hallazgos  = []     # Lista de Hallazgo para este nodo
        self.severidad_max = None  # Cached: severidad máxima actual
        self.risk_score    = 0     # 0-100
        self.perfiles      = []    # Roles detectados: [(nombre, sev)]
        self.delta         = []    # Diferencias vs sesión previa: ["NUEVO", "PUERTOS+"]
        self.subred_id     = None  # None=red principal, o "192.168.43" para islas secundarias

    def actualizar_actividad(self, bytes_paquete=0):
        self.ultimo_visto     = time.time()
        self.veces_visto     += 1
        self.paquetes        += 1
        self.bytes_recibidos += bytes_paquete
        self.en_lobby         = False  # Si vuelve a verse, sale del lobby

    def segundos_sin_actividad(self):
        return time.time() - self.ultimo_visto

    def actualizar_estado(self):
        """Actualiza estado y retorna (anterior, nuevo) si hubo cambio, sino None."""
        anterior = self.estado
        en_lobby_anterior = self.en_lobby

        # Nodo protegido (IP local) — siempre confirmado
        if self.protegido:
            self.estado   = "confirmado"
            self.en_lobby = False
            return None

        segundos = self.segundos_sin_actividad()

        if segundos >= T_LOBBY:
            self.estado   = FANTASMA
            self.en_lobby = True
        elif segundos >= T_FANTASMA:
            self.estado   = FANTASMA
            self.en_lobby = False
        elif segundos >= T_SOSPECHOSO:
            self.estado   = SOSPECHOSO
            self.en_lobby = False
        else:
            # Activo recientemente — confirmar con 2+ apariciones
            if self.veces_visto >= 2:
                self.estado = CONFIRMADO
            else:
                self.estado = SOSPECHOSO
            self.en_lobby = False

        # Detectar cambios relevantes para el log
        cambio_estado = (self.estado != anterior)
        entro_lobby   = (self.en_lobby and not en_lobby_anterior)
        salio_lobby   = (not self.en_lobby and en_lobby_anterior)
        if cambio_estado or entro_lobby or salio_lobby:
            return (anterior, self.estado, self.en_lobby, en_lobby_anterior)
        return None

    def __repr__(self):
        return f"Nodo({self.ip}, {self.tipo}, {self.estado})"


# ─────────────────────────────────────────────────────────────────
# SISTEMA DE HALLAZGOS
# ─────────────────────────────────────────────────────────────────

INFO     = "info"
MEDIO    = "medio"
ALTO     = "alto"
CRITICO  = "critico"

# Puertos → (nombre, severidad)
PUERTO_SEVERIDAD = {
    21:   ("FTP",          ALTO),
    22:   ("SSH",          INFO),
    23:   ("Telnet",       CRITICO),
    25:   ("SMTP",         MEDIO),
    80:   ("HTTP",         INFO),
    443:  ("HTTPS",        INFO),
    445:  ("SMB",          ALTO),
    554:  ("RTSP",         MEDIO),
    1433: ("MSSQL",        ALTO),
    1883: ("MQTT",         MEDIO),
    3306: ("MySQL",        ALTO),
    3389: ("RDP",          ALTO),
    5432: ("PostgreSQL",   ALTO),
    5900: ("VNC",          CRITICO),
    8000: ("Hikvision",    MEDIO),
    8080: ("HTTP-Alt",     INFO),
    8443: ("HTTPS-Alt",    INFO),
    8554: ("RTSP-Alt",     MEDIO),
    9010: ("Hikvision-SDR",MEDIO),
    9100: ("Impresora",    MEDIO),
}

# Combinaciones peligrosas → CRITICO automático
COMBOS_CRITICOS = [
    {23, 445},   # Telnet + SMB
    {23, 3389},  # Telnet + RDP
    {445, 3389}, # SMB + RDP
    {5900, 445}, # VNC + SMB
]


class Hallazgo:
    def __init__(self, ip, puerto, servicio, severidad, detalle=""):
        self.ip        = ip
        self.puerto    = puerto
        self.servicio  = servicio
        self.severidad = severidad
        self.detalle   = detalle
        self.timestamp = datetime.now().strftime("%H:%M:%S")
        self.visto     = False   # True cuando el usuario lo ve

    def __repr__(self):
        return f"[{self.severidad.upper()}] {self.ip}:{self.puerto} {self.servicio}"


def evaluar_puertos(ip, puertos_abiertos):
    """Genera lista de Hallazgo a partir de puertos detectados."""
    import time as _time
    hallazgos = []
    puertos_set = set(puertos_abiertos)

    for puerto in puertos_abiertos:
        if puerto in PUERTO_SEVERIDAD:
            nombre, sev = PUERTO_SEVERIDAD[puerto]
            hallazgos.append(Hallazgo(ip, puerto, nombre, sev))

    # Verificar combos críticos
    for combo in COMBOS_CRITICOS:
        if combo.issubset(puertos_set):
            nombres = "+".join(PUERTO_SEVERIDAD[p][0] for p in combo if p in PUERTO_SEVERIDAD)
            hallazgos.append(Hallazgo(ip, 0, nombres, CRITICO,
                                      f"Combinación peligrosa detectada"))

    return hallazgos


def severidad_maxima(hallazgos):
    """Retorna la severidad más alta de una lista de hallazgos."""
    orden = [INFO, MEDIO, ALTO, CRITICO]
    max_sev = None
    for h in hallazgos:
        if max_sev is None or orden.index(h.severidad) > orden.index(max_sev):
            max_sev = h.severidad
    return max_sev


# ─────────────────────────────────────────────────────────────────
# RISK SCORE (0-100) Y DETECCIÓN DE ROLES ESPECIALES
# ─────────────────────────────────────────────────────────────────

# Peso de cada puerto para el score
PESO_PUERTO = {
    23:   35,  # Telnet — crítico
    5900: 30,  # VNC
    445:  25,  # SMB
    3389: 22,  # RDP
    21:   20,  # FTP
    1433: 20,  # MSSQL
    3306: 18,  # MySQL
    5432: 18,  # PostgreSQL
    502:  18,  # Modbus/OT
    102:  18,  # S7/OT
    25:   12,  # SMTP
    8000: 10,  # Hikvision
    554:  10,  # RTSP
    9010: 10,  # Hikvision SDR
    8080:  8,  # HTTP-Alt
    80:    5,  # HTTP
    22:    5,  # SSH
    443:   3,  # HTTPS
}

# Perfiles especiales por combinación de puertos
PERFILES_ESPECIALES = [
    ({389, 445, 53},  "Posible DC",        CRITICO),
    ({445, 139},      "Posible File Server", ALTO),
    ({3306},          "BD expuesta",        ALTO),
    ({1433},          "MSSQL expuesto",     ALTO),
    ({502},           "Dispositivo OT",     ALTO),
    ({102},           "PLC S7",             ALTO),
    ({5900},          "VNC expuesto",       CRITICO),
    ({9100, 515},     "Impresora expuesta", MEDIO),
    ({554, 8000},     "Cámara IP",          MEDIO),
    ({1883},          "MQTT/IoT",           MEDIO),
]

# Acciones sugeridas por severidad y servicio
ACCIONES = {
    "Telnet":         "Deshabilitar Telnet, usar SSH",
    "VNC":            "Añadir contraseña fuerte o deshabilitar",
    "SMB":            "Deshabilitar SMBv1, verificar shares",
    "RDP":            "Habilitar NLA, restringir acceso por IP",
    "FTP":            "Migrar a SFTP o deshabilitar",
    "MySQL":          "Restringir a localhost o red interna",
    "MSSQL":          "Restringir acceso, auditar cuentas",
    "PostgreSQL":     "Restringir acceso, auditar cuentas",
    "Hikvision":      "Cambiar contraseña por defecto",
    "RTSP":           "Proteger stream con autenticación",
    "HTTP":           "Verificar si necesita exposición",
    "HTTP-Alt":       "Identificar servicio en puerto 8080",
    "Posible DC":     "Auditar acceso a controlador de dominio",
    "BD expuesta":    "Mover BD detrás de firewall",
    "Dispositivo OT": "Aislar de red IT, perfil OT-safe",
    "VNC expuesto":   "Deshabilitar VNC o usar túnel SSH",
    "default":        "Revisar configuración del servicio",
}


def calcular_risk_score(puertos_abiertos):
    """Calcula risk score 0-100 basado en puertos abiertos."""
    if not puertos_abiertos:
        return 0
    score = 0
    for p in puertos_abiertos:
        score += PESO_PUERTO.get(p, 3)
    # Bonus por cantidad de puertos
    if len(puertos_abiertos) > 5:
        score += 10
    if len(puertos_abiertos) > 10:
        score += 15
    # Combos críticos
    ps = set(puertos_abiertos)
    for combo in COMBOS_CRITICOS:
        if combo.issubset(ps):
            score += 25
    return min(score, 100)


def detectar_perfil_especial(puertos_abiertos):
    """Detecta roles especiales por combinación de puertos.
    Retorna lista de (nombre, severidad)."""
    ps = set(puertos_abiertos)
    encontrados = []
    for puertos_req, nombre, sev in PERFILES_ESPECIALES:
        if puertos_req.issubset(ps):
            encontrados.append((nombre, sev))
    return encontrados


def accion_sugerida(servicio):
    """Retorna acción sugerida para un servicio."""
    return ACCIONES.get(servicio, ACCIONES["default"])
