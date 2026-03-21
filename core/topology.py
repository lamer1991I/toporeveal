import threading
import subprocess
import ipaddress
from datetime import datetime
from core.nodes import (Nodo, CONFIRMADO, SOSPECHOSO, FANTASMA,
    evaluar_puertos, severidad_maxima, calcular_risk_score,
    detectar_perfil_especial, accion_sugerida, Hallazgo, ALTO, CRITICO, INFO)

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

IPS_INVALIDAS = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}

def _es_ip_valida(ip):
    if not ip: return False
    if ip in IPS_INVALIDAS: return False
    if ip.endswith(".255"): return False
    if ip.startswith("224.") or ip.startswith("239."): return False
    return True

def _obtener_ip_local():
    try:
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=3)
        ips = r.stdout.strip().split()
        return ips[0] if ips else None
    except:
        return None

# ─────────────────────────────────────────────────────────────────
# DETECCIÓN DE SUBREDES SECUNDARIAS
# ─────────────────────────────────────────────────────────────────

# Rangos RFC1918 — IPs privadas que NO son la subred primaria
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # APIPA / link-local
]

def _es_rfc1918(ip):
    """True si la IP es privada (RFC1918 o link-local)."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in red for red in _RFC1918)
    except ValueError:
        return False

def _prefijo_subred(ip):
    """Retorna los primeros 3 octetos: '192.168.43' para '192.168.43.15'."""
    partes = ip.split(".")
    if len(partes) >= 3:
        return ".".join(partes[:3])
    return None

def _clasificar_subred(prefijo):
    """Clasifica una subred secundaria por su prefijo.
    Retorna (tipo, color_hex, descripcion)."""
    if prefijo.startswith("192.168.43"):
        return ("HOTSPOT", "#f0883e", "Hotspot móvil")
    if prefijo.startswith("10."):
        return ("VPN/LAN", "#a371f7", "Red privada clase A")
    if prefijo.startswith("172."):
        return ("VLAN", "#58d6ff", "Red privada clase B")
    if prefijo.startswith("169.254"):
        return ("LINK-LOCAL", "#8b949e", "Sin DHCP (APIPA)")
    return ("SUBNET", "#3fb950", "Subred secundaria")


class SubredSecundaria:
    """Representa una subred detectada que NO es la red principal."""
    def __init__(self, prefijo):
        self.prefijo      = prefijo        # "192.168.43"
        self.tipo, self.color, self.desc = _clasificar_subred(prefijo)
        self.nodos        = {}             # {ip: Nodo}
        self.primer_visto = datetime.now().strftime("%H:%M:%S")
        self.n_paquetes   = 0

    def __repr__(self):
        return f"SubredSecundaria({self.prefijo}.x, {self.tipo}, {len(self.nodos)} nodos)"


class Topologia:
    def __init__(self):
        self._lock    = threading.Lock()
        self.nodos    = {}
        self.enlaces  = []
        self.externos = {}
        self.router   = None
        self.gateway  = None
        self.ip_local = _obtener_ip_local()
        self.subred   = None
        self.alertas  = []   # Lista global de Hallazgo de toda la red
        # Multi-subnet: islas secundarias detectadas
        self.subredes_secundarias = {}   # {prefijo: SubredSecundaria}

    # ─────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────

    def _es_local(self, ip):
        if not self.subred: return True
        return ip.startswith(self.subred)

    # ─────────────────────────────────────────
    # NODOS
    # ─────────────────────────────────────────

    def agregar_o_actualizar(self, ip, **datos):
        if not _es_ip_valida(ip): return None
        if not self._es_local(ip): return None

        with self._lock:
            if ip not in self.nodos:
                nodo_nuevo = Nodo(ip)
                # IP local nunca pasa a lobby ni cambia de estado
                if ip == self.ip_local:
                    nodo_nuevo.protegido = True
                self.nodos[ip] = nodo_nuevo

            nodo = self.nodos[ip]
            nodo.actualizar_actividad(datos.get("bytes", 0))

            if "mac"        in datos and datos["mac"]:  nodo.mac        = datos["mac"]
            if "fabricante" in datos: nodo.fabricante = datos["fabricante"]
            if "tipo"       in datos: nodo.tipo       = datos["tipo"]
            if "sistema_op" in datos: nodo.sistema_op = datos["sistema_op"]
            if "puertos"    in datos and datos["puertos"]:
                for p in datos["puertos"]:
                    if p not in nodo.puertos_abiertos:
                        nodo.puertos_abiertos.append(p)
            # Fase 3 -> Generar Hallazgos Informativos para mostrar en el panel de alertas
            if "os_version" in datos and datos["os_version"] and datos["os_version"] != getattr(nodo, "os_version", None):
                nodo.os_version = datos["os_version"]
                self._crear_hallazgo_extra(ip, "OS: " + datos["os_version"])

            if "web_info" in datos and datos["web_info"] and datos["web_info"] != getattr(nodo, "web_info", None):
                nodo.web_info = datos["web_info"]
                self._crear_hallazgo_extra(ip, "Web: " + datos["web_info"])

            if "smb_info" in datos and datos["smb_info"] and datos["smb_info"] != getattr(nodo, "smb_info", None):
                nodo.smb_info = datos["smb_info"]
                self._crear_hallazgo_extra(ip, "SMB OS: " + datos["smb_info"])
            
            nodo.actualizar_estado()
            return nodo

    def _crear_hallazgo_extra(self, ip, texto):
        """Crea una alerta visual tipo Info para datos extraídos en Fase 2/Fase 3."""
        nodo = self.nodos.get(ip)
        if not nodo: return
        # Evitar duplicados exactos
        if any(h.servicio == texto for h in nodo.hallazgos):
            return
        h = Hallazgo(ip, 0, texto[:30], INFO, texto)
        nodo.hallazgos.append(h)
        self.alertas.append(h)

    def obtener_nodo(self, ip):
        with self._lock:
            return self.nodos.get(ip, None)

    def todos_los_nodos(self):
        """Todos los nodos incluyendo lobby."""
        with self._lock:
            return list(self.nodos.values())

    def todos_los_nodos_visibles(self):
        """Solo nodos activos — excluye los que están en lobby."""
        with self._lock:
            return [n for n in self.nodos.values() if not n.en_lobby]

    def limpiar_todo(self):
        with self._lock:
            self.nodos.clear()
            self.enlaces.clear()
            self.externos.clear()
            self.alertas.clear()
            self.subredes_secundarias.clear()
            self.router  = None
            self.gateway = None

    # ─────────────────────────────────────────
    # ENLACES
    # ─────────────────────────────────────────

    def agregar_enlace(self, ip_origen, ip_destino, protocolo=""):
        if not _es_ip_valida(ip_origen) or not _es_ip_valida(ip_destino):
            return

        origen_local  = self._es_local(ip_origen)
        destino_local = self._es_local(ip_destino)

        if origen_local and destino_local:
            if ip_origen == ip_destino: return
            with self._lock:
                for i, (o, d, p) in enumerate(self.enlaces):
                    if o == ip_origen and d == ip_destino:
                        self.enlaces[i] = (o, d, protocolo)
                        return
                self.enlaces.append((ip_origen, ip_destino, protocolo))

        elif origen_local and not destino_local:
            # Destino fuera de la subred principal — ¿es RFC1918?
            if _es_rfc1918(ip_destino):
                self._registrar_subred_secundaria(ip_destino, protocolo)
            else:
                self._agregar_externo(ip_origen, ip_destino, protocolo)

        elif destino_local and not origen_local:
            if _es_rfc1918(ip_origen):
                self._registrar_subred_secundaria(ip_origen, protocolo)
            else:
                self._agregar_externo(ip_destino, ip_origen, protocolo)

    def _agregar_externo(self, ip_local, ip_ext, protocolo):
        with self._lock:
            if ip_local not in self.externos:
                self.externos[ip_local] = []
            entrada = (ip_ext, protocolo)
            if entrada not in self.externos[ip_local]:
                self.externos[ip_local].append(entrada)

    def registrar_externo(self, ip_local, ip_ext, protocolo, geo=None):
        """
        Registra una conexión externa con info GeoIP opcional.
        Llamado desde app.py cuando se detecta tráfico saliente.
        """
        self._agregar_externo(ip_local, ip_ext, protocolo)
        # Guardar info geo si viene con datos
        if geo and geo.get("ok"):
            with self._lock:
                if not hasattr(self, '_geo_cache'):
                    self._geo_cache = {}
                self._geo_cache[ip_ext] = geo

    def obtener_geo(self, ip_ext):
        """Retorna info GeoIP de una IP externa si la tenemos."""
        with self._lock:
            if hasattr(self, '_geo_cache'):
                return self._geo_cache.get(ip_ext)
        return None

    def _registrar_subred_secundaria(self, ip_externa_privada, protocolo):
        """Registra o actualiza una subred secundaria detectada."""
        prefijo = _prefijo_subred(ip_externa_privada)
        if not prefijo:
            return
        # No confundir con la propia subred primaria
        if self.subred and prefijo == self.subred:
            return
        with self._lock:
            if prefijo not in self.subredes_secundarias:
                sub = SubredSecundaria(prefijo)
                self.subredes_secundarias[prefijo] = sub
                log(f"[SUBNET] Nueva subred secundaria detectada: "
                    f"{prefijo}.x ({sub.tipo}) via {protocolo}")
            subred = self.subredes_secundarias[prefijo]
            subred.n_paquetes += 1
            # Crear/actualizar nodo en la isla
            if ip_externa_privada not in subred.nodos:
                nodo = Nodo(ip_externa_privada)
                nodo.subred_id = prefijo
                subred.nodos[ip_externa_privada] = nodo
            subred.nodos[ip_externa_privada].paquetes += 1

    def obtener_subredes(self):
        """Retorna lista de SubredSecundaria detectadas."""
        with self._lock:
            return list(self.subredes_secundarias.values())

    def obtener_enlaces(self):
        with self._lock:
            return list(self.enlaces)

    def obtener_externos(self, ip_local):
        with self._lock:
            return list(self.externos.get(ip_local, []))

    # ─────────────────────────────────────────
    # JERARQUÍA
    # ─────────────────────────────────────────

    def deducir_jerarquia(self):
        with self._lock:
            if not self.nodos: return

            if self.gateway:
                partes = self.gateway.split(".")
                self.subred = ".".join(partes[:3])

            if self.gateway and self.gateway in self.nodos:
                self.nodos[self.gateway].tipo = "router"
                self.router = self.gateway

            for ip, nodo in self.nodos.items():
                if ip == self.router: continue
                if nodo.tipo in ("router", "switch"): continue
                if ip == self.ip_local: continue
                # Excluir IPs locales de este equipo (todas las interfaces)
                conexiones = sum(
                    1 for o, d, _ in self.enlaces if o == ip or d == ip
                )
                # Umbral más alto para evitar falsos positivos con modo promiscuo
                if conexiones >= 10:
                    nodo.tipo = "switch"

    def registrar_hallazgos(self, ip, puertos):
        """Evalúa puertos y registra hallazgos nuevos en el nodo y lista global."""
        if not puertos:
            return []
        nuevos = []
        with self._lock:
            nodo = self.nodos.get(ip)
            if not nodo:
                return []
            puertos_existentes = {h.puerto for h in nodo.hallazgos}
            candidatos = evaluar_puertos(ip, puertos)
            for h in candidatos:
                if h.puerto not in puertos_existentes:
                    if not h.detalle:
                        h.detalle = accion_sugerida(h.servicio)
                    nodo.hallazgos.append(h)
                    self.alertas.append(h)
                    nuevos.append(h)
            nodo.severidad_max = severidad_maxima(nodo.hallazgos)
            # Risk score actualizado
            nodo.risk_score = calcular_risk_score(list(nodo.puertos_abiertos))
            # Perfiles especiales (DC, OT, etc.)
            nodo.perfiles = detectar_perfil_especial(list(nodo.puertos_abiertos))
            for nombre, sev in nodo.perfiles:
                if not any(h.servicio == nombre for h in nodo.hallazgos):
                    h = Hallazgo(ip, 0, nombre, sev, accion_sugerida(nombre))
                    nodo.hallazgos.append(h)
                    self.alertas.append(h)
                    nuevos.append(h)
        return nuevos

    def limpiar_inactivos(self):
        with self._lock:
            for nodo in self.nodos.values():
                cambio = nodo.actualizar_estado()
                if cambio:
                    anterior, nuevo_estado, en_lobby, era_lobby = cambio
                    ip = nodo.ip
                    # Emojis de estado para el log
                    if not era_lobby and en_lobby:
                        mins = int(nodo.segundos_sin_actividad() // 60)
                        log(f"[ESTADO] {ip} | {anterior} -> LOBBY (inactivo {mins}min)")
                    elif era_lobby and not en_lobby:
                        log(f"[ESTADO] {ip} | LOBBY -> {nuevo_estado}")
                    else:
                        log(f"[ESTADO] {ip} | {anterior} -> {nuevo_estado}")
