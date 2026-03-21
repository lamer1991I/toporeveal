"""
ja3_fingerprint.py — JA3/JA3S TLS fingerprinting para TopoReveal.

JA3 identifica aplicaciones por su huella TLS Client Hello:
  - Versión TLS
  - Cipher suites
  - Extensiones
  - Curvas elípticas
  - Formatos de punto

JA3S identifica servidores por su TLS Server Hello:
  - Versión TLS
  - Cipher suite elegida
  - Extensiones

Uso:
    ja3 = JA3Fingerprinter(callback=fn)
    # desde capture.py para cada paquete TCP con Raw:
    ja3.procesar_paquete(ip_src, ip_dst, puerto_dst, payload_bytes)
"""

import hashlib
import struct
from datetime import datetime
from collections import defaultdict

_log_fn = None

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    linea = f"[{ts}] {msg}"
    if _log_fn:
        try: _log_fn(linea)
        except Exception: pass
    else:
        print(linea)

def set_log_callback(fn):
    global _log_fn
    _log_fn = fn


# ── Base de datos de hashes JA3 conocidos ────────────────────────────────────
# Hashes de malware/herramientas conocidas
JA3_CONOCIDOS = {
    # Malware conocido
    "e7d705a3286e19ea42f587b344ee6865": ("Trickbot/Emotet",  "critico"),
    "6734f37431670b3ab4292b8f60f29984": ("Cobalt Strike",    "critico"),
    "b386946a5a44d1ddcc843bc75336dfce": ("Cobalt Strike",    "critico"),
    "1aa7bf8b97e540ca5edd75f7b8384bca": ("Metasploit",       "critico"),
    "5d41402abc4b2a76b9719d911017c592": ("Metasploit MSF",   "critico"),
    "d0ec4b50a944b182fc10ff51f883ccf7": ("Dridex",           "critico"),
    "c35b1bee33e5503b45d3ed6f68eddb8f": ("Tofsee Backdoor",  "critico"),
    "bc6c386f480f893c79b7beb3e3c2bab3": ("Zeus Trojan",      "critico"),
    # Herramientas de pentest/reconocimiento
    "de9f2c7fd25e1b3afad3e85a0bd17d9b": ("curl",             "info"),
    "37f463bf4616ecd445d4a1937da06e19": ("Python Requests",  "info"),
    "a0e9f5d64349fb13191bc781f81f42e1": ("Go HTTP",          "info"),
    "8c4a22651d328b31de58e197f6e49e87": ("Nmap NSE",         "medio"),
    "4f7f462f03e06cb36a48a2e4a7543765": ("Masscan",          "medio"),
    "13b5a8ad28c0ef6e21374fcda9a5e6f9": ("Zgrab Scanner",    "medio"),
    # Navegadores legítimos (referencia)
    "773906b0efdefa24a7f2b8eb6985bf37": ("Chrome 96+",       "info"),
    "66918128f1b9b03303d77c6f2eefd128": ("Firefox 95+",      "info"),
    "c27b4c9b3ca3b6a3e5b3f6b7a2e6b5a1": ("Safari iOS",       "info"),
}

# Extensiones GREASE — ignorar en el cálculo JA3
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}


class JA3Fingerprinter:
    """
    Extrae hashes JA3 y JA3S de tráfico TLS capturado.
    Thread-safe. Procesa payloads TCP crudos.
    """

    def __init__(self, callback=None):
        self.callback   = callback
        # {(ip_src, ip_dst, puerto): ja3_hash}
        self._vistos    = {}
        # Estadísticas por IP origen
        self._por_ip    = defaultdict(set)

    def procesar_paquete(self, ip_src, ip_dst, puerto_dst, puerto_src, payload):
        """
        Analiza un payload TCP en busca de TLS Client Hello o Server Hello.
        Llamar desde capture.py/_procesar_paquete() para paquetes TCP con Raw.
        """
        if not payload or len(payload) < 6:
            return

        try:
            # TLS Record: tipo(1) + versión(2) + longitud(2)
            if payload[0] == 0x16:   # Handshake
                handshake_type = payload[5] if len(payload) > 5 else 0
                if handshake_type == 0x01:   # Client Hello
                    self._procesar_client_hello(
                        ip_src, ip_dst, puerto_dst, payload)
                elif handshake_type == 0x02:  # Server Hello
                    self._procesar_server_hello(
                        ip_src, ip_dst, puerto_src, payload)
        except Exception:
            pass

    def _procesar_client_hello(self, ip_src, ip_dst, puerto, payload):
        """Extrae JA3 de un TLS Client Hello."""
        try:
            datos = self._parsear_client_hello(payload)
            if not datos:
                return

            # Construir string JA3
            # Formato: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
            ja3_str = ",".join([
                str(datos["version"]),
                "-".join(str(c) for c in datos["ciphers"]),
                "-".join(str(e) for e in datos["extensions"]),
                "-".join(str(c) for c in datos["curves"]),
                "-".join(str(f) for f in datos["point_formats"]),
            ])

            ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
            clave = (ip_src, ip_dst, puerto)

            if clave in self._vistos:
                return
            self._vistos[clave] = ja3_hash
            self._por_ip[ip_src].add(ja3_hash)

            # Buscar en base de datos de conocidos
            info_conocida = JA3_CONOCIDOS.get(ja3_hash)
            nombre = info_conocida[0] if info_conocida else "Desconocido"
            sev    = info_conocida[1] if info_conocida else "info"

            log(f"[JA3] {ip_src} → {ip_dst}:{puerto} | "
                f"JA3={ja3_hash[:12]}... | {nombre}")

            if self.callback:
                self.callback("JA3", {
                    "ip_src"  : ip_src,
                    "ip_dst"  : ip_dst,
                    "puerto"  : puerto,
                    "hash"    : ja3_hash,
                    "ja3_str" : ja3_str[:60],
                    "app"     : nombre,
                    "severidad": sev,
                    "detalle" : (f"JA3: {ja3_hash} | App: {nombre} | "
                                 f"→ {ip_dst}:{puerto}")
                })

        except Exception as e:
            pass

    def _procesar_server_hello(self, ip_src, ip_dst, puerto, payload):
        """Extrae JA3S de un TLS Server Hello."""
        try:
            datos = self._parsear_server_hello(payload)
            if not datos:
                return

            ja3s_str = ",".join([
                str(datos["version"]),
                str(datos["cipher"]),
                "-".join(str(e) for e in datos["extensions"]),
            ])
            ja3s_hash = hashlib.md5(ja3s_str.encode()).hexdigest()
            clave = ("S", ip_src, puerto)

            if clave in self._vistos:
                return
            self._vistos[clave] = ja3s_hash

            log(f"[JA3S] Servidor {ip_src}:{puerto} | JA3S={ja3s_hash[:12]}...")

            if self.callback:
                self.callback("JA3S", {
                    "ip_src"   : ip_src,
                    "ip_dst"   : ip_dst,
                    "puerto"   : puerto,
                    "hash"     : ja3s_hash,
                    "ja3s_str" : ja3s_str,
                    "severidad": "info",
                    "detalle"  : f"JA3S: {ja3s_hash} | Servidor: {ip_src}:{puerto}"
                })

        except Exception:
            pass

    # ── PARSERS TLS ───────────────────────────────────────────────────────────

    def _parsear_client_hello(self, payload):
        """
        Parsea un TLS Client Hello y extrae los campos JA3.
        Retorna dict o None si no es válido.
        """
        try:
            # TLS Record header (5 bytes) + Handshake header (4 bytes)
            if len(payload) < 9:
                return None

            # Versión TLS del record
            tls_version = struct.unpack("!H", payload[1:3])[0]

            # Handshake header
            hs_type   = payload[5]
            if hs_type != 1:  # No es Client Hello
                return None

            # Client Hello empieza en byte 9
            offset = 9

            # Client Version (2 bytes)
            if offset + 2 > len(payload):
                return None
            client_version = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2

            # Random (32 bytes)
            offset += 32

            # Session ID
            if offset >= len(payload):
                return None
            sid_len = payload[offset]
            offset += 1 + sid_len

            # Cipher Suites
            if offset + 2 > len(payload):
                return None
            cs_len = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2
            ciphers = []
            for i in range(0, cs_len, 2):
                if offset + 2 > len(payload):
                    break
                cs = struct.unpack("!H", payload[offset:offset+2])[0]
                offset += 2
                if cs not in GREASE_VALUES and cs != 0x00FF:
                    ciphers.append(cs)

            # Compression Methods
            if offset >= len(payload):
                return None
            comp_len = payload[offset]
            offset += 1 + comp_len

            # Extensions
            extensions = []
            curves     = []
            point_fmts = []

            if offset + 2 <= len(payload):
                ext_total = struct.unpack("!H", payload[offset:offset+2])[0]
                offset += 2
                ext_end = offset + ext_total

                while offset + 4 <= ext_end and offset + 4 <= len(payload):
                    ext_type = struct.unpack("!H", payload[offset:offset+2])[0]
                    ext_len  = struct.unpack("!H", payload[offset+2:offset+4])[0]
                    offset  += 4

                    if ext_type not in GREASE_VALUES:
                        extensions.append(ext_type)

                    # Extensión 0x000a — Supported Groups (curvas elípticas)
                    if ext_type == 0x000a and offset + 2 <= len(payload):
                        curves_len = struct.unpack(
                            "!H", payload[offset:offset+2])[0]
                        for j in range(2, curves_len + 2, 2):
                            if offset + j + 2 <= len(payload):
                                cv = struct.unpack(
                                    "!H", payload[offset+j:offset+j+2])[0]
                                if cv not in GREASE_VALUES:
                                    curves.append(cv)

                    # Extensión 0x000b — EC Point Formats
                    elif ext_type == 0x000b and offset < len(payload):
                        pf_len = payload[offset]
                        for j in range(1, pf_len + 1):
                            if offset + j < len(payload):
                                point_fmts.append(payload[offset + j])

                    offset += ext_len

            return {
                "version"      : client_version,
                "ciphers"      : ciphers,
                "extensions"   : extensions,
                "curves"       : curves,
                "point_formats": point_fmts,
            }

        except Exception:
            return None

    def _parsear_server_hello(self, payload):
        """Parsea TLS Server Hello para JA3S."""
        try:
            if len(payload) < 11 or payload[5] != 2:
                return None

            offset = 9  # después de record(5) + handshake header(4)
            server_version = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2 + 32  # version + random

            # Session ID
            if offset >= len(payload): return None
            sid_len = payload[offset]
            offset += 1 + sid_len

            # Cipher suite elegida
            if offset + 2 > len(payload): return None
            cipher = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2 + 1  # +1 compression method

            extensions = []
            if offset + 2 <= len(payload):
                ext_total = struct.unpack("!H", payload[offset:offset+2])[0]
                offset += 2
                ext_end = offset + ext_total
                while offset + 4 <= ext_end and offset + 4 <= len(payload):
                    ext_type = struct.unpack("!H", payload[offset:offset+2])[0]
                    ext_len  = struct.unpack("!H", payload[offset+2:offset+4])[0]
                    offset  += 4 + ext_len
                    if ext_type not in GREASE_VALUES:
                        extensions.append(ext_type)

            return {
                "version"   : server_version,
                "cipher"    : cipher,
                "extensions": extensions,
            }
        except Exception:
            return None
