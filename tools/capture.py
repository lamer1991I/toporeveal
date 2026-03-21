"""
capture.py — Captura pasiva con reinicio automático de hilo.
Si el hilo de scapy muere por cualquier razón, un watchdog lo relanza
automáticamente sin intervención del usuario.
"""

import threading
import time
import subprocess
from datetime import datetime

# Log interno — puede ser reemplazado por set_log_callback()
_log_fn = None

def log(msg):
    # Solo imprime en terminal si NO hay callback externo
    # (evita duplicados: el callback ya llama a log() de app.py que hace print)
    if _log_fn is None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    if _log_fn is not None:
        try:
            _log_fn(msg)
        except Exception:
            pass

def set_log_callback(fn):
    """Conecta el log de capture al buffer central de app.py."""
    global _log_fn
    _log_fn = fn

MAX_REINICIOS   = 10      # máximo reinicios antes de rendirse
PAUSA_REINICIO  = 3       # segundos entre reintentos


class Capture:
    def __init__(self, callback):
        self.callback   = callback
        self.corriendo  = False
        self._interfaz  = None
        self._id        = 0
        self._reinicios = 0
        self._lock      = threading.Lock()
        self._stop_evt  = threading.Event()
        self._hilo_capture   = None
        self._hilo_watchdog  = None

    # ── ARRANQUE / PARADA ────────────────────────────────────────

    def iniciar(self, interfaz):
        if self.corriendo:
            log("[CAPTURE] Ya corriendo, ignorando")
            return
        self._interfaz  = interfaz
        self._reinicios = 0
        self._stop_evt.clear()
        self.corriendo  = True
        self._activar_promiscuo(interfaz)

        # Hilo principal de captura
        self._arrancar_hilo_capture()

        # Watchdog independiente que vigila el hilo
        self._hilo_watchdog = threading.Thread(
            target=self._watchdog, daemon=True, name="capture-watchdog")
        self._hilo_watchdog.start()
        log(f"[CAPTURE] Iniciado en {interfaz} (promiscuo + watchdog)")

    def detener(self):
        self._stop_evt.set()
        self.corriendo = False
        self._desactivar_promiscuo(self._interfaz)
        log("[CAPTURE] Detenido")

    def esta_corriendo(self):
        return self.corriendo and (
            self._hilo_capture is not None and
            self._hilo_capture.is_alive()
        )

    # ── WATCHDOG ─────────────────────────────────────────────────

    def _watchdog(self):
        """Vigila el hilo de captura. Si muere, lo relanza."""
        while not self._stop_evt.is_set():
            time.sleep(5)
            if self._stop_evt.is_set():
                break
            if self.corriendo and (
                self._hilo_capture is None or
                not self._hilo_capture.is_alive()
            ):
                if self._reinicios >= MAX_REINICIOS:
                    log(f"[CAPTURE] Watchdog: máximo reinicios ({MAX_REINICIOS}) alcanzado")
                    self.corriendo = False
                    break
                self._reinicios += 1
                log(f"[CAPTURE] Watchdog: hilo muerto, reiniciando "
                    f"({self._reinicios}/{MAX_REINICIOS})...")
                time.sleep(PAUSA_REINICIO)
                if not self._stop_evt.is_set():
                    self._arrancar_hilo_capture()
        log("[CAPTURE] Watchdog terminado")

    def _arrancar_hilo_capture(self):
        with self._lock:
            self._id += 1
            mi_id = self._id
        self._hilo_capture = threading.Thread(
            target=self._capturar_hilo,
            args=(mi_id,), daemon=True,
            name=f"capture-{mi_id}")
        self._hilo_capture.start()

    # ── HILO DE CAPTURA ──────────────────────────────────────────

    def _capturar_hilo(self, mi_id):
        log(f"[CAPTURE] Hilo iniciado (id={mi_id})")
        try:
            from scapy.all import sniff
            while self.corriendo and not self._stop_evt.is_set():
                try:
                    sniff(
                        iface=self._interfaz,
                        prn=self._procesar_paquete,
                        store=False,
                        timeout=2
                    )
                except OSError as e:
                    msg = str(e)
                    if "Network is down" in msg or "100" in msg:
                        time.sleep(1)
                        continue
                    log(f"[CAPTURE] OSError: {e}")
                    time.sleep(1)
                except Exception as e:
                    if self.corriendo:
                        log(f"[CAPTURE] Error en bloque sniff: {type(e).__name__}: {e}")
                    time.sleep(1)

        except PermissionError:
            log("[CAPTURE] Error: necesita sudo para capturar")
            self.corriendo = False
        except ImportError:
            log("[CAPTURE] scapy no instalado — pip install scapy")
            self.corriendo = False
        except Exception as e:
            log(f"[CAPTURE] Error fatal (id={mi_id}): {type(e).__name__}: {e}")
            # No ponemos corriendo=False — el watchdog decide si reiniciar

        log(f"[CAPTURE] Hilo terminado (id={mi_id})")

    # ── PROCESAMIENTO DE PAQUETES ────────────────────────────────

    def _procesar_paquete(self, paquete):
        try:
            from scapy.all import (
                IP, IPv6, TCP, UDP, ICMP, ICMP6Unknown,
                ARP, Ether, DNS, Raw
            )
            # Importaciones opcionales — no todas las versiones de scapy las tienen
            try:
                from scapy.all import IGMP
            except ImportError:
                IGMP = None
            try:
                from scapy.layers.dot11 import Dot11
            except ImportError:
                Dot11 = None
            try:
                from scapy.layers.ipsec import ESP, AH
            except ImportError:
                ESP = None; AH = None
            try:
                from scapy.contrib.sctp import SCTP
            except ImportError:
                SCTP = None

            datos = None
            mac_origen = paquete[Ether].src if paquete.haslayer(Ether) else None

            # ── CAPA 2: CDP (Cisco Discovery Protocol) ───────────
            # EtherType 0x2000, dst MAC 01:00:0c:cc:cc:cc
            if paquete.haslayer(Ether):
                eth = paquete[Ether]
                dst_mac = eth.dst.lower() if eth.dst else ""
                # CDP: dst 01:00:0c:cc:cc:cc
                if dst_mac == "01:00:0c:cc:cc:cc":
                    datos = self._procesar_cdp(paquete, eth)
                # LLDP: dst 01:80:c2:00:00:0e
                elif dst_mac == "01:80:c2:00:00:0e":
                    datos = self._procesar_lldp(paquete, eth)
                if datos:
                    self.callback(datos)
                    return

            # ── CAPA 2: ARP ──────────────────────────────────────
            if paquete.haslayer(ARP):
                arp = paquete[ARP]
                datos = {
                    "tipo"       : "ARP",
                    "ip_origen"  : arp.psrc,
                    "ip_destino" : arp.pdst,
                    "mac_origen" : arp.hwsrc,
                    "bytes"      : len(paquete)
                }

            # ── CAPA 2: WiFi 802.11 ──────────────────────────────
            elif Dot11 and paquete.haslayer(Dot11):
                dot11 = paquete[Dot11]
                # Frame de datos con IP embebida
                if paquete.haslayer(IP):
                    ip = paquete[IP]
                    protocolo, puerto = self._resolver_protocolo_ip(
                        paquete, ip, TCP, UDP, ICMP, IGMP, ESP, AH, SCTP, DNS)
                    datos = {
                        "tipo"          : protocolo,
                        "ip_origen"     : ip.src,
                        "ip_destino"    : ip.dst,
                        "mac_origen"    : dot11.addr2,
                        "ttl"           : ip.ttl,
                        "puerto_destino": puerto,
                        "bytes"         : len(paquete),
                        "capa2"         : "WiFi"
                    }
                else:
                    # Frame 802.11 sin IP — metadatos puros
                    datos = {
                        "tipo"       : "DOT11",
                        "ip_origen"  : None,
                        "ip_destino" : None,
                        "mac_origen" : dot11.addr2,
                        "mac_destino": dot11.addr1,
                        "bytes"      : len(paquete),
                        "capa2"      : "WiFi"
                    }

            # ── CAPA 3+: IPv4 ────────────────────────────────────
            elif paquete.haslayer(IP):
                ip = paquete[IP]
                protocolo, puerto = self._resolver_protocolo_ip(
                    paquete, ip, TCP, UDP, ICMP, IGMP, ESP, AH, SCTP, DNS)
                datos = {
                    "tipo"          : protocolo,
                    "ip_origen"     : ip.src,
                    "ip_destino"    : ip.dst,
                    "mac_origen"    : mac_origen,
                    "ttl"           : ip.ttl,
                    "puerto_destino": puerto,
                    "bytes"         : len(paquete),
                    "capa2"         : "Ethernet"
                }
                # ── JA3: extraer payload TLS de paquetes TCP ─────
                if (paquete.haslayer(TCP) and paquete.haslayer(Raw)):
                    tcp_pkt = paquete[TCP]
                    raw_payload = bytes(paquete[Raw])
                    # Solo Client Hello (0x16 = Handshake) en puertos TLS
                    if (raw_payload and raw_payload[0] == 0x16 and
                            len(raw_payload) > 10):
                        datos["tls_payload"]  = raw_payload
                        datos["puerto_origen"] = tcp_pkt.sport

            # ── CAPA 3+: IPv6 ────────────────────────────────────
            elif paquete.haslayer(IPv6):
                ip6 = paquete[IPv6]
                if paquete.haslayer(TCP):
                    protocolo = self._resolver_app_proto(paquete[TCP].dport, "TCP")
                    puerto    = paquete[TCP].dport
                elif paquete.haslayer(UDP):
                    protocolo = self._resolver_app_proto(paquete[UDP].dport, "UDP")
                    puerto    = paquete[UDP].dport
                else:
                    protocolo = "ICMPv6"
                    puerto    = 0
                datos = {
                    "tipo"          : protocolo,
                    "ip_origen"     : ip6.src,
                    "ip_destino"    : ip6.dst,
                    "mac_origen"    : mac_origen,
                    "ttl"           : ip6.hlim,
                    "puerto_destino": puerto,
                    "bytes"         : len(paquete),
                    "capa2"         : "Ethernet",
                    "ipv6"          : True
                }

            if datos:
                self.callback(datos)

        except Exception:
            pass   # Nunca crashear por un paquete malformado

    def _resolver_protocolo_ip(self, paquete, ip,
                                TCP, UDP, ICMP, IGMP, ESP, AH, SCTP, DNS):
        """
        Detecta el protocolo de transporte y de aplicación.
        Devuelve (nombre_protocolo, puerto_destino).
        """
        # ── Capa 4 ───────────────────────────────────────────────
        if paquete.haslayer(TCP):
            dport    = paquete[TCP].dport
            sport    = paquete[TCP].sport
            protocolo = self._resolver_app_proto(dport, "TCP", sport)
            return protocolo, dport

        elif paquete.haslayer(UDP):
            dport    = paquete[UDP].dport
            sport    = paquete[UDP].sport
            protocolo = self._resolver_app_proto(dport, "UDP", sport)
            return protocolo, dport

        elif SCTP and paquete.haslayer(SCTP):
            return "SCTP", paquete[SCTP].dport

        # ── Capa 3 especial ──────────────────────────────────────
        elif paquete.haslayer(ICMP):
            tipo_icmp = paquete[ICMP].type
            nombres   = {0:"ICMP-Reply", 3:"ICMP-Unreach",
                         8:"ICMP-Echo",  11:"ICMP-TTL",
                         5:"ICMP-Redirect"}
            return nombres.get(tipo_icmp, "ICMP"), 0

        elif IGMP and paquete.haslayer(IGMP):
            return "IGMP", 0

        elif ESP and paquete.haslayer(ESP):
            return "IPSec-ESP", 0

        elif AH and paquete.haslayer(AH):
            return "IPSec-AH", 0

        # ── Protocolo IP numérico como fallback ──────────────────
        else:
            proto_num = ip.proto
            nombres_proto = {
                1:"ICMP", 2:"IGMP", 4:"IP-in-IP",
                6:"TCP",  17:"UDP", 41:"IPv6-in-IP",
                50:"IPSec-ESP", 51:"IPSec-AH",
                58:"ICMPv6", 89:"OSPF", 132:"SCTP"
            }
            return nombres_proto.get(proto_num, f"IP-{proto_num}"), 0

    def _resolver_app_proto(self, dport, base, sport=0):
        """
        Infiere protocolo de capa 7 por número de puerto.
        Devuelve string descriptivo.
        """
        # QUIC corre sobre UDP/443 o UDP/80
        if base == "UDP" and dport in (443, 80):
            return "QUIC"

        APP_PROTOS = {
            # Capa 7 — puertos estándar
            20: "FTP-Data", 21: "FTP",
            22: "SSH",      23: "Telnet",
            25: "SMTP",     53: "DNS",
            67: "DHCP",     68: "DHCP",
            69: "TFTP",     80: "HTTP",
            110: "POP3",    119: "NNTP",
            123: "NTP",     143: "IMAP",
            161: "SNMP",    162: "SNMP-Trap",
            179: "BGP",     389: "LDAP",
            443: "HTTPS",   445: "SMB",
            465: "SMTPS",   500: "IKE",
            514: "Syslog",  515: "LPD",
            554: "RTSP",    587: "SMTP-Sub",
            631: "IPP",     636: "LDAPS",
            993: "IMAPS",   995: "POP3S",
            1194: "OpenVPN",1433: "MSSQL",
            1723: "PPTP",   1883: "MQTT",
            3306: "MySQL",  3389: "RDP",
            5060: "SIP",    5061: "SIP-TLS",
            5222: "XMPP",   5432: "PostgreSQL",
            5900: "VNC",    6379: "Redis",
            8080: "HTTP-Alt",8443:"HTTPS-Alt",
            8883: "MQTT-TLS",8888:"HTTP-Dev",
            9200: "Elasticsearch",27017:"MongoDB",
            # Puertos Hikvision
            8000: "Hikvision", 9010: "Hikvision-SDR",
        }
        nombre = APP_PROTOS.get(dport) or APP_PROTOS.get(sport)
        if nombre:
            return nombre
        return base

    # ── PROMISCUO ────────────────────────────────────────────────

    def _procesar_cdp(self, paquete, eth):
        """
        Parsea un frame CDP (Cisco Discovery Protocol).
        Extrae: device_id, plataforma, dirección IP, versión IOS,
        capacidades (router/switch/bridge) y puerto de origen.
        CDP va sobre LLC/SNAP — payload raw después del header Ethernet.
        """
        try:
            from scapy.all import Raw
            mac = eth.src
            payload = bytes(paquete)

            # CDP usa LLC/SNAP — el payload empieza después del header Ethernet (14 bytes)
            # Luego LLC (3 bytes) + SNAP (5 bytes) + CDP header (4 bytes)
            # TLV parsing a partir del offset 26
            raw = payload[26:] if len(payload) > 26 else b""

            info = {
                "tipo"       : "CDP_DISCOVERY",
                "mac_origen" : mac,
                "ip_origen"  : None,
                "ip_destino" : None,
                "device_id"  : None,
                "plataforma" : None,
                "version"    : None,
                "puerto"     : None,
                "capacidades": [],
                "bytes"      : len(paquete),
            }

            # Parsear TLVs
            offset = 0
            while offset + 4 <= len(raw):
                tlv_type   = (raw[offset] << 8) | raw[offset+1]
                tlv_len    = (raw[offset+2] << 8) | raw[offset+3]
                if tlv_len < 4 or offset + tlv_len > len(raw):
                    break
                value = raw[offset+4 : offset+tlv_len]

                if tlv_type == 0x0001:   # Device ID
                    info["device_id"] = value.decode("utf-8", errors="replace").strip("\x00")
                elif tlv_type == 0x0002: # Addresses
                    # IP embebida a partir del byte 9
                    if len(value) >= 13:
                        ip_bytes = value[9:13]
                        info["ip_origen"] = ".".join(str(b) for b in ip_bytes)
                elif tlv_type == 0x0003: # Port ID
                    info["puerto"] = value.decode("utf-8", errors="replace").strip("\x00")
                elif tlv_type == 0x0004: # Capabilities
                    if len(value) >= 4:
                        caps = (value[0]<<24)|(value[1]<<16)|(value[2]<<8)|value[3]
                        if caps & 0x01: info["capacidades"].append("Router")
                        if caps & 0x02: info["capacidades"].append("TransparentBridge")
                        if caps & 0x04: info["capacidades"].append("SourceRouteBridge")
                        if caps & 0x08: info["capacidades"].append("Switch")
                        if caps & 0x10: info["capacidades"].append("Host")
                        if caps & 0x20: info["capacidades"].append("IGMPFilter")
                        if caps & 0x40: info["capacidades"].append("Repeater")
                elif tlv_type == 0x0005: # IOS Version
                    info["version"] = value.decode("utf-8", errors="replace")[:60].strip()
                elif tlv_type == 0x0006: # Platform
                    info["plataforma"] = value.decode("utf-8", errors="replace")[:40].strip()

                offset += tlv_len

            if info["device_id"] or info["ip_origen"]:
                log(f"[CDP] Dispositivo Cisco: {info['device_id'] or '?'} "
                    f"IP:{info['ip_origen'] or '?'} "
                    f"Plataforma:{info['plataforma'] or '?'} "
                    f"Capacidades:{','.join(info['capacidades'])}")
                return info

        except Exception as e:
            log(f"[CDP] Error parseando: {e}")
        return None

    def _procesar_lldp(self, paquete, eth):
        """
        Parsea un frame LLDP (Link Layer Discovery Protocol).
        Extrae: chassis ID, port ID, system name, system description,
        system capabilities, management address.
        """
        try:
            mac = eth.src
            # LLDP payload empieza en byte 14 (después del header Ethernet)
            payload = bytes(paquete)[14:]

            info = {
                "tipo"        : "LLDP_DISCOVERY",
                "mac_origen"  : mac,
                "ip_origen"   : None,
                "ip_destino"  : None,
                "chassis_id"  : None,
                "port_id"     : None,
                "system_name" : None,
                "system_desc" : None,
                "capacidades" : [],
                "mgmt_ip"     : None,
                "bytes"       : len(paquete),
            }

            offset = 0
            while offset + 2 <= len(payload):
                # TLV header: 7 bits tipo + 9 bits longitud
                header = (payload[offset] << 8) | payload[offset+1]
                tlv_type = (header >> 9) & 0x7F
                tlv_len  = header & 0x1FF
                offset  += 2

                if tlv_type == 0:   # End of LLDPDU
                    break
                if offset + tlv_len > len(payload):
                    break

                value = payload[offset : offset+tlv_len]
                offset += tlv_len

                if tlv_type == 1:   # Chassis ID
                    subtype = value[0] if value else 0
                    if subtype == 4 and len(value) >= 7:  # MAC address
                        info["chassis_id"] = ":".join(f"{b:02x}" for b in value[1:7])
                    elif len(value) > 1:
                        info["chassis_id"] = value[1:].decode("utf-8", errors="replace").strip()
                elif tlv_type == 2: # Port ID
                    if len(value) > 1:
                        info["port_id"] = value[1:].decode("utf-8", errors="replace").strip()
                elif tlv_type == 3: # TTL — ignorar
                    pass
                elif tlv_type == 4: # Port Description — ignorar
                    pass
                elif tlv_type == 5: # System Name
                    info["system_name"] = value.decode("utf-8", errors="replace").strip()
                elif tlv_type == 6: # System Description
                    info["system_desc"] = value.decode("utf-8", errors="replace")[:80].strip()
                elif tlv_type == 7: # System Capabilities
                    if len(value) >= 4:
                        caps = (value[0] << 8) | value[1]
                        if caps & 0x04:  info["capacidades"].append("Bridge")
                        if caps & 0x08:  info["capacidades"].append("WLAN-AP")
                        if caps & 0x10:  info["capacidades"].append("Router")
                        if caps & 0x20:  info["capacidades"].append("Phone")
                        if caps & 0x40:  info["capacidades"].append("DocsisCable")
                        if caps & 0x80:  info["capacidades"].append("StationOnly")
                        if caps & 0x100: info["capacidades"].append("CVLAN")
                        if caps & 0x200: info["capacidades"].append("SVLAN")
                elif tlv_type == 8: # Management Address
                    if len(value) >= 6:
                        addr_len    = value[0]
                        addr_subtype = value[1]
                        if addr_subtype == 1 and addr_len == 5:  # IPv4
                            info["mgmt_ip"] = ".".join(str(b) for b in value[2:6])
                            info["ip_origen"] = info["mgmt_ip"]

            if info["system_name"] or info["chassis_id"]:
                log(f"[LLDP] Dispositivo: {info['system_name'] or info['chassis_id'] or '?'} "
                    f"| Puerto:{info['port_id'] or '?'} "
                    f"| IP:{info['mgmt_ip'] or '?'} "
                    f"| Cap:{','.join(info['capacidades'])}")
                return info

        except Exception as e:
            log(f"[LLDP] Error parseando: {e}")
        return None

    def _activar_promiscuo(self, interfaz):
        try:
            subprocess.run(["ip","link","set", interfaz,"promisc","on"],
                           capture_output=True, timeout=3)
            log(f"[CAPTURE] Modo promiscuo activado en {interfaz}")
        except Exception as e:
            log(f"[CAPTURE] No se pudo activar promiscuo: {e}")

    def _desactivar_promiscuo(self, interfaz):
        try:
            subprocess.run(["ip","link","set", interfaz,"promisc","off"],
                           capture_output=True, timeout=3)
        except Exception:
            pass
