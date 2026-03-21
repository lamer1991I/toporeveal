"""
ipv6_scanner.py — Escáner IPv6 para TopoReveal.

Capacidades:
  1. Descubrimiento de hosts IPv6 en el segmento local (fe80::/10)
     - NDP (Neighbor Discovery Protocol) — equivalente a ARP en IPv6
     - Ping6 a la dirección multicast de todos los nodos (ff02::1)
     - nmap -6 sobre el rango link-local

  2. Escaneo de puertos en hosts IPv6 descubiertos

  3. Detección de túneles IPv6-in-IPv4 (6to4, Teredo, ISATAP)
     — estos pueden usarse para evadir firewalls

  4. Enriquecimiento de nodos existentes con su dirección IPv6

Integración con TopoReveal:
  - Los hosts IPv6 nuevos se agregan a la topología como nodos normales
  - Los nodos IPv4 existentes se enriquecen con su IPv6 link-local
  - Se detecta si un host usa IPv6 globalmente (2xxx::/4) — puede
    indicar conectividad dual-stack o túneles

  callback(tipo, datos):
    tipo = "HOST_IPV6"    → datos = {ip6, mac, ip4_asociada}
    tipo = "PUERTO_IPV6"  → datos = {ip6, puerto, servicio}
    tipo = "TUNEL_IPV6"   → datos = {ip4, tipo_tunel, ip6_embebida}
"""

import subprocess
import threading
import re
import time
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


# Puertos importantes a escanear en hosts IPv6
PUERTOS_IPV6 = "22,23,80,443,445,8080,8443,3389,5900"

# Prefijos de túneles conocidos
TUNEL_PREFIJOS = {
    "2002:": "6to4",          # 2002::/16 — túnel 6to4
    "2001:0:": "Teredo",      # 2001::/32 — Teredo
    "fe80::5efe": "ISATAP",   # ISATAP link-local
    "::ffff:": "IPv4-mapped", # IPv4 mapeado en IPv6
}


class IPv6Scanner:
    """
    Escáner IPv6 pasivo+activo para TopoReveal.
    Corre en hilos separados para no bloquear la UI.
    """

    def __init__(self, callback=None):
        self.callback  = callback
        self._lock     = threading.Lock()
        self._stop     = threading.Event()
        self._hosts_v6 = {}   # {ip6: {"mac": ..., "ip4": ..., "puertos": []}}
        self._escaneados = set()

    def iniciar(self, interfaz):
        """Lanza el escaneo IPv6 en segundo plano."""
        self._interfaz = interfaz
        self._stop.clear()
        threading.Thread(
            target=self._pipeline,
            args=(interfaz,),
            daemon=True, name="ipv6-scanner"
        ).start()

    def detener(self):
        self._stop.set()

    def registrar_paquete_ipv6(self, ip6_src, ip6_dst, mac_src):
        """
        Llamar desde capture.py cuando se ve un paquete IPv6.
        Descubrimiento pasivo — sin enviar nada.
        """
        if not ip6_src or ip6_src.startswith("::") or ip6_src == "fe80::":
            return

        with self._lock:
            if ip6_src not in self._hosts_v6:
                self._hosts_v6[ip6_src] = {
                    "mac": mac_src or "?",
                    "ip4": None,
                    "puertos": [],
                    "descubierto": "pasivo",
                }
                tipo_addr = self._clasificar_ipv6(ip6_src)
                log(f"[IPv6] Host descubierto (pasivo): {ip6_src} "
                    f"[{tipo_addr}] MAC:{mac_src or '?'}")

                # Detectar túneles
                tunel = self._detectar_tunel(ip6_src)
                if tunel:
                    log(f"[IPv6] ⚠ Túnel {tunel['tipo']} detectado: "
                        f"{ip6_src} → IPv4 embebida: {tunel.get('ip4','?')}")
                    if self.callback:
                        self.callback("TUNEL_IPV6", {
                            "ip6"      : ip6_src,
                            "mac"      : mac_src,
                            "tipo_tunel": tunel["tipo"],
                            "ip4_embed" : tunel.get("ip4", "?"),
                            "detalle"  : (
                                f"Túnel {tunel['tipo']}: {ip6_src} "
                                f"| IPv4 embebida: {tunel.get('ip4','?')}"
                            )
                        })
                else:
                    if self.callback:
                        self.callback("HOST_IPV6", {
                            "ip6"    : ip6_src,
                            "mac"    : mac_src or "?",
                            "ip4"    : None,
                            "tipo"   : tipo_addr,
                            "detalle": f"Host IPv6 {tipo_addr}: {ip6_src}"
                        })

    # ── PIPELINE ACTIVO ───────────────────────────────────────────────────────

    def _pipeline(self, interfaz):
        """Pipeline de escaneo activo IPv6."""
        log(f"[IPv6] Iniciando escaneo activo en {interfaz}")

        # Paso 1: Ping6 multicast — descubre todos los nodos link-local
        self._ping6_multicast(interfaz)
        if self._stop.is_set(): return

        # Paso 2: NDP dump — tabla de vecinos IPv6 del kernel
        self._ndp_dump(interfaz)
        if self._stop.is_set(): return

        # Esperar un poco para que lleguen respuestas
        time.sleep(5)
        if self._stop.is_set(): return

        # Paso 3: nmap -6 sobre hosts descubiertos
        self._nmap_ipv6(interfaz)
        if self._stop.is_set(): return

        # Paso 4: Escaneo de rango global si hay prefijo global
        self._detectar_prefijo_global(interfaz)

        log(f"[IPv6] Pipeline completado — "
            f"{len(self._hosts_v6)} hosts IPv6 conocidos")

    def _ping6_multicast(self, interfaz):
        """Ping6 a ff02::1 — todos los nodos del segmento."""
        log(f"[IPv6] Ping6 multicast ff02::1 en {interfaz}...")
        try:
            res = subprocess.run(
                ["ping6", "-c", "3", "-I", interfaz, "ff02::1"],
                capture_output=True, text=True, timeout=10)

            # Parsear respuestas — cada línea "from fe80::..." es un host
            for linea in res.stdout.splitlines():
                m = re.search(r'from (fe80::[0-9a-f:]+)', linea, re.IGNORECASE)
                if m:
                    ip6 = m.group(1).strip().split("%")[0]
                    with self._lock:
                        if ip6 not in self._hosts_v6:
                            self._hosts_v6[ip6] = {
                                "mac": "?",
                                "ip4": None,
                                "puertos": [],
                                "descubierto": "ping6",
                            }
                            log(f"[IPv6] Host respondió a ping6: {ip6}")
                            if self.callback:
                                self.callback("HOST_IPV6", {
                                    "ip6"    : ip6,
                                    "mac"    : "?",
                                    "ip4"    : None,
                                    "tipo"   : "link-local",
                                    "detalle": f"Respondió a ping6 multicast"
                                })
        except FileNotFoundError:
            log("[IPv6] ping6 no disponible — usando nmap")
        except subprocess.TimeoutExpired:
            log("[IPv6] Timeout en ping6 multicast")
        except Exception as e:
            log(f"[IPv6] Error ping6: {e}")

    def _ndp_dump(self, interfaz):
        """Lee la tabla NDP del kernel — equivalente a arp -n para IPv6."""
        log("[IPv6] Leyendo tabla NDP del kernel...")
        try:
            # ip -6 neigh show — muestra caché NDP
            res = subprocess.run(
                ["ip", "-6", "neigh", "show", "dev", interfaz],
                capture_output=True, text=True, timeout=5)

            for linea in res.stdout.splitlines():
                # Formato: fe80::xxxx lladdr aa:bb:cc:dd:ee:ff REACHABLE
                m = re.match(
                    r'(fe80::[0-9a-f:]+|[0-9a-f:]{4,}::[0-9a-f:]*)'
                    r'.*lladdr\s+([0-9a-f:]{17})',
                    linea, re.IGNORECASE)
                if m:
                    ip6 = m.group(1).strip()
                    mac = m.group(2).strip()
                    with self._lock:
                        if ip6 not in self._hosts_v6:
                            self._hosts_v6[ip6] = {
                                "mac": mac,
                                "ip4": None,
                                "puertos": [],
                                "descubierto": "ndp",
                            }
                            log(f"[IPv6] Host en tabla NDP: {ip6} MAC:{mac}")
                            if self.callback:
                                self.callback("HOST_IPV6", {
                                    "ip6"    : ip6,
                                    "mac"    : mac,
                                    "ip4"    : None,
                                    "tipo"   : self._clasificar_ipv6(ip6),
                                    "detalle": f"Tabla NDP | MAC: {mac}"
                                })
                        else:
                            # Actualizar MAC si la teníamos desconocida
                            if self._hosts_v6[ip6]["mac"] == "?":
                                self._hosts_v6[ip6]["mac"] = mac

        except Exception as e:
            log(f"[IPv6] Error NDP: {e}")

    def _nmap_ipv6(self, interfaz):
        """Escaneo de puertos sobre hosts IPv6 descubiertos."""
        with self._lock:
            hosts = list(self._hosts_v6.keys())

        if not hosts:
            return

        log(f"[IPv6] Escaneando puertos en {len(hosts)} host(s) IPv6...")

        for ip6 in hosts:
            if self._stop.is_set():
                break
            if ip6 in self._escaneados:
                continue
            self._escaneados.add(ip6)

            # Formatear para nmap — añadir interfaz para link-local
            target = f"{ip6}%{interfaz}" if ip6.startswith("fe80") else ip6

            try:
                res = subprocess.run([
                    "nmap", "-6", "-Pn",
                    "-p", PUERTOS_IPV6,
                    "--host-timeout", "15s",
                    "-sV", "--version-intensity", "3",
                    target],
                    capture_output=True, text=True, timeout=25)

                for linea in res.stdout.splitlines():
                    m = re.match(
                        r'^(\d+)/tcp\s+open\s+(\S+)\s*(.*)', linea)
                    if m:
                        puerto  = int(m.group(1))
                        servicio = m.group(2)
                        version  = m.group(3).strip()[:40]

                        with self._lock:
                            if ip6 in self._hosts_v6:
                                self._hosts_v6[ip6]["puertos"].append(puerto)

                        log(f"[IPv6] {ip6}:{puerto} {servicio} {version}")
                        if self.callback:
                            self.callback("PUERTO_IPV6", {
                                "ip6"     : ip6,
                                "mac"     : self._hosts_v6.get(ip6, {}).get("mac", "?"),
                                "puerto"  : puerto,
                                "servicio": servicio,
                                "version" : version,
                                "detalle" : (
                                    f"IPv6 puerto abierto: "
                                    f"{puerto}/{servicio} {version}"
                                )
                            })

            except subprocess.TimeoutExpired:
                log(f"[IPv6] Timeout escaneando {ip6}")
            except Exception as e:
                log(f"[IPv6] Error nmap en {ip6}: {e}")

    def _detectar_prefijo_global(self, interfaz):
        """
        Detecta si la interfaz tiene dirección IPv6 global (2xxx::/4).
        Si la tiene, busca otros hosts en el mismo /64.
        """
        try:
            res = subprocess.run(
                ["ip", "-6", "addr", "show", interfaz],
                capture_output=True, text=True, timeout=5)

            for linea in res.stdout.splitlines():
                # Buscar inet6 con dirección global (no fe80)
                m = re.search(r'inet6\s+([2-3][0-9a-f:]+)/(\d+)', linea)
                if m:
                    ip6_local = m.group(1)
                    prefijo   = int(m.group(2))
                    log(f"[IPv6] Dirección global detectada: "
                        f"{ip6_local}/{prefijo}")

                    # Solo escanear si es /64 o menor
                    if prefijo <= 64:
                        # Construir el prefijo /64
                        partes = ip6_local.split(":")[:4]
                        rango  = ":".join(partes) + "::/64"
                        log(f"[IPv6] Escaneando rango global {rango}...")
                        try:
                            res2 = subprocess.run([
                                "nmap", "-6", "-sn", "--host-timeout", "5s",
                                rango],
                                capture_output=True, text=True, timeout=60)
                            # Parsear hosts encontrados
                            for l2 in res2.stdout.splitlines():
                                hm = re.search(
                                    r'Nmap scan report for (.+)', l2)
                                if hm:
                                    host = hm.group(1).strip()
                                    if ":" in host and host != ip6_local:
                                        log(f"[IPv6] Host global: {host}")
                                        if self.callback:
                                            self.callback("HOST_IPV6", {
                                                "ip6"    : host,
                                                "mac"    : "?",
                                                "ip4"    : None,
                                                "tipo"   : "global",
                                                "detalle": f"IPv6 global en {rango}"
                                            })
                        except Exception:
                            pass
        except Exception as e:
            log(f"[IPv6] Error detectando prefijo global: {e}")

    # ── UTILIDADES ────────────────────────────────────────────────────────────

    def _clasificar_ipv6(self, ip6):
        """Clasifica una dirección IPv6 por su tipo."""
        ip6 = ip6.lower()
        if ip6.startswith("fe80"):   return "link-local"
        if ip6.startswith("fc") or ip6.startswith("fd"):
            return "unique-local"
        if ip6.startswith("ff"):     return "multicast"
        if ip6.startswith("2002"):   return "6to4"
        if ip6.startswith("2001:0:"): return "Teredo"
        if ip6.startswith("::1"):    return "loopback"
        if ip6.startswith("::ffff"): return "IPv4-mapped"
        if ip6[0] in "23":           return "global"
        return "desconocido"

    def _detectar_tunel(self, ip6):
        """
        Detecta si una dirección IPv6 es producto de un túnel.
        Retorna {"tipo": ..., "ip4": ...} o None.
        """
        ip6 = ip6.lower()

        # 6to4: 2002:xxyy:zzww::/48 donde xx.yy.zz.ww es IPv4
        if ip6.startswith("2002:"):
            try:
                partes = ip6.split(":")
                if len(partes) >= 3:
                    hex_ip4 = partes[1] + partes[2]
                    # Rellenar a 8 chars
                    hex_ip4 = hex_ip4.zfill(8)
                    ip4 = ".".join(str(int(hex_ip4[i:i+2], 16))
                                   for i in range(0, 8, 2))
                    return {"tipo": "6to4", "ip4": ip4}
            except Exception:
                pass

        # Teredo: 2001:0000:xxxx... — IPv4 del servidor Teredo embebida
        if ip6.startswith("2001:0:") or ip6.startswith("2001:0000:"):
            return {"tipo": "Teredo", "ip4": "embebida"}

        # ISATAP: fe80::5efe:x.x.x.x
        if "5efe:" in ip6:
            return {"tipo": "ISATAP", "ip4": "embebida"}

        return None

    def hosts_descubiertos(self):
        """Retorna dict de todos los hosts IPv6 conocidos."""
        with self._lock:
            return dict(self._hosts_v6)
