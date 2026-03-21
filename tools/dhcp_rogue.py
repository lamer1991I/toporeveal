"""
dhcp_rogue.py — Detección de DHCP Rogue (servidores DHCP no autorizados).

Lógica:
  Escucha paquetes DHCP Offer/ACK en la red.
  El primer servidor que responde se registra como "legítimo".
  Si aparece un segundo servidor distinto ofreciendo IPs → ROGUE DHCP.

  Integración:
    desde capture.py/_procesar_dhcp() llamar a:
        dhcp_rogue.registrar_oferta(ip_servidor, mac_servidor, ip_ofrecida)

    desde app.py:
        self._dhcp_rogue = DhcpRogueDetector(
            gateway_ip=self.topologia.gateway,
            callback=self._on_dhcp_rogue)
"""

import threading
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


class DhcpRogueDetector:
    """
    Detecta servidores DHCP no autorizados en la red.
    Thread-safe. Callback se llama desde hilo de captura.
    """

    def __init__(self, gateway_ip=None, callback=None):
        """
        gateway_ip  — IP del gateway legítimo (pre-autorizado)
        callback(ip_rogue, mac_rogue, ip_ofrecida, ip_legitimo)
        """
        self.gateway_ip  = gateway_ip
        self.callback    = callback
        self._lock       = threading.Lock()

        # {ip_servidor: {"mac": ..., "ofertas": n, "primera_vez": ts}}
        self._servidores = {}
        self._alertados  = set()   # IPs ya alertadas

    def registrar_oferta(self, ip_servidor, mac_servidor, ip_ofrecida="?"):
        """
        Registra una oferta DHCP vista en la red.
        Llamar desde capture.py cuando se detecta DHCP Offer o ACK.
        """
        if not ip_servidor or ip_servidor in ("0.0.0.0", "255.255.255.255"):
            return

        with self._lock:
            if ip_servidor not in self._servidores:
                self._servidores[ip_servidor] = {
                    "mac"         : mac_servidor or "?",
                    "ofertas"     : 0,
                    "primera_vez" : datetime.now().strftime("%H:%M:%S"),
                }
                log(f"[DHCP] Servidor detectado: {ip_servidor} "
                    f"({mac_servidor or '?'})")

            self._servidores[ip_servidor]["ofertas"] += 1

            # ── Verificar si es rogue ─────────────────────────────
            # Es legítimo si coincide con el gateway
            es_legitimo = (
                self.gateway_ip and
                ip_servidor == self.gateway_ip
            )

            # Si hay más de un servidor Y este no es el gateway → ROGUE
            n_servidores = len(self._servidores)
            if n_servidores > 1 and not es_legitimo:
                if ip_servidor not in self._alertados:
                    self._alertados.add(ip_servidor)
                    # Identificar cuál es el legítimo
                    ip_legitimo = self.gateway_ip or next(
                        (ip for ip in self._servidores if ip != ip_servidor),
                        "desconocido"
                    )
                    log(f"[DHCP] ⚠ ROGUE DHCP detectado: {ip_servidor} "
                        f"({mac_servidor}) ofrece {ip_ofrecida} | "
                        f"Legítimo: {ip_legitimo}")
                    if self.callback:
                        try:
                            self.callback(
                                ip_servidor, mac_servidor,
                                ip_ofrecida, ip_legitimo)
                        except Exception as e:
                            log(f"[DHCP] Error en callback: {e}")

    def servidores_conocidos(self):
        """Retorna dict de servidores DHCP vistos."""
        with self._lock:
            return dict(self._servidores)

    def resetear(self):
        """Limpia el estado para nueva sesión."""
        with self._lock:
            self._servidores.clear()
            self._alertados.clear()
