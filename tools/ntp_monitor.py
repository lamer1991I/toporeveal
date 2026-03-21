"""
ntp_monitor.py — Monitoreo de drift NTP para TopoReveal.

Dos modos de operación:
  1. PASIVO — cuando capture.py ve tráfico NTP, extrae el timestamp
     del paquete y lo compara con el tiempo local del sistema.
  2. ACTIVO — consulta directamente al servidor NTP detectado y
     mide el offset con ntpdate o nmap ntp-info.

Umbrales:
  offset > 300s (5 min)  → ALTO   — rompe autenticación Kerberos
  offset > 60s  (1 min)  → MEDIO  — sospechoso, posible manipulación
  offset > 5s            → INFO   — desviación menor, documentar
"""

import subprocess
import threading
import struct
import time
import socket
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


class NTPMonitor:
    """
    Mide el drift NTP de los servidores detectados en la red.
    Se activa automáticamente cuando se detecta tráfico NTP.
    """

    def __init__(self, callback=None):
        self.callback    = callback
        self._analizados = set()   # servidores ya medidos
        self._lock       = threading.Lock()

    def analizar_servidor(self, ip_servidor, ip_cliente=None):
        """
        Mide el offset NTP del servidor dado.
        Llamar desde app.py cuando se detecta tráfico NTP externo.
        No bloquea — corre en hilo separado.
        """
        with self._lock:
            if ip_servidor in self._analizados:
                return
            self._analizados.add(ip_servidor)

        threading.Thread(
            target=self._medir_drift,
            args=(ip_servidor, ip_cliente),
            daemon=True,
            name=f"ntp-{ip_servidor}"
        ).start()

    def _medir_drift(self, ip_servidor, ip_cliente):
        """Mide el offset NTP usando socket raw (RFC 5905)."""
        log(f"[NTP] Midiendo drift de {ip_servidor}...")

        offset = None
        metodo = "raw"

        # Método 1 — Query NTP raw (sin dependencias externas)
        try:
            offset = self._query_ntp_raw(ip_servidor)
            metodo = "socket"
        except Exception as e:
            log(f"[NTP] Socket raw falló en {ip_servidor}: {e}")

        # Método 2 — ntpdate -q como fallback
        if offset is None:
            try:
                res = subprocess.run(
                    ["ntpdate", "-q", ip_servidor],
                    capture_output=True, text=True, timeout=10)
                import re
                m = re.search(r'offset\s+([-\d.]+)\s+sec', res.stdout)
                if m:
                    offset = float(m.group(1))
                    metodo = "ntpdate"
            except Exception:
                pass

        # Método 3 — nmap ntp-info como último recurso
        if offset is None:
            try:
                res = subprocess.run([
                    "nmap", "-Pn", "-sU", "-p", "123",
                    "--script", "ntp-info",
                    "--script-timeout", "8s", ip_servidor],
                    capture_output=True, text=True, timeout=15)
                import re
                # Extraer receive time del output
                m = re.search(r'receive time:\s*(.+)', res.stdout)
                if m:
                    log(f"[NTP] {ip_servidor}: activo (nmap) — "
                        f"offset no medible sin ntpdate")
                    if self.callback:
                        self.callback(ip_servidor, ip_cliente, 0.0, "info",
                                      f"Servidor NTP activo — offset no medible")
                    return
            except Exception:
                pass

        if offset is None:
            log(f"[NTP] {ip_servidor}: no responde a consultas NTP")
            return

        # Clasificar por severidad
        abs_offset = abs(offset)
        if abs_offset > 300:
            severidad = "alto"
            resumen   = (f"CRÍTICO: offset {offset:+.1f}s — "
                         f"rompe autenticación Kerberos (max 300s)")
        elif abs_offset > 60:
            severidad = "medio"
            resumen   = (f"Offset significativo: {offset:+.1f}s — "
                         f"posible manipulación de tiempo")
        elif abs_offset > 5:
            severidad = "info"
            resumen   = f"Offset menor: {offset:+.3f}s — documentado"
        else:
            severidad = "info"
            resumen   = f"Tiempo sincronizado — offset: {offset:+.3f}s"

        log(f"[NTP] {ip_servidor}: offset={offset:+.3f}s "
            f"[{severidad.upper()}] vía {metodo}")

        if self.callback:
            self.callback(ip_servidor, ip_cliente, offset, severidad, resumen)

    def _query_ntp_raw(self, ip_servidor, puerto=123, timeout=5):
        """
        Consulta NTP usando socket UDP raw según RFC 5905.
        Retorna el offset en segundos (float).
        """
        # Packet NTP v3, modo cliente (3)
        # LI=0, VN=3, Mode=3 → primer byte = 0b00_011_011 = 0x1B
        paquete = b'\x1b' + 47 * b'\0'

        # Timestamp de envío (t1)
        t1 = time.time()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(paquete, (ip_servidor, puerto))
            datos, _ = sock.recvfrom(1024)
        finally:
            sock.close()

        # Timestamp de recepción (t4)
        t4 = time.time()

        if len(datos) < 48:
            raise ValueError("Respuesta NTP demasiado corta")

        # Extraer timestamps del servidor (32 bits entero + 32 bits fracción)
        # NTP epoch = 1 enero 1900, Unix epoch = 1 enero 1970 → diff = 70 años
        NTP_DELTA = 2208988800  # segundos entre 1900 y 1970

        def _ts(offset_bytes):
            secs  = struct.unpack("!I", datos[offset_bytes:offset_bytes+4])[0]
            frac  = struct.unpack("!I", datos[offset_bytes+4:offset_bytes+8])[0]
            return (secs - NTP_DELTA) + frac / 2**32

        # T2 = receive timestamp del servidor (byte 32)
        # T3 = transmit timestamp del servidor (byte 40)
        t2 = _ts(32)
        t3 = _ts(40)

        # Offset = ((T2 - T1) + (T3 - T4)) / 2
        offset = ((t2 - t1) + (t3 - t4)) / 2
        return offset
