"""
arsenal.py — Arsenal nmap por nodo
Cada función lanza un escaneo específico en un hilo daemon
y devuelve los resultados al callback cuando termina.

Escaneos disponibles:
  1. Ping Check        — ¿sigue vivo? (2s)
  2. Quick Ports       — top 20 puertos más comunes (8s)
  3. Full Ports        — todos los 1000 puertos estándar (30s)
  4. Service Versions  — nmap -sV detección de servicios (45s)
  5. OS Detection      — nmap -O detección de SO (30s)
  6. Scripts Seguros   — nmap --script=safe (60s)
  7. Vuln Scan         — nmap --script=vuln (120s)
  8. UDP Top 20        — puertos UDP más comunes (20s)
"""

import subprocess
import threading
import re
from datetime import datetime

# Log global — se reemplaza desde app.py
_log_fn = None

def set_log_callback(fn):
    global _log_fn
    _log_fn = fn

def _log(msg):
    ts = datetime.now().strftime('%H:%M:%S')
    print(f"[{ts}] {msg}")
    if _log_fn:
        try: _log_fn(msg)
        except: pass


# ─────────────────────────────────────────────────────────
# DEFINICIÓN DE ESCANEOS
# ─────────────────────────────────────────────────────────

ESCANEOS = [
    {
        "id":      "ping",
        "nombre":  "🟢 Ping Check",
        "desc":    "¿Sigue activo? (2s)",
        "cmd":     ["nmap", "-sn", "-Pn", "--host-timeout", "3s"],
        "timeout": 8,
    },
    {
        "id":      "quick",
        "nombre":  "⚡ Quick Ports",
        "desc":    "Top 20 puertos rápido (8s)",
        "cmd":     ["nmap", "-Pn", "--top-ports", "20",
                    "--open", "--host-timeout", "6s"],
        "timeout": 15,
    },
    {
        "id":      "standard",
        "nombre":  "🔍 Standard Scan",
        "desc":    "1000 puertos estándar (30s)",
        "cmd":     ["nmap", "-Pn", "--host-timeout", "8s", "--open"],
        "timeout": 60,
    },
    {
        "id":      "versions",
        "nombre":  "🏷  Service Versions",
        "desc":    "Detección de servicios y versiones (45s)",
        "cmd":     ["nmap", "-Pn", "-sV", "--version-intensity", "5",
                    "--host-timeout", "10s", "--open",
                    "-p", "21,22,23,25,53,80,110,143,443,445,"
                           "554,3306,3389,5432,5900,6379,8000,"
                           "8080,8443,8554,9010,9100,27017"],
        "timeout": 90,
    },
    {
        "id":      "os",
        "nombre":  "💻 OS Detection",
        "desc":    "Detección de sistema operativo (30s)",
        "cmd":     ["nmap", "-Pn", "-O", "--osscan-guess",
                    "--host-timeout", "8s",
                    "-p", "22,80,443,445,3389"],
        "timeout": 60,
    },
    {
        "id":      "scripts",
        "nombre":  "📜 Safe Scripts",
        "desc":    "Scripts de reconocimiento seguros (60s)",
        "cmd":     ["nmap", "-Pn", "-sC", "--script=safe",
                    "--host-timeout", "12s", "--open",
                    "-p", "22,23,25,80,110,143,443,445,"
                           "554,3306,3389,5900,8080,8443"],
        "timeout": 120,
    },
    {
        "id":      "vuln",
        "nombre":  "🔴 Vuln Scan",
        "desc":    "Detección de vulnerabilidades (2min)",
        "cmd":     ["nmap", "-Pn", "--script=vuln",
                    "--host-timeout", "20s", "--open",
                    "-p", "21,22,23,25,80,110,143,443,445,"
                           "3306,3389,5432,5900,8080,8443"],
        "timeout": 180,
    },
    {
        "id":      "udp",
        "nombre":  "📡 UDP Top Ports",
        "desc":    "Top 20 puertos UDP (20s)",
        "cmd":     ["nmap", "-sU", "--top-ports", "20",
                    "--host-timeout", "8s", "-Pn"],
        "timeout": 60,
    },
]


# ─────────────────────────────────────────────────────────
# MOTOR DE ESCANEO
# ─────────────────────────────────────────────────────────

class Arsenal:
    """Ejecuta escaneos nmap individuales por IP en hilos daemon."""

    def __init__(self, callback=None):
        """
        callback_resultado(ip, escaneo_id, titulo, texto, puertos)
        Se llama cuando termina cada escaneo. Se pueden añadir más con
        añadir_listener().
        """
        self._listeners = []
        if callback:
            self._listeners.append(callback)
        self._activos = {}   # {ip:id: threading.Thread}
        self._lock    = threading.Lock()

    def añadir_listener(self, fn):
        """Añade un listener adicional para resultados."""
        if fn not in self._listeners:
            self._listeners.append(fn)

    def quitar_listener(self, fn):
        """Quita un listener."""
        try: self._listeners.remove(fn)
        except ValueError: pass

    # Compatibilidad con código que asigna .callback directamente
    @property
    def callback(self):
        return self._listeners[0] if self._listeners else None

    @callback.setter
    def callback(self, fn):
        if fn and fn not in self._listeners:
            self._listeners.append(fn)

    def esta_corriendo(self, ip, escaneo_id):
        key = f"{ip}:{escaneo_id}"
        with self._lock:
            t = self._activos.get(key)
            return t is not None and t.is_alive()

    def lanzar(self, ip, escaneo_id):
        """Lanza el escaneo en background. Si ya corre, ignora."""
        escaneo = next((e for e in ESCANEOS if e["id"] == escaneo_id), None)
        if not escaneo:
            _log(f"[ARSENAL] Escaneo desconocido: {escaneo_id}")
            return

        key = f"{ip}:{escaneo_id}"
        if self.esta_corriendo(ip, escaneo_id):
            _log(f"[ARSENAL] {escaneo_id} en {ip} ya está corriendo")
            return

        hilo = threading.Thread(
            target=self._ejecutar,
            args=(ip, escaneo),
            daemon=True,
            name=f"arsenal-{escaneo_id}-{ip}"
        )
        with self._lock:
            self._activos[key] = hilo
        hilo.start()
        _log(f"[ARSENAL] Iniciando {escaneo['nombre']} en {ip}...")

    def _ejecutar(self, ip, escaneo):
        key = f"{ip}:{escaneo['id']}"
        try:
            cmd = escaneo["cmd"] + [ip]
            _log(f"[ARSENAL] CMD: {' '.join(cmd)}")
            resultado = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=escaneo["timeout"]
            )
            salida = resultado.stdout.strip()
            if resultado.stderr.strip():
                salida += "\n--- STDERR ---\n" + resultado.stderr.strip()

            if not salida:
                salida = "(Sin resultados — el host puede estar filtrando)"

            _log(f"[ARSENAL] {escaneo['nombre']} en {ip} completado "
                 f"({len(salida.splitlines())} líneas)")

            # Extraer puertos del resultado para actualizar el nodo
            puertos_nuevos = _extraer_puertos(salida)

            self._notificar(
                ip=ip,
                escaneo_id=escaneo["id"],
                titulo=escaneo["nombre"],
                texto=salida,
                puertos=puertos_nuevos,
            )

        except subprocess.TimeoutExpired:
            msg = f"Timeout ({escaneo['timeout']}s) — escaneo cancelado"
            _log(f"[ARSENAL] Timeout en {escaneo['id']} para {ip}")
            self._notificar(ip=ip, escaneo_id=escaneo["id"],
                            titulo=escaneo["nombre"], texto=msg, puertos=[])
        except Exception as e:
            msg = f"Error: {type(e).__name__}: {e}"
            _log(f"[ARSENAL] Error en {escaneo['id']} para {ip}: {e}")
            self._notificar(ip=ip, escaneo_id=escaneo["id"],
                            titulo=escaneo["nombre"], texto=msg, puertos=[])
        finally:
            with self._lock:
                self._activos.pop(key, None)

    def _notificar(self, **kwargs):
        """Notifica a todos los listeners registrados."""
        for fn in list(self._listeners):
            try:
                fn(**kwargs)
            except Exception as e:
                _log(f"[ARSENAL] Error en listener: {e}")


def _extraer_puertos(texto):
    """Extrae lista de puertos TCP abiertos del output de nmap."""
    puertos = []
    for linea in texto.splitlines():
        m = re.search(r'^(\d+)/tcp\s+open', linea)
        if m:
            try: puertos.append(int(m.group(1)))
            except: pass
    return puertos
