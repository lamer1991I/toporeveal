"""
beacon_detector.py — Detección de C2 Beacon por análisis de intervalos.

Un beacon C2 es una conexión que un malware hace periódicamente
al servidor de comando y control. Características clave:
  - Mismo host origen → misma IP destino
  - Intervalos de tiempo muy regulares (jitter bajo)
  - Puede ser TCP o UDP
  - Ejemplos reales: Cobalt Strike (~60s), Metasploit (~5s),
    Hikvision backdoor (~60s hacia HUAWEI CLOUDS)

Algoritmo:
  1. Por cada par (ip_local, ip_externa) registramos timestamps
  2. Calculamos los intervalos entre conexiones sucesivas
  3. Si hay ≥ MIN_HITS intervalos con desviación estándar < JITTER_MAX
     → confirmamos beacon y generamos hallazgo CRÍTICO/ALTO
"""

import threading
import math
from datetime import datetime
from collections import defaultdict

# ── Parámetros de detección ───────────────────────────────────────────────────
MIN_HITS         = 4       # mínimo de intervalos para confirmar (evita falsos positivos)
JITTER_MAX_PCT   = 0.20    # desviación estándar / media ≤ 20% → beacon confirmado
JITTER_WARN_PCT  = 0.35    # entre 20-35% → posible beacon (alerta menor)
INTERVALO_MIN    = 5       # segundos — ignorar conexiones más frecuentes (son normales)
INTERVALO_MAX    = 600     # segundos — 10 min max, más que eso es ruido estadístico
MAX_TIMESTAMPS   = 30      # máximo de timestamps por par para no crecer infinito

# IPs que NUNCA son C2 — CDNs, DNS, NTP conocidos
WHITELIST_IPS = {
    "8.8.8.8", "8.8.4.4",          # Google DNS
    "1.1.1.1", "1.0.0.1",          # Cloudflare DNS
    "200.24.51.144",                 # UNE Colombia DNS
    "190.240.115.151",               # UNE Colombia DNS alternativo
    "224.0.0.1", "224.0.0.251",      # Multicast
    "239.255.255.250",               # SSDP multicast
    "255.255.255.255",               # Broadcast
}

# Organizaciones conocidas como CDN/legítimas (por prefijo de org en GeoIP)
WHITELIST_ORGS = {
    "akamai", "cloudflare", "fastly", "google",
    "amazon", "microsoft", "facebook", "apple",
}

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

_log_fn = None

def set_log_callback(fn):
    global _log_fn
    _log_fn = fn

def _log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    if _log_fn:
        try:
            _log_fn(msg)
        except Exception:
            pass


class BeaconDetector:
    """
    Analiza el tráfico capturado en busca de patrones C2 beacon.

    Uso:
        detector = BeaconDetector(callback_hallazgo)
        # En cada paquete capturado:
        detector.registrar(ip_local, ip_externa, protocolo, geo_org)
        # El callback se llama cuando se detecta un beacon:
        # callback(ip_local, ip_externa, intervalo_seg, jitter_pct, protocolo)
    """

    def __init__(self, callback=None, callback_alerta=None):
        """
        callback / callback_alerta(ip_local, ip_ext, intervalo_seg, jitter_pct, proto, n_hits)
        Acepta ambos nombres para compatibilidad.
        """
        self.callback  = callback or callback_alerta
        self._lock     = threading.Lock()

        # {(ip_local, ip_ext): [timestamp, timestamp, ...]}
        self._timestamps: dict = defaultdict(list)

        # {(ip_local, ip_ext): True} — pares ya alertados para no duplicar
        self._alertados: set = set()

    def registrar(self, ip_local: str, ip_ext: str,
                  protocolo: str = "TCP", org: str = ""):
        """
        Registra una conexión y evalúa si hay patrón beacon.
        Llamar desde app.py en _on_externo, solo para IPs externas.
        """
        if not ip_local or not ip_ext:
            return

        # Filtrar IPs no relevantes
        if ip_ext in WHITELIST_IPS:
            return
        if ip_ext.startswith(("224.", "239.", "255.", "127.", "0.")):
            return

        # Filtrar organizaciones CDN conocidas
        if org:
            org_lower = org.lower()
            if any(w in org_lower for w in WHITELIST_ORGS):
                return

        clave = (ip_local, ip_ext)
        ahora = datetime.now().timestamp()

        with self._lock:
            lista = self._timestamps[clave]

            # Si la última conexión fue hace menos de INTERVALO_MIN segundos,
            # es la misma "ráfaga" — no la registramos como nuevo beacon tick
            if lista and (ahora - lista[-1]) < INTERVALO_MIN:
                return

            lista.append(ahora)

            # Limitar tamaño
            if len(lista) > MAX_TIMESTAMPS:
                self._timestamps[clave] = lista[-MAX_TIMESTAMPS:]
                lista = self._timestamps[clave]

            # Necesitamos al menos MIN_HITS + 1 timestamps para tener MIN_HITS intervalos
            if len(lista) < MIN_HITS + 1:
                return

            # Ya alertado — reevaluar cada 5 hits nuevos para detectar cambios
            if clave in self._alertados:
                if len(lista) % 5 != 0:
                    return

            # Calcular intervalos
            intervalos = [
                lista[i+1] - lista[i]
                for i in range(len(lista) - 1)
            ]

            # Filtrar intervalos fuera del rango razonable
            intervalos = [t for t in intervalos
                          if INTERVALO_MIN <= t <= INTERVALO_MAX]

            if len(intervalos) < MIN_HITS:
                return

            media  = sum(intervalos) / len(intervalos)
            if media < INTERVALO_MIN:
                return

            # Desviación estándar
            varianza = sum((t - media) ** 2 for t in intervalos) / len(intervalos)
            std      = math.sqrt(varianza)
            jitter   = std / media  # coeficiente de variación

            # Evaluar resultado
            if jitter <= JITTER_MAX_PCT:
                nivel = "confirmado"
            elif jitter <= JITTER_WARN_PCT:
                nivel = "posible"
            else:
                return  # demasiado irregular

            if clave not in self._alertados or nivel == "confirmado":
                self._alertados.add(clave)
                _log(f"[BEACON] {nivel.upper()} | {ip_local} → {ip_ext} | "
                     f"intervalo: {media:.1f}s ± {std:.1f}s | "
                     f"jitter: {jitter*100:.1f}% | hits: {len(lista)}")
                self.callback(
                    ip_local, ip_ext,
                    round(media, 1),
                    round(jitter * 100, 1),
                    protocolo,
                    len(lista),
                    nivel
                )

    def limpiar(self):
        """Limpia todos los datos acumulados (para nueva sesión)."""
        with self._lock:
            self._timestamps.clear()
            self._alertados.clear()

    def obtener_resumen(self) -> list:
        """
        Retorna lista de (ip_local, ip_ext, n_hits, media_seg, jitter_pct)
        para todos los pares con suficientes datos.
        """
        resultado = []
        with self._lock:
            for clave, lista in self._timestamps.items():
                if len(lista) < MIN_HITS + 1:
                    continue
                intervalos = [
                    lista[i+1] - lista[i]
                    for i in range(len(lista) - 1)
                    if INTERVALO_MIN <= lista[i+1] - lista[i] <= INTERVALO_MAX
                ]
                if len(intervalos) < MIN_HITS:
                    continue
                media  = sum(intervalos) / len(intervalos)
                std    = math.sqrt(
                    sum((t - media)**2 for t in intervalos) / len(intervalos))
                jitter = std / media
                resultado.append({
                    "ip_local" : clave[0],
                    "ip_ext"   : clave[1],
                    "n_hits"   : len(lista),
                    "intervalo": round(media, 1),
                    "jitter"   : round(jitter * 100, 1),
                    "alertado" : clave in self._alertados,
                })
        return sorted(resultado, key=lambda x: x["jitter"])
