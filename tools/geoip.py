"""
geoip.py — Módulo GeoIP para TopoReveal
Lookup de IPs externas contra base de datos local MaxMind GeoLite2.

Funciona 100% offline — sin API, sin internet, sin límites.
La base de datos se descarga UNA SOLA VEZ con el instalador.

Uso:
    from tools.geoip import GeoIP
    geo = GeoIP()
    info = geo.lookup("47.241.18.77")
    # → {"pais": "China", "ciudad": "Shanghai", "org": "Alibaba Cloud",
    #     "iso": "CN", "bandera": "🇨🇳", "asn": "AS37963"}
"""

import os
import socket
import threading

# ── Ruta de la base de datos ──────────────────────────────────────
# Se busca en orden de prioridad
_RUTAS_DB = [
    # 1. Junto al proyecto
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "data", "GeoLite2-City.mmdb"),
    # 2. Carpeta del usuario real (cuando corre con sudo)
    os.path.expanduser("~/.local/share/toporeveal/GeoLite2-City.mmdb"),
    # 3. Ruta del usuario SUDO_USER
    os.path.join("/home",
                 os.environ.get("SUDO_USER", "root"),
                 ".local", "share", "toporeveal", "GeoLite2-City.mmdb"),
    # 4. Sistema
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
]

_RUTA_ASN_DB = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "data", "GeoLite2-ASN.mmdb"),
    os.path.join("/home",
                 os.environ.get("SUDO_USER", "root"),
                 ".local", "share", "toporeveal", "GeoLite2-ASN.mmdb"),
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
]

# ── Mapa de países ISO → nombre corto para terminal/tkinter ──────
# Los emojis de bandera (Regional Indicator) no se renderizan en
# la mayoría de terminales Linux ni en tkinter Listbox.
# Usamos el código ISO entre corchetes como sustituto visual claro.
_PAIS_CORTO = {
    "US": "USA", "CN": "China", "DE": "Alemania", "GB": "UK",
    "FR": "Francia", "BR": "Brasil", "JP": "Japón", "KR": "Corea",
    "RU": "Rusia", "IN": "India", "CA": "Canadá", "AU": "Australia",
    "NL": "Holanda", "SE": "Suecia", "SG": "Singapur", "HK": "Hong Kong",
    "CO": "Colombia", "MX": "México", "AR": "Argentina", "CL": "Chile",
    "PE": "Perú", "EC": "Ecuador", "VE": "Venezuela", "PA": "Panamá",
    "ES": "España", "IT": "Italia", "PL": "Polonia", "CH": "Suiza",
    "IE": "Irlanda", "FI": "Finlandia", "NO": "Noruega", "DK": "Dinamarca",
    "AT": "Austria", "BE": "Bélgica", "PT": "Portugal", "CZ": "Checoslovaq",
    "ZA": "S.África", "NG": "Nigeria", "EG": "Egipto", "KE": "Kenia",
    "IL": "Israel", "SA": "Arabia S", "AE": "Emirates", "TR": "Turquía",
    "ID": "Indonesia", "TH": "Tailandia", "VN": "Vietnam", "MY": "Malasia",
    "TW": "Taiwán", "NZ": "N.Zelanda", "UA": "Ucrania", "PK": "Pakistán",
}

def _iso_a_bandera(iso):
    """
    Convierte código ISO-2 a etiqueta legible en terminal y tkinter.
    Formato: [CO] en lugar de emoji de bandera que no renderiza.
    """
    if not iso or len(iso) != 2:
        return "[??]"
    return f"[{iso.upper()}]"

def _iso_a_pais_corto(iso):
    """Nombre corto del país para mostrar en panel."""
    if not iso:
        return ""
    return _PAIS_CORTO.get(iso.upper(), iso.upper())

# ── Resultado vacío ────────────────────────────────────────────────
_VACIO = {
    "pais"   : "Desconocido",
    "ciudad" : "",
    "org"    : "",
    "iso"    : "",
    "bandera": "[??]",
    "asn"    : "",
    "ok"     : False
}

# ── Caché en memoria ───────────────────────────────────────────────
_cache      = {}
_cache_lock = threading.Lock()


class GeoIP:
    """
    Lookup GeoIP usando base de datos local MaxMind GeoLite2.
    Thread-safe con caché en memoria para no releer el archivo.
    """

    def __init__(self):
        self._reader_city = None
        self._reader_asn  = None
        self._disponible  = False
        self._msg_error   = ""
        self._inicializar()

    def _inicializar(self):
        """Carga el reader de geoip2. Silencioso si no está disponible."""
        try:
            import geoip2.database
        except ImportError:
            self._msg_error = (
                "geoip2 no instalado. "
                "Ejecuta: pip install geoip2 --break-system-packages"
            )
            return

        # Buscar base de datos de ciudad
        for ruta in _RUTAS_DB:
            if os.path.exists(ruta):
                try:
                    self._reader_city = geoip2.database.Reader(ruta)
                    break
                except Exception:
                    continue

        # Buscar base de datos de ASN
        for ruta in _RUTA_ASN_DB:
            if os.path.exists(ruta):
                try:
                    self._reader_asn = geoip2.database.Reader(ruta)
                    break
                except Exception:
                    continue

        if self._reader_city:
            self._disponible = True
        else:
            self._msg_error = (
                "Base de datos GeoLite2-City.mmdb no encontrada. "
                "Ejecuta el instalador o descárgala manualmente."
            )

    @property
    def disponible(self):
        return self._disponible

    @property
    def mensaje_error(self):
        return self._msg_error

    def lookup(self, ip):
        """
        Devuelve info geográfica de una IP externa.
        Retorna dict con: pais, ciudad, org, iso, bandera, asn, ok.
        Resultado cacheado en memoria — lookup repetido es instantáneo.
        """
        if not ip:
            return dict(_VACIO)

        # IPs privadas/locales — no buscar
        if self._es_local(ip):
            return dict(_VACIO)

        # Cache
        with _cache_lock:
            if ip in _cache:
                return dict(_cache[ip])

        if not self._disponible:
            return dict(_VACIO)

        resultado = dict(_VACIO)
        try:
            # Ciudad / País
            resp = self._reader_city.city(ip)
            pais    = resp.country.name or "Desconocido"
            iso     = resp.country.iso_code or ""
            ciudad  = resp.city.name or ""
            resultado.update({
                "pais"   : pais,
                "ciudad" : ciudad,
                "iso"    : iso,
                "bandera": _iso_a_bandera(iso),
                "ok"     : True
            })
        except Exception:
            pass

        try:
            # ASN / Organización
            if self._reader_asn:
                resp_asn = self._reader_asn.asn(ip)
                org = resp_asn.autonomous_system_organization or ""
                asn = f"AS{resp_asn.autonomous_system_number}" \
                      if resp_asn.autonomous_system_number else ""
                resultado.update({"org": org, "asn": asn})
        except Exception:
            pass

        # Guardar en caché
        with _cache_lock:
            _cache[ip] = dict(resultado)

        return resultado

    def _es_local(self, ip):
        """True si la IP es privada, loopback o multicast."""
        try:
            partes = [int(x) for x in ip.split(".")]
            if len(partes) != 4:
                return True
            p = partes[0]
            # RFC 1918 privadas
            if p == 10: return True
            if p == 172 and 16 <= partes[1] <= 31: return True
            if p == 192 and partes[1] == 168: return True
            # Loopback, link-local, multicast, broadcast
            if p == 127: return True
            if p == 169 and partes[1] == 254: return True
            if p >= 224: return True
            return False
        except Exception:
            return True

    def formato_corto(self, ip):
        """
        Devuelve string compacto para el panel lateral y el log.
        Ejemplo: '[CN] Alibaba Cloud · Shanghai'
        """
        info = self.lookup(ip)
        if not info.get("ok"):
            return ""
        iso    = info.get("iso", "")
        tag    = f"[{iso}]" if iso else "[??]"
        org    = info.get("org", "")
        if len(org) > 20:
            org = org[:18] + "…"
        ciudad = info.get("ciudad", "") or _iso_a_pais_corto(iso)
        texto  = f"{org} · {ciudad}" if org and ciudad else (org or ciudad)
        return f"{tag} {texto}"

    def formato_completo(self, ip):
        """
        Devuelve string completo para tooltip o informe.
        Ejemplo: '[CN] China · Shanghai · Alibaba Cloud (AS37963)'
        """
        info = self.lookup(ip)
        if not info.get("ok"):
            return ip
        iso  = info.get("iso", "")
        tag  = f"[{iso}]" if iso else "[??]"
        pais = _iso_a_pais_corto(iso) or info.get("pais", "")
        partes = [tag, pais]
        if info.get("ciudad"):
            partes.append(info["ciudad"])
        if info.get("org"):
            partes.append(info["org"])
        if info.get("asn"):
            partes.append(f"({info['asn']})")
        return " · ".join(partes)

    def cerrar(self):
        """Cierra los readers de base de datos."""
        try:
            if self._reader_city: self._reader_city.close()
            if self._reader_asn:  self._reader_asn.close()
        except Exception:
            pass


# ── Instancia global (singleton) ─────────────────────────────────
# Se importa desde app.py y se pasa a los módulos que lo necesitan
_instancia = None
_instancia_lock = threading.Lock()

def obtener_geoip():
    """Retorna la instancia singleton de GeoIP."""
    global _instancia
    with _instancia_lock:
        if _instancia is None:
            _instancia = GeoIP()
    return _instancia
