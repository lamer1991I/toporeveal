"""
rutas.py — Rutas del proyecto TopoReveal.

Detecta automáticamente dónde está instalado el proyecto
usando la ubicación de este archivo como referencia.
Funciona sin importar dónde esté instalado.
"""

import os

# Directorio raíz del proyecto — donde está este archivo (core/)
# subimos un nivel para llegar a la raíz
_RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def raiz():
    """Retorna la ruta raíz del proyecto."""
    return _RAIZ


def logs():
    """Carpeta de logs de sesión."""
    ruta = os.path.join(_RAIZ, "logs")
    os.makedirs(ruta, exist_ok=True)
    return ruta


def exports():
    """Carpeta de exportaciones (PDF, CSV, JSON, PNG)."""
    ruta = os.path.join(_RAIZ, "exports")
    os.makedirs(ruta, exist_ok=True)
    return ruta


def data():
    """Carpeta de datos (GeoIP, etc.)."""
    ruta = os.path.join(_RAIZ, "data")
    os.makedirs(ruta, exist_ok=True)
    return ruta


def historial_db():
    """Ruta de la base de datos SQLite de historial."""
    return os.path.join(_RAIZ, "toporeveal_history.db")


def geoip_city():
    """Ruta del archivo GeoLite2-City.mmdb."""
    return os.path.join(_RAIZ, "data", "GeoLite2-City.mmdb")


def geoip_asn():
    """Ruta del archivo GeoLite2-ASN.mmdb."""
    return os.path.join(_RAIZ, "data", "GeoLite2-ASN.mmdb")


def assets_icons():
    """Carpeta de iconos."""
    return os.path.join(_RAIZ, "assets", "icons")
