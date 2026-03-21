#!/usr/bin/env python3
"""
descargar_geoip.py — Descarga la base de datos GeoLite2 de MaxMind
Se ejecuta UNA SOLA VEZ durante la instalación o setup inicial.

Uso:
    sudo python3 tools/descargar_geoip.py

La base se guarda en: data/GeoLite2-City.mmdb
                       data/GeoLite2-ASN.mmdb
"""

import os
import sys
import urllib.request
import tarfile
import shutil

# URL de descarga directa desde db-ip.com (alternativa libre a MaxMind)
# db-ip ofrece bases GeoLite2-compatibles sin registro
BASES = [
    {
        "nombre": "GeoLite2-City.mmdb",
        "url": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
        "alternativa": "https://git.io/GeoLite2-City.mmdb"
    },
    {
        "nombre": "GeoLite2-ASN.mmdb",
        "url": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb",
        "alternativa": "https://git.io/GeoLite2-ASN.mmdb"
    }
]

def descargar(nombre, url, destino):
    print(f"  Descargando {nombre}...", end=" ", flush=True)
    try:
        urllib.request.urlretrieve(url, destino)
        size_mb = os.path.getsize(destino) / 1024 / 1024
        print(f"✓ ({size_mb:.1f} MB)")
        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def main():
    # Carpeta data/ relativa al proyecto
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(base_dir, "data")
    os.makedirs(data_dir, exist_ok=True)

    print("TopoReveal — Descarga de base de datos GeoIP")
    print("=" * 50)
    print(f"Destino: {data_dir}")
    print()

    exito = 0
    for base in BASES:
        destino = os.path.join(data_dir, base["nombre"])
        if os.path.exists(destino):
            size_mb = os.path.getsize(destino) / 1024 / 1024
            print(f"  {base['nombre']} ya existe ({size_mb:.1f} MB) — omitiendo")
            exito += 1
            continue

        ok = descargar(base["nombre"], base["url"], destino)
        if not ok and base.get("alternativa"):
            print(f"  Intentando alternativa...", end=" ", flush=True)
            ok = descargar(base["nombre"], base["alternativa"], destino)
        if ok:
            exito += 1

    print()
    if exito == len(BASES):
        print("✓ Bases de datos GeoIP instaladas correctamente.")
        print("  TopoReveal mostrará banderas y organizaciones en conexiones externas.")
    else:
        print("⚠ Algunas bases no se descargaron.")
        print("  GeoIP funcionará parcialmente o estará deshabilitado.")
        print()
        print("  Descarga manual:")
        print("  https://github.com/P3TERX/GeoLite.mmdb")
        print(f"  Copiar .mmdb a: {data_dir}/")

    # Verificar que geoip2 está instalado
    try:
        import geoip2
        print()
        print("✓ librería geoip2 disponible.")
    except ImportError:
        print()
        print("⚠ Falta instalar la librería:")
        print("  pip install geoip2 --break-system-packages")

if __name__ == "__main__":
    main()
