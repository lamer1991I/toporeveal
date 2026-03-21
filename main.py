#!/usr/bin/env python3
"""
TopoReveal — Network Topology Viewer
Requiere sudo para capturar paquetes.

Uso:
    sudo python3 main.py
"""

import os
import sys

def verificar_sudo():
    """Cierra el programa si no se está ejecutando con sudo."""
    if os.geteuid() != 0:
        print("╔══════════════════════════════════════╗")
        print("║  TopoReveal necesita permisos root   ║")
        print("║  Usa: sudo python3 main.py           ║")
        print("╚══════════════════════════════════════╝")
        sys.exit(1)

def verificar_dependencias():
    """Verifica que scapy y tkinter estén instalados."""
    errores = []

    try:
        import tkinter
    except ImportError:
        errores.append("tkinter  → sudo apt install python3-tk")

    try:
        import scapy
    except ImportError:
        errores.append("scapy    → pip install scapy")

    try:
        import subprocess
        resultado = subprocess.run(
            ["nmap", "--version"],
            capture_output=True, timeout=5
        )
        if resultado.returncode != 0:
            errores.append("nmap     → sudo apt install nmap")
    except FileNotFoundError:
        errores.append("nmap     → sudo apt install nmap")

    if errores:
        print("╔══════════════════════════════════════╗")
        print("║  Faltan dependencias:                ║")
        for e in errores:
            print(f"║  • {e:<36}║")
        print("╠══════════════════════════════════════╣")
        print("║  O ejecuta: bash install.sh          ║")
        print("╚══════════════════════════════════════╝")
        sys.exit(1)

if __name__ == "__main__":
    verificar_sudo()
    verificar_dependencias()

    from ui.app import App
    app = App()
    app.iniciar()
