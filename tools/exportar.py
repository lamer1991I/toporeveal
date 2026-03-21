"""
exportar.py — Exportación de datos de la red.
  - PNG del canvas (captura via PIL)
  - JSON completo de todos los nodos
  - CSV de hosts para análisis
  - Log de texto (ya existente, aquí lo estandarizamos)
"""

import os
import json
import csv
import time
import subprocess
from datetime import datetime

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def _carpeta_salida():
    """Carpeta de exports usando home del usuario real."""
    import pwd
    usuario = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
    try:
        home = pwd.getpwnam(usuario).pw_dir
    except Exception:
        home = os.path.expanduser("~")
    carpeta = os.path.join(home, "Proyectos", "toporeveal", "exports")
    os.makedirs(carpeta, exist_ok=True)
    return carpeta


def _timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


# ─────────────────────────────────────────────────────────────────
# PNG DEL CANVAS
# ─────────────────────────────────────────────────────────────────

def exportar_png_canvas(canvas_widget, ventana_raiz):
    """
    Captura el canvas de Tkinter como PNG.
    Usa xwd + ImageMagick si están disponibles, o PIL con grab.
    Devuelve ruta del archivo o None si falla.
    """
    carpeta = _carpeta_salida()
    ruta = os.path.join(carpeta, f"topologia_{_timestamp()}.png")

    try:
        # Método 1: PIL ImageGrab (funciona en la mayoría de sistemas)
        from PIL import ImageGrab
        ventana_raiz.update()
        x = canvas_widget.winfo_rootx()
        y = canvas_widget.winfo_rooty()
        w = canvas_widget.winfo_width()
        h = canvas_widget.winfo_height()
        img = ImageGrab.grab(bbox=(x, y, x+w, y+h))
        img.save(ruta, "PNG")
        log(f"[EXPORT] PNG guardado: {ruta}")
        return ruta
    except Exception as e1:
        log(f"[EXPORT] PIL grab falló: {e1}, intentando xwd...")

    try:
        # Método 2: xwd (X11)
        wid = canvas_widget.winfo_id()
        ruta_xwd = ruta.replace(".png", ".xwd")
        r1 = subprocess.run(
            ["xwd", "-id", str(wid), "-out", ruta_xwd],
            capture_output=True, timeout=10)
        if r1.returncode == 0:
            subprocess.run(
                ["convert", ruta_xwd, ruta],
                capture_output=True, timeout=10)
            os.remove(ruta_xwd)
            log(f"[EXPORT] PNG (xwd) guardado: {ruta}")
            return ruta
    except Exception as e2:
        log(f"[EXPORT] xwd falló: {e2}")

    # Método 3: screenshot de toda la ventana con scrot
    try:
        ventana_raiz.update()
        xoff = canvas_widget.winfo_rootx()
        yoff = canvas_widget.winfo_rooty()
        w = canvas_widget.winfo_width()
        h = canvas_widget.winfo_height()
        subprocess.run(
            ["scrot", "-a", f"{xoff},{yoff},{w},{h}", ruta],
            capture_output=True, timeout=10)
        log(f"[EXPORT] PNG (scrot) guardado: {ruta}")
        return ruta
    except Exception as e3:
        log(f"[EXPORT] scrot falló: {e3}")

    log("[EXPORT] No se pudo exportar PNG — instala python3-pil o scrot")
    return None


# ─────────────────────────────────────────────────────────────────
# JSON COMPLETO
# ─────────────────────────────────────────────────────────────────

def exportar_json(topologia):
    """Exporta todos los nodos con todos sus datos a JSON."""
    carpeta = _carpeta_salida()
    ruta = os.path.join(carpeta, f"red_{_timestamp()}.json")

    datos = {
        "generado":  datetime.now().isoformat(),
        "gateway":   topologia.gateway or topologia.router or "—",
        "subred":    topologia.subred or "—",
        "ip_local":  topologia.ip_local or "—",
        "hosts":     [],
        "alertas":   [],
        "subredes_secundarias": []
    }

    for nodo in topologia.todos_los_nodos():
        h = {
            "ip":            nodo.ip,
            "mac":           nodo.mac or "—",
            "tipo":          nodo.tipo,
            "fabricante":    nodo.fabricante,
            "sistema_op":    nodo.sistema_op,
            "estado":        nodo.estado,
            "en_lobby":      nodo.en_lobby,
            "paquetes":      nodo.paquetes,
            "puertos":       sorted(list(nodo.puertos_abiertos)),
            "risk_score":    getattr(nodo, "risk_score", 0),
            "severidad_max": getattr(nodo, "severidad_max", None),
            "perfiles":      [p[0] for p in getattr(nodo, "perfiles", [])],
            "hallazgos":     [
                {"puerto": ha.puerto, "servicio": ha.servicio,
                 "severidad": ha.severidad, "detalle": ha.detalle,
                 "timestamp": ha.timestamp}
                for ha in getattr(nodo, "hallazgos", [])
            ]
        }
        datos["hosts"].append(h)

    for alerta in topologia.alertas:
        datos["alertas"].append({
            "ip":        alerta.ip,
            "puerto":    alerta.puerto,
            "servicio":  alerta.servicio,
            "severidad": alerta.severidad,
            "detalle":   alerta.detalle,
            "timestamp": alerta.timestamp,
        })

    # Subredes secundarias detectadas
    if hasattr(topologia, 'obtener_subredes'):
        for sub in topologia.obtener_subredes():
            datos["subredes_secundarias"].append({
                "prefijo":      sub.prefijo,
                "tipo":         sub.tipo,
                "descripcion":  sub.desc,
                "primer_visto": sub.primer_visto,
                "n_paquetes":   sub.n_paquetes,
                "hosts": [
                    {"ip": ip, "paquetes": n.paquetes}
                    for ip, n in sub.nodos.items()
                ]
            })

    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=2, ensure_ascii=False)

    log(f"[EXPORT] JSON guardado: {ruta}")
    return ruta


# ─────────────────────────────────────────────────────────────────
# CSV DE HOSTS
# ─────────────────────────────────────────────────────────────────

def exportar_csv(topologia):
    """Exporta lista de hosts a CSV — fácil de abrir en LibreOffice/Excel."""
    carpeta = _carpeta_salida()
    ruta = os.path.join(carpeta, f"hosts_{_timestamp()}.csv")

    campos = ["IP","MAC","Tipo","Fabricante","Sistema","Estado",
              "Paquetes","Puertos","RiskScore","Severidad","Perfiles","Alertas"]

    with open(ruta, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        for nodo in sorted(topologia.todos_los_nodos(),
                           key=lambda n: [int(x) for x in n.ip.split(".")]):
            w.writerow({
                "IP":        nodo.ip,
                "MAC":       nodo.mac or "—",
                "Tipo":      nodo.tipo,
                "Fabricante":nodo.fabricante,
                "Sistema":   nodo.sistema_op,
                "Estado":    nodo.estado,
                "Paquetes":  nodo.paquetes,
                "Puertos":   " ".join(str(p) for p in sorted(nodo.puertos_abiertos)),
                "RiskScore": getattr(nodo, "risk_score", 0),
                "Severidad": getattr(nodo, "severidad_max", "—") or "—",
                "Perfiles":  " | ".join(p[0] for p in getattr(nodo, "perfiles", [])),
                "Alertas":   len(getattr(nodo, "hallazgos", [])),
            })

    log(f"[EXPORT] CSV guardado: {ruta}")
    return ruta
