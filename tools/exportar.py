"""
exportar.py — Exportación de datos de TopoReveal.

Formatos:
  - PNG   : captura del canvas de topología
  - JSON  : estructura completa para importar en SIEMs, BloodHound, etc.
  - CSV   : tablas separadas para hosts, hallazgos y conexiones externas
"""

import os
import json
import csv
from datetime import datetime


def _carpeta_exports():
    usuario = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
    try:
        import pwd
        home = pwd.getpwnam(usuario).pw_dir
    except Exception:
        home = os.path.expanduser("~")
    carpeta = os.path.join(home, "Proyectos", "toporeveal", "exports")
    os.makedirs(carpeta, exist_ok=True)
    return carpeta


def exportar_png_canvas(canvas_widget, ruta=None):
    """Exporta el canvas de topología como PNG."""
    if not ruta:
        ts  = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        ruta = os.path.join(_carpeta_exports(), f"topologia_{ts}.png")
    try:
        import subprocess
        # Usar xwd + convert (ImageMagick) como fallback universal
        x  = canvas_widget.winfo_rootx()
        y  = canvas_widget.winfo_rooty()
        w  = canvas_widget.winfo_width()
        h  = canvas_widget.winfo_height()
        subprocess.run([
            "import", "-window", "root",
            "-crop", f"{w}x{h}+{x}+{y}",
            ruta], check=True, capture_output=True)
    except Exception:
        try:
            # Fallback: PostScript → PNG
            ps_ruta = ruta.replace(".png", ".ps")
            canvas_widget.postscript(file=ps_ruta, colormode="color")
            subprocess.run(["gs", "-dNOPAUSE", "-dBATCH",
                "-sDEVICE=pngalpha", f"-sOutputFile={ruta}", ps_ruta],
                capture_output=True)
            os.remove(ps_ruta)
        except Exception as e:
            raise RuntimeError(f"No se pudo exportar PNG: {e}")
    return ruta


# ── JSON ──────────────────────────────────────────────────────────────────────

def exportar_json(topologia, log_buffer=None, hora_inicio=None, ruta=None):
    """
    Exporta toda la información de la sesión en JSON completo.
    Compatible con importación en SIEMs, BloodHound, Splunk, etc.
    """
    if not ruta:
        ts   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        ruta = os.path.join(_carpeta_exports(), f"toporeveal_{ts}.json")

    hora_fin = datetime.now()
    buf_str  = "\n".join(str(l) for l in (log_buffer or []))

    nodos    = list(topologia.todos_los_nodos())
    activos  = [n for n in nodos if not n.en_lobby]
    en_lobby = [n for n in nodos if n.en_lobby]
    alertas  = list(getattr(topologia, 'alertas', []))
    externos = getattr(topologia, 'externos', {})
    geo_cache= getattr(topologia, '_geo_cache', {})

    # Score de riesgo
    sev_c = {}
    for h in alertas:
        sev_c[h.severidad] = sev_c.get(h.severidad, 0) + 1
    score = 0
    if sev_c.get('critico',0): score += min(4, sev_c['critico'])
    if sev_c.get('alto',0):    score += min(3, sev_c['alto'])
    if sev_c.get('medio',0):   score += min(2, sev_c['medio'])
    if "[BEACON] CONFIRMADO" in buf_str: score += 2
    score = min(10, score)

    # Extraer beacons del log
    import re
    beacons_raw = re.findall(
        r'\[BEACON\] CONFIRMADO \| (\S+) → (\S+) \| intervalo: ([\d.]+)s',
        buf_str)
    beacons = [{"ip_src":b[0],"ip_dst":b[1],"intervalo_s":float(b[2])}
               for b in beacons_raw]

    # Construcción del JSON
    data = {
        "meta": {
            "herramienta"   : "TopoReveal v2.0",
            "version"       : "2.0.0",
            "fecha_inicio"  : hora_inicio.isoformat() if hora_inicio else None,
            "fecha_fin"     : hora_fin.isoformat(),
            "duracion_s"    : int((hora_fin - hora_inicio).total_seconds())
                              if hora_inicio else None,
            "gateway"       : topologia.gateway,
            "subred"        : f"{topologia.subred}.0/24" if topologia.subred else None,
            "riesgo_global" : score,
            "nivel_riesgo"  : ("critico" if score>=8 else "alto" if score>=5
                               else "medio" if score>=3 else "bajo"),
        },
        "resumen": {
            "hosts_activos"     : len(activos),
            "hosts_lobby"       : len(en_lobby),
            "hosts_total_sesion": len(nodos),
            "alertas_critico"   : sev_c.get('critico', 0),
            "alertas_alto"      : sev_c.get('alto', 0),
            "alertas_medio"     : sev_c.get('medio', 0),
            "alertas_info"      : sev_c.get('info', 0),
            "alertas_total"     : len(alertas),
            "puertos_abiertos"  : sum(len(n.puertos_abiertos) for n in activos),
            "conexiones_externas": sum(len(v) for v in externos.values()),
            "beacons_c2"        : len(beacons),
        },
        "hosts": [_nodo_a_dict(n) for n in sorted(
            activos, key=lambda n: [int(x) for x in n.ip.split(".")])],
        "hosts_lobby": [_nodo_a_dict(n) for n in en_lobby],
        "hallazgos": [_hallazgo_a_dict(h) for h in sorted(
            alertas,
            key=lambda h: {"critico":0,"alto":1,"medio":2,"info":3}.get(
                h.severidad, 4))],
        "conexiones_externas": _externos_a_dict(externos, geo_cache),
        "beacons_c2": beacons,
        "subredes_secundarias": _subredes_a_dict(topologia),
        "cobertura_herramientas": _cobertura_a_dict(topologia, buf_str, alertas),
    }

    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)

    return ruta


def _nodo_a_dict(n):
    return {
        "ip"           : n.ip,
        "mac"          : n.mac or "",
        "hostname"     : getattr(n, 'hostname', '') or "",
        "tipo"         : n.tipo or "desconocido",
        "fabricante"   : n.fabricante or "",
        "sistema_op"   : n.sistema_op or "",
        "estado"       : n.estado or "",
        "risk_score"   : getattr(n, 'risk_score', 0) or 0,
        "severidad_max": n.severidad_max or "",
        "puertos"      : sorted(n.puertos_abiertos) if n.puertos_abiertos else [],
        "paquetes"     : n.paquetes,
        "perfiles"     : getattr(n, 'perfiles', []) or [],
        "ipv6"         : getattr(n, 'ip6', '') or "",
        "hallazgos"    : [_hallazgo_a_dict(h) for h in getattr(n, 'hallazgos', [])],
    }


def _hallazgo_a_dict(h):
    return {
        "ip"       : h.ip or "",
        "puerto"   : h.puerto if h.puerto else 0,
        "servicio" : h.servicio or "",
        "severidad": h.severidad or "info",
        "detalle"  : getattr(h, 'detalle', '') or getattr(h, 'desc', '') or "",
        "timestamp": getattr(h, 'timestamp', '') or "",
    }


def _externos_a_dict(externos, geo_cache):
    result = []
    for ip_src, lista in externos.items():
        for item in lista:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                ip_dst, proto = item[0], item[1]
            else:
                continue
            geo = geo_cache.get(ip_dst, {}) or {}
            result.append({
                "ip_origen" : ip_src,
                "ip_destino": ip_dst,
                "protocolo" : proto or "",
                "pais"      : geo.get("iso", ""),
                "ciudad"    : geo.get("ciudad", ""),
                "org"       : geo.get("org", ""),
            })
    return result


def _subredes_a_dict(topologia):
    result = []
    if hasattr(topologia, 'obtener_subredes'):
        for sub in topologia.obtener_subredes():
            result.append({
                "prefijo"     : sub.prefijo,
                "tipo"        : sub.tipo,
                "descripcion" : sub.desc,
                "n_hosts"     : len(sub.nodos),
                "n_paquetes"  : sub.n_paquetes,
                "primer_visto": sub.primer_visto,
            })
    return result


def _cobertura_a_dict(topologia, buf_str, alertas):
    def chk(cond): return "si" if cond else "no"
    return {
        "nivel1": {
            "hosts_descubiertos"  : chk(len(list(topologia.nodos.values())) > 0),
            "gateway_identificado": chk(bool(topologia.gateway)),
            "puertos_escaneados"  : chk(any(n.puertos_abiertos for n in topologia.nodos.values())),
            "trafico_externo"     : chk("[EXTERNO]" in buf_str),
            "flujos_internos"     : chk("[FLUJO]" in buf_str),
            "os_fingerprinting"   : chk(any(
                n.sistema_op and n.sistema_op != "Desconocido"
                for n in topologia.nodos.values())),
        },
        "nivel2": {
            "http"              : chk("HTTP" in buf_str),
            "ssl_tls"           : chk("SSL" in buf_str),
            "dhcp"              : chk("DHCP" in buf_str),
            "dns_interno"       : chk("DNS" in buf_str),
            "ntp"               : chk("NTP" in buf_str),
            "rtsp"              : chk("RTSP" in buf_str),
            "smb_shares"        : chk(any("Network Shares" in (h.servicio or "") for h in alertas)),
            "credenciales_default": chk(any("Cred. por Defecto" in (h.servicio or "") for h in alertas)),
        },
        "nivel3": {
            "active_directory"  : chk(any("DC/" in (h.servicio or "") for h in alertas)),
            "ldap"              : chk(any("LDAP" in (h.servicio or "") for h in alertas)),
            "kerberos"          : chk(any("Kerberos" in (h.servicio or "") for h in alertas)),
            "ssl_certificados"  : chk(any("SSL" in (h.servicio or "") for h in alertas)),
            "nfs"               : chk(any("NFS" in (h.servicio or "") for h in alertas)),
            "vpn_tuneles"       : chk("IPSec" in buf_str or "IKE" in buf_str),
        },
        "nivel4": {
            "ipv6"              : chk("[IPv6]" in buf_str),
            "llmnr_nbtns"       : chk("[LLMNR]" in buf_str or "[NBT-NS]" in buf_str),
            "wpad"              : chk("[WPAD]" in buf_str),
            "vlan_hopping"      : chk("[VLAN]" in buf_str),
            "cdp_lldp"          : chk("[CDP]" in buf_str or "[LLDP]" in buf_str),
            "dhcp_rogue"        : chk(any("DHCP Rogue" in (h.servicio or "") for h in alertas)),
        },
        "nivel5": {
            "ipmi_idrac"        : chk(any("IPMI" in (h.servicio or "") for h in alertas)),
            "beacon_c2"         : chk("[BEACON] CONFIRMADO" in buf_str),
            "ja3_fingerprinting": chk("[JA3]" in buf_str),
            "ntp_drift"         : chk("[NTP]" in buf_str and "offset" in buf_str.lower()),
        },
    }


# ── CSV ───────────────────────────────────────────────────────────────────────

def exportar_csv(topologia, log_buffer=None, hora_inicio=None, ruta_base=None):
    """
    Exporta tres archivos CSV:
      1. hosts_FECHA.csv         — inventario completo de hosts
      2. hallazgos_FECHA.csv     — todos los hallazgos de seguridad
      3. conexiones_FECHA.csv    — conexiones externas con GeoIP
    """
    if not ruta_base:
        ts       = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        carpeta  = _carpeta_exports()
        ruta_base = os.path.join(carpeta, ts)

    buf_str  = "\n".join(str(l) for l in (log_buffer or []))
    nodos    = list(topologia.todos_los_nodos())
    activos  = [n for n in nodos if not n.en_lobby]
    en_lobby = [n for n in nodos if n.en_lobby]
    alertas  = list(getattr(topologia, 'alertas', []))
    externos = getattr(topologia, 'externos', {})
    geo_cache= getattr(topologia, '_geo_cache', {})

    rutas = []

    # ── 1. Hosts ──────────────────────────────────────────────────
    ruta_hosts = f"{ruta_base}_hosts.csv"
    with open(ruta_hosts, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "IP","MAC","Hostname","Tipo","Fabricante","Sistema_OS",
            "Estado","En_Lobby","Risk_Score","Severidad_Max",
            "Puertos_Abiertos","N_Puertos","Paquetes","Perfiles","IPv6"
        ])
        for n in sorted(nodos, key=lambda n: [int(x) for x in n.ip.split(".")]):
            w.writerow([
                n.ip,
                n.mac or "",
                getattr(n,'hostname','') or "",
                n.tipo or "desconocido",
                n.fabricante or "",
                n.sistema_op or "",
                n.estado or "",
                "si" if n.en_lobby else "no",
                getattr(n,'risk_score',0) or 0,
                n.severidad_max or "",
                ",".join(str(p) for p in sorted(n.puertos_abiertos)) if n.puertos_abiertos else "",
                len(n.puertos_abiertos),
                n.paquetes,
                ",".join(getattr(n,'perfiles',[]) or []),
                getattr(n,'ip6','') or "",
            ])
    rutas.append(ruta_hosts)

    # ── 2. Hallazgos ──────────────────────────────────────────────
    ruta_hall = f"{ruta_base}_hallazgos.csv"
    with open(ruta_hall, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "IP","Puerto","Servicio","Severidad","Detalle","Timestamp",
            "Tipo_Dispositivo","Fabricante","Risk_Score_Host"
        ])
        nodos_dict = {n.ip: n for n in nodos}
        for h in sorted(alertas,
                key=lambda h: {"critico":0,"alto":1,"medio":2,"info":3}.get(
                    h.severidad, 4)):
            nodo = nodos_dict.get(h.ip)
            w.writerow([
                h.ip or "",
                h.puerto if h.puerto else 0,
                h.servicio or "",
                h.severidad or "info",
                getattr(h,'detalle','') or getattr(h,'desc','') or "",
                getattr(h,'timestamp','') or "",
                nodo.tipo if nodo else "",
                nodo.fabricante if nodo else "",
                getattr(nodo,'risk_score',0) if nodo else 0,
            ])
    rutas.append(ruta_hall)

    # ── 3. Conexiones externas ────────────────────────────────────
    ruta_ext = f"{ruta_base}_conexiones.csv"
    with open(ruta_ext, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "IP_Origen","IP_Destino","Protocolo",
            "Pais","Ciudad","Organizacion","Es_Beacon"
        ])
        # Extraer beacons para marcarlos
        import re
        beacons_dst = set(re.findall(
            r'\[BEACON\] CONFIRMADO \| \S+ → (\S+)', buf_str))
        for ip_src, lista in externos.items():
            for item in lista:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    ip_dst, proto = item[0], item[1]
                else:
                    continue
                geo = geo_cache.get(ip_dst, {}) or {}
                w.writerow([
                    ip_src,
                    ip_dst,
                    proto or "",
                    geo.get("iso",""),
                    geo.get("ciudad",""),
                    geo.get("org",""),
                    "si" if ip_dst in beacons_dst else "no",
                ])
    rutas.append(ruta_ext)

    return rutas
