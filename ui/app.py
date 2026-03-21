import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import time
import sys
from datetime import datetime

from core.topology import Topologia
from tools.scanner import Scanner, set_log_callback as _scanner_set_log
from tools.capture import Capture, set_log_callback as _capture_set_log
from tools.interceptor import Interceptor, set_log_callback as _interceptor_set_log
from tools.fingerprint import fingerprint, fingerprint_completo
from tools.arsenal import Arsenal, set_log_callback as _arsenal_set_log
from tools.beacon_detector import BeaconDetector
from tools.anomalias import DetectorAnomalias
from tools.dhcp_rogue import DhcpRogueDetector, set_log_callback as _dhcp_set_log
from tools.ipv6_scanner import IPv6Scanner, set_log_callback as _ipv6_set_log
from tools.ofensivo import ModulosOfensivos, set_log_callback as _ofensivo_set_log
from tools.ntp_monitor import NTPMonitor, set_log_callback as _ntp_set_log
from tools.ja3_fingerprint import JA3Fingerprinter, set_log_callback as _ja3_set_log
from ui.canvas import Canvas
from ui.panel import Panel
from ui.panel_alertas import PanelAlertas
from tools.exportar import exportar_png_canvas, exportar_json, exportar_csv
import ui.toast as toast
from tools.historial import Historial, comparar_nodos
from ui.ventana_stats import VentanaStats
from tools.geoip import obtener_geoip

COLOR_FONDO   = "#0d1117"
COLOR_PANEL   = "#161b22"
COLOR_BORDE   = "#30363d"
COLOR_TEXTO   = "#e6edf3"
COLOR_TEXTO_SUB = "#8b949e"
COLOR_BOTON   = "#238636"
COLOR_PELIGRO = "#da3633"
COLOR_LIMPIAR = "#6e7681"
COLOR_SALIR   = "#21262d"

_LOG_BUFFER = []  # Acumula todas las líneas del log en memoria

def log(msg):
    linea = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(linea)
    _LOG_BUFFER.append(linea)


def guardar_log(topologia=None, hora_inicio=None):
    import os, hashlib, socket, platform
    from datetime import datetime as dt
    from collections import defaultdict
    if not _LOG_BUFFER:
        return
    from core.rutas import logs as _logs_dir
    carpeta = _logs_dir()
    hora_fin = dt.now()
    if not hora_inicio:
        hora_inicio = hora_fin
    nombre = hora_fin.strftime("sesion_%Y-%m-%d_%H-%M-%S.txt")
    ruta = os.path.join(carpeta, nombre)
    try:
        buf = "\n".join(str(l) for l in _LOG_BUFFER)
        # Pre-procesar datos del log para estadísticas
        proto_por_host = defaultdict(set)
        ext_por_host   = defaultdict(list)
        bytes_ext      = 0
        for linea in _LOG_BUFFER:
            if "[FLUJO]" in linea:
                try:
                    partes = linea.split("] ", 2)[-1]
                    ip_o   = partes.split(" → ")[0].strip()
                    proto  = partes.split("[")[1].split("]")[0]
                    proto_por_host[ip_o].add(proto)
                except: pass
            if "[EXTERNO]" in linea:
                try:
                    partes  = linea.split("] ", 2)[-1]
                    ip_o    = partes.split(" → ")[0].strip()
                    ip_ext  = partes.split(" → ")[1].split(" ")[0]
                    proto   = partes.split("[")[1].split("]")[0]
                    ext_por_host[ip_o].append(ip_ext)
                    proto_por_host[ip_o].add(proto)
                    bytes_ext += 1500  # estimado por paquete
                except: pass

        with open(ruta, "w", encoding="utf-8") as f:
            SEP  = "=" * 70
            SEP2 = "-" * 70

            # ── CABECERA ──────────────────────────────────────────────────
            f.write(SEP + "\n")
            f.write("  TopoReveal — Informe de Auditoría de Red\n")
            f.write(f"  Versión: 1.0 | Kali Linux\n")
            f.write(SEP + "\n\n")

            duracion = int((hora_fin - hora_inicio).total_seconds())
            f.write(f"  Inicio    : {hora_inicio.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Fin       : {hora_fin.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Duración  : {duracion//60}m {duracion%60}s\n")
            try:
                mi_host = socket.gethostname()
            except: mi_host = "desconocido"
            f.write(f"  Agente    : {mi_host} | {usuario_real}\n")
            f.write(f"  Líneas    : {len(_LOG_BUFFER)} eventos capturados\n")
            # Hash SHA-256 del log para cadena de custodia
            sha256 = hashlib.sha256(buf.encode()).hexdigest()
            f.write(f"  SHA-256   : {sha256}\n")
            f.write("\n" + SEP + "\n\n")

            if topologia:
                nodos    = list(topologia.todos_los_nodos())
                scanners = [n for n in nodos if n.tipo == "arp-scanner"]
                en_lobby = [n for n in nodos if n.en_lobby]
                visibles = [n for n in nodos if not n.en_lobby]
                alertas  = list(getattr(topologia, 'alertas', []))
                externos = getattr(topologia, 'externos', {})
                gw       = topologia.router or topologia.gateway or "?"
                subred   = getattr(topologia, 'subred', '?')
                n_puertos_total = sum(len(n.puertos_abiertos) for n in nodos)

                # ── 1. RESUMEN EJECUTIVO ──────────────────────────────────
                f.write("1. RESUMEN EJECUTIVO\n")
                f.write(SEP2 + "\n")
                f.write(f"  Hosts activos        : {len(visibles)}\n")
                f.write(f"  Hosts en lobby       : {len(en_lobby)}\n")
                f.write(f"  Total sesión         : {len(nodos)}\n")
                f.write(f"  Gateway              : {gw}\n")
                f.write(f"  Subred               : {subred}.x\n")
                f.write(f"  Puertos abiertos     : {n_puertos_total}\n")
                f.write(f"  Conexiones externas  : {sum(len(v) for v in ext_por_host.values())} eventos\n")
                f.write(f"  Tráfico ext estimado : ~{bytes_ext//1024} KB\n")
                f.write(f"  ARP Scanners         : {len(scanners)}\n")
                sev_c = {h.severidad: 0 for h in alertas}
                for h in alertas: sev_c[h.severidad] = sev_c.get(h.severidad,0)+1
                f.write(f"  Alertas CRITICO      : {sev_c.get('critico',0)}\n")
                f.write(f"  Alertas ALTO         : {sev_c.get('alto',0)}\n")
                f.write(f"  Alertas MEDIO        : {sev_c.get('medio',0)}\n")
                f.write(f"  Alertas INFO         : {sev_c.get('info',0)}\n")

                # Score de riesgo global (0-10)
                score = 0
                if sev_c.get('critico',0): score += min(4, sev_c['critico'])
                if sev_c.get('alto',0):    score += min(3, sev_c['alto'])
                if sev_c.get('medio',0):   score += min(2, sev_c['medio'])
                if any("Beacon" in (h.servicio or "") for h in alertas): score += 2
                score = min(10, score)
                bar = "█" * score + "░" * (10-score)
                f.write(f"\n  RIESGO GLOBAL: {score}/10  [{bar}]\n")
                if score >= 8:   nivel_r = "CRÍTICO — acción inmediata requerida"
                elif score >= 5: nivel_r = "ALTO — revisar hallazgos prioritarios"
                elif score >= 3: nivel_r = "MEDIO — monitorear y planificar"
                else:            nivel_r = "BAJO — red en estado aceptable"
                f.write(f"  Nivel: {nivel_r}\n")
                f.write("\n" + SEP + "\n\n")

                # ── 2. INVENTARIO DE HOSTS ────────────────────────────────
                f.write("2. INVENTARIO DE HOSTS\n")
                f.write(SEP2 + "\n")
                f.write(f"  {'IP':<18} {'MAC':<19} {'TIPO':<13} {'OS':<13} "
                        f"{'ESTADO':<11} {'PKTs':>5}  {'PUERTOS'}\n")
                f.write("  " + "-" * 100 + "\n")
                for nodo in sorted(visibles, key=lambda n:
                        [int(x) for x in n.ip.split(".")]):
                    puertos_str = ",".join(str(p) for p in
                        sorted(nodo.puertos_abiertos)[:6]) or "—"
                    f.write(f"  {nodo.ip:<18} {(nodo.mac or '—'):<19} "
                            f"{(nodo.tipo or '—'):<13} {(nodo.sistema_op or '—'):<13} "
                            f"{nodo.estado:<11} {nodo.paquetes:>5}  {puertos_str}\n")

                tipos_ids    = {n.tipo for n in visibles if n.tipo and n.tipo!="desconocido"}
                fabricantes_ = {n.fabricante for n in visibles
                                if n.fabricante and "Privada" not in n.fabricante}
                sistemas_    = {n.sistema_op for n in visibles
                                if n.sistema_op and n.sistema_op!="Desconocido"}
                f.write(f"\n  Tipos       : {', '.join(sorted(tipos_ids)) or '—'}\n")
                f.write(f"  Fabricantes : {', '.join(list(fabricantes_)[:6]) or '—'}\n")
                f.write(f"  Sistemas OS : {', '.join(sistemas_) or '—'}\n")

                if en_lobby:
                    f.write(f"\n  LOBBY ({len(en_lobby)} inactivos):\n")
                    for n in en_lobby:
                        f.write(f"    {n.ip:<18} {n.mac or '—'}\n")
                if scanners:
                    f.write(f"\n  ARP SCANNERS ({len(scanners)}):\n")
                    for n in scanners:
                        f.write(f"    {n.ip:<18} {n.mac or '—'}\n")
                f.write("\n" + SEP + "\n\n")

                # ── 3. HALLAZGOS POR HOST ─────────────────────────────────
                f.write("3. HALLAZGOS POR HOST\n")
                f.write(SEP2 + "\n")
                hallazgos_por_ip = defaultdict(list)
                for h in alertas:
                    hallazgos_por_ip[h.ip].append(h)
                for ip, hs in sorted(hallazgos_por_ip.items()):
                    nodo_h = next((n for n in nodos if n.ip == ip), None)
                    tipo_h = nodo_h.tipo if nodo_h else "?"
                    f.write(f"\n  [{ip}] — {tipo_h} | Risk: "
                            f"{getattr(nodo_h,'risk_score',0) or 0}/100\n")
                    for h in sorted(hs, key=lambda x:
                            {"critico":0,"alto":1,"medio":2,"info":3}.get(x.severidad,4)):
                        sev_tag = h.severidad.upper()[:4]
                        det = getattr(h,'detalle',getattr(h,'desc','')) or ''
                        f.write(f"    [{sev_tag}] {h.puerto:>5} | {(h.servicio or '?'):<22} "
                                f"| {det[:55]}\n")
                if not hallazgos_por_ip:
                    f.write("  Sin hallazgos registrados\n")
                f.write("\n" + SEP + "\n\n")

                # ── 4. CONEXIONES EXTERNAS ────────────────────────────────
                f.write("4. CONEXIONES EXTERNAS\n")
                f.write(SEP2 + "\n")
                if ext_por_host:
                    for ip, ips_ext in sorted(ext_por_host.items()):
                        unicas = list(dict.fromkeys(ips_ext))
                        f.write(f"  {ip} ({len(unicas)} destinos):\n")
                        for ip_e in unicas[:12]:
                            f.write(f"    → {ip_e}\n")
                    if any("HUAWEI" in l or "Beacon" in l for l in _LOG_BUFFER):
                        beacons_ = [h for h in alertas if "Beacon" in (h.servicio or "")]
                        if beacons_:
                            f.write("\n  BEACONS C2 CONFIRMADOS:\n")
                            for b in beacons_:
                                f.write(f"    {b.ip} — {getattr(b,'detalle','')}\n")
                else:
                    f.write("  Sin conexiones externas registradas\n")
                f.write("\n" + SEP + "\n\n")

                # ── 5. COBERTURA POR NIVEL ────────────────────────────────
                f.write("5. COBERTURA DE HERRAMIENTAS (Iceberg de Seguridad)\n")
                f.write(SEP2 + "\n")

                def chk(cond, nombre, detalle=""):
                    s = "✓" if cond else "○"
                    ln = f"  {s}  {nombre}"
                    if detalle: ln += f"  →  {detalle}"
                    f.write(ln + "\n")
                    return cond

                f.write("\n  NIVEL 1 — Descubrimiento básico\n")
                chk(len(visibles)>0,       "Hosts vivos (ARP/ping)",      f"{len(visibles)} hosts")
                chk(bool(gw),              "Gateway identificado",         gw)
                chk(n_puertos_total>0,     "Puertos TCP escaneados",       f"{n_puertos_total} puertos")
                chk("[EXTERNO]" in buf,    "Tráfico externo capturado",    f"{sum(len(v) for v in ext_por_host.values())} eventos")
                chk("[FLUJO]" in buf,      "Flujos internos detectados")
                chk(bool(sistemas_),       "OS fingerprinting",            ", ".join(sistemas_))

                f.write("\n  NIVEL 2 — Estándar\n")
                chk("HTTP" in buf,                              "HTTP detectado")
                chk("SSL Autofirmado" in buf or "SSL" in buf,  "SSL/TLS analizado")
                chk("DHCP" in buf,                              "DHCP capturado")
                chk("DNS" in buf,                               "DNS interno")
                chk("XMPP" in buf or "QUIC" in buf,            "Protocolos app (XMPP/QUIC)")
                chk("IGMP" in buf,                              "IGMP/multicast")
                chk("NTP" in buf,                               "NTP detectado")
                chk("RTSP" in buf,                              "RTSP (cámara/stream)")
                chk("FTP" in buf,                               "FTP analizado")
                chk("SNMP" in buf,                              "SNMP enumerado")
                chk(any("Network Shares" in (h.servicio or "") for h in alertas), "SMB Shares")
                chk(any("Cred. por Defecto" in (h.servicio or "") for h in alertas), "Credenciales default")

                f.write("\n  NIVEL 3 — Persistencia\n")
                chk(any("DC/" in (h.servicio or "") for h in alertas),    "Active Directory/DC")
                chk(any("LDAP" in (h.servicio or "") for h in alertas),   "LDAP enumerado")
                chk(any("Kerberos" in (h.servicio or "") for h in alertas),"Kerberos SPN")
                chk(any("SSL" in (h.servicio or "") for h in alertas),    "Certificados SSL")
                chk(any("NFS" in (h.servicio or "") for h in alertas),    "NFS exportaciones")
                chk("IKE" in buf or "IPSec" in buf or "VPN" in buf,       "VPN/túneles detectados")

                f.write("\n  NIVEL 4 — Avanzado\n")
                chk("[IPv6]" in buf,    "IPv6 completo",
                    "hosts encontrados" if "Host respondió" in buf else "activo/sin hosts")
                chk("[LLMNR]" in buf or "[NBT-NS]" in buf, "LLMNR/NBT-NS poisoning")
                chk("[WPAD]" in buf,   "WPAD spoofing")
                chk("[VLAN]" in buf,   "VLAN hopping")
                chk("[CDP]" in buf or "[LLDP]" in buf, "CDP/LLDP")
                chk(any("Anomalía" in (h.servicio or "") for h in alertas), "Shadow IT / anomalías")

                f.write("\n  NIVEL 5 — Elite\n")
                chk(any("IPMI" in (h.servicio or "") for h in alertas),   "IPMI/iDRAC/iLO")
                chk("[BEACON] CONFIRMADO" in buf, "Beacon C2 detection",
                    f"{buf.count('[BEACON] CONFIRMADO')//max(1,buf.count('[BEACON] CONFIRMADO'))} confirmados")
                chk("[JA3]" in buf,    "JA3/JA3S TLS fingerprinting")
                chk(any("DHCP Rogue" in (h.servicio or "") for h in alertas), "DHCP Rogue")

                f.write("\n  NIVEL 6 — Capa invisible\n")
                chk("[NTP]" in buf and "offset" in buf.lower(), "NTP drift medido")
                chk("[JA3]" in buf and "Malware" not in buf,    "JA3 fingerprinting activo")

                f.write("\n  NO DISPARADAS (red no las tiene):\n")
                no_disp = []
                if "[CDP]" not in buf and "[LLDP]" not in buf:
                    no_disp.append("CDP/LLDP — sin switches Cisco/LLDP")
                if "DHCP Rogue" not in buf:
                    no_disp.append("DHCP Rogue — un solo servidor DHCP")
                if "[IPv6] Host respondió" not in buf:
                    no_disp.append("IPv6 hosts — red sin IPv6 activo")
                if "DC/Active Directory" not in buf:
                    no_disp.append("AD/DC — sin controlador de dominio")
                if "[IPMI]" not in buf:
                    no_disp.append("IPMI — sin servidores con BMC expuesto")
                for nd in no_disp:
                    f.write(f"    -  {nd}\n")

                f.write("\n" + SEP + "\n\n")

                # ── 6. SUBREDES ───────────────────────────────────────────
                if hasattr(topologia, 'obtener_subredes'):
                    subredes = topologia.obtener_subredes()
                    if subredes:
                        f.write("6. SUBREDES SECUNDARIAS\n")
                        f.write(SEP2 + "\n")
                        for sub in subredes:
                            f.write(f"  {sub.prefijo}.x [{sub.tipo}] {sub.desc} | "
                                    f"{len(sub.nodos)} host(s) | "
                                    f"detectada {sub.primer_visto}\n")
                        f.write("\n" + SEP + "\n\n")

            # ── RESUMEN DE CAPACIDADES ────────────────────────────────────
            if topologia:
                f.write("RESUMEN DE CAPACIDADES — QUÉ DETECTÓ ESTA SESIÓN:\n")
                f.write("-" * 60 + "\n")

                nodos_todos = list(topologia.todos_los_nodos())
                alertas     = list(getattr(topologia, 'alertas', []))
                externos    = getattr(topologia, 'externos', {})
                buf         = "\n".join(str(l) for l in _LOG_BUFFER)

                def check(condicion, nombre, detalle=""):
                    simbolo = "✓" if condicion else "○"
                    linea = f"  {simbolo}  {nombre}"
                    if detalle:
                        linea += f"  →  {detalle}"
                    f.write(linea + "\n")
                    return condicion

                f.write("\n[DESCUBRIMIENTO]\n")
                n_hosts = len([n for n in nodos_todos if not n.en_lobby])
                check(n_hosts > 0, "Hosts descubiertos (ARP)",
                      f"{n_hosts} hosts activos")
                check(bool(topologia.gateway), "Gateway identificado",
                      topologia.gateway or "—")
                n_puertos = sum(len(n.puertos_abiertos) for n in nodos_todos)
                check(n_puertos > 0, "Puertos TCP escaneados",
                      f"{n_puertos} puertos abiertos en total")
                check("[EXTERNO]" in buf, "Tráfico externo capturado",
                      f"{len(externos)} hosts con conexiones externas")
                check("[FLUJO]" in buf, "Flujos internos detectados")

                f.write("\n[ANÁLISIS DE PROTOCOLOS]\n")
                check("[HALLAZGO] " in buf and "HTTP" in buf,
                      "HTTP detectado")
                check("SSL" in buf or "TLS" in buf or "HTTPS" in buf,
                      "SSL/TLS analizado",
                      "autofirmado detectado" if "SSL Autofirmado" in buf else "OK")
                check("DHCP" in buf, "DHCP capturado")
                check("[FLUJO]" in buf and "DNS" in buf, "DNS interno")
                check("XMPP" in buf or "QUIC" in buf, "Protocolos aplicación (XMPP/QUIC)")
                check("IGMP" in buf, "IGMP/multicast")
                check("NTP" in buf, "NTP detectado")
                check("RTSP" in buf, "RTSP (cámara/stream)")

                f.write("\n[FINGERPRINTING E IDENTIFICACIÓN]\n")
                tipos = {n.tipo for n in nodos_todos if n.tipo and n.tipo != "desconocido"}
                check(len(tipos) > 1, "Tipos de dispositivo identificados",
                      ", ".join(sorted(tipos)))
                fabricantes = {n.fabricante for n in nodos_todos
                               if n.fabricante and "Privada" not in n.fabricante}
                check(bool(fabricantes), "Fabricantes identificados",
                      ", ".join(list(fabricantes)[:4]))
                sistemas = {n.sistema_op for n in nodos_todos
                            if n.sistema_op and n.sistema_op != "Desconocido"}
                check(bool(sistemas), "OS detectados",
                      ", ".join(list(sistemas)[:4]))
                check(any(n.perfiles for n in nodos_todos),
                      "Perfiles especiales detectados",
                      ", ".join(p for n in nodos_todos for p in (n.perfiles or [])))

                f.write("\n[HALLAZGOS DE SEGURIDAD]\n")
                sev_counts = {}
                for h in alertas:
                    sev_counts[h.severidad] = sev_counts.get(h.severidad, 0) + 1
                check(sev_counts.get("critico", 0) > 0, "Hallazgos CRÍTICOS",
                      str(sev_counts.get("critico", 0)))
                check(sev_counts.get("alto", 0) > 0, "Hallazgos ALTOS",
                      str(sev_counts.get("alto", 0)))
                check(sev_counts.get("medio", 0) > 0, "Hallazgos MEDIOS",
                      str(sev_counts.get("medio", 0)))
                check(any("SSL Autofirmado" in (h.servicio or "") for h in alertas),
                      "Certificados SSL autofirmados")
                check(any("Beacon" in (h.servicio or "") for h in alertas),
                      "Beacon C2 detectado",
                      ", ".join({h.ip for h in alertas if "Beacon" in (h.servicio or "")}))
                check(any("Anomalía" in (h.servicio or "") for h in alertas),
                      "Anomalías vs baseline")
                check(any("DHCP Rogue" in (h.servicio or "") for h in alertas),
                      "DHCP Rogue detectado")
                check(any("UPnP" in (h.servicio or "") for h in alertas),
                      "UPnP descubierto")
                check(any("DC/" in (h.servicio or "") for h in alertas),
                      "Domain Controller detectado")
                check(any("Network Shares" in (h.servicio or "") for h in alertas),
                      "Network Shares encontrados")
                check(any("LDAP" in (h.servicio or "") for h in alertas),
                      "LDAP enumerado")

                f.write("\n[DETECCIÓN AVANZADA]\n")
                check("[BEACON] CONFIRMADO" in buf, "Análisis de beacons C2",
                      buf.count("[BEACON] CONFIRMADO") // 2 - 1 if "[BEACON] CONFIRMADO" in buf else "")
                check("[IPv6]" in buf, "Escaneo IPv6",
                      "hosts encontrados" if "Host respondió" in buf else "sin hosts IPv6")
                check("[CDP]" in buf or "[LLDP]" in buf,
                      "CDP/LLDP detectado")
                check("[ANOMALIAS]" in buf and "Sin historial" not in buf,
                      "Análisis de anomalías vs baseline")
                check("[MONITOR]" in buf and "Sniff 802.11" in buf,
                      "Monitor 802.11 activo")
                check("[BEACON]" in buf, "Detector de beacons activo")
                check(bool(getattr(topologia, 'subredes_secundarias', {})),
                      "Subredes secundarias detectadas")

                f.write("\n[HERRAMIENTAS NO DISPARADAS (red no las tiene)]\n")
                no_list = []
                if "[CDP]" not in buf and "[LLDP]" not in buf:
                    no_list.append("CDP/LLDP (no hay switches Cisco/LLDP en la red)")
                if "Beacon" not in buf or "[BEACON] CONFIRMADO" not in buf:
                    no_list.append("Beacon C2 (no hay tráfico periódico sospechoso)")
                if "DHCP Rogue" not in buf:
                    no_list.append("DHCP Rogue (un solo servidor DHCP en la red)")
                if "[IPv6] Host respondió" not in buf:
                    no_list.append("IPv6 hosts (red sin IPv6 activo o sin hosts duales)")
                if "DC/Active Directory" not in buf:
                    no_list.append("AD/DC (no hay controlador de dominio)")
                if "Network Shares" not in buf:
                    no_list.append("SMB Shares (no hay shares accesibles)")
                for item in no_list:
                    f.write(f"  -  {item}\n")
                if not no_list:
                    f.write("  (todas las herramientas detectaron algo)\n")

                f.write("\n" + "=" * 60 + "\n\n")
            f.write("LOG DE EVENTOS:\n\n")
            f.write("\n".join(str(l) for l in _LOG_BUFFER))

        print(f"[LOG] Sesion guardada en: {ruta}")
    except Exception as e:
        print(f"[LOG] Error guardando sesion: {e}")


class App:
    def __init__(self):
        self.ventana = tk.Tk()
        self.ventana.title("TopoReveal — Network Topology Viewer")
        self.ventana.configure(bg=COLOR_FONDO)
        self.ventana.geometry("1200x750")
        self.ventana.minsize(900, 600)

        self.topologia    = Topologia()
        self.interfaz     = tk.StringVar(value="eth0")
        self._arrancado   = False   # Evita doble arranque

        self.scanner = Scanner(callback=self._on_dispositivo_encontrado)
        _scanner_set_log(log)
        self.capture = Capture(callback=self._on_paquete_capturado)
        _capture_set_log(log)
        self.interceptor = Interceptor(
            callback=self._on_paquete_capturado,
            callback_wifi=self._on_evento_wifi
        )
        _interceptor_set_log(log)
        self.arsenal      = Arsenal()
        self.historial    = Historial()
        self._estado_previo = self.historial.obtener_ultimo_estado()
        self._beacon    = BeaconDetector(callback_alerta=self._on_beacon_detectado)
        self._dhcp_rogue  = DhcpRogueDetector(callback=self._on_dhcp_rogue)
        _dhcp_set_log(log)
        self._ipv6        = IPv6Scanner(callback=self._on_ipv6_hallazgo)
        _ipv6_set_log(log)
        self._ofensivo    = None   # se crea al arrancar con interfaz
        self._ntp         = NTPMonitor(callback=self._on_ntp_drift)
        _ntp_set_log(log)
        self._ja3         = JA3Fingerprinter(callback=self._on_ja3_hallazgo)
        _ja3_set_log(log)

        # Detector de anomalías vs baseline histórico
        import os as _os
        from core.rutas import historial_db as _hdb
        _db = _hdb()
        self._anomalias = DetectorAnomalias(ruta_db=_db)
        self._anomalias.callback_anomalia = self._on_anomalia_detectada
        self._anomalias.cargar_baseline()

        # GeoIP
        self.geoip = obtener_geoip()
        if self.geoip.disponible:
            log("[APP] GeoIP disponible — base de datos local cargada")
        else:
            log(f"[APP] GeoIP no disponible: {self.geoip.mensaje_error}")

        self.arsenal.añadir_listener(self._on_arsenal_resultado)
        _arsenal_set_log(log)
        self._flujo_contador      = 0
        self._tcp_masivo_ventana  = {}
        self._tcp_masivo_alertado = set()

        self._construir_barra_superior()
        self._construir_area_principal()
        self._cargar_interfaces()

        self.panel.set_topologia(self.topologia)
        self.canvas.ip_local = self.topologia.ip_local
        def _on_nodo_click_canvas(nodo):
            self.panel.mostrar_nodo(nodo)
            self.canvas.seleccionar_nodo(nodo.ip)
            self.canvas.redibujar()
        self.canvas.on_nodo_seleccionado = _on_nodo_click_canvas
        self.canvas.arsenal = self.arsenal
        self.panel._on_alerta_seleccionada    = self._seleccionar_nodo_por_ip
        self.panel._on_arsenal_desde_alerta   = self._arsenal_desde_alerta
        self.panel._on_verificar_lobby        = self._verificar_lobby_manual
        self.panel._on_seleccion_en_lista = lambda ip: (
            self.canvas.seleccionar_nodo(ip), self.canvas.redibujar()
        )
        self.panel_alertas.set_topologia(self.topologia)
        self.panel_alertas._on_nodo_click = self._seleccionar_nodo_por_ip
        self.panel_alertas._on_arsenal    = self._arsenal_desde_alerta

        self.ventana.protocol("WM_DELETE_WINDOW", self._salir)
        self._ciclo_actualizacion()
        toast.inicializar(self.ventana)

        # ── Splash Screen ─────────────────────────────────────────
        self._splash = None
        try:
            from ui.splash import mostrar_splash
            self._splash = mostrar_splash(
                self.ventana,
                callback_listo=self._splash_terminado
            )
            # Simular progreso mientras la app se inicializa
            self._splash_progress = 0.0
            self.ventana.after(200, self._avanzar_splash)
        except Exception as e:
            log(f"[APP] Splash no disponible: {e}")
            self.ventana.deiconify()
            self.ventana.after(500, self._arranque_automatico)

        # Hilo de actualización profunda del panel izquierdo cada 15s
        self._hilo_stats = threading.Thread(
            target=self._loop_stats_profundo, daemon=True, name="stats-loop")
        self._hilo_stats.start()

    # ─────────────────────────────────────────
    # CONSTRUCCIÓN
    # ─────────────────────────────────────────

    def _construir_barra_superior(self):
        barra = tk.Frame(self.ventana, bg=COLOR_PANEL, height=46)
        barra.pack(fill=tk.X, side=tk.TOP)
        barra.pack_propagate(False)

        tk.Label(barra, text="⬡ TopoReveal",
            bg=COLOR_PANEL, fg=COLOR_TEXTO,
            font=("Monospace", 12, "bold")).pack(side=tk.LEFT, padx=10)

        tk.Frame(barra, bg=COLOR_BORDE, width=1).pack(
            side=tk.LEFT, fill=tk.Y, pady=6)

        # Interfaz — label más corto
        tk.Label(barra, text="iface:",
            bg=COLOR_PANEL, fg=COLOR_TEXTO_SUB,
            font=("Monospace", 8)).pack(side=tk.LEFT, padx=(8, 3))

        self.combo_interfaz = ttk.Combobox(
            barra, textvariable=self.interfaz,
            width=8, state="readonly")
        self.combo_interfaz.pack(side=tk.LEFT, padx=(0, 8))

        tk.Frame(barra, bg=COLOR_BORDE, width=1).pack(
            side=tk.LEFT, fill=tk.Y, pady=6)

        # Botones de control — más compactos
        self.btn_escanear = tk.Button(barra, text="▶ Scan",
            bg=COLOR_BOTON, fg=COLOR_TEXTO,
            font=("Monospace", 9, "bold"),
            relief=tk.FLAT, padx=8, pady=3,
            cursor="hand2", command=self._iniciar_escaneo)
        self.btn_escanear.pack(side=tk.LEFT, padx=3)

        self.btn_detener = tk.Button(barra, text="■ Stop",
            bg=COLOR_PELIGRO, fg=COLOR_TEXTO,
            font=("Monospace", 9, "bold"),
            relief=tk.FLAT, padx=8, pady=3,
            cursor="hand2", command=self._detener,
            state=tk.DISABLED)
        self.btn_detener.pack(side=tk.LEFT, padx=3)

        self.btn_limpiar = tk.Button(barra, text="⌫",
            bg=COLOR_LIMPIAR, fg=COLOR_TEXTO,
            font=("Monospace", 9, "bold"),
            relief=tk.FLAT, padx=6, pady=3,
            cursor="hand2", command=self._limpiar)
        self.btn_limpiar.pack(side=tk.LEFT, padx=3)

        tk.Frame(barra, bg=COLOR_BORDE, width=1).pack(
            side=tk.LEFT, fill=tk.Y, pady=6)

        # Checkbox tráfico lateral — más compacto
        self.var_lateral = tk.BooleanVar(value=True)
        tk.Checkbutton(barra, text="Lateral",
            variable=self.var_lateral,
            bg=COLOR_PANEL, fg=COLOR_TEXTO,
            selectcolor=COLOR_FONDO,
            font=("Monospace", 8),
            command=self._toggle_lateral).pack(side=tk.LEFT, padx=8)

        tk.Frame(barra, bg=COLOR_BORDE, width=1).pack(
            side=tk.LEFT, fill=tk.Y, pady=6)

        # Menú "Ver" — agrupa Dashboard + WiFi Scope
        self.btn_ver = tk.Menubutton(barra, text="⬡ Ver",
            bg="#161b22", fg="#58d6ff",
            font=("Monospace", 9, "bold"),
            relief=tk.FLAT, padx=8, pady=3,
            cursor="hand2")
        self.btn_ver.pack(side=tk.LEFT, padx=3)

        menu_ver = tk.Menu(self.btn_ver, tearoff=0,
            bg=COLOR_PANEL, fg=COLOR_TEXTO,
            activebackground="#1f6feb",
            font=("Monospace", 9))
        menu_ver.add_command(
            label="📊  Dashboard de red",
            command=self._abrir_stats)
        menu_ver.add_command(
            label="⚡  WiFi Scope",
            command=self._abrir_ventana_wifi)
        menu_ver.add_command(
            label="📡  Análisis de Tráfico",
            command=self._abrir_ventana_trafico)
        menu_ver.add_separator()
        menu_ver.add_command(
            label="⚔  Módulos Ofensivos",
            command=self._abrir_modulos_ofensivos)
        self.btn_ver["menu"] = menu_ver

        # Menú Exportar
        self.btn_exportar = tk.Menubutton(barra, text="⇪ Export",
            bg=COLOR_BOTON, fg=COLOR_TEXTO,
            font=("Monospace", 9, "bold"),
            relief=tk.FLAT, padx=8, pady=3,
            cursor="hand2")
        self.btn_exportar.pack(side=tk.RIGHT, padx=(3, 10))

        self.menu_exportar = tk.Menu(self.btn_exportar, tearoff=0,
            bg=COLOR_PANEL, fg=COLOR_TEXTO,
            activebackground=COLOR_BORDE,
            font=("Monospace", 9))
        self.menu_exportar.add_command(label="PNG",  command=self._exportar_png)
        self.menu_exportar.add_command(label="JSON", command=self._exportar_json)
        self.menu_exportar.add_command(label="CSV",  command=self._exportar_csv)
        self.menu_exportar.add_separator()
        self.menu_exportar.add_command(label="📄 Informe PDF",
            command=self._exportar_pdf)
        self.btn_exportar["menu"] = self.menu_exportar

        tk.Button(barra, text="✕",
            bg=COLOR_SALIR, fg=COLOR_PELIGRO,
            font=("Monospace", 9, "bold"),
            relief=tk.FLAT, padx=6, pady=3,
            cursor="hand2", command=self._salir).pack(side=tk.RIGHT, padx=3)

        # Indicador de sondeo + estado — lado derecho
        self.label_sondeo = tk.Label(barra, text="◌",
            bg=COLOR_PANEL, fg="#6e7681",
            font=("Monospace", 8))
        self.label_sondeo.pack(side=tk.RIGHT, padx=5)

        self.label_estado = tk.Label(barra, text="● Init",
            bg=COLOR_PANEL, fg="#8b949e",
            font=("Monospace", 8))
        self.label_estado.pack(side=tk.RIGHT, padx=5)

    def _construir_area_principal(self):
        contenedor = tk.Frame(self.ventana, bg=COLOR_FONDO)
        contenedor.pack(fill=tk.BOTH, expand=True)

        # Panel alertas izquierdo
        self.panel_alertas = PanelAlertas(contenedor)
        self.panel_alertas.frame.pack(side=tk.LEFT, fill=tk.Y)

        tk.Frame(contenedor, bg=COLOR_BORDE, width=1).pack(
            side=tk.LEFT, fill=tk.Y)

        # Canvas central
        self.canvas = Canvas(contenedor, self.topologia)
        self.canvas.frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Frame(contenedor, bg=COLOR_BORDE, width=1).pack(
            side=tk.LEFT, fill=tk.Y)

        # Panel derecho
        self.panel = Panel(contenedor)
        self.panel.frame.pack(side=tk.RIGHT, fill=tk.Y)

    # ─────────────────────────────────────────
    # INTERFACES
    # ─────────────────────────────────────────

    def _cargar_interfaces(self):
        try:
            resultado = subprocess.run(["ip", "-o", "link", "show"],
                capture_output=True, text=True, timeout=5)
            interfaces = []
            for linea in resultado.stdout.splitlines():
                partes = linea.split(":")
                if len(partes) >= 2:
                    nombre = partes[1].strip()
                    if nombre != "lo":
                        interfaces.append(nombre)
            if interfaces:
                self.combo_interfaz["values"] = interfaces
                self.interfaz.set(interfaces[0])
                self._interfaz_actual = interfaces[0] # Guardar para historial
        except Exception as e:
            log(f"[APP] Error cargando interfaces: {e}")

    # ─────────────────────────────────────────
    # ARRANQUE
    # ─────────────────────────────────────────

    def _avanzar_splash(self):
        """Avanza el progreso del splash — simula carga real."""
        if not self._splash:
            return
        self._splash_progress += 0.04   # ~25 pasos × 200ms = 5 segundos
        self._splash.set_progreso(
            self._splash_progress,
            cerrar_al_terminar=(self._splash_progress >= 1.0)
        )
        if self._splash_progress < 1.0:
            self.ventana.after(200, self._avanzar_splash)

    def _splash_terminado(self):
        """Callback cuando el splash cierra — mostrar app y arrancar."""
        self._splash = None
        self.ventana.deiconify()
        self.ventana.after(100, self._arranque_automatico)

    def _arranque_automatico(self):
        """Se ejecuta UNA SOLA VEZ al abrir."""
        if self._arrancado:
            return
        self._arrancado = True

        interfaz = self.interfaz.get()
        if not interfaz:
            self.label_estado.config(text="● Sin interfaz", fg=COLOR_PELIGRO)
            return

        log(f"[APP] Arranque automático en {interfaz}")
        self._configurar_red(interfaz)
        self._arrancar(interfaz)

    def _configurar_red(self, interfaz):
        """Detecta gateway, subred y MAC/IP propios al arrancar."""
        gateway = self.scanner.obtener_gateway(interfaz)
        if gateway:
            self.topologia.gateway = gateway
            # Informar al detector DHCP cuál es el servidor legítimo
            if hasattr(self, '_dhcp_rogue'):
                self._dhcp_rogue.gateway_ip = gateway
            partes = gateway.split(".")
            self.topologia.subred = ".".join(partes[:3])
            log(f"[APP] Gateway: {gateway} | Subred: {self.topologia.subred}.x")
        else:
            log(f"[APP] Sin gateway en {interfaz}")

        # Leer MAC propia directamente del sistema — no depender de paquetes
        mac_local = self._leer_mac_interfaz(interfaz)
        if mac_local:
            self._mac_local_cache = mac_local

        # Registrar nodo propio con MAC correcta si ya tenemos IP local
        if self.topologia.ip_local and mac_local:
            nodo_propio = self.topologia.agregar_o_actualizar(
                self.topologia.ip_local,
                mac=mac_local,
                tipo="pc",
                bytes=0
            )
            if nodo_propio:
                nodo_propio.fabricante = "Local"
                nodo_propio.sistema_op = "Linux"
                # Asegurar que el hostname local también se guarda
                try:
                    import socket as _sock
                    hostname_local = _sock.gethostname()
                    if hostname_local:
                        nodo_propio.hostname = hostname_local
                except Exception:
                    pass
                log(f"[APP] Nodo propio: {self.topologia.ip_local} "
                    f"| MAC: {mac_local}")

        # Pasar ip_local al canvas para resaltarlo visualmente
        if hasattr(self, 'canvas') and self.topologia.ip_local:
            self.canvas.ip_local = self.topologia.ip_local

    def _leer_mac_interfaz(self, interfaz):
        """
        Lee la MAC real de la interfaz directamente del sistema.
        Siempre funciona aunque corra con sudo.
        """
        try:
            with open(f"/sys/class/net/{interfaz}/address") as f:
                mac = f.read().strip()
                if mac and mac != "00:00:00:00:00:00":
                    return mac
        except Exception:
            pass
        # Fallback: ip link show
        try:
            import re
            r = subprocess.run(
                ["ip", "link", "show", interfaz],
                capture_output=True, text=True, timeout=3)
            m = re.search(r'link/ether ([0-9a-fA-F:]{17})', r.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
        return None

    def _arrancar(self, interfaz):
        """Inicia escaneo, captura pasiva e interceptación activa."""
        if not self.scanner.corriendo:
            log(f"[APP] Iniciando escaneo en {interfaz}")
        self.btn_escanear.config(state=tk.DISABLED)
        self.btn_detener.config(state=tk.NORMAL)
        self.label_estado.config(text="● Escaneando...", fg="#f0883e")
        self.scanner.escanear(interfaz)
        if not self.capture.esta_corriendo():
            self.capture.iniciar(interfaz)
        else:
            log("[APP] Captura ya estaba corriendo")
        self._hora_inicio = __import__("datetime").datetime.now()
        # IPv6 — arranca 10s después del ARP sweep inicial
        self.ventana.after(10000, lambda: self._ipv6.iniciar(interfaz))
        # Lanzar interceptor 15s después — el scanner necesita tiempo
        # para descubrir hosts y obtener sus MACs via ARP
        self.ventana.after(15000, lambda: self._arrancar_interceptor(interfaz))

    def _arrancar_interceptor(self, interfaz):
        """
        Lanza ARP spoofing + monitor WiFi una vez que hay hosts con MAC conocida.
        Orden: Descubrimiento → esperar 15s → Spoof → esperar 5s → Monitor.
        Si el gateway aún no tiene MAC, fuerza resolución ARP directa.
        """
        if not self.topologia.gateway:
            log("[APP] Sin gateway — interceptor no puede iniciar")
            return

        gw_ip   = self.topologia.gateway
        gw_nodo = self.topologia.obtener_nodo(gw_ip)
        gw_mac  = gw_nodo.mac if gw_nodo else None

        # Fix 5: si el nmap no encontró la MAC del gateway (ARP timeout),
        # intentar resolución directa con arping o leyendo la tabla ARP del SO
        if not gw_mac:
            gw_mac = self._resolver_mac_gateway(gw_ip)
            if gw_mac and gw_nodo:
                gw_nodo.mac = gw_mac
                log(f"[APP] MAC del gateway resuelta directamente: {gw_mac}")

        if not gw_mac:
            log(f"[APP] MAC del gateway {gw_ip} desconocida — reintentando en 10s")
            self.ventana.after(10000, lambda: self._arrancar_interceptor(interfaz))
            return

        ip_local = self.topologia.ip_local
        hosts = []
        for nodo in self.topologia.todos_los_nodos():
            if nodo.ip == ip_local: continue
            if nodo.ip == gw_ip:   continue
            if not nodo.mac:       continue
            if nodo.en_lobby:      continue
            hosts.append((nodo.ip, nodo.mac))

        if not hosts:
            log("[APP] Sin hosts con MAC conocida — reintentando en 15s")
            self.ventana.after(15000, lambda: self._arrancar_interceptor(interfaz))
            return

        log(f"[APP] Lanzando interceptor | gateway: {gw_ip} ({gw_mac}) | "
            f"{len(hosts)} hosts")
        self.interceptor.iniciar(
            interfaz=interfaz,
            gateway_ip=gw_ip,
            gateway_mac=gw_mac,
            hosts=hosts,
            gateway_bssid=gw_mac
        )

    def _resolver_mac_gateway(self, gw_ip):
        """
        Resuelve la MAC del gateway leyendo la tabla ARP del sistema operativo.
        Fallback cuando nmap no pudo hacer el ARP sweep (timeout con monitor activo).
        """
        try:
            # Leer /proc/net/arp directamente — siempre disponible en Linux
            with open("/proc/net/arp", "r") as f:
                for linea in f.readlines()[1:]:  # saltar cabecera
                    partes = linea.split()
                    if len(partes) >= 4 and partes[0] == gw_ip:
                        mac = partes[3]
                        if mac and mac != "00:00:00:00:00:00":
                            return mac
        except Exception:
            pass
        # Fallback: arping
        try:
            r = subprocess.run(
                ["arping", "-c", "2", "-I",
                 self.interfaz.get(), gw_ip],
                capture_output=True, text=True, timeout=5)
            import re
            m = re.search(r'\[([0-9a-fA-F:]{17})\]', r.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
        return None

    # ─────────────────────────────────────────
    # CALLBACKS
    # ─────────────────────────────────────────

    def _on_dispositivo_encontrado(self, datos):
        ip           = datos.get("ip")
        mac          = datos.get("mac")
        puertos      = datos.get("puertos", [])
        solo_puertos = datos.get("solo_puertos", False)
        if not ip: return

        # ── Hallazgo directo desde scanner (SSL, DC, Shares, LDAP…) ─────────
        # Acepta tanto "hallazgo" (legacy) como "hallazgo_directo" (nuevo)
        hallazgo_directo = datos.get("hallazgo_directo") or datos.get("hallazgo")
        if hallazgo_directo:
            nodo = self.topologia.obtener_nodo(ip)
            if nodo is None:
                nodo = self.topologia.agregar_o_actualizar(ip, mac=mac, bytes=0)
            if nodo:
                from core.nodes import Hallazgo
                h = Hallazgo(
                    ip,
                    hallazgo_directo.get("puerto", 0),
                    hallazgo_directo.get("servicio", "?"),
                    hallazgo_directo.get("severidad", "info"),
                    hallazgo_directo.get("descripcion", "")
                )
                ya_existe = any(
                    hh.servicio == h.servicio and hh.puerto == h.puerto
                    for hh in nodo.hallazgos
                )
                if not ya_existe:
                    nodo.hallazgos.append(h)
                    self.topologia.alertas.append(h)   # ← panel de alertas
                    from core.nodes import severidad_maxima
                    nodo.severidad_max = severidad_maxima(nodo.hallazgos)
                    bump = {"critico": 50, "alto": 25, "medio": 10, "info": 0}
                    nodo.risk_score = min(100, (nodo.risk_score or 0) +
                                         bump.get(h.severidad, 0))
                    detalle = getattr(h, 'detalle', getattr(h, 'desc', ''))
                    log(f"[HALLAZGO] {ip}:{h.puerto} {h.servicio} "
                        f"[{h.severidad.upper()}] — {detalle}")
                    if h.severidad in ("alto", "critico"):
                        toast.notificar(
                            f"{h.severidad.upper()}: {ip}",
                            f"{h.servicio}:{h.puerto} — {detalle[:50]}",
                            h.severidad
                        )

                # DC Detection — actualizar tipo y perfil del nodo
                tipo_dev = datos.get("tipo_dispositivo")
                perfil   = datos.get("perfil")
                if tipo_dev:
                    nodo.tipo = tipo_dev
                if perfil and perfil not in (nodo.perfiles or []):
                    if not nodo.perfiles:
                        nodo.perfiles = []
                    nodo.perfiles.append(perfil)

            return  # hallazgo directo ya procesado

        # ── Hostname DNS resuelto en Fase 1 ──────────────────────────────────
        hostname = datos.get("hostname")

        if solo_puertos:
            nodo = self.topologia.obtener_nodo(ip)
            if nodo and puertos:
                for p in puertos:
                    if p not in nodo.puertos_abiertos:
                        nodo.puertos_abiertos.append(p)
                fingerprint_completo(nodo)
        else:
            es_nuevo = ip not in self.topologia.nodos
            datos_limpios = {k: v for k, v in datos.items()
                             if k not in ("ip", "hallazgo", "hostname")}
            nodo = self.topologia.agregar_o_actualizar(ip, **datos_limpios)
            if nodo:
                # Guardar hostname si lo tenemos
                if hostname and not getattr(nodo, 'hostname', None):
                    nodo.hostname = hostname
                    log(f"[DNS] {ip} → {hostname}")

                fingerprint_completo(nodo)

                # Análisis diferencial con historial SQLite
                if not nodo.delta:
                    prev = self._estado_previo.get(ip)
                    nodo.delta = comparar_nodos(nodo, prev)
                    if "NUEVO" in nodo.delta:
                        log(f"[HISTORIAL] Nuevo host detectado en red: {ip}")
                else:
                    prev = self._estado_previo.get(ip)
                    nuevos_deltas = comparar_nodos(nodo, prev)
                    if nuevos_deltas != nodo.delta:
                        nodo.delta = nuevos_deltas

                if nodo.tipo == "arp-scanner":
                    toast.notificar(
                        f"ARP Scanner: {ip}",
                        f"Este host está haciendo escaneo activo de la red",
                        "alto"
                    )

        # Registrar hallazgos si hay puertos nuevos
        if puertos:
            nodo = self.topologia.obtener_nodo(ip)
            nuevos_hallazgos = self.topologia.registrar_hallazgos(ip, puertos)
            for h in nuevos_hallazgos:
                log(f"[HALLAZGO] {h.ip}:{h.puerto} {h.servicio} [{h.severidad.upper()}]")
                if h.severidad in ("alto", "critico"):
                    nivel_t = "critico" if h.severidad == "critico" else "alto"
                    toast.notificar(
                        f"{h.severidad.upper()}: {h.ip}",
                        f"Puerto {h.puerto} — {h.servicio}",
                        nivel_t
                    )
        else:
            nuevos_hallazgos = []

        if self.topologia.gateway:
            self.topologia.deducir_jerarquia()

    def _on_paquete_capturado(self, datos):
        # ── Tipos especiales de enriquecimiento ──────────────────
        tipo = datos.get("tipo")

        # DHCP fingerprint — identifica OS por Option 55
        if tipo == "DHCP_FINGERPRINT":
            self._on_dhcp_fingerprint(datos)
            # También notificar al detector rogue si es Offer/ACK del servidor
            msg_type = datos.get("dhcp_type", "")
            if msg_type in ("offer", "ack", 2, 5):
                ip_srv = datos.get("ip_origen") or datos.get("server_id", "")
                mac_srv = datos.get("mac_origen", "")
                ip_ofr  = datos.get("ip_ofrecida", "?")
                if ip_srv and hasattr(self, '_dhcp_rogue'):
                    self._dhcp_rogue.registrar_oferta(ip_srv, mac_srv, ip_ofr)
            return

        # mDNS — nombre real del dispositivo
        if tipo == "MDNS_DISCOVERY":
            self._on_mdns(datos)
            return

        # SSDP/UPnP — modelo y fabricante de smart devices
        if tipo == "SSDP_DISCOVERY":
            self._on_ssdp(datos)
            return

        # HTTP payload — User-Agent, host, credenciales
        if tipo == "HTTP_PAYLOAD":
            self._on_http_payload(datos)
            return

        # FTP en texto plano — credenciales y banners
        if tipo in ("FTP_USER", "FTP_PASS", "FTP_BANNER",
                    "FTP_LOGIN_OK", "FTP_LOGIN_FAIL"):
            self._on_ftp(datos)
            return

        # Telnet en texto plano — sesión completa
        if tipo == "TELNET_DATA":
            self._on_telnet(datos)
            return

        # Paquetes DOT11 (modo monitor sin IP) — solo actividad por MAC
        if datos.get("tipo") == "DOT11":
            mac_origen = datos.get("mac_origen")
            if mac_origen:
                for nodo in self.topologia.todos_los_nodos():
                    if nodo.mac and nodo.mac.lower() == mac_origen.lower():
                        nodo.actualizar_actividad(datos.get("bytes", 0))
                        break
            return

        # Flag que marca paquetes capturados via ARP spoof o monitor
        # En estos casos la MAC origen viene envenenada con nuestra propia MAC
        # → NO actualizar MAC del nodo para evitar corrupción del fingerprint
        es_interceptado = datos.get("interceptado", False)

        ip_origen  = datos.get("ip_origen")
        ip_destino = datos.get("ip_destino")
        mac_origen = datos.get("mac_origen")
        ttl        = datos.get("ttl")
        protocolo  = datos.get("tipo", "")
        bytes_pkt  = datos.get("bytes", 0)

        # ── Descubrimiento pasivo IPv6 ───────────────────────────────────────
        if datos.get("ipv6") and ip_origen and hasattr(self, '_ipv6'):
            # No bloquear — registrar en segundo plano
            def _reg_ipv6(ip6=ip_origen, mac=mac_origen):
                self._ipv6.registrar_paquete_ipv6(ip6, ip_destino, mac)
            self.ventana.after(0, _reg_ipv6)

        # ── JA3/JA3S — fingerprint TLS ──────────────────────────────────────
        tls_payload = datos.get("tls_payload")
        if tls_payload and ip_origen and ip_destino and hasattr(self, '_ja3'):
            puerto_dst = datos.get("puerto_destino", 443)
            puerto_src = datos.get("puerto_origen", 0)
            self._ja3.procesar_paquete(
                ip_origen, ip_destino, puerto_dst, puerto_src, tls_payload)

        # ── Detectar ARP scan masivo ─────────────────────────────────────
        # Si un host envía ARP a destinos que NO existen en la red,
        # es un escaneo — lo contamos pero NO lo registramos como enlace
        # ni lo incluimos en el log de flujo.
        if protocolo == "ARP" and ip_origen and ip_destino:
            destino_conocido = ip_destino in self.topologia.nodos
            if not destino_conocido:
                # Contar cuántos ARP a desconocidos por origen
                clave = f"arp_scan:{ip_origen}"
                if not hasattr(self, "_arp_scan_contadores"):
                    self._arp_scan_contadores = {}
                self._arp_scan_contadores[clave] = \
                    self._arp_scan_contadores.get(clave, 0) + 1
                n = self._arp_scan_contadores[clave]

                # Umbral: 20 ARPs a desconocidos = ARP scan
                es_router   = (ip_origen == self.topologia.router)
                es_ip_local = (ip_origen == self.topologia.ip_local)
                # Filtrar IPs de subredes ajenas (VPN, túneles, etc.)
                subred_local = self.topologia.subred  # "10.11.8"
                es_subred_ajena = subred_local and not ip_origen.startswith(subred_local)
                if n == 20 and not es_router and not es_ip_local and not es_subred_ajena:
                    log(f"[ALERTA] {ip_origen} está haciendo ARP scan "
                        f"(≥20 ARPs a hosts desconocidos)")
                    nodo = self.topologia.nodos.get(ip_origen)
                    if nodo:
                        nodo.tipo = "arp-scanner"

                # No procesar este paquete más allá — ignorar el enlace
                # Sí actualizamos actividad del origen
                if ip_origen:
                    nodo = self.topologia.agregar_o_actualizar(
                        ip_origen, mac=mac_origen, bytes=bytes_pkt)
                    if nodo and ttl:
                        nodo.ttl = ttl
                return  # ← salir sin crear enlace a IP desconocida
        # ────────────────────────────────────────────────────────────────

        if ip_origen:
            ya_existia = ip_origen in self.topologia.nodos
            ip_local = self.topologia.ip_local

            if es_interceptado:
                if ip_origen == ip_local:
                    mac_a_usar = self._obtener_mac_local()
                else:
                    mac_a_usar = None
            else:
                mac_a_usar = mac_origen

            nodo = self.topologia.agregar_o_actualizar(
                ip_origen, mac=mac_a_usar, bytes=bytes_pkt)
            if nodo:
                if ttl: nodo.ttl = ttl
                # Para el nodo propio: mantener tipo/fabricante correcto
                # La captura pasiva puede sobreescribirlo con 'desconocido'
                if ip_origen == ip_local:
                    if not nodo.tipo or nodo.tipo == "desconocido":
                        nodo.tipo = "pc"
                    if not nodo.fabricante or nodo.fabricante == "Desconocido":
                        nodo.fabricante = "Local"
                fingerprint_completo(nodo)
                if not ya_existia:
                    log(f"[RED] Nuevo host: {ip_origen} "
                        f"| MAC: {mac_origen or '—'} | via {protocolo}")
                    # Toast nuevo host
                    tipo_str = nodo.tipo or "desconocido"
                    fab_str  = nodo.fabricante or "?"
                    toast.notificar(
                        f"Nuevo host: {ip_origen}",
                        f"{tipo_str.capitalize()} — {fab_str} | via {protocolo}",
                        "info"
                    )
                    # Encolar para escaneo de puertos en background
                    if hasattr(self.scanner, 'encolar_nodo'):
                        self.scanner.encolar_nodo(ip_origen)

        # CDP — Cisco Discovery Protocol
        if tipo == "CDP_DISCOVERY":
            self._on_cdp_lldp(datos, "CDP")
            return

        # LLDP — Link Layer Discovery Protocol
        if tipo == "LLDP_DISCOVERY":
            self._on_cdp_lldp(datos, "LLDP")
            return

        # DHCP rogue — notificar al detector y continuar procesamiento normal
        if protocolo == "DHCP" and ip_origen and ip_origen != "0.0.0.0":
            if hasattr(self, '_dhcp_rogue'):
                self._dhcp_rogue.registrar_oferta(
                    ip_origen, datos.get("mac_origen",""), ip_destino or "?")

        if ip_origen and ip_destino:
            # Solo crear enlace si el destino es un host conocido en la red
            origen_local  = self.topologia._es_local(ip_origen)
            destino_local = self.topologia._es_local(ip_destino)
            destino_conocido = ip_destino in self.topologia.nodos
            origen_conocido  = ip_origen  in self.topologia.nodos

            if es_interceptado:
                # Paquetes MITM: ambas IPs son hosts reales de la red.
                # Registrar el enlace siempre que ambas sean IPs locales,
                # aunque el host no esté en nodos aún — esto alimenta el
                # tráfico lateral del canvas.
                if origen_local and destino_local and ip_origen != ip_destino:
                    self.topologia.agregar_enlace(ip_origen, ip_destino, protocolo)
                    # Log de flujo 1 vez cada 30s — igual que tráfico normal
                    if not hasattr(self, "_flujos_vistos"):
                        self._flujos_vistos = {}
                    ahora2 = __import__("time").time()
                    clave_f = f"{ip_origen}>{ip_destino}:{protocolo}"
                    if ahora2 - self._flujos_vistos.get(clave_f, 0) > 30:
                        self._flujos_vistos[clave_f] = ahora2
                        log(f"[FLUJO] {ip_origen} → {ip_destino} [{protocolo}]")
                elif origen_local and not destino_local:
                    self.topologia.agregar_enlace(ip_origen, ip_destino, protocolo)
            elif destino_conocido or not (origen_local and destino_local):
                self.topologia.agregar_enlace(ip_origen, ip_destino, protocolo)

            if not hasattr(self, "_flujos_vistos"):
                self._flujos_vistos = {}
            ahora = __import__("time").time()

            # Flujo local conocido — log 1 vez cada 30s por par+proto
            # Incluye paquetes interceptados (es_interceptado=True)
            origen_conocido = ip_origen in self.topologia.nodos
            if origen_local and destino_local and destino_conocido \
                    and ip_origen != ip_destino:
                clave_flujo = f"{ip_origen}>{ip_destino}:{protocolo}"
                if ahora - self._flujos_vistos.get(clave_flujo, 0) > 30:
                    self._flujos_vistos[clave_flujo] = ahora
                    log(f"[FLUJO] {ip_origen} → {ip_destino} [{protocolo}]")

            # Conexión externa — todos los protocolos de red relevantes
            # (excluir ARP, DOT11 y protocolos sin IP externa real)
            PROTOS_EXTERNOS = {
                "TCP","UDP","HTTPS","HTTP","SSH","DNS","QUIC",
                "SMTP","FTP","ICMP","ICMP-Echo","ICMP-Reply",
                "IPSec-ESP","IPSec-AH","SCTP","RTSP","SIP",
                "MQTT","RDP","SMB","NTP","SNMP","IGMP",
                "Hikvision","Hikvision-SDR","OpenVPN","IMAP",
                "IMAPS","POP3","POP3S","SMTPS","LDAP","LDAPS",
                "MSSQL","MySQL","PostgreSQL","Redis","MongoDB",
                "FTP-Data","Telnet","TFTP","Syslog","BGP","OSPF",
                "XMPP","VNC","HTTP-Alt","HTTPS-Alt","MQTT-TLS",
            }
            if origen_local and not destino_local \
                    and protocolo in PROTOS_EXTERNOS:
                clave_ext = f"ext:{ip_origen}>{ip_destino}"
                if ahora - self._flujos_vistos.get(clave_ext, 0) > 60:
                    self._flujos_vistos[clave_ext] = ahora
                    # Enriquecer con GeoIP si está disponible
                    geo_info = None
                    geo_str  = ""
                    if self.geoip.disponible:
                        geo_info = self.geoip.lookup(ip_destino)
                        geo_str  = self.geoip.formato_corto(ip_destino)
                    if geo_str:
                        log(f"[EXTERNO] {ip_origen} → {ip_destino} "
                            f"[{protocolo}] {geo_str}")
                    else:
                        log(f"[EXTERNO] {ip_origen} → {ip_destino} [{protocolo}]")
                    # Registrar en topología con info geo
                    self.topologia.registrar_externo(
                        ip_origen, ip_destino, protocolo, geo=geo_info)

                    # ── NTP drift — medir offset cuando vemos tráfico NTP ──
                    if protocolo == "NTP" and hasattr(self, '_ntp'):
                        self._ntp.analizar_servidor(ip_destino, ip_origen)

                    # ── Beacon C2 Detection ───────────────────────
                    # Alimentar el detector con CADA conexión externa
                    # (sin el filtro de 60s — el detector maneja su propio historial)
                    self._beacon.registrar(ip_origen, ip_destino, protocolo)

                    # Alimentar ventana de tráfico si está abierta
                    if hasattr(self, '_ventana_trafico') and self._ventana_trafico:
                        try:
                            self._ventana_trafico.registrar_flujo(
                                ip_origen, ip_destino, protocolo,
                                geo=geo_info, bytes_n=bytes_pkt)
                        except Exception:
                            pass

            # Detección evento TCP masivo — muchos hosts → mismo destino en <10s
            if protocolo in ("TCP","HTTPS","HTTP","SSH","RDP","SMB") \
                    and origen_local and not destino_local:
                ventana = self._tcp_masivo_ventana.setdefault(ip_destino, {})
                ventana[ip_origen] = ahora
                viejos = [k for k, t in ventana.items() if ahora - t > 10]
                for k in viejos: del ventana[k]
                if len(ventana) >= 10 and ip_destino not in self._tcp_masivo_alertado:
                    self._tcp_masivo_alertado.add(ip_destino)
                    log(f"[EVENTO] {len(ventana)} hosts se conectaron a "
                        f"{ip_destino} [{protocolo}] en <10s — posible autenticación masiva")


    # ─────────────────────────────────────────
    # ACCIONES DE BOTONES
    # ─────────────────────────────────────────

    def _iniciar_escaneo(self):
        interfaz = self.interfaz.get()
        if not interfaz:
            messagebox.showwarning("Interfaz", "Selecciona una interfaz de red")
            return
        log(f"[APP] Botón Escanear presionado — interfaz: {interfaz}")
        self._configurar_red(interfaz)
        self._arrancar(interfaz)

    def _detener(self):
        log("[APP] Botón Detener presionado")
        self.capture.detener()
        if hasattr(self, 'interceptor') and self.interceptor.corriendo:
            threading.Thread(
                target=self.interceptor.detener,
                daemon=True, name="interceptor-stop").start()
        self.btn_escanear.config(state=tk.NORMAL)
        self.btn_detener.config(state=tk.DISABLED)
        self.label_estado.config(text="● Detenido", fg="#8b949e")

    def _limpiar(self):
        log("[APP] Botón Limpiar presionado")
        self.capture.detener()
        if hasattr(self, 'interceptor') and self.interceptor.corriendo:
            threading.Thread(
                target=self.interceptor.detener,
                daemon=True, name="interceptor-stop-limpiar").start()
        self._mac_local_cache = None
        self.topologia.limpiar_todo()
        # Limpiar historial del detector de beacons
        if hasattr(self, '_beacon'):
            self._beacon.limpiar()
        self.canvas.redibujar()
        interfaz = self.interfaz.get()
        if interfaz:
            self._configurar_red(interfaz)
            self.ventana.after(3000, lambda: self._arrancar(interfaz))

    def _toggle_lateral(self):
        estado = self.var_lateral.get()
        self.canvas.mostrar_lateral = estado
        log(f"[APP] Tráfico lateral: {'activado' if estado else 'desactivado'}")

    def _abrir_stats(self):
        """Abre el dashboard de estadísticas."""
        log("[APP] Abriendo dashboard de analíticas...")
        VentanaStats(self.ventana, self.topologia)

    def _abrir_ventana_wifi(self):
        """Abre el panel WiFi Scope."""
        from ui.ventana_wifi import VentanaWifi
        log("[APP] Abriendo WiFi Scope...")
        # Obtener BSSID de nuestra red (== MAC del gateway en WiFi)
        bssid_propio = None
        if self.topologia.gateway:
            gw_nodo = self.topologia.obtener_nodo(self.topologia.gateway)
            if gw_nodo and gw_nodo.mac:
                bssid_propio = gw_nodo.mac

        if not hasattr(self, '_ventana_wifi') or not self._ventana_wifi:
            self._ventana_wifi = VentanaWifi(self.ventana,
                                             bssid_propio=bssid_propio)
        else:
            try:
                self._ventana_wifi.ventana.lift()
                # Actualizar BSSID por si aún no lo tenía
                if bssid_propio:
                    self._ventana_wifi.set_bssid_propio(bssid_propio)
            except Exception:
                self._ventana_wifi = VentanaWifi(self.ventana,
                                                 bssid_propio=bssid_propio)

    def _on_ja3_hallazgo(self, tipo, datos):
        """Callback del JA3Fingerprinter."""
        def _ui():
            from core.nodes import Hallazgo, severidad_maxima
            ip_src   = datos.get("ip_src", "?")
            ja3_hash = datos.get("hash", "")
            app_name = datos.get("app", "Desconocido")
            sev      = datos.get("severidad", "info")
            detalle  = datos.get("detalle", "")

            nodo = self.topologia.obtener_nodo(ip_src)
            if not nodo:
                return

            clave = f"{tipo}:{ja3_hash[:8]}"
            ya_existe = any(clave in (h.servicio or "") for h in nodo.hallazgos)
            if ya_existe:
                return

            h = Hallazgo(nodo.ip, datos.get("puerto", 443),
                         clave, sev, detalle[:80])
            nodo.hallazgos.append(h)
            self.topologia.alertas.append(h)
            nodo.severidad_max = severidad_maxima(nodo.hallazgos)

            if sev == "critico":
                nodo.risk_score = min(100, (nodo.risk_score or 0) + 40)
                toast.notificar(
                    f"🔴 {tipo} Malware: {ip_src}",
                    f"{app_name} | {ja3_hash[:16]}...",
                    sev)
            # info solo va al log, no toast
            log(f"[{tipo}] {ip_src} → {datos.get('ip_dst','')}:"
                f"{datos.get('puerto',443)} | {ja3_hash[:12]}... | {app_name}")

        self.ventana.after(0, _ui)

    def _on_ntp_drift(self, ip_servidor, ip_cliente, offset, severidad, resumen):
        """Callback del NTPMonitor — crea hallazgo en el nodo cliente o servidor."""
        def _ui():
            from core.nodes import Hallazgo, severidad_maxima
            # El hallazgo va al nodo cliente (quien consultó el NTP)
            ip_target = ip_cliente or ip_servidor
            nodo = self.topologia.obtener_nodo(ip_target)
            if not nodo:
                return
            clave = f"NTP Drift:{ip_servidor[:12]}"
            ya_existe = any(clave in (h.servicio or "") for h in nodo.hallazgos)
            if ya_existe:
                return
            detalle = f"{resumen} | Servidor: {ip_servidor}"
            h = Hallazgo(nodo.ip, 123, clave, severidad, detalle[:80])
            nodo.hallazgos.append(h)
            self.topologia.alertas.append(h)
            nodo.severidad_max = severidad_maxima(nodo.hallazgos)
            if severidad in ("alto", "medio"):
                toast.notificar(
                    f"⏱ NTP Drift: {ip_servidor}",
                    resumen[:50], severidad)
        self.ventana.after(0, _ui)

    def _abrir_modulos_ofensivos(self):
        """Abre la ventana de módulos ofensivos con advertencia opt-in."""
        from tkinter import messagebox, Toplevel, Label, Button, Frame, BooleanVar, Checkbutton

        advertencia = (
            "⚠ MÓDULOS OFENSIVOS — USO RESPONSABLE\n\n"
            "Estos módulos realizan ataques activos en la red:\n"
            "• LLMNR/NBT-NS Poisoning — captura hashes NTLMv2\n"
            "• WPAD Spoofing — intercepta configuración de proxy\n"
            "• VLAN Hopping — prueba segmentación de red\n\n"
            "SOLO usar en redes propias o con permiso escrito.\n"
            "Uso no autorizado es ilegal en la mayoría de países.\n\n"
            "¿Confirmas que tienes autorización para esta red?"
        )
        if not messagebox.askyesno(
                "Advertencia — Módulos Ofensivos",
                advertencia, icon="warning"):
            return

        # Crear instancia si no existe
        interfaz = self.interfaz.get() or "wlan0"
        if not self._ofensivo:
            self._ofensivo = ModulosOfensivos(
                interfaz=interfaz,
                callback=self._on_ofensivo_hallazgo)
            _ofensivo_set_log(log)

        # Ventana de control
        win = Toplevel(self.ventana)
        win.title("Módulos Ofensivos")
        win.geometry("380x280")
        win.configure(bg="#0d1117")
        win.resizable(False, False)

        Label(win, text="⚔ MÓDULOS OFENSIVOS",
              bg="#0d1117", fg="#f0883e",
              font=("Monospace", 11, "bold")).pack(pady=10)

        def _boton_modulo(texto, nombre, fn_iniciar, fn_detener):
            f = Frame(win, bg="#161b22")
            f.pack(fill="x", padx=15, pady=4)
            Label(f, text=texto, bg="#161b22", fg="#c9d1d9",
                  font=("Monospace", 9), anchor="w", width=28).pack(side="left")
            activo = self._ofensivo.esta_activo(nombre)

            def _toggle(b=None, _nombre=nombre, _fi=fn_iniciar, _fd=fn_detener):
                if self._ofensivo.esta_activo(_nombre):
                    _fd()
                    btn.config(text="▶ Activar", bg="#21262d", fg="#58d6ff")
                else:
                    _fi()
                    btn.config(text="⏹ Detener", bg="#da3633", fg="white")

            btn = Button(f, text="⏹ Detener" if activo else "▶ Activar",
                bg="#da3633" if activo else "#21262d",
                fg="white" if activo else "#58d6ff",
                font=("Monospace", 8), relief="flat",
                cursor="hand2", command=_toggle, padx=6)
            btn.pack(side="right")

        _boton_modulo("LLMNR/NBT-NS Poisoning", "llmnr",
            self._ofensivo.iniciar_llmnr,
            self._ofensivo.detener_llmnr)
        _boton_modulo("WPAD Spoofing", "wpad",
            self._ofensivo.iniciar_wpad,
            self._ofensivo.detener_wpad)
        _boton_modulo("VLAN Hopping (detección)", "vlan",
            lambda: self._ofensivo.iniciar_vlan_hop(
                gateway_mac=getattr(self.topologia, 'gateway_mac', None)),
            self._ofensivo.detener_vlan)

        Label(win,
              text="Los resultados aparecen en el panel de alertas",
              bg="#0d1117", fg="#6e7681",
              font=("Monospace", 7)).pack(pady=12)

        Button(win, text="Detener todo y cerrar",
               bg="#161b22", fg="#f0883e",
               font=("Monospace", 8), relief="flat", cursor="hand2",
               command=lambda: [self._ofensivo.detener_todo(), win.destroy()]
        ).pack(pady=4)

    def _on_ofensivo_hallazgo(self, tipo, datos):
        """Callback de módulos ofensivos — crea hallazgo en el panel."""
        def _ui():
            from core.nodes import Hallazgo, severidad_maxima
            ip_victima = datos.get("ip_victima", "?")
            detalle    = datos.get("detalle", "")

            # Buscar o crear nodo
            nodo = self.topologia.obtener_nodo(ip_victima)
            if not nodo and ip_victima != "?":
                nodo = self.topologia.agregar_o_actualizar(
                    ip_victima, bytes=0)
            if not nodo:
                return

            sev_map = {
                "LLMNR_QUERY"   : ("medio",  "LLMNR Envenenado"),
                "NBTNS_QUERY"   : ("medio",  "NBT-NS Envenenado"),
                "WPAD_QUERY"    : ("alto",   "WPAD Interceptado"),
                "WPAD_DOWNLOAD" : ("alto",   "WPAD Descargado"),
                "VLAN_HOP"      : ("critico","VLAN Hopping"),
            }
            sev, servicio = sev_map.get(tipo, ("info", tipo))

            clave = f"{servicio}:{ip_victima}"
            ya_existe = any(clave in (h.servicio or "")
                            for h in nodo.hallazgos)
            if ya_existe:
                return

            h = Hallazgo(nodo.ip, 0, servicio, sev, detalle[:80])
            nodo.hallazgos.append(h)
            self.topologia.alertas.append(h)
            nodo.severidad_max = severidad_maxima(nodo.hallazgos)
            nodo.risk_score = min(100, (nodo.risk_score or 0) +
                                  {"critico":40,"alto":25,"medio":15}.get(sev,0))

            log(f"[OFENSIVO] {tipo}: {detalle[:60]}")
            icono = "🔴" if sev == "critico" else "🟠" if sev == "alto" else "🟡"
            toast.notificar(
                f"{icono} {servicio}: {ip_victima}",
                detalle[:50], sev)

        self.ventana.after(0, _ui)

    def _abrir_ventana_trafico(self):
        """Abre el panel de Análisis de Tráfico en Tiempo Real."""
        from ui.ventana_trafico import VentanaTrafico
        log("[APP] Abriendo análisis de tráfico...")
        if not hasattr(self, '_ventana_trafico') or not self._ventana_trafico:
            self._ventana_trafico = VentanaTrafico(
                self.ventana, topologia=self.topologia)
        else:
            try:
                self._ventana_trafico.ventana.lift()
            except Exception:
                self._ventana_trafico = VentanaTrafico(
                    self.ventana, topologia=self.topologia)

    def _on_dhcp_fingerprint(self, datos):
        """
        Procesa fingerprint DHCP Option 55 — identifica OS del dispositivo.
        Es la técnica pasiva más precisa: el dispositivo se delata solo.
        """
        ip  = datos.get("ip_origen")
        mac = datos.get("mac_origen")
        opt = datos.get("option_55")
        hostname = datos.get("hostname")
        vendor   = datos.get("vendor_id")

        if not ip and not mac:
            return

        # Buscar o crear el nodo
        nodo = self.topologia.obtener_nodo(ip) if ip else None
        if not nodo and mac:
            for n in self.topologia.todos_los_nodos():
                if n.mac and n.mac.lower() == mac.lower():
                    nodo = n
                    break
        if not nodo:
            return

        from tools.fingerprint import registrar_dhcp_fingerprint
        if opt:
            registrar_dhcp_fingerprint(nodo, opt)

        # Hostname DHCP — nombre real del dispositivo
        if hostname and not getattr(nodo, 'hostname', None):
            nodo.hostname = hostname
            log(f"[DHCP] {ip or mac} → hostname: {hostname}")

        # Vendor class ID (ej: "android-dhcp-11", "MSFT 5.0")
        if vendor:
            if "android" in vendor.lower():
                nodo.sistema_op = f"Android ({vendor[:20]})"
                nodo.tipo = "smartphone"
            elif "msft" in vendor.lower() or "windows" in vendor.lower():
                nodo.sistema_op = "Windows"
                nodo.tipo = "pc"
            elif "apple" in vendor.lower():
                nodo.sistema_op = "iOS/macOS"
            log(f"[DHCP] {ip or mac} → vendor: {vendor[:30]}")

    def _on_mdns(self, datos):
        """
        Procesa anuncios mDNS — nombre real del dispositivo en la red.
        'iPhone-de-Juan.local', 'HP-LaserJet-400.local', etc.
        """
        ip      = datos.get("ip_origen")
        nombres = datos.get("nombres", [])
        if not ip or not nombres:
            return

        nodo = self.topologia.obtener_nodo(ip)
        if not nodo:
            return

        for nombre in nombres:
            nombre = nombre.lower()
            # Filtrar nombres genéricos sin info útil
            if len(nombre) < 4 or nombre in ("local", "in-addr.arpa"):
                continue
            # Quitar sufijo .local
            nombre_limpio = nombre.replace(".local", "").replace("._tcp", "")

            # Guardar hostname si no lo tenemos
            if not getattr(nodo, 'hostname', None):
                nodo.hostname = nombre_limpio[:40]
                log(f"[mDNS] {ip} → {nombre_limpio}")

            # Inferir tipo por nombre
            nombre_l = nombre_limpio.lower()
            if "iphone" in nombre_l or "ipad" in nombre_l:
                nodo.tipo = "smartphone"
                nodo.fabricante = "Apple"
                nodo.sistema_op = "iOS"
            elif "macbook" in nombre_l or "imac" in nombre_l:
                nodo.tipo = "pc"
                nodo.fabricante = "Apple"
                nodo.sistema_op = "macOS"
            elif any(x in nombre_l for x in ("printer","impresora","laserjet","deskjet")):
                nodo.tipo = "impresora"
            elif "chromecast" in nombre_l or "roku" in nombre_l:
                nodo.tipo = "smart_tv"
            elif "samsung" in nombre_l:
                nodo.fabricante = "Samsung"
            break  # con el primer nombre útil es suficiente

    def _on_ssdp(self, datos):
        """
        Procesa anuncios SSDP/UPnP — modelo exacto de smart devices.
        Smart TVs, consolas, routers NAS se identifican aquí.
        """
        ip          = datos.get("ip_origen")
        server      = datos.get("server", "")
        tipo_device = datos.get("tipo_device")
        if not ip:
            return

        nodo = self.topologia.obtener_nodo(ip)
        if not nodo:
            return

        if tipo_device and nodo.tipo == "desconocido":
            nodo.tipo = tipo_device

        if server:
            server_l = server.lower()
            # Identificar fabricante por string de servidor
            for fab, palabras in [
                ("Samsung",  ["samsung"]),
                ("LG",       ["webos", "lg "]),
                ("Sony",     ["sony", "bravia"]),
                ("Philips",  ["philips"]),
                ("Roku",     ["roku"]),
                ("Xbox",     ["xbox"]),
                ("PlayStation",["playstation","ps4","ps5"]),
                ("Synology", ["synology"]),
                ("QNAP",     ["qnap"]),
                ("Hikvision",["hikvision", "dahua"]),
                ("Tenda",    ["tenda"]),
            ]:
                if any(p in server_l for p in palabras):
                    if nodo.fabricante in ("Desconocido", "Privada/Aleatoria"):
                        nodo.fabricante = fab
                    if nodo.tipo in ("desconocido",):
                        nodo.tipo = tipo_device or "iot"
                    log(f"[SSDP] {ip} → {fab} | {server[:40]}")
                    break

    def _on_http_payload(self, datos):
        """
        Procesa payload HTTP plano — extrae User-Agent y detecta credenciales.
        Es la fuente más precisa para identificar dispositivos móviles.
        Solo funciona en HTTP (no HTTPS).
        """
        ip_src     = datos.get("ip_origen")
        user_agent = datos.get("user_agent", "")
        host       = datos.get("host", "")
        credencial = datos.get("credencial")

        if not ip_src:
            return

        nodo = self.topologia.obtener_nodo(ip_src)
        if not nodo:
            return

        # Aplicar User-Agent fingerprinting
        if user_agent:
            from tools.fingerprint import registrar_user_agent
            registrar_user_agent(nodo, user_agent)
            log(f"[HTTP] {ip_src} → UA: {user_agent[:60]}")

        # Comportamiento DNS desde el Host header
        if host:
            from tools.fingerprint import registrar_dns_comportamiento
            registrar_dns_comportamiento(nodo, host)

        # Credenciales en texto plano — hallazgo CRÍTICO
        if credencial:
            from core.nodes import Hallazgo, CRITICO, severidad_maxima
            h = Hallazgo(ip_src, 80, "Credencial HTTP",
                         CRITICO,
                         f"Basic Auth en claro → {credencial[:30]}")
            if not any(hh.servicio == "Credencial HTTP"
                       for hh in nodo.hallazgos):
                nodo.hallazgos.append(h)
                nodo.severidad_max = severidad_maxima(nodo.hallazgos)
                log(f"[HTTP] ⚠ CREDENCIAL EN TEXTO CLARO: {ip_src} → {credencial[:30]}")
                import ui.toast as toast
                toast.notificar(
                    f"⚠ CREDENCIAL: {ip_src}",
                    f"HTTP Basic Auth en texto claro",
                    "critico"
                )

    def _on_ftp(self, datos):
        """
        Procesa tráfico FTP en texto plano.
        Captura banners, usuarios, contraseñas y estado de login.
        """
        ip_src = datos.get("ip_origen")
        ip_dst = datos.get("ip_destino")
        tipo   = datos.get("tipo")
        dato   = datos.get("dato", "")

        if not ip_src:
            return

        if tipo == "FTP_BANNER":
            log(f"[FTP] Banner de {ip_dst}: {dato[:50]}")
            nodo = self.topologia.obtener_nodo(ip_dst)
            if nodo and not any(h.servicio == "FTP" for h in nodo.hallazgos):
                from core.nodes import Hallazgo, MEDIO
                h = Hallazgo(ip_dst, 21, "FTP", MEDIO,
                             f"FTP en texto plano — {dato[:40]}")
                nodo.hallazgos.append(h)

        elif tipo == "FTP_USER":
            log(f"[FTP] {ip_src} → USER: {dato}")

        elif tipo == "FTP_PASS":
            log(f"[FTP] ⚠ CONTRASEÑA FTP en claro: {ip_src} → {dato[:20]}")
            nodo = self.topologia.obtener_nodo(ip_src)
            if nodo:
                from core.nodes import Hallazgo, CRITICO, severidad_maxima
                h = Hallazgo(ip_src, 21, "Credencial FTP",
                             CRITICO,
                             f"PASS en texto claro → {dato[:30]}")
                if not any(hh.servicio == "Credencial FTP"
                           for hh in nodo.hallazgos):
                    nodo.hallazgos.append(h)
                    nodo.severidad_max = severidad_maxima(nodo.hallazgos)
                    import ui.toast as toast
                    toast.notificar(
                        f"⚠ CREDENCIAL FTP: {ip_src}",
                        f"Contraseña en texto plano interceptada",
                        "critico"
                    )

        elif tipo == "FTP_LOGIN_OK":
            log(f"[FTP] {ip_src} → Login exitoso en {ip_dst}")

    def _on_telnet(self, datos):
        """
        Procesa tráfico Telnet en texto plano.
        Todo lo que se escribe en Telnet es visible — incluyendo contraseñas.
        """
        ip_src     = datos.get("ip_origen")
        ip_dst     = datos.get("ip_destino")
        payload    = datos.get("payload", "")
        es_cliente = datos.get("es_cliente", True)

        if not ip_src or not payload:
            return

        # Solo loggear primera vez — Telnet genera mucho volumen
        clave = f"telnet:{ip_src}:{ip_dst}"
        if not hasattr(self, '_telnet_visto'):
            self._telnet_visto = set()

        if clave not in self._telnet_visto:
            self._telnet_visto.add(clave)
            log(f"[TELNET] ⚠ Sesión Telnet detectada: {ip_src} → {ip_dst}")

            # Crear hallazgo ALTO en el servidor Telnet
            ip_servidor = ip_dst if es_cliente else ip_src
            nodo = self.topologia.obtener_nodo(ip_servidor)
            if nodo:
                from core.nodes import Hallazgo, ALTO, severidad_maxima
                h = Hallazgo(ip_servidor, 23, "Telnet",
                             ALTO,
                             "Sesión Telnet en texto plano interceptada")
                if not any(hh.servicio == "Telnet"
                           for hh in nodo.hallazgos):
                    nodo.hallazgos.append(h)
                    nodo.severidad_max = severidad_maxima(nodo.hallazgos)
                    import ui.toast as toast
                    toast.notificar(
                        f"⚠ TELNET: {ip_servidor}",
                        f"Sesión en texto plano — {payload[:30]}",
                        "alto"
                    )

        # Loggear comandos del cliente (no respuestas del servidor)
        if es_cliente and len(payload) > 3:
            log(f"[TELNET] {ip_src} → cmd: {payload[:60]}")

    def _on_evento_wifi(self, evento):
        """Callback del monitor 802.11 — hilo secundario → usar after()."""
        tipo = evento.get("tipo")

        # ── Traducir formato interceptor → formato WiFi Scope ────────────────
        # El interceptor usa "tipo": "ap_detectado"/"handshake_wpa2"/"cliente"
        # El WiFi Scope v2 usa "tipo_wifi": "BEACON"/"HANDSHAKE_M1"/"DATA"
        if "tipo_wifi" not in evento:
            if tipo == "ap_detectado":
                evento = dict(evento, tipo_wifi="BEACON")
            elif tipo == "handshake_wpa2":
                evento = dict(evento, tipo_wifi="EAPOL")
            elif tipo in ("cliente", "cliente_detectado"):
                evento = dict(evento, tipo_wifi="DATA")
            elif tipo == "deauth":
                evento = dict(evento, tipo_wifi="DEAUTH")

        if tipo == "handshake_wpa2":
            cliente    = evento.get("cliente_mac", "?")
            bssid      = evento.get("bssid", "?")
            es_nuestra = evento.get("es_nuestra_red", False)
            frames     = evento.get("frames", [])
            ssid       = evento.get("ssid", bssid[:8] if bssid else "unknown")

            log(f"[WIFI] Handshake WPA2 | cliente: {cliente} | "
                f"AP: {bssid} | nuestra: {es_nuestra}")

            # Guardar .pcap en exports/
            ruta_pcap = self._guardar_handshake_pcap(
                frames, bssid, ssid, cliente)

            if es_nuestra:
                from core.nodes import Hallazgo, ALTO
                h = Hallazgo(bssid, 0, "Handshake WPA2", ALTO,
                             f"Handshake | cliente: {cliente}")
                self.ventana.after(0, lambda: self.topologia.alertas.append(h))

            # Toast de notificación
            nombre_red = ssid if ssid and ssid != "?" else bssid[:12]
            msg_extra  = f"Guardado: {ruta_pcap}" if ruta_pcap else ""
            self.ventana.after(0, lambda n=nombre_red, r=ruta_pcap: toast.notificar(
                f"⚡ Handshake WPA2: {n}",
                f"Cliente: {cliente} | {r or 'no guardado'}",
                "alto"
            ))

        # Si el WiFi Scope no tiene BSSID propio aún, dárselo
        if tipo == "ap_detectado" and evento.get("es_nuestra_red"):
            bssid = evento.get("bssid")
            if bssid and hasattr(self, '_ventana_wifi') and self._ventana_wifi:
                self.ventana.after(0, lambda b=bssid:
                    self._ventana_wifi.set_bssid_propio(b)
                    if self._ventana_wifi else None)

        # Pasar al panel WiFi si está abierto
        if hasattr(self, '_ventana_wifi') and self._ventana_wifi:
            self.ventana.after(0, lambda e=evento:
                self._ventana_wifi.procesar_evento(e)
                if self._ventana_wifi else None)

    def _guardar_handshake_pcap(self, frames, bssid, ssid, cliente_mac):
        """
        Guarda los frames EAPOL del handshake en un archivo .pcap en exports/.
        Retorna la ruta del archivo o None si falló.
        Compatible con Wireshark y hcxtools para hashcat.
        """
        if not frames:
            return None
        try:
            import os
            from datetime import datetime as dt
            from core.rutas import exports as _exp

            carpeta = _exp()  # detecta automáticamente dónde está instalado

            # Nombre: handshake_SSID_timestamp.pcap
            ssid_safe = "".join(c for c in ssid if c.isalnum() or c in "-_")[:20]
            ts = dt.now().strftime("%Y-%m-%d_%H-%M-%S")
            nombre = f"handshake_{ssid_safe}_{ts}.pcap"
            ruta = os.path.join(carpeta, nombre)

            from scapy.all import wrpcap
            wrpcap(ruta, frames)

            log(f"[WIFI] Handshake guardado: {ruta} ({len(frames)} frames)")
            return nombre  # Solo el nombre para el toast, no ruta completa
        except Exception as e:
            log(f"[WIFI] Error guardando handshake pcap: {e}")
            return None

    def _salir(self):
        """Detener todo, guardar log/historial y salir — con ventana de estado."""
        log("[APP] Botón Salir presionado — cerrando...")

        # Minimizar ventana principal inmediatamente
        try:
            self.ventana.iconify()
        except Exception:
            pass

        # Mostrar ventana de cierre
        cierre = self._ventana_cerrando()

        def _proceso_cierre():
            try:
                cierre.set_estado("Deteniendo captura de tráfico...")
                self.capture.detener()
                self.scanner.detener()
                if hasattr(self, '_ipv6'):
                    self._ipv6.detener()
            except Exception:
                pass
            try:
                cierre.set_estado("Restaurando red — ARP cleanup...")
                if hasattr(self, 'interceptor') and self.interceptor.corriendo:
                    self.interceptor.detener()
            except Exception:
                pass
            try:
                cierre.set_estado("Guardando sesión y log...")
                guardar_log(topologia=self.topologia,
                            hora_inicio=getattr(self, '_hora_inicio', None))
                log("[APP] Guardando historial diferencial...")
            except Exception:
                pass
            try:
                cierre.set_estado("Guardando historial diferencial...")
                self.historial.guardar_sesion(
                    self._interfaz_actual or "?",
                    self.topologia.nodos)
            except Exception as e:
                log(f"[ERROR] No se pudo guardar historial: {e}")

            cierre.set_estado("✓ Listo — hasta pronto")
            import time as _t
            _t.sleep(0.8)
            self.ventana.after(0, self.ventana.quit)

        import threading as _th
        _th.Thread(target=_proceso_cierre, daemon=True).start()

    def _ventana_cerrando(self):
        """Crea y retorna una mini-ventana de estado de cierre."""
        import tkinter as _tk

        win = _tk.Toplevel(self.ventana)
        win.overrideredirect(True)
        win.configure(bg="#020810")
        win.attributes("-topmost", True)

        W, H = 420, 130
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        win.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        # Marco
        _tk.Frame(win, bg="#00d4ff", height=2).pack(fill=_tk.X)

        cuerpo = _tk.Frame(win, bg="#020810")
        cuerpo.pack(fill=_tk.BOTH, expand=True, padx=16, pady=12)

        _tk.Label(cuerpo,
            text="TopoReveal — Cerrando",
            bg="#020810", fg="#00d4ff",
            font=("Courier", 11, "bold")
        ).pack(anchor="w")

        lbl_estado = _tk.Label(cuerpo,
            text="Iniciando cierre...",
            bg="#020810", fg="#4a7fa5",
            font=("Courier", 9)
        )
        lbl_estado.pack(anchor="w", pady=(6, 0))

        # Barra de progreso indeterminada
        canvas_bar = _tk.Canvas(cuerpo, bg="#020810",
            height=6, highlightthickness=0)
        canvas_bar.pack(fill=_tk.X, pady=(10, 0))

        # Animación de barra indeterminada
        _pos = [0]
        def _animar_barra():
            try:
                canvas_bar.delete("all")
                w = canvas_bar.winfo_width() or 380
                seg = 80
                x = _pos[0] % (w + seg) - seg
                canvas_bar.create_rectangle(0, 0, w, 6,
                    fill="#0a1628", outline="")
                canvas_bar.create_rectangle(x, 0, x + seg, 6,
                    fill="#00d4ff", outline="")
                _pos[0] += 8
                win.after(30, _animar_barra)
            except Exception:
                pass
        win.after(50, _animar_barra)

        class _Cierre:
            def set_estado(self_, msg):
                try:
                    self.ventana.after(0, lambda m=msg: lbl_estado.config(text=m))
                except Exception:
                    pass

        return _Cierre()

    # ─────────────────────────────────────────
    # CICLO
    # ─────────────────────────────────────────

    def _ciclo_actualizacion(self):
        try:
            self.topologia.limpiar_inactivos()
            self.canvas.redibujar()
            # Pasar subredes secundarias al canvas para dibujar islas
            self.canvas.subredes_secundarias = self.topologia.obtener_subredes()
            nodos_visibles = self.topologia.todos_los_nodos_visibles()
            nodos_todos    = self.topologia.todos_los_nodos()
            self.panel.actualizar(nodos_visibles)

            # Agregar hosts nuevos al interceptor si ya está corriendo
            if hasattr(self, 'interceptor') and self.interceptor.corriendo:
                ip_local = self.topologia.ip_local
                gw_ip    = self.topologia.gateway
                for nodo in nodos_todos:
                    if (nodo.mac and
                        not nodo.en_lobby and
                        nodo.ip != ip_local and
                        nodo.ip != gw_ip):
                        self.interceptor.agregar_host(nodo.ip, nodo.mac)

            if self.capture.esta_corriendo():
                self.label_estado.config(text="● Capturando", fg="#3fb950")
                paquetes_total = sum(n.paquetes for n in nodos_todos)
                self.label_sondeo.config(
                    text=f"⬡ Sondeo activo | pkts: {paquetes_total}",
                    fg="#3fb950")
            else:
                self.label_sondeo.config(text="◌ Sin sondeo", fg="#6e7681")

            # Contar nodos en lobby
            en_lobby = sum(1 for n in nodos_todos if n.en_lobby)
            if en_lobby > 0:
                self.label_sondeo.config(
                    text=f"⬡ Sondeo | pkts: {sum(n.paquetes for n in nodos_todos)} | lobby: {en_lobby}",
                    fg="#3fb950")
            # Actualizar panel alertas izquierdo en cada ciclo
            if hasattr(self, 'panel_alertas'):
                self.panel_alertas.actualizar()

        except Exception as e:
            log(f"[APP] Error en ciclo: {e}")

        self.ventana.after(2000, self._ciclo_actualizacion)

    def _exportar_png(self):
        try:
            ruta = exportar_png_canvas(self.canvas.c, self.ventana)
            if ruta:
                self._mostrar_toast(f"PNG guardado en exports/")
            else:
                self._mostrar_toast("No se pudo exportar PNG")
        except Exception as e:
            log(f"[EXPORT] Error PNG: {e}")

    def _exportar_json(self):
        try:
            ruta = exportar_json(self.topologia,
                                 log_buffer=_LOG_BUFFER,
                                 hora_inicio=getattr(self,'_hora_inicio',None))
            self._mostrar_toast("JSON guardado en exports/")
        except Exception as e:
            log(f"[EXPORT] Error JSON: {e}")

    def _exportar_csv(self):
        try:
            rutas = exportar_csv(self.topologia,
                                 log_buffer=_LOG_BUFFER,
                                 hora_inicio=getattr(self,'_hora_inicio',None))
            self._mostrar_toast(f"CSV guardado ({len(rutas)} archivos)")
        except Exception as e:
            log(f"[EXPORT] Error CSV: {e}")

    def _exportar_pdf(self):
        """Genera el informe PDF profesional."""
        import threading as _th
        log("[EXPORT] Generando informe PDF...")
        self._mostrar_toast("Generando PDF...")

        def _generar():
            try:
                from tools.generar_pdf import generar_informe
                ruta = generar_informe(
                    self.topologia,
                    log_buffer=_LOG_BUFFER,
                    hora_inicio=getattr(self, '_hora_inicio', None))
                log(f"[EXPORT] PDF guardado: {ruta}")
                nombre = ruta.split("/")[-1] if ruta else "informe.pdf"
                self.ventana.after(0, lambda: self._mostrar_toast(
                    f"PDF listo: {nombre}"))
                # Toast prominente
                import ui.toast as toast
                self.ventana.after(0, lambda: toast.notificar(
                    "📄 Informe PDF generado",
                    f"Guardado en exports/{nombre}",
                    "info"
                ))
            except Exception as e:
                log(f"[EXPORT] Error PDF: {e}")
                self.ventana.after(0, lambda: self._mostrar_toast(
                    f"Error generando PDF: {e}"))

        _th.Thread(target=_generar, daemon=True).start()

    def _mostrar_toast(self, msg):
        # Mensaje temporal en la barra de título
        titulo_orig = self.ventana.title()
        self.ventana.title(f"✓ {msg}")
        self.ventana.after(3000, lambda: self.ventana.title(titulo_orig))

    def _on_arsenal_resultado(self, ip, escaneo_id, titulo, texto, puertos):
        """Callback del Arsenal — recibe resultados de nmap en hilo de fondo."""
        # Este callback corre en hilo daemon, no en hilo UI.
        # Todo lo visual debe ir dentro de after(0, ...).
        log(f"[ARSENAL] Resultado: {titulo} en {ip}")

        nodo = self.topologia.obtener_nodo(ip)
        if not nodo:
            return

        # ── PING CHECK: solo actualizar estado — NO crear alerta ─────────────
        if escaneo_id == "ping":
            host_up   = "Host is up"      in texto or "host is up"      in texto
            host_down = "Host seems down" in texto or "0 hosts up"      in texto
            if host_up:
                nodo.actualizar_actividad()
                log(f"[ARSENAL] Ping {ip}: ACTIVO → confirmado")
                # Actualizar fabricante si aparece MAC
                import re as _re
                mac_m = _re.search(r'MAC Address: (\S+)\s+\((.+)\)', texto)
                if mac_m and not nodo.fabricante:
                    nodo.fabricante = mac_m.group(2)
            elif host_down:
                log(f"[ARSENAL] Ping {ip}: SIN RESPUESTA")
            # PING nunca crea alertas en el panel — solo actualiza estado
            return

        # ── OS DETECTION: actualizar sistema_op y crear alerta ────────────
        elif escaneo_id == "os":
            import re as _re
            # Buscar línea OS details
            os_match = _re.search(r'OS details?:\s*(.+)', texto)
            running_match = _re.search(r'Running:\s*(.+)', texto)
            os_str = None
            if os_match:
                os_str = os_match.group(1).strip()[:50]
            elif running_match:
                os_str = running_match.group(1).strip()[:50]

            if os_str:
                nodo.sistema_op = os_str
                log(f"[ARSENAL] OS {ip}: {os_str}")
                # Crear hallazgo informativo con el OS detectado
                from core.nodes import Hallazgo, INFO
                h = Hallazgo(ip, 0, f"OS: {os_str[:28]}", INFO,
                             f"Sistema operativo detectado por nmap -O")
                if not any(hh.servicio.startswith("OS:") for hh in nodo.hallazgos):
                    nodo.hallazgos.append(h)
                    self.topologia.alertas.append(h)
                    from core.nodes import severidad_maxima
                    nodo.severidad_max = severidad_maxima(nodo.hallazgos)

        # ── VULN SCAN: crear hallazgos críticos si hay vulnerabilidades ───
        elif escaneo_id == "vuln":
            import re as _re
            from core.nodes import Hallazgo, CRITICO, ALTO
            vulns_encontradas = []
            for linea in texto.splitlines():
                if "VULNERABLE" in linea.upper():
                    cve = _re.search(r'CVE-\d{4}-\d+', linea)
                    servicio = cve.group(0) if cve else "Vulnerabilidad"
                    h = Hallazgo(ip, 0, servicio, CRITICO,
                                 linea.strip()[:60])
                    if not any(hh.servicio == servicio for hh in nodo.hallazgos):
                        nodo.hallazgos.append(h)
                        self.topologia.alertas.append(h)
                        vulns_encontradas.append(servicio)
                elif linea.strip().startswith("| ") and "state: VULNERABLE" in linea.lower():
                    h = Hallazgo(ip, 0, "Vuln detectada", CRITICO,
                                 linea.strip()[:60])
                    if not any(hh.servicio == "Vuln detectada" for hh in nodo.hallazgos):
                        nodo.hallazgos.append(h)
                        self.topologia.alertas.append(h)
                        vulns_encontradas.append("Vuln detectada")
            if vulns_encontradas:
                log(f"[ARSENAL] \U0001f534 Vuln {ip}: {len(vulns_encontradas)} vulnerabilidades \u2192 {', '.join(vulns_encontradas)}")
                from core.nodes import severidad_maxima
                nodo.severidad_max = severidad_maxima(nodo.hallazgos)
                nodo.risk_score = min(nodo.risk_score + 30, 100)
                # Toast critico de vulnerabilidad
                toast.notificar(
                    f"\U0001f534 VULN CR\u00cdTICA: {ip}",
                    f"{len(vulns_encontradas)} vuln(s): {', '.join(vulns_encontradas[:2])}",
                    "critico"
                )
            else:
                log(f"[ARSENAL] Vuln scan {ip}: sin vulnerabilidades críticas detectadas")
                from core.nodes import Hallazgo, INFO
                h = Hallazgo(ip, 0, "Vuln scan OK", INFO,
                             "Vuln scan completado sin vulnerabilidades críticas")
                if not any(hh.servicio == "Vuln scan OK" for hh in nodo.hallazgos):
                    nodo.hallazgos.append(h)
                    self.topologia.alertas.append(h)

        # ── UDP: crear hallazgos para puertos UDP abiertos ────────────────
        elif escaneo_id == "udp":
            import re as _re
            from core.nodes import Hallazgo, MEDIO, INFO
            UDP_SERVICIOS = {
                53: ("DNS/UDP", INFO), 67: ("DHCP-Server/UDP", MEDIO),
                68: ("DHCP-Client/UDP", INFO), 69: ("TFTP/UDP", MEDIO),
                123: ("NTP/UDP", INFO), 161: ("SNMP/UDP", MEDIO),
                162: ("SNMP-Trap/UDP", MEDIO), 500: ("ISAKMP/UDP", MEDIO),
                514: ("Syslog/UDP", INFO), 1900: ("UPnP/UDP", INFO),
            }
            udp_abiertos = []
            for linea in texto.splitlines():
                m = _re.match(r'^(\d+)/udp\s+open\s*(\S*)', linea)
                if m:
                    puerto_udp = int(m.group(1))
                    svc_name, sev = UDP_SERVICIOS.get(puerto_udp,
                                        (f"UDP:{puerto_udp}", INFO))
                    h = Hallazgo(ip, puerto_udp, svc_name, sev,
                                 f"Puerto UDP {puerto_udp} abierto")
                    existe = any(hh.puerto == puerto_udp and "/UDP" in hh.servicio
                                 for hh in nodo.hallazgos)
                    if not existe:
                        nodo.hallazgos.append(h)
                        self.topologia.alertas.append(h)
                        udp_abiertos.append(puerto_udp)
            if udp_abiertos:
                log(f"[ARSENAL] UDP {ip}: puertos abiertos: {udp_abiertos}")
                from core.nodes import severidad_maxima
                nodo.severidad_max = severidad_maxima(nodo.hallazgos)

        # ── SERVICE VERSIONS: actualizar fabricante/OS si hay info nueva ──
        elif escaneo_id == "versions":
            import re as _re
            from core.nodes import Hallazgo, INFO
            for linea in texto.splitlines():
                m = _re.match(r'^(\d+)/tcp\s+open\s+(\S+)\s+(.+)', linea)
                if m:
                    puerto_n = int(m.group(1))
                    svc      = m.group(2)
                    version  = m.group(3).strip()[:50]
                    h = Hallazgo(ip, puerto_n, f"Ver: {svc[:15]}", INFO, version)
                    if not any(hh.servicio == f"Ver: {svc[:15]}" for hh in nodo.hallazgos):
                        nodo.hallazgos.append(h)
                        self.topologia.alertas.append(h)
                        log(f"[ARSENAL] SVC {ip}:{puerto_n} {svc} → {version[:30]}")

        # ── SAFE SCRIPTS: extraer hallazgos reales del output ─────────────────
        elif escaneo_id == "scripts":
            import re as _re
            from core.nodes import Hallazgo, INFO, MEDIO, ALTO

            # UPnP activo → hallazgo MEDIO
            if "usn:" in texto or "UPnP" in texto or "MiniUPnP" in texto:
                srv_m = _re.search(r'server:\s*(.+)', texto)
                srv   = srv_m.group(1).strip()[:40] if srv_m else "UPnP activo"
                loc_m = _re.search(r'location:\s*(\S+)', texto)
                detalle = f"{srv}"
                if loc_m:
                    detalle += f" | {loc_m.group(1)[:40]}"
                h = Hallazgo(ip, 1900, "UPnP Descubierto", MEDIO, detalle)
                if not any(hh.servicio == "UPnP Descubierto" for hh in nodo.hallazgos):
                    nodo.hallazgos.append(h)
                    self.topologia.alertas.append(h)
                    log(f"[ARSENAL] Scripts {ip}: UPnP → {detalle[:40]}")
                    toast.notificar(f"UPnP: {ip}", detalle[:50], "medio")

            # DHCP activo — info de red
            if "IP Offered:" in texto:
                ip_m  = _re.search(r'IP Offered:\s*(\S+)', texto)
                dns_m = _re.search(r'Domain Name Server:\s*(.+)', texto)
                detalle = f"DHCP ofrece: {ip_m.group(1) if ip_m else '?'}"
                if dns_m:
                    detalle += f" | DNS: {dns_m.group(1).strip()[:30]}"
                h = Hallazgo(ip, 67, "DHCP Activo", INFO, detalle)
                if not any(hh.servicio == "DHCP Activo" for hh in nodo.hallazgos):
                    nodo.hallazgos.append(h)
                    self.topologia.alertas.append(h)
                    log(f"[ARSENAL] Scripts {ip}: {detalle}")

            # 802.1X / EAP — potencialmente relevante
            if "EAP-TTLS" in texto or "EAP-TLS" in texto or "PEAP" in texto:
                metodos = _re.findall(r'unknown\s+(EAP-\S+|PEAP)', texto)
                detalle = f"802.1X/EAP: {', '.join(metodos[:4])}"
                h = Hallazgo(ip, 0, "802.1X Detectado", INFO, detalle)
                if not any(hh.servicio == "802.1X Detectado" for hh in nodo.hallazgos):
                    nodo.hallazgos.append(h)
                    self.topologia.alertas.append(h)
                    log(f"[ARSENAL] Scripts {ip}: {detalle}")

            # IPv6 addresses descubiertos
            ipv6_hosts = _re.findall(r'IP: (2[89a-f0-9:]+)\s+MAC: (\S+)', texto)
            if ipv6_hosts:
                log(f"[ARSENAL] Scripts {ip}: {len(ipv6_hosts)} host(s) IPv6 detectados")

            from core.nodes import severidad_maxima
            nodo.severidad_max = severidad_maxima(nodo.hallazgos)

        # ── STANDARD / QUICK: agregar puertos TCP nuevos ──────────────────────
        if puertos:
            nuevos = [p for p in puertos if p not in nodo.puertos_abiertos]
            if nuevos:
                for p in nuevos:
                    nodo.puertos_abiertos.append(p)
                log(f"[ARSENAL] {ip}: +{len(nuevos)} puerto(s) TCP nuevo(s): "
                    f"{', '.join(str(p) for p in sorted(nuevos))}")
                self.topologia.registrar_hallazgos(ip, list(nodo.puertos_abiertos))

    def _on_cdp_lldp(self, datos, protocolo):
        """Procesa hallazgos de CDP o LLDP — enriquece el nodo con info real del dispositivo."""
        def _ui():
            mac  = datos.get("mac_origen", "")
            ip   = datos.get("ip_origen") or datos.get("mgmt_ip")

            # Buscar nodo por MAC o IP
            nodo = None
            if ip:
                nodo = self.topologia.obtener_nodo(ip)
            if not nodo and mac:
                for n in self.topologia.todos_los_nodos():
                    if n.mac and n.mac.lower() == mac.lower():
                        nodo = n
                        break
            if not nodo and ip:
                nodo = self.topologia.agregar_o_actualizar(ip, mac=mac, bytes=0)
            if not nodo:
                return

            from core.nodes import Hallazgo, severidad_maxima

            # Enriquecer con info del protocolo
            if protocolo == "CDP":
                device_id  = datos.get("device_id", "")
                plataforma = datos.get("plataforma", "")
                version    = datos.get("version", "")
                caps       = datos.get("capacidades", [])
                if device_id and not nodo.hostname:
                    nodo.hostname = device_id
                if plataforma and not nodo.fabricante:
                    nodo.fabricante = f"Cisco ({plataforma})"
                if "Router" in caps:
                    nodo.tipo = "router"
                elif "Switch" in caps:
                    nodo.tipo = "switch"
                detalle = (f"CDP: {device_id or '?'} | "
                           f"Plataforma: {plataforma or '?'} | "
                           f"Caps: {','.join(caps)}")
                if version:
                    detalle += f" | IOS: {version[:40]}"

            else:  # LLDP
                sys_name = datos.get("system_name", "")
                sys_desc = datos.get("system_desc", "")
                caps     = datos.get("capacidades", [])
                if sys_name and not nodo.hostname:
                    nodo.hostname = sys_name
                if "Router" in caps:
                    nodo.tipo = "router"
                elif "Bridge" in caps or "WLAN-AP" in caps:
                    nodo.tipo = "switch"
                elif "Phone" in caps:
                    nodo.tipo = "voip"
                detalle = (f"LLDP: {sys_name or '?'} | "
                           f"Caps: {','.join(caps)}")
                if sys_desc:
                    detalle += f" | {sys_desc[:40]}"

            # Crear hallazgo INFO con la info descubierta
            clave = f"{protocolo}:{mac[:8]}"
            ya_existe = any(clave in (h.servicio or "") for h in nodo.hallazgos)
            if not ya_existe:
                h = Hallazgo(nodo.ip, 0, clave, "info", detalle[:80])
                nodo.hallazgos.append(h)
                self.topologia.alertas.append(h)
                log(f"[{protocolo}] {nodo.ip} — {detalle[:60]}")
                toast.notificar(
                    f"📡 {protocolo}: {nodo.ip}",
                    detalle[:50], "info")

        self.ventana.after(0, _ui)

    def _on_ipv6_hallazgo(self, tipo, datos):
        """
        Callback del IPv6Scanner.
        Tipos: HOST_IPV6, PUERTO_IPV6, TUNEL_IPV6
        """
        def _ui():
            from core.nodes import Hallazgo, severidad_maxima

            ip6     = datos.get("ip6", "?")
            mac     = datos.get("mac", "?")
            detalle = datos.get("detalle", "")

            if tipo == "HOST_IPV6":
                # Enriquecer nodo existente con su IPv6, o crear nodo nuevo
                tipo_addr = datos.get("tipo", "link-local")
                # Buscar si ya existe el nodo por MAC
                nodo_match = None
                if mac and mac != "?":
                    for n in self.topologia.todos_los_nodos():
                        if n.mac and n.mac.lower() == mac.lower():
                            nodo_match = n
                            break
                if nodo_match:
                    # Enriquecer el nodo IPv4 existente con su IPv6
                    if not hasattr(nodo_match, 'ip6') or not nodo_match.ip6:
                        nodo_match.ip6 = ip6
                        log(f"[IPv6] {nodo_match.ip} tiene IPv6: {ip6} [{tipo_addr}]")
                else:
                    # Host solo visible en IPv6 — agregar como nodo nuevo
                    nodo = self.topologia.agregar_o_actualizar(
                        ip6, mac=mac if mac != "?" else None, bytes=0)
                    if nodo:
                        nodo.sistema_op = "IPv6"
                        if not hasattr(nodo, 'ip6'):
                            nodo.ip6 = ip6
                        log(f"[IPv6] Nuevo nodo IPv6: {ip6} [{tipo_addr}]")

            elif tipo == "PUERTO_IPV6":
                puerto  = datos.get("puerto", 0)
                servicio = datos.get("servicio", "?")
                version  = datos.get("version", "")
                # Buscar el nodo por ip6 o MAC
                nodo = None
                for n in self.topologia.todos_los_nodos():
                    if getattr(n, 'ip6', None) == ip6 or n.ip == ip6:
                        nodo = n
                        break
                if nodo:
                    if puerto not in nodo.puertos_abiertos:
                        nodo.puertos_abiertos.append(puerto)
                    h = Hallazgo(nodo.ip, puerto,
                        f"IPv6:{servicio[:12]}", "info",
                        f"{detalle} {version}".strip()[:80])
                    if not any(hh.servicio == h.servicio for hh in nodo.hallazgos):
                        nodo.hallazgos.append(h)
                        self.topologia.alertas.append(h)

            elif tipo == "TUNEL_IPV6":
                tipo_tunel = datos.get("tipo_tunel", "?")
                ip4_embed  = datos.get("ip4_embed", "?")
                sev = "alto"   # túneles son siempre relevantes
                # Buscar nodo por MAC
                nodo = None
                if mac and mac != "?":
                    for n in self.topologia.todos_los_nodos():
                        if n.mac and n.mac.lower() == mac.lower():
                            nodo = n
                            break
                if nodo:
                    h = Hallazgo(nodo.ip, 0,
                        f"Túnel {tipo_tunel}", sev,
                        f"IPv6 túnel {tipo_tunel}: {ip6} | "
                        f"IPv4 embebida: {ip4_embed}")
                    if not any(hh.servicio == h.servicio for hh in nodo.hallazgos):
                        nodo.hallazgos.append(h)
                        self.topologia.alertas.append(h)
                        nodo.severidad_max = severidad_maxima(nodo.hallazgos)
                        log(f"[IPv6] ⚠ Túnel {tipo_tunel} en {nodo.ip}: {ip6}")
                        toast.notificar(
                            f"⚠ Túnel IPv6: {nodo.ip}",
                            f"{tipo_tunel}: {ip6}",
                            sev)

        self.ventana.after(0, _ui)

    def _on_dhcp_rogue(self, ip_rogue, mac_rogue, ip_ofrecida, ip_legitimo):
        """Callback cuando se detecta un servidor DHCP no autorizado."""
        def _ui():
            from core.nodes import Hallazgo, severidad_maxima
            nodo = self.topologia.obtener_nodo(ip_rogue)
            if not nodo:
                nodo = self.topologia.agregar_o_actualizar(
                    ip_rogue, mac=mac_rogue, bytes=0)
            if not nodo:
                return
            detalle = (f"DHCP Rogue: {ip_rogue} ({mac_rogue}) "
                       f"ofrece IP {ip_ofrecida} | "
                       f"Servidor legítimo: {ip_legitimo}")
            clave = "DHCP Rogue"
            ya_existe = any(clave in (h.servicio or "") for h in nodo.hallazgos)
            if ya_existe:
                return
            h = Hallazgo(ip_rogue, 67, clave, "critico", detalle)
            nodo.hallazgos.append(h)
            self.topologia.alertas.append(h)
            nodo.severidad_max = severidad_maxima(nodo.hallazgos)
            nodo.risk_score = min(100, (nodo.risk_score or 0) + 50)
            log(f"[DHCP] 🔴 ROGUE DHCP: {ip_rogue} — {detalle[:60]}")
            toast.notificar(
                f"🔴 DHCP ROGUE: {ip_rogue}",
                f"Servidor no autorizado ofrece {ip_ofrecida}",
                "critico")
        self.ventana.after(0, _ui)

    def _on_anomalia_detectada(self, ip, tipo, detalle, severidad):
        """Callback del DetectorAnomalias — corre en hilo del scanner."""
        def _ui():
            nodo = self.topologia.obtener_nodo(ip)
            if not nodo:
                return
            from core.nodes import Hallazgo, severidad_maxima
            clave = f"Anomalía:{tipo[:20]}"
            ya_existe = any(clave in (h.servicio or "") for h in nodo.hallazgos)
            if ya_existe:
                return
            h = Hallazgo(ip, 0, clave, severidad, detalle)
            nodo.hallazgos.append(h)
            self.topologia.alertas.append(h)
            nodo.severidad_max = severidad_maxima(nodo.hallazgos)
            log(f"[ANOMALIA] {ip} | {tipo}: {detalle[:50]}")
            icono = "🔴" if severidad == "critico" else "🟠" if severidad == "alto" else "🟡"
            toast.notificar(
                f"{icono} Anomalía: {ip}",
                f"{tipo} — {detalle[:50]}",
                severidad)
        self.ventana.after(0, _ui)

    def _on_beacon_detectado(self, ip_src, ip_dst,
                              intervalo, jitter_pct, protocolo,
                              conteo, nivel="confirmado", org=""):
        """
        Callback del BeaconDetector.
        Firma real: (ip_local, ip_ext, media, jitter*100, protocolo, n_hits, nivel)
        """
        # Convertir a float seguro por si viene como string
        try:
            intervalo  = float(intervalo)
        except (TypeError, ValueError):
            intervalo  = 60.0
        try:
            jitter_pct = float(jitter_pct)
        except (TypeError, ValueError):
            jitter_pct = 0.0

        # Severidad según intervalo
        severidad = "alto" if intervalo <= 60 else "medio"

        # Enriquecer con GeoIP
        geo_str = org or ""
        if not geo_str and self.geoip.disponible:
            geo_str = self.geoip.formato_corto(ip_dst) or ""

        periodo = f"{intervalo:.0f}s"
        if intervalo >= 60:
            periodo = f"{intervalo/60:.1f}min"

        log(f"[BEACON] ⚠ {ip_src} → {ip_dst} [{protocolo}] "
            f"cada {periodo} ± {jitter_pct*100:.1f}% "
            f"({conteo} eventos) {geo_str}")

        def _actualizar_ui():
            nodo = self.topologia.obtener_nodo(ip_src)
            if not nodo:
                return

            from core.nodes import Hallazgo, severidad_maxima
            from datetime import datetime as _dt

            geo_parte = f" | {geo_str}" if geo_str else ""
            detalle = (
                f"Beacon C2: contacta {ip_dst} cada {periodo} "
                f"(±{jitter_pct*100:.1f}% jitter, {conteo} eventos)"
                f"{geo_parte}"
            )

            clave_beacon = f"Beacon:{ip_dst[:15]}"
            ya_existe = any(
                clave_beacon in (hh.servicio or "")
                for hh in nodo.hallazgos
            )
            if ya_existe:
                for hh in nodo.hallazgos:
                    if clave_beacon in (hh.servicio or ""):
                        try:
                            hh.detalle = detalle
                            hh.timestamp = _dt.now().strftime("%H:%M:%S")
                        except Exception:
                            pass
                return

            h = Hallazgo(ip_src, 0, clave_beacon, severidad, detalle)
            nodo.hallazgos.append(h)
            self.topologia.alertas.append(h)
            nodo.severidad_max = severidad_maxima(nodo.hallazgos)

            bump = {"critico": 40, "alto": 25, "medio": 10}.get(severidad, 10)
            nodo.risk_score = min(100, (nodo.risk_score or 0) + bump)

            if "Beacon C2" not in (nodo.perfiles or []):
                if not nodo.perfiles:
                    nodo.perfiles = []
                nodo.perfiles.append("Beacon C2")

            icono = "🔴" if severidad == "critico" else "🟠"
            toast.notificar(
                f"{icono} BEACON C2: {ip_src}",
                f"→ {ip_dst} cada {periodo} | {geo_str}",
                severidad
            )

        self.ventana.after(0, _actualizar_ui)

    def _verificar_lobby_manual(self):
        """Lanza ping a todos los nodos del lobby manualmente."""
        import threading as _th
        nodos_lobby = [n for n in self.topologia.todos_los_nodos()
                       if n.en_lobby]
        if not nodos_lobby:
            return
        log(f"[LOBBY] Verificación manual — {len(nodos_lobby)} nodo(s)")

        def _ping_todos():
            for nodo in nodos_lobby:
                ip = nodo.ip
                try:
                    import subprocess as _sp
                    r = _sp.run(["nmap", "-sn", "-Pn",
                                 "--host-timeout", "8s", ip],
                                capture_output=True, text=True, timeout=12)
                    vivo = "Host is up" in r.stdout
                except Exception:
                    vivo = False

                def _accion(ip=ip, n=nodo, v=vivo):
                    if v:
                        n.actualizar_actividad()
                        log(f"[LOBBY] {ip}: responde → vuelve a activo")
                    else:
                        with self.topologia._lock:
                            self.topologia.nodos.pop(ip, None)
                        log(f"[LOBBY] {ip}: sin respuesta → eliminado")
                self.ventana.after(0, _accion)

        _th.Thread(target=_ping_todos, daemon=True,
                   name="lobby-verify-manual").start()

    def _arsenal_desde_alerta(self, ip, escaneo_id):
        """
        Lanza un escaneo del arsenal directamente desde el panel de alertas.
        Mapea escaneo_id a nombre legible y delega al canvas.
        """
        NOMBRES = {
            "ping"    : "🟢 Ping Check",
            "quick"   : "⚡ Quick Ports",
            "standard": "🔍 Standard Scan",
            "versions": "🏷  Service Versions",
            "os"      : "💻 OS Detection",
            "scripts" : "📜 Safe Scripts",
            "vuln"    : "🔴 Vuln Scan",
            "udp"     : "📡 UDP Top Ports",
        }
        nombre = NOMBRES.get(escaneo_id, escaneo_id)
        log(f"[ARSENAL] Lanzado desde alerta: {nombre} en {ip}")
        # Seleccionar el nodo en el canvas primero
        self.canvas.seleccionar_nodo(ip)
        self.canvas.redibujar()
        # Lanzar el escaneo
        try:
            self.canvas._lanzar_escaneo(ip, escaneo_id, nombre)
        except Exception as e:
            log(f"[ARSENAL] Error lanzando desde alerta: {e}")

    def _seleccionar_nodo_por_ip(self, ip):
        nodo = self.topologia.obtener_nodo(ip)
        if nodo and self.panel.mostrar_nodo:
            self.panel.mostrar_nodo(nodo)
            self.canvas.seleccionar_nodo(ip)
            self.canvas.redibujar()

    def _obtener_mac_local(self):
        """
        Obtiene la MAC real de esta máquina leyendo directamente del sistema.
        Se cachea para no hacer syscall en cada paquete.
        """
        if not hasattr(self, '_mac_local_cache') or not self._mac_local_cache:
            interfaz = self.interfaz.get()
            try:
                with open(f"/sys/class/net/{interfaz}/address") as f:
                    self._mac_local_cache = f.read().strip()
            except Exception:
                try:
                    r = subprocess.run(
                        ["cat", f"/sys/class/net/{interfaz}/address"],
                        capture_output=True, text=True, timeout=2)
                    self._mac_local_cache = r.stdout.strip() or None
                except Exception:
                    self._mac_local_cache = None
        return self._mac_local_cache

    def _loop_stats_profundo(self):
        # Hilo independiente — recorre todos los nodos cada 15s
        import time as _time
        while True:
            try:
                _time.sleep(15)
                if not hasattr(self, 'topologia'):
                    continue
                nodos = self.topologia.todos_los_nodos()

                # ── Scoring compuesto ─────────────────────────────
                for nodo in nodos:
                    from core.nodes import calcular_risk_score, detectar_perfil_especial
                    puertos = list(nodo.puertos_abiertos)
                    if puertos:
                        score_base = calcular_risk_score(puertos)
                        nodo.perfiles = detectar_perfil_especial(puertos)
                        score_previo = getattr(nodo, 'risk_score', 0) or 0
                        nodo.risk_score = score_base
                        from tools.fingerprint import fingerprint_completo
                        fingerprint_completo(nodo)
                        nodo.risk_score = max(
                            nodo.risk_score,
                            score_previo if score_previo > score_base else 0
                        )

                # ── Hallazgos pendientes ──────────────────────────
                for nodo in nodos:
                    if nodo.puertos_abiertos and not nodo.hallazgos:
                        self.topologia.registrar_hallazgos(
                            nodo.ip, list(nodo.puertos_abiertos))

                # ── Anomalías vs baseline ─────────────────────────
                if hasattr(self, '_anomalias') and self._anomalias._cargado:
                    try:
                        resultados = self._anomalias.analizar(self.topologia)
                        for r in resultados:
                            self.ventana.after(0, lambda r=r:
                                self._on_anomalia_detectada(
                                    r["ip"], r["tipo"],
                                    r["detalle"], r["severidad"]))
                    except Exception as e:
                        log(f"[ANOMALIA] Error en análisis: {e}")

                # ── Auto-verificación y borrado del lobby ─────────
                # Nodos en lobby con 5+ minutos sin actividad:
                # 1) Ping silencioso — si responde, vuelve a activo
                # 2) Si no responde, se elimina de la topología
                LOBBY_TIMEOUT_SEG = 5 * 60   # 5 minutos
                nodos_lobby = [n for n in nodos if n.en_lobby]
                for nodo in nodos_lobby:
                    try:
                        segs = nodo.segundos_sin_actividad()
                    except Exception:
                        continue
                    if segs < LOBBY_TIMEOUT_SEG:
                        continue

                    ip = nodo.ip
                    log(f"[LOBBY] {ip} lleva {int(segs//60)}min inactivo — verificando...")

                    # Ping silencioso en hilo aparte
                    def _verificar_y_borrar(ip=ip, nodo=nodo):
                        try:
                            import subprocess as _sp
                            r = _sp.run(
                                ["nmap", "-sn", "-Pn",
                                 "--host-timeout", "8s", ip],
                                capture_output=True, text=True, timeout=12)
                            vivo = "Host is up" in r.stdout
                        except Exception:
                            vivo = False

                        def _accion():
                            if vivo:
                                nodo.actualizar_actividad()
                                log(f"[LOBBY] {ip}: responde → vuelve a activo")
                            else:
                                # Eliminar de la topología
                                with self.topologia._lock:
                                    self.topologia.nodos.pop(ip, None)
                                log(f"[LOBBY] {ip}: sin respuesta → eliminado "
                                    f"(guardado en historial)")

                        self.ventana.after(0, _accion)

                    import threading as _th
                    _th.Thread(target=_verificar_y_borrar,
                               daemon=True, name=f"lobby-check-{ip}").start()

                log(f"[STATS] Recálculo: {len(nodos)} nodos | "
                    f"alertas: {len(self.topologia.alertas)}")
            except Exception as e:
                log(f"[STATS] Error en loop stats: {e}")
            except Exception as e:
                log(f"[STATS] Error en loop stats: {e}")

    def iniciar(self):
        self.ventana.mainloop()
