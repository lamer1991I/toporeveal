"""
generar_pdf.py — Informe PDF profesional de TopoReveal
Genera un documento listo para entregar a un cliente o auditor.

Estructura:
  Página 1 — Portada con metadata de la sesión
  Página 2 — Resumen ejecutivo + estadísticas
  Página 3+ — Tabla de hosts activos
  Página N  — Hallazgos y alertas priorizadas
  Página N  — Conexiones externas con GeoIP
  Página N  — Apéndice técnico
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.platypus import Flowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle, Polygon
from reportlab.graphics import renderPDF
from datetime import datetime
import os
import math


# ── Paleta de colores ─────────────────────────────────────────────────────────
NEGRO      = colors.HexColor("#0d1117")
AZUL_OSC   = colors.HexColor("#0d1f3c")
AZUL_MED   = colors.HexColor("#1a3a5c")
CYAN       = colors.HexColor("#00d4ff")
CYAN_OSC   = colors.HexColor("#005f7a")
VERDE      = colors.HexColor("#00c853")
NARANJA    = colors.HexColor("#ff8c00")
ROJO       = colors.HexColor("#e53935")
GRIS_CLARO = colors.HexColor("#f0f4f8")
GRIS_MED   = colors.HexColor("#c8d6e5")
GRIS_TEXTO = colors.HexColor("#4a5568")
BLANCO     = colors.white
AMARILLO   = colors.HexColor("#ffb300")

SEV_COLOR = {
    "critico": ROJO,
    "alto"   : NARANJA,
    "medio"  : AMARILLO,
    "info"   : CYAN,
    None     : GRIS_MED,
}


# ── Estilos de párrafo ────────────────────────────────────────────────────────
def _estilos():
    return {
        "titulo1": ParagraphStyle("titulo1",
            fontName="Helvetica-Bold", fontSize=18,
            textColor=NEGRO, spaceAfter=6, leading=22),

        "titulo2": ParagraphStyle("titulo2",
            fontName="Helvetica-Bold", fontSize=13,
            textColor=AZUL_OSC, spaceAfter=4, leading=16),

        "titulo3": ParagraphStyle("titulo3",
            fontName="Helvetica-Bold", fontSize=10,
            textColor=AZUL_MED, spaceAfter=2, leading=12),

        "normal": ParagraphStyle("normal",
            fontName="Helvetica", fontSize=9,
            textColor=GRIS_TEXTO, leading=13, spaceAfter=3),

        "normal_neg": ParagraphStyle("normal_neg",
            fontName="Helvetica-Bold", fontSize=9,
            textColor=NEGRO, leading=13),

        "mono": ParagraphStyle("mono",
            fontName="Courier", fontSize=8,
            textColor=NEGRO, leading=11),

        "caption": ParagraphStyle("caption",
            fontName="Helvetica-Oblique", fontSize=8,
            textColor=GRIS_TEXTO, leading=10, spaceAfter=6),

        "centrado": ParagraphStyle("centrado",
            fontName="Helvetica", fontSize=9,
            textColor=GRIS_TEXTO, alignment=TA_CENTER, leading=12),

        "alerta_critico": ParagraphStyle("alerta_critico",
            fontName="Helvetica-Bold", fontSize=9,
            textColor=ROJO, leading=11),

        "alerta_alto": ParagraphStyle("alerta_alto",
            fontName="Helvetica-Bold", fontSize=9,
            textColor=NARANJA, leading=11),

        "alerta_medio": ParagraphStyle("alerta_medio",
            fontName="Helvetica-Bold", fontSize=9,
            textColor=AMARILLO, leading=11),
    }


# ── Flowable: línea divisoria con título ──────────────────────────────────────
class SeccionTitulo(Flowable):
    def __init__(self, texto, color=AZUL_OSC):
        super().__init__()
        self.texto = texto
        self.color = color
        self.height = 22
        self.width  = A4[0] - 4*cm

    def draw(self):
        c = self.canv
        # Fondo
        c.setFillColor(self.color)
        c.roundRect(0, 2, self.width, 18, 3, fill=1, stroke=0)
        # Texto
        c.setFillColor(BLANCO)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(8, 6, self.texto.upper())


# ── Flowable: badge de severidad ─────────────────────────────────────────────
class Badge(Flowable):
    def __init__(self, texto, color):
        super().__init__()
        self.texto = texto
        self.color = color
        self.width  = 55
        self.height = 14

    def draw(self):
        c = self.canv
        c.setFillColor(self.color)
        c.roundRect(0, 0, self.width, 12, 4, fill=1, stroke=0)
        c.setFillColor(BLANCO)
        c.setFont("Helvetica-Bold", 7)
        c.drawCentredString(self.width / 2, 3, self.texto.upper())


# ── Cabecera/pie de página ────────────────────────────────────────────────────
class PlantillaPagina:
    def __init__(self, titulo_doc, fecha):
        self.titulo_doc = titulo_doc
        self.fecha      = fecha
        self._num       = 0

    def primera_pagina(self, canvas, doc):
        canvas.saveState()
        self._pie(canvas, doc, es_portada=True)
        canvas.restoreState()

    def paginas_siguientes(self, canvas, doc):
        canvas.saveState()
        self._cabecera(canvas, doc)
        self._pie(canvas, doc)
        canvas.restoreState()

    def _cabecera(self, canvas, doc):
        w, h = A4
        # Banda superior
        canvas.setFillColor(AZUL_OSC)
        canvas.rect(0, h - 18*mm, w, 18*mm, fill=1, stroke=0)
        # Logo texto
        canvas.setFillColor(CYAN)
        canvas.setFont("Helvetica-Bold", 12)
        canvas.drawString(2*cm, h - 12*mm, "TopoReveal")
        canvas.setFillColor(BLANCO)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(6.2*cm, h - 12*mm, "Network Topology Viewer")
        # Título del documento derecha
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(GRIS_MED)
        canvas.drawRightString(w - 2*cm, h - 12*mm, self.titulo_doc)
        # Línea cian
        canvas.setStrokeColor(CYAN)
        canvas.setLineWidth(1.5)
        canvas.line(0, h - 18*mm, w, h - 18*mm)

    def _pie(self, canvas, doc, es_portada=False):
        w, h = A4
        # Línea superior del pie
        canvas.setStrokeColor(GRIS_MED)
        canvas.setLineWidth(0.5)
        canvas.line(2*cm, 18*mm, w - 2*cm, 18*mm)
        # Texto izquierdo
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(GRIS_TEXTO)
        canvas.drawString(2*cm, 13*mm,
            f"TopoReveal Security Suite  ·  {self.fecha}")
        canvas.drawString(2*cm, 9*mm,
            "CONFIDENCIAL — Solo para uso interno")
        # Número de página derecha
        if not es_portada:
            canvas.drawRightString(w - 2*cm, 13*mm,
                f"Página {doc.page}")
        # Logo watermark muy sutil
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(GRIS_MED)
        canvas.drawCentredString(w / 2, 9*mm, "TOPOREVEAL")


# ── GENERACIÓN DEL DOCUMENTO ──────────────────────────────────────────────────

def generar_informe(topologia, ruta_salida=None, log_buffer=None, hora_inicio=None):
    """
    Genera el informe PDF completo con estructura de iceberg de seguridad.
    """
    import hashlib, socket
    if not ruta_salida:
        usuario = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
        try:
            import pwd
            home = pwd.getpwnam(usuario).pw_dir
        except Exception:
            home = os.path.expanduser("~")
        carpeta = os.path.join(home, "Proyectos", "toporeveal", "exports")
        os.makedirs(carpeta, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
        ruta_salida = os.path.join(carpeta, f"informe_{ts}.pdf")

    fecha_str   = datetime.now().strftime("%d/%m/%Y %H:%M")
    hora_fin    = datetime.now()
    estilos     = _estilos()
    plantilla   = PlantillaPagina("Informe de Auditoría de Red", fecha_str)

    doc = SimpleDocTemplate(
        ruta_salida,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.2*cm, bottomMargin=2.5*cm,
        title="Informe de Auditoría de Red — TopoReveal",
        author="TopoReveal Security Suite",
    )

    buf_str = "\n".join(str(l) for l in (log_buffer or []))

    historia = []
    historia += _portada(topologia, estilos, fecha_str,
                         hora_inicio, hora_fin, buf_str)
    historia.append(PageBreak())
    historia += _resumen_ejecutivo(topologia, estilos, buf_str)
    historia.append(PageBreak())
    historia += _tabla_hosts(topologia, estilos)
    historia += _hallazgos(topologia, estilos)
    historia += _conexiones_externas(topologia, estilos)
    historia.append(PageBreak())
    historia += _cobertura_niveles(topologia, estilos, buf_str)
    historia += _apendice(topologia, estilos, fecha_str)

    doc.build(
        historia,
        onFirstPage=plantilla.primera_pagina,
        onLaterPages=plantilla.paginas_siguientes,
    )
    return ruta_salida


# ── SECCIÓN: PORTADA ──────────────────────────────────────────────────────────

def _portada(topologia, estilos, fecha, hora_inicio=None, hora_fin=None, buf_str=""):
    """Portada de una página completa."""
    w, h = A4
    items = []

    # Espacio superior
    items.append(Spacer(1, 3*cm))

    # Banda de título con tabla para control total de layout
    items.append(Table(
        [[Paragraph("INFORME DE AUDITORÍA", ParagraphStyle("p_portada_sub",
            fontName="Helvetica", fontSize=12, textColor=GRIS_TEXTO,
            alignment=TA_CENTER))]],
        colWidths=[w - 4*cm],
        style=TableStyle([("TOPPADDING",(0,0),(-1,-1),8),
                          ("BOTTOMPADDING",(0,0),(-1,-1),8)])
    ))

    items.append(Spacer(1, 0.3*cm))

    items.append(Table(
        [[Paragraph("Topología de Red", ParagraphStyle("p_portada_tit",
            fontName="Helvetica-Bold", fontSize=32, textColor=AZUL_OSC,
            alignment=TA_CENTER))]],
        colWidths=[w - 4*cm],
        style=TableStyle([("BACKGROUND",(0,0),(-1,-1),GRIS_CLARO),
                          ("TOPPADDING",(0,0),(-1,-1),16),
                          ("BOTTOMPADDING",(0,0),(-1,-1),16),
                          ("LINEABOVE",(0,0),(-1,0),2,CYAN),
                          ("LINEBELOW",(0,-1),(-1,-1),2,CYAN)])
    ))

    items.append(Spacer(1, 0.5*cm))

    items.append(Table(
        [[Paragraph("Network Intelligence Platform — TopoReveal v2.0",
            ParagraphStyle("p_portada_sub2",
            fontName="Helvetica", fontSize=11, textColor=GRIS_TEXTO,
            alignment=TA_CENTER))]],
        colWidths=[w - 4*cm],
    ))

    items.append(Spacer(1, 2*cm))

    # Caja de metadata
    import hashlib, socket
    gw     = topologia.gateway or "—"
    subred = f"{topologia.subred}.x" if topologia.subred else "—"
    nodos_todos = list(topologia.nodos.values())
    n_hosts   = len([n for n in nodos_todos if not n.en_lobby])
    n_lobby   = len([n for n in nodos_todos if n.en_lobby])
    n_alertas = len(topologia.alertas) if hasattr(topologia, 'alertas') else 0
    alertas   = list(getattr(topologia, 'alertas', []))

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
    if score >= 8:   nivel_r = "CRÍTICO"
    elif score >= 5: nivel_r = "ALTO"
    elif score >= 3: nivel_r = "MEDIO"
    else:            nivel_r = "BAJO"

    sev_max = "—"
    sevs = [n.severidad_max for n in nodos_todos if n.severidad_max]
    for s in ["critico","alto","medio","info"]:
        if s in sevs:
            sev_max = s.upper()
            break

    # Duración
    duracion_str = "—"
    if hora_inicio and hora_fin:
        seg = int((hora_fin - hora_inicio).total_seconds())
        duracion_str = f"{seg//60}m {seg%60}s"

    # SHA-256 del log para cadena de custodia
    sha256_str = hashlib.sha256(buf_str.encode()).hexdigest()[:32] + "..."

    try:
        mi_host = socket.gethostname()
    except Exception:
        mi_host = "desconocido"

    metadata = [
        ["Fecha inicio",      hora_inicio.strftime("%Y-%m-%d %H:%M:%S") if hora_inicio else fecha],
        ["Fecha fin",         hora_fin.strftime("%Y-%m-%d %H:%M:%S") if hora_fin else fecha],
        ["Duración",          duracion_str],
        ["Agente",            mi_host],
        ["Gateway",           gw],
        ["Subred",            subred],
        ["Hosts activos",     str(n_hosts)],
        ["Hosts en lobby",    str(n_lobby)],
        ["Total alertas",     str(n_alertas)],
        ["Riesgo global",     f"{score}/10 — {nivel_r}"],
        ["Gravedad máxima",   sev_max],
        ["SHA-256 log",       sha256_str],
        ["Herramienta",       "TopoReveal v2.0"],
        ["Clasificación",     "CONFIDENCIAL"],
    ]

    tabla_meta = Table(metadata,
        colWidths=[5.5*cm, 9*cm])
    tabla_meta.setStyle(TableStyle([
        ("FONTNAME",    (0,0),(0,-1), "Helvetica-Bold"),
        ("FONTNAME",    (1,0),(1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0),(-1,-1), 9),
        ("TEXTCOLOR",   (0,0),(0,-1), AZUL_OSC),
        ("TEXTCOLOR",   (1,0),(1,-1), NEGRO),
        ("BACKGROUND",  (0,0),(-1,0), GRIS_CLARO),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[BLANCO, GRIS_CLARO]),
        ("GRID",        (0,0),(-1,-1), 0.5, GRIS_MED),
        ("TOPPADDING",  (0,0),(-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("LEFTPADDING", (0,0),(-1,-1), 8),
    ]))
    items.append(tabla_meta)

    items.append(Spacer(1, 2*cm))
    items.append(Paragraph(
        "Este informe fue generado automáticamente por TopoReveal. "
        "Contiene información confidencial sobre la topología, dispositivos y "
        "vulnerabilidades detectadas en la red auditada. "
        "Su distribución debe limitarse al personal autorizado.",
        estilos["caption"]))

    return items


# ── SECCIÓN: RESUMEN EJECUTIVO ────────────────────────────────────────────────

def _resumen_ejecutivo(topologia, estilos, buf_str=""):
    items = []
    items.append(SeccionTitulo("Resumen Ejecutivo", AZUL_OSC))
    items.append(Spacer(1, 0.3*cm))

    nodos    = list(topologia.nodos.values())
    activos  = [n for n in nodos if not n.en_lobby]
    alertas  = list(getattr(topologia, 'alertas', []))
    externos = getattr(topologia, 'externos', {})

    sev_c = {}
    for h in alertas:
        sev_c[h.severidad] = sev_c.get(h.severidad, 0) + 1
    n_critico = sev_c.get('critico', 0)
    n_alto    = sev_c.get('alto', 0)
    n_medio   = sev_c.get('medio', 0)

    # Score de riesgo
    score = 0
    if n_critico: score += min(4, n_critico)
    if n_alto:    score += min(3, n_alto)
    if n_medio:   score += min(2, n_medio)
    if "[BEACON] CONFIRMADO" in buf_str: score += 2
    score = min(10, score)
    color_score = ROJO if score >= 7 else NARANJA if score >= 4 else AMARILLO if score >= 2 else AZUL_OSC
    nivel_r = "CRÍTICO" if score >= 8 else "ALTO" if score >= 5 else "MEDIO" if score >= 3 else "BAJO"

    n_puertos = sum(len(n.puertos_abiertos) for n in activos)
    n_externos = sum(len(v) for v in externos.values())

    # Tarjetas de estadísticas
    stats = [
        [_tarjeta_stat("HOSTS\nACTIVOS",   str(len(activos)), AZUL_OSC),
         _tarjeta_stat("PUERTOS\nABIERTOS", str(n_puertos),  AZUL_MED),
         _tarjeta_stat("ALERTAS",           str(len(alertas)), GRIS_MED),
         _tarjeta_stat("CRÍTICO",           str(n_critico),  ROJO),
         _tarjeta_stat("ALTO",              str(n_alto),     NARANJA)],
    ]
    tabla_stats = Table(stats, colWidths=[3.2*cm]*5)
    tabla_stats.setStyle(TableStyle([
        ("ALIGN",       (0,0),(-1,-1), "CENTER"),
        ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING",  (0,0),(-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
    ]))
    items.append(tabla_stats)
    items.append(Spacer(1, 0.4*cm))

    # Barra de riesgo visual
    items.append(Paragraph("Nivel de Riesgo Global",
        ParagraphStyle("riesgo_lbl", fontName="Helvetica-Bold",
            fontSize=9, textColor=GRIS_TEXTO)))
    barra = "█" * score + "░" * (10 - score)
    items.append(Paragraph(
        f'<font color="#{_hex(color_score)}">{barra}</font>  '
        f'<b>{score}/10 — {nivel_r}</b>',
        ParagraphStyle("barra", fontName="Courier", fontSize=12,
            textColor=color_score, spaceAfter=6)))
    items.append(Spacer(1, 0.3*cm))

    # Texto resumen
    gw     = topologia.gateway or "desconocido"
    subred = f"{topologia.subred}.0/24" if topologia.subred else "desconocida"
    resumen_texto = (
        f"El análisis de la red <b>{subred}</b> (gateway <b>{gw}</b>) detectó "
        f"<b>{len(activos)} hosts activos</b> con <b>{n_puertos} puertos abiertos</b> "
        f"y <b>{n_externos} conexiones externas</b>. "
        f"Se registraron {len(alertas)} hallazgos de seguridad — "
        f"{n_critico} críticos, {n_alto} altos, {n_medio} medios. "
    )
    beacons = [h for h in alertas if "Beacon" in (h.servicio or "")]
    if beacons:
        ips_c2 = {h.ip for h in beacons}
        resumen_texto += (
            f"<b>Alerta C2:</b> se detectaron {len(beacons)} patrón(es) de "
            f"beacon en {', '.join(ips_c2)}. "
        )
    items.append(Paragraph(resumen_texto,
        ParagraphStyle("resumen", fontName="Helvetica", fontSize=9,
            textColor=GRIS_TEXTO, leading=14, spaceAfter=8)))

    # Top 5 hallazgos críticos/altos
    top = sorted(alertas,
        key=lambda h: {"critico":0,"alto":1,"medio":2,"info":3}.get(h.severidad,4))[:5]
    if top:
        items.append(Spacer(1, 0.3*cm))
        items.append(SeccionTitulo("Top Hallazgos Prioritarios", AZUL_MED))
        filas = [["#","IP","Servicio","Severidad","Detalle"]]
        for i, h in enumerate(top, 1):
            filas.append([
                str(i),
                h.ip or "—",
                h.servicio or "—",
                (h.severidad or "—").upper(),
                (getattr(h,'detalle','') or "")[:55],
            ])
        t = Table(filas, colWidths=[0.6*cm,2.5*cm,3*cm,2*cm,8.2*cm], repeatRows=1)
        t.setStyle(_estilo_tabla_base())
        items.append(t)

    # Distribución por tipo
    items.append(Spacer(1, 0.4*cm))
    items.append(SeccionTitulo("Distribución por Tipo de Dispositivo", AZUL_MED))
    tipos = {}
    for n in activos:
        t = n.tipo or "desconocido"
        tipos[t] = tipos.get(t, 0) + 1
    tipo_rows = [["Tipo","Cantidad","% Total","Fabricantes"]]
    for tipo, cnt in sorted(tipos.items(), key=lambda x: x[1], reverse=True):
        pct  = f"{cnt/max(len(activos),1)*100:.0f}%"
        fabs = {n.fabricante for n in activos
                if n.tipo == tipo and n.fabricante and "Privada" not in n.fabricante}
        tipo_rows.append([tipo.capitalize(), str(cnt), pct,
                          ", ".join(list(fabs)[:3]) or "—"])
    tabla_tipos = Table(tipo_rows, colWidths=[4*cm,2.5*cm,2*cm,8*cm])
    tabla_tipos.setStyle(_estilo_tabla_base())
    items.append(tabla_tipos)

    return items


def _hex(color):
    """Convierte HexColor a string hex para f-strings."""
    try:
        r = int(color.red * 255)
        g = int(color.green * 255)
        b = int(color.blue * 255)
        return f"{r:02x}{g:02x}{b:02x}"
    except Exception:
        return "ffffff"

    # Estadísticas en tarjetas
    stats = [
        [_tarjeta_stat("HOSTS\nACTIVOS", str(len(activos)), AZUL_OSC),
         _tarjeta_stat("ALERTAS\nTOTALES",
             str(len(topologia.alertas) if hasattr(topologia,'alertas') else 0),
             AZUL_MED),
         _tarjeta_stat("CRÍTICO", str(n_critico), ROJO),
         _tarjeta_stat("ALTO",    str(n_alto),    NARANJA),
         _tarjeta_stat("MEDIO",   str(n_medio),   AMARILLO)],
    ]
    tabla_stats = Table(stats, colWidths=[3.2*cm]*5)
    tabla_stats.setStyle(TableStyle([
        ("ALIGN",       (0,0),(-1,-1), "CENTER"),
        ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING",  (0,0),(-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
    ]))
    items.append(tabla_stats)
    items.append(Spacer(1, 0.5*cm))

    # Párrafo de resumen
    gw = topologia.gateway or "desconocido"
    subred = f"{topologia.subred}.0/24" if topologia.subred else "desconocida"

    resumen_texto = (
        f"El análisis de la red <b>{subred}</b> con gateway <b>{gw}</b> detectó "
        f"<b>{len(activos)} hosts activos</b>. "
        f"Se identificaron {n_critico} dispositivos de riesgo crítico, "
        f"{n_alto} de riesgo alto y {n_medio} de riesgo medio. "
    )

    # Mencionar cámaras/servidores
    camaras = [n for n in activos if n.tipo in ("camara","servidor") and
               any("Hikvision" in (h.servicio or "") or "RTSP" in (h.servicio or "")
                   for h in getattr(n,'hallazgos',[]))]
    if camaras:
        resumen_texto += (
            f"Se encontraron <b>{len(camaras)} cámara(s) IP</b> con "
            "servicios expuestos sin autenticación fuerte. "
        )

    items.append(Paragraph(resumen_texto,
        ParagraphStyle("resumen", fontName="Helvetica", fontSize=9,
            textColor=GRIS_TEXTO, leading=14, spaceAfter=8)))

    # Distribución por tipo de dispositivo
    items.append(Spacer(1, 0.3*cm))
    items.append(SeccionTitulo("Distribución por Tipo de Dispositivo", AZUL_MED))
    items.append(Spacer(1, 0.2*cm))

    tipos = {}
    for n in activos:
        t = n.tipo or "desconocido"
        tipos[t] = tipos.get(t, 0) + 1

    tipo_rows = [["Tipo de Dispositivo", "Cantidad", "% del Total"]]
    for tipo, cnt in sorted(tipos.items(), key=lambda x: x[1], reverse=True):
        pct = f"{cnt / max(len(activos),1) * 100:.0f}%"
        tipo_rows.append([tipo.capitalize(), str(cnt), pct])

    tabla_tipos = Table(tipo_rows, colWidths=[8*cm, 3*cm, 3*cm])
    tabla_tipos.setStyle(_estilo_tabla_base())
    items.append(tabla_tipos)

    return items


def _tarjeta_stat(titulo, valor, color):
    """Retorna contenido de celda para tarjeta de estadística."""
    return [
        Paragraph(valor, ParagraphStyle("stat_val",
            fontName="Helvetica-Bold", fontSize=22,
            textColor=color, alignment=TA_CENTER, leading=26)),
        Paragraph(titulo, ParagraphStyle("stat_lbl",
            fontName="Helvetica", fontSize=7,
            textColor=GRIS_TEXTO, alignment=TA_CENTER, leading=9)),
    ]


# ── SECCIÓN: TABLA DE HOSTS ───────────────────────────────────────────────────

def _tabla_hosts(topologia, estilos):
    items = []
    items.append(SeccionTitulo("Inventario de Hosts Activos", AZUL_OSC))
    items.append(Spacer(1, 0.3*cm))

    nodos = sorted(
        [n for n in topologia.nodos.values() if not n.en_lobby],
        key=lambda n: [int(x) for x in n.ip.split(".")]
    )

    cabecera = [
        Paragraph("IP", estilos["normal_neg"]),
        Paragraph("MAC", estilos["normal_neg"]),
        Paragraph("Tipo", estilos["normal_neg"]),
        Paragraph("Fabricante", estilos["normal_neg"]),
        Paragraph("OS", estilos["normal_neg"]),
        Paragraph("Puertos", estilos["normal_neg"]),
        Paragraph("Risk", estilos["normal_neg"]),
        Paragraph("Estado", estilos["normal_neg"]),
    ]
    filas = [cabecera]

    for n in nodos:
        puertos = ", ".join(str(p) for p in (n.puertos_abiertos or [])[:6])
        if len(n.puertos_abiertos or []) > 6:
            puertos += "…"
        risk_score = getattr(n, 'risk_score', 0) or 0
        risk_color = ROJO if risk_score >= 70 else \
                     NARANJA if risk_score >= 40 else \
                     AMARILLO if risk_score >= 20 else VERDE

        fila = [
            Paragraph(n.ip or "—",
                ParagraphStyle("ip_mono", fontName="Courier",
                    fontSize=8, textColor=AZUL_OSC)),
            Paragraph((n.mac or "—")[:17],
                ParagraphStyle("mac_mono", fontName="Courier",
                    fontSize=7, textColor=GRIS_TEXTO)),
            Paragraph((n.tipo or "—").capitalize(), estilos["normal"]),
            Paragraph((n.fabricante or "—")[:14], estilos["normal"]),
            Paragraph((n.sistema_op or "—")[:14], estilos["normal"]),
            Paragraph(puertos or "—",
                ParagraphStyle("mono_s", fontName="Courier",
                    fontSize=7, textColor=NEGRO)),
            Paragraph(str(risk_score),
                ParagraphStyle("risk", fontName="Helvetica-Bold",
                    fontSize=9, textColor=risk_color, alignment=TA_CENTER)),
            Paragraph((n.estado or "—").capitalize(), estilos["normal"]),
        ]
        filas.append(fila)

    tabla = Table(filas,
        colWidths=[2.6*cm, 3.1*cm, 2.2*cm, 2.4*cm, 2.2*cm, 2.0*cm, 1.2*cm, 2.0*cm],
        repeatRows=1)
    tabla.setStyle(_estilo_tabla_base())
    items.append(tabla)

    return items


# ── SECCIÓN: HALLAZGOS ────────────────────────────────────────────────────────

def _hallazgos(topologia, estilos):
    items = []
    items.append(PageBreak())
    items.append(SeccionTitulo("Hallazgos y Alertas de Seguridad", AZUL_OSC))
    items.append(Spacer(1, 0.3*cm))

    alertas = getattr(topologia, 'alertas', [])
    if not alertas:
        items.append(Paragraph("No se registraron alertas en esta sesión.",
            estilos["normal"]))
        return items

    # Agrupar por severidad
    orden_sev = ["critico", "alto", "medio", "info"]
    por_sev   = {s: [] for s in orden_sev}
    for h in alertas:
        sev = (h.severidad or "info").lower()
        if sev in por_sev:
            por_sev[sev].append(h)
        else:
            por_sev["info"].append(h)

    for sev in orden_sev:
        grupo = por_sev[sev]
        if not grupo:
            continue

        color_sev = SEV_COLOR.get(sev, GRIS_MED)
        etiqueta  = sev.upper()

        items.append(Spacer(1, 0.3*cm))

        # Sub-cabecera de severidad
        items.append(Table(
            [[Paragraph(f"● {etiqueta}  —  {len(grupo)} hallazgo(s)",
                ParagraphStyle("sev_hdr", fontName="Helvetica-Bold",
                    fontSize=10, textColor=BLANCO))]],
            colWidths=[A4[0] - 4*cm],
            style=TableStyle([
                ("BACKGROUND", (0,0),(-1,-1), color_sev),
                ("TOPPADDING", (0,0),(-1,-1), 5),
                ("BOTTOMPADDING",(0,0),(-1,-1), 5),
                ("LEFTPADDING",(0,0),(-1,-1), 8),
                ("ROUNDEDCORNERS",[3]),
            ])
        ))
        items.append(Spacer(1, 0.15*cm))

        # Filas de hallazgos
        cab = [
            Paragraph("IP", estilos["normal_neg"]),
            Paragraph("Puerto", estilos["normal_neg"]),
            Paragraph("Servicio", estilos["normal_neg"]),
            Paragraph("Detalle / Acción recomendada", estilos["normal_neg"]),
            Paragraph("Hora", estilos["normal_neg"]),
        ]
        filas = [cab]
        for h in grupo:
            filas.append([
                Paragraph(h.ip or "—",
                    ParagraphStyle("m", fontName="Courier",
                        fontSize=8, textColor=AZUL_OSC)),
                Paragraph(str(h.puerto) if h.puerto else "—",
                    estilos["mono"]),
                Paragraph(h.servicio or "—", estilos["normal_neg"]),
                Paragraph(getattr(h,'detalle','') or "—", estilos["normal"]),
                Paragraph(getattr(h,'timestamp','') or "—",
                    ParagraphStyle("ts", fontName="Courier",
                        fontSize=7, textColor=GRIS_TEXTO)),
            ])

        tabla = Table(filas,
            colWidths=[2.5*cm, 1.5*cm, 3.0*cm, 8.0*cm, 1.7*cm],
            repeatRows=1)
        tabla.setStyle(_estilo_tabla_base())
        items.append(tabla)

    return items


# ── SECCIÓN: CONEXIONES EXTERNAS ─────────────────────────────────────────────

def _conexiones_externas(topologia, estilos):
    items = []
    items.append(PageBreak())
    items.append(SeccionTitulo("Conexiones Externas — GeoIP", AZUL_OSC))
    items.append(Spacer(1, 0.2*cm))
    items.append(Paragraph(
        "Conexiones hacia IPs externas detectadas durante la sesión, "
        "enriquecidas con información GeoIP.",
        estilos["normal"]))
    items.append(Spacer(1, 0.3*cm))

    # Recopilar conexiones externas de topologia.externos + _geo_cache
    externas = []
    externos = getattr(topologia, 'externos', {})
    geo_cache = getattr(topologia, '_geo_cache', {})

    for ip_src, lista in externos.items():
        for ip_dst, protocolo in lista:
            geo = geo_cache.get(ip_dst, {})
            externas.append({
                "ip_src" : ip_src,
                "ip_dst" : ip_dst,
                "proto"  : protocolo or "—",
                "pais"   : geo.get("iso","") if geo else "",
                "org"    : geo.get("org","") if geo else "",
                "ciudad" : geo.get("ciudad","") if geo else "",
            })

    if not externas:
        items.append(Paragraph(
            "No se registraron conexiones externas en esta sesión.",
            estilos["normal"]))
        return items

    cab = [
        Paragraph("IP Origen",   estilos["normal_neg"]),
        Paragraph("IP Destino",  estilos["normal_neg"]),
        Paragraph("Proto",       estilos["normal_neg"]),
        Paragraph("País",        estilos["normal_neg"]),
        Paragraph("Ciudad",      estilos["normal_neg"]),
        Paragraph("Organización",estilos["normal_neg"]),
    ]
    filas = [cab]
    for e in externas[:80]:   # máx 80 filas
        filas.append([
            Paragraph(e["ip_src"], ParagraphStyle("m",fontName="Courier",
                fontSize=8,textColor=AZUL_OSC)),
            Paragraph(e["ip_dst"], ParagraphStyle("m",fontName="Courier",
                fontSize=8,textColor=NEGRO)),
            Paragraph(e["proto"],  estilos["mono"]),
            Paragraph(f"[{e['pais']}]" if e["pais"] else "—", estilos["normal"]),
            Paragraph(e["ciudad"][:16] if e["ciudad"] else "—", estilos["normal"]),
            Paragraph(e["org"][:22]    if e["org"]    else "—", estilos["normal"]),
        ])
    if len(externas) > 80:
        filas.append([
            Paragraph(f"… {len(externas)-80} conexiones adicionales no mostradas",
                estilos["caption"]),
            "", "", "", "", ""
        ])

    tabla = Table(filas,
        colWidths=[2.6*cm, 2.8*cm, 1.5*cm, 1.6*cm, 2.5*cm, 5.7*cm],
        repeatRows=1)
    tabla.setStyle(_estilo_tabla_base())
    items.append(tabla)

    return items


# ── SECCIÓN: APÉNDICE ─────────────────────────────────────────────────────────

def _cobertura_niveles(topologia, estilos, buf_str=""):
    """Sección de cobertura por niveles del iceberg de seguridad."""
    items = []
    items.append(SeccionTitulo("Cobertura de Herramientas — Iceberg de Seguridad", AZUL_OSC))
    items.append(Spacer(1, 0.2*cm))
    items.append(Paragraph(
        "Cobertura de cada nivel de análisis durante esta sesión. "
        "✓ = detectado/activo  ○ = activo pero sin hallazgos en esta red.",
        ParagraphStyle("cob_desc", fontName="Helvetica", fontSize=8,
            textColor=GRIS_TEXTO, spaceAfter=8)))

    alertas = list(getattr(topologia, 'alertas', []))
    nodos   = list(topologia.nodos.values())
    activos = [n for n in nodos if not n.en_lobby]
    n_puertos = sum(len(n.puertos_abiertos) for n in activos)

    def fila(cond, nombre, detalle=""):
        s   = "✓" if cond else "○"
        col = AZUL_OSC if cond else GRIS_MED
        return [
            Paragraph(s, ParagraphStyle("s", fontName="Helvetica-Bold",
                fontSize=9, textColor=col)),
            Paragraph(nombre, ParagraphStyle("n", fontName="Helvetica",
                fontSize=8, textColor=NEGRO if cond else GRIS_MED)),
            Paragraph(detalle[:60],
                ParagraphStyle("d", fontName="Helvetica", fontSize=7,
                    textColor=GRIS_TEXTO)),
        ]

    def cabecera_nivel(texto, color):
        return Table(
            [[Paragraph(texto, ParagraphStyle("nh", fontName="Helvetica-Bold",
                fontSize=9, textColor=BLANCO))]],
            colWidths=[A4[0]-4*cm],
            style=TableStyle([
                ("BACKGROUND",(0,0),(-1,-1), color),
                ("TOPPADDING",(0,0),(-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
                ("LEFTPADDING",(0,0),(-1,-1), 8),
            ]))

    col_w = [0.8*cm, 6*cm, 9.5*cm]
    estilo_t = TableStyle([
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING",(0,0),(-1,-1),3),
        ("BOTTOMPADDING",(0,0),(-1,-1),3),
        ("LINEBELOW",(0,0),(-1,-1),0.3,GRIS_MED),
        ("LEFTPADDING",(0,0),(-1,-1),4),
    ])

    # Nivel 1
    items.append(cabecera_nivel("NIVEL 1 — Descubrimiento básico (Lo Inevitable)", AZUL_OSC))
    filas1 = [
        fila(len(activos)>0, "Hosts vivos (ARP/ping)", f"{len(activos)} hosts"),
        fila(bool(topologia.gateway), "Gateway identificado", topologia.gateway or ""),
        fila(n_puertos>0, "Puertos TCP escaneados", f"{n_puertos} puertos abiertos"),
        fila("[EXTERNO]" in buf_str, "Tráfico externo capturado"),
        fila("[FLUJO]" in buf_str, "Flujos internos detectados"),
        fila(any(n.sistema_op and n.sistema_op!="Desconocido" for n in activos), "OS fingerprinting"),
        fila(any(n.fabricante for n in activos), "Identificación de fabricantes"),
    ]
    t1 = Table(filas1, colWidths=col_w)
    t1.setStyle(estilo_t)
    items.append(t1)
    items.append(Spacer(1, 0.3*cm))

    # Nivel 2
    items.append(cabecera_nivel("NIVEL 2 — Estándar (75–90%)", AZUL_MED))
    filas2 = [
        fila("HTTP" in buf_str, "HTTP detectado"),
        fila("SSL Autofirmado" in buf_str, "SSL/TLS analizado",
             "autofirmado detectado" if "SSL Autofirmado" in buf_str else ""),
        fila("DHCP" in buf_str, "DHCP capturado"),
        fila("DNS" in buf_str, "DNS interno"),
        fila("XMPP" in buf_str or "QUIC" in buf_str, "Protocolos aplicación (XMPP/QUIC)"),
        fila("NTP" in buf_str, "NTP detectado"),
        fila("RTSP" in buf_str, "RTSP (cámara/stream)"),
        fila("FTP" in buf_str, "FTP analizado"),
        fila(any("Network Shares" in (h.servicio or "") for h in alertas), "SMB Shares"),
        fila(any("Cred. por Defecto" in (h.servicio or "") for h in alertas),
             "Credenciales por defecto"),
    ]
    t2 = Table(filas2, colWidths=col_w)
    t2.setStyle(estilo_t)
    items.append(t2)
    items.append(Spacer(1, 0.3*cm))

    # Nivel 3
    items.append(cabecera_nivel("NIVEL 3 — Persistencia y vectores (40–70%)", NARANJA))
    filas3 = [
        fila(any("DC/" in (h.servicio or "") for h in alertas), "Active Directory/DC"),
        fila(any("LDAP" in (h.servicio or "") for h in alertas), "LDAP enumerado"),
        fila(any("Kerberos" in (h.servicio or "") for h in alertas), "Kerberos SPN"),
        fila(any("SSL" in (h.servicio or "") for h in alertas), "Certificados SSL analizados"),
        fila(any("NFS" in (h.servicio or "") for h in alertas), "NFS exportaciones"),
        fila("IPSec" in buf_str or "VPN" in buf_str or "IKE" in buf_str, "VPN/túneles"),
    ]
    t3 = Table(filas3, colWidths=col_w)
    t3.setStyle(estilo_t)
    items.append(t3)
    items.append(Spacer(1, 0.3*cm))

    # Nivel 4
    items.append(cabecera_nivel("NIVEL 4 — Técnicas Avanzadas (10–30%)", ROJO))
    filas4 = [
        fila("[IPv6]" in buf_str, "IPv6 completo",
             "hosts encontrados" if "Host respondió" in buf_str else "activo/sin hosts IPv6"),
        fila("[LLMNR]" in buf_str or "[NBT-NS]" in buf_str, "LLMNR/NBT-NS poisoning"),
        fila("[WPAD]" in buf_str, "WPAD spoofing"),
        fila("[VLAN]" in buf_str, "VLAN hopping"),
        fila("[CDP]" in buf_str or "[LLDP]" in buf_str, "CDP/LLDP discovery"),
        fila(any("Anomalía" in (h.servicio or "") for h in alertas), "Shadow IT / anomalías"),
        fila(any("DHCP Rogue" in (h.servicio or "") for h in alertas), "DHCP Rogue"),
    ]
    t4 = Table(filas4, colWidths=col_w)
    t4.setStyle(estilo_t)
    items.append(t4)
    items.append(Spacer(1, 0.3*cm))

    # Nivel 5
    items.append(cabecera_nivel("NIVEL 5 — Elite (1–5%)", ROJO))
    filas5 = [
        fila(any("IPMI" in (h.servicio or "") for h in alertas), "IPMI/iDRAC/iLO"),
        fila("[BEACON] CONFIRMADO" in buf_str, "Beacon C2 detection",
             f"{buf_str.count('[BEACON] CONFIRMADO')//max(1,1)} confirmados"),
        fila("[JA3]" in buf_str, "JA3/JA3S TLS fingerprinting"),
        fila("[NTP]" in buf_str and "offset" in buf_str.lower(), "NTP drift medido"),
    ]
    t5 = Table(filas5, colWidths=col_w)
    t5.setStyle(estilo_t)
    items.append(t5)

    return items


def _apendice(topologia, estilos, fecha):
    items = []
    items.append(PageBreak())
    items.append(SeccionTitulo("Apéndice Técnico", AZUL_OSC))
    items.append(Spacer(1, 0.3*cm))

    items.append(Paragraph("Metodología de Análisis", estilos["titulo2"]))
    items.append(Paragraph(
        "TopoReveal utiliza un pipeline de tres fases para el descubrimiento y análisis de la red:",
        estilos["normal"]))

    metodologia = [
        ["Fase 1 — Descubrimiento ARP",
         "ARP sweep activo + captura pasiva de broadcasts. "
         "Identifica todos los hosts activos en la subred en 3-5 segundos."],
        ["Fase 2 — Fingerprinting",
         "Análisis de TTL, puertos abiertos, banner grabbing, "
         "comportamiento DNS, DHCP Option 55 y User-Agent HTTP. "
         "Sistema de scoring compuesto para clasificación de riesgo."],
        ["Fase 3 — Análisis Profundo",
         "SSL/TLS certificate inspection, SNMP community strings, "
         "UPnP enumeration, análisis de payload HTTP, "
         "detección de servicios IoT (MQTT, Modbus, RTSP)."],
        ["MITM — Interceptación",
         "ARP spoofing controlado con restauración automática. "
         "Captura de tráfico HTTP plano, credenciales Basic Auth, "
         "User-Agent para identificación precisa de dispositivos."],
        ["GeoIP",
         "Base de datos MaxMind GeoLite2 local (sin internet). "
         "Enriquece cada conexión externa con país, ciudad y organización."],
    ]

    tabla_met = Table(metodologia, colWidths=[4.5*cm, 12.2*cm])
    tabla_met.setStyle(TableStyle([
        ("FONTNAME",    (0,0),(0,-1), "Helvetica-Bold"),
        ("FONTNAME",    (1,0),(1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0),(-1,-1), 8),
        ("TEXTCOLOR",   (0,0),(0,-1), AZUL_OSC),
        ("TEXTCOLOR",   (1,0),(1,-1), GRIS_TEXTO),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[BLANCO, GRIS_CLARO]),
        ("GRID",        (0,0),(-1,-1), 0.3, GRIS_MED),
        ("TOPPADDING",  (0,0),(-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("LEFTPADDING", (0,0),(-1,-1), 6),
        ("VALIGN",      (0,0),(-1,-1), "TOP"),
    ]))
    items.append(tabla_met)

    items.append(Spacer(1, 0.5*cm))
    items.append(Paragraph("Escala de Riesgo", estilos["titulo2"]))

    escala = [
        ["CRÍTICO (70-100)", "Compromiso inmediato probable. "
         "Credenciales expuestas, servicios de administración "
         "sin cifrado, combinaciones de vulnerabilidades activas."],
        ["ALTO (40-69)", "Riesgo significativo. Servicios con "
         "autenticación débil, firmware desactualizado, "
         "puertos de gestión expuestos."],
        ["MEDIO (20-39)", "Riesgo moderado. Servicios HTTP sin HTTPS, "
         "certificados SSL con emisor desconocido, "
         "puertos innecesariamente abiertos."],
        ["INFO (0-19)", "Sin riesgo inmediato. "
         "Información de contexto sobre el dispositivo."],
    ]
    tabla_esc = Table(escala, colWidths=[3.5*cm, 13.2*cm])
    colores_esc = [ROJO, NARANJA, AMARILLO, CYAN]
    esc_style = [
        ("FONTNAME",   (0,0),(0,-1), "Helvetica-Bold"),
        ("FONTNAME",   (1,0),(1,-1), "Helvetica"),
        ("FONTSIZE",   (0,0),(-1,-1), 8),
        ("TEXTCOLOR",  (1,0),(1,-1), GRIS_TEXTO),
        ("GRID",       (0,0),(-1,-1), 0.3, GRIS_MED),
        ("TOPPADDING", (0,0),(-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING",(0,0),(-1,-1), 6),
        ("VALIGN",     (0,0),(-1,-1), "TOP"),
    ]
    for i, c in enumerate(colores_esc):
        esc_style.append(("TEXTCOLOR", (0,i),(0,i), c))
        esc_style.append(("BACKGROUND",(0,i),(0,i),
            colors.Color(c.red, c.green, c.blue, 0.08)))
    tabla_esc.setStyle(TableStyle(esc_style))
    items.append(tabla_esc)

    items.append(Spacer(1, 0.5*cm))
    items.append(Paragraph(
        f"Informe generado por TopoReveal v2.0 el {fecha}. "
        "Para más información contacte al administrador de red.",
        estilos["caption"]))

    return items


# ── UTILIDADES ────────────────────────────────────────────────────────────────

def _estilo_tabla_base():
    return TableStyle([
        # Cabecera
        ("BACKGROUND",   (0,0),(-1,0), AZUL_OSC),
        ("TEXTCOLOR",    (0,0),(-1,0), BLANCO),
        ("FONTNAME",     (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0),(-1,0), 9),
        # Cuerpo
        ("FONTNAME",     (0,1),(-1,-1), "Helvetica"),
        ("FONTSIZE",     (0,1),(-1,-1), 8),
        ("TEXTCOLOR",    (0,1),(-1,-1), NEGRO),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [BLANCO, GRIS_CLARO]),
        # Padding
        ("TOPPADDING",   (0,0),(-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
        ("LEFTPADDING",  (0,0),(-1,-1), 5),
        ("RIGHTPADDING", (0,0),(-1,-1), 5),
        # Bordes
        ("GRID",         (0,0),(-1,-1), 0.3, GRIS_MED),
        ("LINEBELOW",    (0,0),(-1,0),  1.0, CYAN),
        ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
        ("ALIGN",        (0,0),(-1,-1), "LEFT"),
    ])
