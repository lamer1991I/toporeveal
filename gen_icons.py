"""
gen_icons.py — Genera iconos PNG estilo neón para TopoReveal
Ejecutar una vez: python3 gen_icons.py
Genera: assets/icons/*.png  (64x64 px, fondo transparente)
"""

from PIL import Image, ImageDraw, ImageFilter
import os, math

OUT = os.path.join(os.path.dirname(__file__), "assets", "icons")
os.makedirs(OUT, exist_ok=True)

S = 64          # tamaño del canvas del icono
C = S // 2      # centro

# ── paleta neón ────────────────────────────────────────────────────
VERDE   = (63,  185,  80)    # confirmado
AZUL    = (56,  139, 253)    # internet / neutro
CYAN    = (88,  214, 255)    # tú / local
NARANJA = (240, 136,  62)    # alerta
ROJO    = (218,  54,  51)    # fantasma
VIOLETA = (169,  87, 229)
BLANCO  = (230, 237, 243)
GRIS    = (139, 148, 158)


def nueva(bg=(0,0,0,0)):
    return Image.new("RGBA", (S, S), bg)


def glow(img, color, radio=3):
    """Añade halo neón alrededor de los píxeles dibujados."""
    r, g, b = color[:3]
    glow_layer = Image.new("RGBA", (S, S), (0,0,0,0))
    # Extraer canal alpha del dibujo y usarlo como máscara de brillo
    mask = img.split()[3]
    for dx in range(-radio, radio+1):
        for dy in range(-radio, radio+1):
            if dx==0 and dy==0: continue
            dist = math.sqrt(dx*dx+dy*dy)
            if dist > radio: continue
            alpha = int(120 * (1 - dist/radio))
            layer = Image.new("RGBA", (S, S), (r,g,b,0))
            layer.putalpha(mask.point(lambda p: int(p * alpha / 255)))
            shifted = Image.new("RGBA", (S, S), (0,0,0,0))
            shifted.paste(layer, (dx, dy))
            glow_layer = Image.alpha_composite(glow_layer, shifted)
    return Image.alpha_composite(glow_layer, img)


def circulo_base(draw, color, r=28, width=2):
    draw.ellipse([C-r, C-r, C+r, C+r], outline=(*color, 255), width=width)


def guardar(img, nombre):
    img.save(os.path.join(OUT, f"{nombre}.png"), "PNG")
    print(f"  ✓ {nombre}.png")


# ══════════════════════════════════════════════════════════════════
# ROUTER — hexágono con punto central y 3 antenas
# ══════════════════════════════════════════════════════════════════
def icono_router():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = VERDE
    # Hexágono
    pts = [(C + 22*math.cos(math.radians(a+30)),
            C + 22*math.sin(math.radians(a+30))) for a in range(0,360,60)]
    d.polygon(pts, outline=(*color,255), fill=(*color,30), width=2)
    # Círculo interior
    d.ellipse([C-6,C-6,C+6,C+6], fill=(*color,255))
    # 3 líneas radiales
    for ang in [90, 210, 330]:
        rad = math.radians(ang)
        x2 = C + 14*math.cos(rad)
        y2 = C + 14*math.sin(rad)
        d.line([C,C,x2,y2], fill=(*color,200), width=2)
    guardar(glow(img, color), "router")


# ══════════════════════════════════════════════════════════════════
# SWITCH — rectángulo con puertos
# ══════════════════════════════════════════════════════════════════
def icono_switch():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = AZUL
    # Cuerpo
    d.rounded_rectangle([8,22,56,42], radius=4, outline=(*color,255), fill=(*color,25), width=2)
    # 5 puertos
    for i, px in enumerate([16,24,32,40,48]):
        d.rectangle([px-3,27,px+3,33], outline=(*color,255), fill=(*color,80), width=1)
    # LED indicadores
    for i, px in enumerate([16,24,32,40,48]):
        col = VERDE if i%2==0 else NARANJA
        d.ellipse([px-2,36,px+2,40], fill=(*col,220))
    guardar(glow(img, color, 2), "switch")


# ══════════════════════════════════════════════════════════════════
# PC — monitor con base
# ══════════════════════════════════════════════════════════════════
def icono_pc():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = AZUL
    # Pantalla
    d.rounded_rectangle([8,10,56,44], radius=3, outline=(*color,255), fill=(*color,25), width=2)
    # Pantalla interior
    d.rectangle([12,14,52,40], fill=(*color,40))
    # Base
    d.rectangle([26,44,38,50], fill=(*color,180))
    d.rectangle([18,50,46,53], outline=(*color,255), fill=(*color,80), width=1)
    # Indicador LED
    d.ellipse([C-2,37,C+2,41], fill=(*VERDE,220))
    guardar(glow(img, color, 2), "pc")


# ══════════════════════════════════════════════════════════════════
# LAPTOP — pantalla inclinada con teclado
# ══════════════════════════════════════════════════════════════════
def icono_laptop():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = AZUL
    # Tapa
    d.polygon([(10,38),(54,38),(50,12),(14,12)], outline=(*color,255), fill=(*color,25), width=2)
    # Pantalla interior
    d.polygon([(14,35),(50,35),(47,16),(17,16)], fill=(*color,40))
    # Base teclado
    d.rounded_rectangle([6,38,58,50], radius=2, outline=(*color,255), fill=(*color,40), width=2)
    # Teclas (líneas)
    for y in [42,46]:
        d.line([12,y,52,y], fill=(*color,100), width=1)
    guardar(glow(img, color, 2), "laptop")


# ══════════════════════════════════════════════════════════════════
# SMARTPHONE — teléfono vertical con pantalla
# ══════════════════════════════════════════════════════════════════
def icono_smartphone():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = CYAN
    # Cuerpo
    d.rounded_rectangle([18,6,46,58], radius=5, outline=(*color,255), fill=(*color,25), width=2)
    # Pantalla
    d.rounded_rectangle([21,11,43,50], radius=3, fill=(*color,40))
    # Home button
    d.ellipse([29,52,35,56], outline=(*color,255), width=1)
    # Cámara frontal
    d.ellipse([C-2,8,C+2,12], fill=(*color,180))
    guardar(glow(img, color, 2), "smartphone")


# ══════════════════════════════════════════════════════════════════
# SERVIDOR — stack de discos
# ══════════════════════════════════════════════════════════════════
def icono_servidor():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = AZUL
    for i, y in enumerate([10, 24, 38]):
        c = VERDE if i==0 else NARANJA if i==1 else color
        d.rounded_rectangle([8,y,56,y+12], radius=3,
                             outline=(*color,255), fill=(*color,30), width=2)
        d.ellipse([10,y+3,16,y+9], fill=(*c,220))
        d.line([20,y+6,48,y+6], fill=(*color,80), width=1)
    guardar(glow(img, color, 2), "servidor")


# ══════════════════════════════════════════════════════════════════
# CÁMARA — ojo con lente
# ══════════════════════════════════════════════════════════════════
def icono_camara():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = (56, 139, 253)   # azul
    # Cuerpo cámara
    d.rounded_rectangle([10,18,46,46], radius=4, outline=(*color,255), fill=(*color,25), width=2)
    # Lente
    d.ellipse([14,22,42,42], outline=(*color,200), fill=(*color,40), width=2)
    d.ellipse([19,27,37,37], outline=(*color,180), fill=(*color,60), width=1)
    d.ellipse([24,29,32,35], fill=(*color,200))
    # Flash/grip derecho
    d.rounded_rectangle([46,22,56,32], radius=2, outline=(*color,180), fill=(*color,30), width=1)
    # LED rojo recording
    d.ellipse([48,34,54,40], fill=(218,54,51,220))
    guardar(glow(img, color, 2), "camara")


# ══════════════════════════════════════════════════════════════════
# IMPRESORA — caja con papel saliendo
# ══════════════════════════════════════════════════════════════════
def icono_impresora():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = GRIS
    # Cuerpo
    d.rounded_rectangle([8,24,56,50], radius=3, outline=(*color,255), fill=(*color,25), width=2)
    # Papel saliendo
    d.rectangle([18,12,46,28], outline=(*BLANCO,200), fill=(*BLANCO,30), width=1)
    d.line([18,16,46,16], fill=(*GRIS,100), width=1)
    d.line([18,20,46,20], fill=(*GRIS,100), width=1)
    # LED
    d.ellipse([44,30,50,36], fill=(*VERDE,200))
    # Ranura papel
    d.rectangle([14,26,50,30], fill=(*color,60))
    guardar(glow(img, color, 2), "impresora")


# ══════════════════════════════════════════════════════════════════
# IOT — chip con señal wifi
# ══════════════════════════════════════════════════════════════════
def icono_iot():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = VIOLETA
    # Chip cuadrado
    d.rounded_rectangle([18,28,46,54], radius=3, outline=(*color,255), fill=(*color,30), width=2)
    # Pines
    for px in [22,30,38,44]:
        d.line([px,54,px,58], fill=(*color,180), width=2)
        d.line([px,28,px,24], fill=(*color,180), width=2)
    # Wifi arcs arriba
    for r, a in [(8,150),(13,150),(18,150)]:
        d.arc([C-r, 6, C+r, 6+r*2], start=a, end=180+30, fill=(*color,180), width=2)
    guardar(glow(img, color, 2), "iot")


# ══════════════════════════════════════════════════════════════════
# ACCESS POINT — antenas con ondas
# ══════════════════════════════════════════════════════════════════
def icono_ap():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = CYAN
    # Base
    d.rounded_rectangle([16,42,48,54], radius=4, outline=(*color,255), fill=(*color,30), width=2)
    # Antena central
    d.line([C,42,C,18], fill=(*color,220), width=2)
    # Ondas wifi
    for r in [10,16,22]:
        d.arc([C-r,20,C+r,20+r], start=210, end=330, fill=(*color,200-(r*4)), width=2)
    # LED
    d.ellipse([C-3,44,C+3,50], fill=(*VERDE,220))
    guardar(glow(img, color, 2), "ap")


# ══════════════════════════════════════════════════════════════════
# FIREWALL — escudo con candado
# ══════════════════════════════════════════════════════════════════
def icono_firewall():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = ROJO
    # Escudo
    pts = [C, 6, 54, 18, 54, 38, C, 58, 10, 38, 10, 18]
    d.polygon(pts, outline=(*color,255), fill=(*color,30), width=2)
    # Candado cuerpo
    d.rounded_rectangle([C-8,32,C+8,46], radius=2, outline=(*color,220), fill=(*color,80), width=2)
    # Aro candado
    d.arc([C-6,22,C+6,36], start=0, end=180, fill=(*color,220), width=2)
    # Ojo
    d.ellipse([C-2,37,C+2,41], fill=(*BLANCO,200))
    guardar(glow(img, color, 2), "firewall")


# ══════════════════════════════════════════════════════════════════
# ARP-SCANNER — triángulo alerta con símbolo
# ══════════════════════════════════════════════════════════════════
def icono_scanner():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = NARANJA
    # Triángulo
    d.polygon([C,6, 58,54, 6,54], outline=(*color,255), fill=(*color,30), width=2)
    # Exclamación
    d.rectangle([C-2,20,C+2,40], fill=(*color,240))
    d.ellipse([C-3,44,C+3,52], fill=(*color,240))
    guardar(glow(img, color, 3), "arp-scanner")


# ══════════════════════════════════════════════════════════════════
# DESCONOCIDO — círculo con ?
# ══════════════════════════════════════════════════════════════════
def icono_desconocido():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = GRIS
    d.ellipse([8,8,56,56], outline=(*color,200), fill=(*color,20), width=2)
    # Signo ?  — dibujado con líneas
    # Arco superior
    d.arc([C-8,14,C+8,30], start=200, end=340, fill=(*color,220), width=3)
    # Línea bajando
    d.line([C,30,C,42], fill=(*color,220), width=3)
    # Punto
    d.ellipse([C-2,46,C+2,50], fill=(*color,220))
    guardar(glow(img, color, 2), "desconocido")


# ══════════════════════════════════════════════════════════════════
# INTERNET / WAN — globo con meridianos
# ══════════════════════════════════════════════════════════════════
def icono_internet():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = AZUL
    # Círculo exterior
    d.ellipse([6,6,58,58], outline=(*color,255), fill=(*color,20), width=2)
    # Meridianos verticales
    d.arc([18,6,46,58], start=0, end=360, fill=(*color,120), width=1)
    d.line([C,6,C,58], fill=(*color,120), width=1)
    # Ecuador
    d.line([6,C,58,C], fill=(*color,120), width=1)
    # Paralelo superior e inferior
    d.arc([10,18,54,34], start=0, end=180, fill=(*color,100), width=1)
    d.arc([10,30,54,46], start=180, end=360, fill=(*color,100), width=1)
    guardar(glow(img, color, 2), "internet")


# ══════════════════════════════════════════════════════════════════
# SMART TV — pantalla ancha con patas
# ══════════════════════════════════════════════════════════════════
def icono_tv():
    img = nueva()
    d = ImageDraw.Draw(img)
    color = (139, 87, 229)
    d.rounded_rectangle([6,10,58,46], radius=3, outline=(*color,255), fill=(*color,25), width=2)
    d.rectangle([10,14,54,42], fill=(*color,40))
    # Patas
    d.line([20,46,16,54], fill=(*color,180), width=2)
    d.line([44,46,48,54], fill=(*color,180), width=2)
    d.line([14,54,50,54], fill=(*color,180), width=2)
    # LED
    d.ellipse([50,36,55,41], fill=(*ROJO,200))
    guardar(glow(img, color, 2), "smart_tv")



# ══════════════════════════════════════════════════════════════════
# TABLET
# ══════════════════════════════════════════════════════════════════
def icono_tablet():
    img = nueva(); d = ImageDraw.Draw(img)
    c = AZUL
    d.rounded_rectangle([10,4,54,60], radius=6, outline=(*c,255), fill=(*c,25), width=2)
    d.rounded_rectangle([13,10,51,52], radius=4, fill=(*c,45))
    for y in [18,24,30,38]:
        d.line([17,y,47,y], fill=(*c,90), width=1)
    d.ellipse([C-3,54,C+3,58], outline=(*c,200), width=1)
    d.ellipse([C-2,6,C+2,10], fill=(*c,180))
    guardar(glow(img, c), "tablet")


# ══════════════════════════════════════════════════════════════════
# VOIP
# ══════════════════════════════════════════════════════════════════
def icono_voip():
    img = nueva(); d = ImageDraw.Draw(img)
    c = (32, 201, 151)
    d.arc([12,8,52,52], start=0, end=180, fill=(*c,255), width=3)
    d.ellipse([8,42,20,56], outline=(*c,255), fill=(*c,40), width=2)
    d.ellipse([44,42,56,56], outline=(*c,255), fill=(*c,40), width=2)
    for r in [8,13]:
        d.arc([C-r,C-r,C+r,C+r], start=300, end=60, fill=(*c,150), width=1)
    guardar(glow(img, c), "voip")


# ══════════════════════════════════════════════════════════════════
# HISTORIAN / NAS
# ══════════════════════════════════════════════════════════════════
def icono_historian():
    img = nueva(); d = ImageDraw.Draw(img)
    c = (219, 68, 170)
    d.ellipse([10,6,54,20], outline=(*c,255), fill=(*c,50), width=2)
    d.rectangle([10,13,54,50], fill=(*c,25))
    d.line([10,13,10,50], fill=(*c,200), width=2)
    d.line([54,13,54,50], fill=(*c,200), width=2)
    d.ellipse([10,42,54,56], outline=(*c,255), fill=(*c,50), width=2)
    d.polygon([C+14,28, C+22,22, C+22,26, C+30,26, C+30,30, C+22,30, C+22,34], fill=(*c,200))
    guardar(glow(img, c), "historian")


# ══════════════════════════════════════════════════════════════════
# CONTROLLER / PLC
# ══════════════════════════════════════════════════════════════════
def icono_controller():
    img = nueva(); d = ImageDraw.Draw(img)
    c = (32, 201, 151)
    d.rounded_rectangle([6,14,58,54], radius=4, outline=(*c,255), fill=(*c,25), width=2)
    d.rounded_rectangle([10,18,38,34], radius=2, outline=(*c,180), fill=(0,20,30,200), width=1)
    for y in [23,28]:
        d.line([13,y,35,y], fill=(*c,100), width=1)
    for by in [20,28,36,44]:
        col = VERDE if by in [20,36] else NARANJA
        d.ellipse([42,by,50,by+6], fill=(*col,210))
    for px in [14,22,30,38,46]:
        d.rectangle([px-3,46,px+3,52], outline=(*c,160), fill=(0,0,0,80), width=1)
    guardar(glow(img, c), "controller")


# ══════════════════════════════════════════════════════════════════
# SNIFFER
# ══════════════════════════════════════════════════════════════════
def icono_sniffer():
    img = nueva(); d = ImageDraw.Draw(img)
    c = VERDE
    d.ellipse([6,20,58,44], outline=(*c,255), fill=(*c,20), width=2)
    d.ellipse([20,24,44,40], outline=(*c,200), fill=(*c,40), width=2)
    d.ellipse([26,27,38,37], fill=(*c,220))
    d.ellipse([29,29,33,33], fill=(0,0,0,200))
    d.line([C,20,C,8], fill=(*c,200), width=2)
    d.arc([C-8,4,C+8,14], start=0, end=180, fill=(*c,200), width=2)
    for r in [6,10]:
        d.arc([4,C-r,4+r*2,C+r], start=270, end=90, fill=(*c,140), width=1)
        d.arc([60-r*2,C-r,60,C+r], start=90, end=270, fill=(*c,140), width=1)
    guardar(glow(img, c), "sniffer")


# ══════════════════════════════════════════════════════════════════
# WIRED GENERIC
# ══════════════════════════════════════════════════════════════════
def icono_wired():
    img = nueva(); d = ImageDraw.Draw(img)
    c = GRIS
    d.rounded_rectangle([14,20,50,50], radius=4, outline=(*c,200), fill=(*c,20), width=2)
    d.rounded_rectangle([22,44,42,56], radius=2, outline=(*c,180), fill=(*c,40), width=1)
    for px in [26,30,34,38]:
        d.line([px,46,px,54], fill=(*c,120), width=1)
    d.line([C,20,C,10], fill=(*c,180), width=2)
    d.arc([C-8,6,C+8,16], start=180, end=360, fill=(*c,180), width=2)
    guardar(glow(img, c), "wired_generic")

# ══════════════════════════════════════════════════════════════════
# EJECUTAR TODO
# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("Generando iconos TopoReveal...")
    icono_router()
    icono_switch()
    icono_pc()
    icono_laptop()
    icono_smartphone()
    icono_servidor()
    icono_camara()
    icono_impresora()
    icono_iot()
    icono_ap()
    icono_firewall()
    icono_scanner()
    icono_desconocido()
    icono_internet()
    icono_tv()
    print(f"\nListo — {len(os.listdir(OUT))} iconos en {OUT}/")
