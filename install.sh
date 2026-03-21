#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  TopoReveal — Instalador v2.0
#  Autor: Albert (ha-king)
#  Licencia: GPL v3
#  Uso: sudo bash install.sh
#  Repositorio: https://github.com/ha-king/toporeveal
# ═══════════════════════════════════════════════════════════════════

set -e

# ── Colores ──────────────────────────────────────────────────────────
C_CYAN='\033[0;36m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[0;31m'
C_BOLD='\033[1m'
C_RESET='\033[0m'

ok()   { echo -e "  ${C_GREEN}✓${C_RESET}  $1"; }
info() { echo -e "  ${C_CYAN}→${C_RESET}  $1"; }
warn() { echo -e "  ${C_YELLOW}⚠${C_RESET}  $1"; }
err()  { echo -e "  ${C_RED}✗${C_RESET}  $1"; exit 1; }
hdr()  { echo -e "\n${C_BOLD}${C_CYAN}$1${C_RESET}"; }

# ── Banner ────────────────────────────────────────────────────────────
clear
echo -e "${C_CYAN}"
cat << 'EOF'
  ████████╗ ██████╗ ██████╗  ██████╗ ██████╗ ███████╗██╗   ██╗███████╗ █████╗ ██╗
  ╚══██╔══╝██╔═══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝██║   ██║██╔════╝██╔══██╗██║
     ██║   ██║   ██║██████╔╝██║   ██║██████╔╝█████╗  ██║   ██║█████╗  ███████║██║
     ██║   ██║   ██║██╔═══╝ ██║   ██║██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██║██║
     ██║   ╚██████╔╝██║     ╚██████╔╝██║  ██║███████╗ ╚████╔╝ ███████╗██║  ██║███████╗
     ╚═╝    ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝
EOF
echo -e "${C_RESET}"
echo -e "  ${C_BOLD}Network Intelligence Platform v2.0${C_RESET}"
echo -e "  Autor: Albert (ha-king) | Licencia: GPL v3\n"
echo -e "  ${C_YELLOW}⚠  Solo usar en redes propias o con autorización escrita${C_RESET}\n"
echo -e "${C_CYAN}══════════════════════════════════════════════════════════════${C_RESET}\n"

# ── Verificar root ────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "Ejecuta con sudo: sudo bash install.sh"
fi

# ── Detectar usuario real (no root) ──────────────────────────────────
USUARIO_REAL="${SUDO_USER:-$USER}"
if [[ "$USUARIO_REAL" == "root" ]]; then
    warn "Ejecutando como root puro — el proyecto se instalará en /root/"
fi
HOME_REAL=$(getent passwd "$USUARIO_REAL" | cut -d: -f6 2>/dev/null || echo "/root")
INSTALL_DIR="$HOME_REAL/Proyectos/toporeveal"

# ── Detectar distribución ─────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    DISTRO="debian"
elif command -v dnf &>/dev/null; then
    DISTRO="fedora"
elif command -v pacman &>/dev/null; then
    DISTRO="arch"
else
    DISTRO="desconocido"
    warn "Distribución no reconocida — instala las dependencias manualmente"
fi

ok "Usuario: $USUARIO_REAL | Home: $HOME_REAL"
ok "Directorio instalación: $INSTALL_DIR"
ok "Distribución: $DISTRO"

# ── [ 1/8 ] Crear estructura de directorios ───────────────────────────
hdr "[ 1/8 ] Creando estructura de directorios..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$SCRIPT_DIR/main.py" ]]; then
    err "No se encontró main.py. Ejecuta install.sh desde la raíz del proyecto TopoReveal."
fi

mkdir -p "$INSTALL_DIR"/{ui,tools,core,assets/icons,data,exports,logs}
ok "Directorios creados"

# ── [ 2/8 ] Copiar archivos del proyecto ─────────────────────────────
hdr "[ 2/8 ] Copiando archivos del proyecto..."

# Archivos principales
cp "$SCRIPT_DIR/main.py" "$INSTALL_DIR/"

# Módulos UI
UI_FILES=(
    app.py canvas.py panel.py panel_alertas.py
    ventana_wifi.py ventana_stats.py ventana_trafico.py
    ventana_arsenal.py splash.py toast.py
)
for f in "${UI_FILES[@]}"; do
    [[ -f "$SCRIPT_DIR/ui/$f" ]] && cp "$SCRIPT_DIR/ui/$f" "$INSTALL_DIR/ui/" && ok "ui/$f" || warn "ui/$f — no encontrado"
done

# Módulos Tools
TOOLS_FILES=(
    scanner.py capture.py fingerprint.py arsenal.py
    interceptor.py geoip.py generar_pdf.py exportar.py
    historial.py beacon_detector.py anomalias.py
    dhcp_rogue.py ipv6_scanner.py ofensivo.py
    ntp_monitor.py ja3_fingerprint.py
)
for f in "${TOOLS_FILES[@]}"; do
    [[ -f "$SCRIPT_DIR/tools/$f" ]] && cp "$SCRIPT_DIR/tools/$f" "$INSTALL_DIR/tools/" && ok "tools/$f" || warn "tools/$f — no encontrado"
done

# Módulos Core
CORE_FILES=(topology.py nodes.py)
for f in "${CORE_FILES[@]}"; do
    [[ -f "$SCRIPT_DIR/core/$f" ]] && cp "$SCRIPT_DIR/core/$f" "$INSTALL_DIR/core/" && ok "core/$f" || warn "core/$f — no encontrado"
done

# Assets (iconos)
[[ -d "$SCRIPT_DIR/assets" ]] && cp -r "$SCRIPT_DIR/assets/"* "$INSTALL_DIR/assets/" && ok "Assets copiados"

# __init__.py para que Python reconozca los paquetes
for pkg in ui tools core; do
    touch "$INSTALL_DIR/$pkg/__init__.py"
done

# Datos GeoIP si existen
[[ -d "$SCRIPT_DIR/data" ]] && cp -r "$SCRIPT_DIR/data/"*.mmdb "$INSTALL_DIR/data/" 2>/dev/null && ok "Datos GeoIP copiados" || true

ok "Archivos del proyecto copiados"

# ── [ 3/8 ] Instalar dependencias del sistema ────────────────────────
hdr "[ 3/8 ] Instalando dependencias del sistema..."

if [[ "$DISTRO" == "debian" ]]; then
    apt-get update -qq
    PKGS=(
        python3 python3-pip python3-tk python3-dev
        nmap aircrack-ng airmon-ng net-tools
        ntpdate iproute2 wget curl git
        libpcap-dev tcpdump wireshark-common
        smbclient nfs-common showmount
        macchanger whatweb imagemagick
        ghostscript ldap-utils
    )
    for pkg in "${PKGS[@]}"; do
        if dpkg -l "$pkg" &>/dev/null 2>&1; then
            ok "$pkg (ya instalado)"
        else
            info "Instalando $pkg..."
            apt-get install -y -qq "$pkg" &>/dev/null && ok "$pkg" || warn "$pkg — no disponible, continuando"
        fi
    done

elif [[ "$DISTRO" == "fedora" ]]; then
    PKGS=(python3 python3-pip python3-tkinter nmap aircrack-ng
          net-tools ntpdate iproute wget curl git libpcap tcpdump
          wireshark samba-client nfs-utils macchanger openldap-clients)
    for pkg in "${PKGS[@]}"; do
        dnf install -y -q "$pkg" &>/dev/null && ok "$pkg" || warn "$pkg — falló"
    done

elif [[ "$DISTRO" == "arch" ]]; then
    PKGS=(python python-pip tk nmap aircrack-ng net-tools
          ntp iproute2 wget curl git libpcap tcpdump
          wireshark-qt smbclient nfs-utils macchanger openldap)
    for pkg in "${PKGS[@]}"; do
        pacman -S --noconfirm --needed -q "$pkg" &>/dev/null && ok "$pkg" || warn "$pkg — falló"
    done
fi

# ── [ 4/8 ] Instalar dependencias Python ─────────────────────────────
hdr "[ 4/8 ] Instalando dependencias Python..."

PIP_PKGS=(
    "scapy>=2.5.0"
    "reportlab>=4.0"
    "geoip2>=4.7"
    "maxminddb>=2.4"
    "requests>=2.31"
    "matplotlib>=3.7"
)

for pkg in "${PIP_PKGS[@]}"; do
    nombre=$(echo "$pkg" | cut -d'>' -f1 | cut -d'=' -f1)
    info "Instalando $nombre..."
    pip3 install -q "$pkg" --break-system-packages 2>/dev/null && ok "$nombre" || \
    pip3 install -q "$pkg" 2>/dev/null && ok "$nombre" || \
    warn "$nombre — falló (puede que ya esté instalado)"
done

# ── [ 5/8 ] Configurar base de datos GeoIP ───────────────────────────
hdr "[ 5/8 ] Configurando base de datos GeoIP (MaxMind)..."

GEOIP_DIR="$INSTALL_DIR/data"

if [[ -f "$GEOIP_DIR/GeoLite2-City.mmdb" ]]; then
    ok "GeoLite2-City.mmdb ya presente"
else
    warn "GeoIP no encontrado — funcionalidad GeoIP limitada"
    info "Para habilitar GeoIP completo:"
    echo ""
    echo "  1. Regístrate gratis en: https://www.maxmind.com/en/geolite2/signup"
    echo "  2. Descarga GeoLite2-City.mmdb y GeoLite2-ASN.mmdb"
    echo "  3. Colócalos en: $GEOIP_DIR/"
    echo ""
fi

# ── [ 6/8 ] Configurar permisos ──────────────────────────────────────
hdr "[ 6/8 ] Configurando permisos..."

# Dar permisos al usuario real sobre el directorio
chown -R "$USUARIO_REAL:$USUARIO_REAL" "$INSTALL_DIR" 2>/dev/null || true
chmod -R 755 "$INSTALL_DIR"
chmod 644 "$INSTALL_DIR"/**/*.py 2>/dev/null || true

# Permisos especiales para captura de red (sin sudo)
# Permitir que python3 capture paquetes sin root
if command -v setcap &>/dev/null; then
    PYTHON_BIN=$(which python3)
    setcap cap_net_raw,cap_net_admin=eip "$PYTHON_BIN" 2>/dev/null && \
        ok "Permisos de captura configurados (python3)" || \
        warn "No se pudieron configurar permisos de captura — usa sudo al ejecutar"
fi

ok "Permisos configurados"

# ── [ 7/8 ] Crear lanzador ───────────────────────────────────────────
hdr "[ 7/8 ] Creando lanzador..."

LAUNCHER="/usr/local/bin/toporeveal"
cat > "$LAUNCHER" << LAUNCHER_EOF
#!/usr/bin/env bash
# Lanzador de TopoReveal
# Requiere sudo para captura de red y ARP spoofing

if [[ \$EUID -ne 0 ]]; then
    echo "TopoReveal requiere sudo para captura de red."
    exec sudo python3 "$INSTALL_DIR/main.py" "\$@"
else
    cd "$INSTALL_DIR"
    exec python3 "$INSTALL_DIR/main.py" "\$@"
fi
LAUNCHER_EOF

chmod +x "$LAUNCHER"
ok "Lanzador creado: $LAUNCHER"
info "Ahora puedes ejecutar: toporeveal"

# Acceso directo en el escritorio (si hay entorno gráfico)
DESKTOP_DIR="$HOME_REAL/Desktop"
[[ -d "$HOME_REAL/.local/share/applications" ]] && DESKTOP_DIR="$HOME_REAL/.local/share/applications"
if [[ -d "$DESKTOP_DIR" ]]; then
    cat > "$DESKTOP_DIR/toporeveal.desktop" << DESK_EOF
[Desktop Entry]
Version=2.0
Type=Application
Name=TopoReveal
GenericName=Network Intelligence Platform
Comment=Auditoría y análisis de seguridad de redes
Exec=sudo toporeveal
Icon=$INSTALL_DIR/assets/icon.png
Terminal=true
Categories=Network;Security;
Keywords=network;security;audit;pentest;
DESK_EOF
    chown "$USUARIO_REAL:$USUARIO_REAL" "$DESKTOP_DIR/toporeveal.desktop" 2>/dev/null || true
    ok "Acceso directo creado"
fi

# ── [ 8/8 ] Verificación final ───────────────────────────────────────
hdr "[ 8/8 ] Verificación final..."

ERRORES=0

python3 -c "import tkinter" 2>/dev/null    && ok "tkinter" || { warn "tkinter no disponible"; ((ERRORES++)); }
python3 -c "import scapy" 2>/dev/null      && ok "scapy" || { warn "scapy no disponible"; ((ERRORES++)); }
python3 -c "import reportlab" 2>/dev/null  && ok "reportlab (PDF)" || { warn "reportlab no disponible — PDF desactivado"; }
python3 -c "import geoip2" 2>/dev/null     && ok "geoip2" || { warn "geoip2 no disponible — GeoIP desactivado"; }
python3 -c "import matplotlib" 2>/dev/null && ok "matplotlib (gráficos)" || warn "matplotlib no disponible — Dashboard desactivado"
command -v nmap &>/dev/null                && ok "nmap" || { warn "nmap no encontrado"; ((ERRORES++)); }
command -v airmon-ng &>/dev/null           && ok "airmon-ng (WiFi Scope)" || warn "airmon-ng no disponible — modo monitor desactivado"
command -v wireshark &>/dev/null           && ok "wireshark" || warn "wireshark no disponible — análisis .pcap limitado"
[[ -f "$GEOIP_DIR/GeoLite2-City.mmdb" ]]  && ok "GeoLite2-City.mmdb" || warn "GeoIP sin datos"

# ── Resumen final ──────────────────────────────────────────────────────
echo ""
echo -e "${C_CYAN}══════════════════════════════════════════════════════════════${C_RESET}"

if [[ $ERRORES -eq 0 ]]; then
    echo -e "\n  ${C_GREEN}${C_BOLD}✓ TopoReveal v2.0 instalado correctamente${C_RESET}\n"
else
    echo -e "\n  ${C_YELLOW}${C_BOLD}⚠ Instalado con $ERRORES advertencia(s)${C_RESET}\n"
fi

echo -e "  ${C_BOLD}Instalado en:${C_RESET} $INSTALL_DIR"
echo -e "  ${C_BOLD}Para ejecutar:${C_RESET}"
echo ""
echo -e "    ${C_CYAN}toporeveal${C_RESET}          # desde cualquier terminal"
echo -e "    ${C_CYAN}sudo python3 $INSTALL_DIR/main.py${C_RESET}  # forma directa"
echo ""
echo -e "  ${C_YELLOW}⚠  Recuerda: solo usar en redes propias o con autorización escrita.${C_RESET}"
echo -e "${C_CYAN}══════════════════════════════════════════════════════════════${C_RESET}\n"
