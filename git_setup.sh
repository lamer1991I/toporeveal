#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  TopoReveal — Setup de Git y GitHub
#  Ejecutar UNA SOLA VEZ antes de subir a GitHub
#  Uso: bash git_setup.sh
# ═══════════════════════════════════════════════════════════════════

C_CYAN='\033[0;36m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_RESET='\033[0m'

ok()   { echo -e "  ${C_GREEN}✓${C_RESET}  $1"; }
info() { echo -e "  ${C_CYAN}→${C_RESET}  $1"; }
warn() { echo -e "  ${C_YELLOW}⚠${C_RESET}  $1"; }

echo -e "\n${C_CYAN}  TopoReveal — Configuración de Git${C_RESET}\n"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# ── Configurar identidad Git (solo Albert aparece) ──────────────────
info "Configurando identidad Git..."

# Pide los datos al usuario
read -p "  Tu nombre completo para Git [Albert]: " GIT_NAME
GIT_NAME="${GIT_NAME:-Albert}"

read -p "  Tu email para Git (el de GitHub): " GIT_EMAIL
if [[ -z "$GIT_EMAIL" ]]; then
    warn "Email requerido para Git"
    exit 1
fi

# Configurar SOLO para este repositorio (no global)
git config user.name "$GIT_NAME"
git config user.email "$GIT_EMAIL"
ok "Identidad configurada: $GIT_NAME <$GIT_EMAIL>"

# ── Inicializar repositorio si no existe ────────────────────────────
if [[ ! -d ".git" ]]; then
    info "Inicializando repositorio Git..."
    git init
    git branch -m main
    ok "Repositorio inicializado (rama: main)"
else
    ok "Repositorio Git ya existe"
fi

# ── Copiar .gitignore ───────────────────────────────────────────────
if [[ -f "gitignore_toporeveal.txt" ]]; then
    cp gitignore_toporeveal.txt .gitignore
    ok ".gitignore configurado"
elif [[ ! -f ".gitignore" ]]; then
    cat > .gitignore << 'EOF'
__pycache__/
*.py[cod]
*.pyo
data/*.mmdb
exports/
logs/
*.pcap
*.pcapng
*.cap
toporeveal_history.db
*.db
.env
venv/
.vscode/
.idea/
*.swp
*~
.DS_Store
EOF
    ok ".gitignore creado"
fi

# ── Primer commit ──────────────────────────────────────────────────
info "Preparando primer commit..."

# Agregar todos los archivos excepto los ignorados
git add .

# Verificar que no se agregaron archivos sensibles
SENSIBLES=$(git diff --cached --name-only | grep -E '\.mmdb$|\.db$|\.pcap$' || true)
if [[ -n "$SENSIBLES" ]]; then
    warn "Archivos sensibles detectados — removiendo:"
    echo "$SENSIBLES" | while read f; do
        git rm --cached "$f" 2>/dev/null && warn "  Removido: $f"
    done
fi

# Commit inicial
git commit -m "TopoReveal v2.0 — Network Intelligence Platform

Herramienta de auditoría de seguridad de redes con:
- Descubrimiento activo/pasivo de hosts (ARP, nmap, scapy)
- Scanner de 3 fases con fingerprinting y hallazgos
- Beacon C2 detection + JA3/JA3S fingerprinting
- WiFi Scope con captura pasiva de handshakes WPA2
- Módulos ofensivos opt-in (LLMNR, WPAD, VLAN hopping)
- Exportación PDF/JSON/CSV con score de riesgo
- Panel de alertas con tarjetas expandibles
- GeoIP offline con MaxMind

Autor: $GIT_NAME <$GIT_EMAIL>
Licencia: GPL v3"

ok "Primer commit creado"

# ── Instrucciones para GitHub ────────────────────────────────────────
echo ""
echo -e "${C_CYAN}══════════════════════════════════════════════════════${C_RESET}"
echo -e "\n  ${C_GREEN}✓ Repositorio listo${C_RESET}\n"
echo -e "  Para subir a GitHub:\n"
echo -e "  ${C_CYAN}1.${C_RESET} Crea el repositorio en github.com/new"
echo -e "     Nombre: toporeveal"
echo -e "     Visibilidad: Public (o Private si prefieres)"
echo -e "     NO inicialices con README (ya tienes uno)\n"
echo -e "  ${C_CYAN}2.${C_RESET} Conecta y sube:"
echo ""
echo -e "     git remote add origin https://github.com/$GIT_NAME/toporeveal.git"
echo -e "     git push -u origin main"
echo ""
echo -e "  ${C_YELLOW}⚠${C_RESET}  Verifica en GitHub que solo aparece tu nombre"
echo -e "     en la sección Contributors antes de hacerlo público."
echo -e "${C_CYAN}══════════════════════════════════════════════════════${C_RESET}\n"
