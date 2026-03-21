# TopoReveal v2.0

**Network Intelligence Platform — Auditoría activa/pasiva de seguridad de redes**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-cyan.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-red.svg)](https://www.kali.org/)

---

## ¿Qué es TopoReveal?

TopoReveal es una herramienta de auditoría de seguridad de redes con interfaz gráfica que cubre desde descubrimiento básico de hosts hasta detección avanzada de amenazas como beacons C2, rogue APs y anomalías vs baseline histórico.

**Solo para uso en redes propias o con autorización escrita del propietario.**

---

## Capacidades

### Nivel 1 — Descubrimiento básico
- ARP sweep + ping sweep automático al iniciar
- Escaneo de puertos TCP/UDP completo con nmap
- OS fingerprinting + extracción de banners y versiones
- Identificación de gateway y jerarquía de red
- Captura pasiva de tráfico con scapy en modo promiscuo

### Nivel 2 — Análisis estándar
- Captura de protocolos en claro (HTTP, FTP, Telnet, SMTP)
- Enumeración SMB/NetBIOS y network shares
- Prueba de credenciales por defecto en paneles web
- Enumeración DNS interna + detección SNMP
- Detección de servidores de bases de datos

### Nivel 3 — Persistencia y vectores
- Detección de Domain Controllers y Active Directory
- Enumeración LDAP anónima + Kerberos SPN
- Análisis SSL/TLS (certificados caducados, autofirmados, SANs)
- NFS showmount + exportaciones accesibles
- Detección de VPNs/túneles (IPSec, IKE, OpenVPN)

### Nivel 4 — Técnicas avanzadas
- Escaneo IPv6 completo (NDP, ping6 multicast, rango global)
- LLMNR/NBT-NS poisoning (opt-in con confirmación)
- WPAD spoofing (opt-in con confirmación)
- VLAN hopping detection con frames 802.1Q dobles
- CDP/LLDP passive discovery (switches Cisco/HP)
- Detección de Rogue DHCP + Shadow IT

### Nivel 5 — Elite
- Beacon C2 detection — intervalos regulares de tráfico externo
- JA3/JA3S TLS fingerprinting — identifica apps por handshake TLS
- IPMI/iDRAC/iLO detection + Cipher Suite 0 vulnerability
- NTP drift measurement — desincronización de tiempo

### WiFi Scope
- Mapa visual de APs cercanos con señal, canal y cifrado
- Captura pasiva de handshakes WPA2 (sin deauth)
- Detección de rogue APs, WEP, WPS activo, redes ocultas
- Detección de deauth attacks en curso
- Canal heatmap 2.4GHz / 5GHz

---

## Instalación

```bash
git clone https://github.com/ha-king/toporeveal.git
cd toporeveal
sudo bash install.sh
```

El instalador:
1. Detecta tu distribución (Debian/Ubuntu/Kali, Fedora, Arch)
2. Instala dependencias del sistema (nmap, aircrack-ng, smbclient, etc.)
3. Instala dependencias Python (scapy, reportlab, geoip2, matplotlib)
4. Configura permisos de captura de red
5. Crea el lanzador `/usr/local/bin/toporeveal`

### GeoIP (opcional pero recomendado)

```bash
# 1. Registro gratuito en https://www.maxmind.com/en/geolite2/signup
# 2. Descargar GeoLite2-City.mmdb y GeoLite2-ASN.mmdb
# 3. Copiar a:
cp GeoLite2-*.mmdb ~/Proyectos/toporeveal/data/
```

### Dependencias mínimas

```bash
sudo apt install python3 python3-tk nmap scapy
pip3 install scapy reportlab geoip2 matplotlib --break-system-packages
```

---

## Uso

```bash
# Lanzar normalmente
toporeveal

# O directamente
sudo python3 ~/Proyectos/toporeveal/main.py
```

Al iniciar, TopoReveal detecta automáticamente la interfaz de red, el gateway y los hosts activos. El escaneo de 3 fases arranca en segundo plano sin intervención.

---

## Exportaciones

Desde el menú **⇪ Export**:
- **PNG** — captura de la topología visual
- **JSON** — estructura completa compatible con SIEMs y BloodHound
- **CSV** — tres archivos: hosts, hallazgos, conexiones externas
- **PDF** — informe profesional con score de riesgo y cobertura por niveles

---

## Requisitos

| Componente | Versión mínima |
|---|---|
| Python | 3.10+ |
| Sistema | Kali Linux, Ubuntu 22.04+, Debian 12+ |
| nmap | 7.80+ |
| scapy | 2.5.0+ |
| RAM | 512 MB |
| Tarjeta WiFi | Opcional (modo monitor para WiFi Scope) |

---

## Aviso legal

TopoReveal es una herramienta de auditoría de seguridad diseñada para administradores de red y profesionales de ciberseguridad.

**El uso de esta herramienta en redes sin autorización explícita del propietario es ilegal** en la mayoría de jurisdicciones. El autor no se hace responsable del uso indebido.

---

## Licencia

GPL v3 — ver [LICENSE](LICENSE)

Copyright © 2026 Albert (ha-king)
# toporeveal
# toporeveal

## Screenshots

![Topología de red](screenshots/captura1.png)
![Panel de alertas](screenshots/captura2.png)
![WiFi Scope](screenshots/captura3.png)
