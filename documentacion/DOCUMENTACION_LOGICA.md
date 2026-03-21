# 📚 DOCUMENTACIÓN LÓGICA — TopoReveal
## _Guía para no programadores_

---

## 🏛️ ARQUITECTURA GENERAL

**TopoReveal** es como una **cámara de vigilancia inteligente para redes**. Mientras tu red funciona, esta herramienta observa silenciosamente, identificando qué dispositivos hay, con quién hablan y qué puertos tienen abiertos (vulnerabilidades potenciales).

---

# 📁 CARPETA: `core/` — El cerebro del sistema

El `core/` contiene la **lógica central** que mantiene toda la información organizada.

## Archivo: `nodes.py` — "La Identidad de cada dispositivo"

**Analogía:** Es como si cada dispositivo en la red fuera una _ficha en una carpeta médica_. Almacena:
- **IP**: Tu dirección en la red (como tu número de casa)
- **MAC**: Tu identificador único de hardware (como tu DNI)
- **Tipo**: ¿Eres un router? ¿Una cámara? ¿Una laptop?
- **Estado**: ¿Estás activo, sospechoso o "fantasma" (inactivo)?
- **Puertos abiertos**: Puertas por las que alguien podría entrar
- **Risk score**: "Peligrosidad" del dispositivo (0-100)

### Estados del nodo:
- **CONFIRMADO** 🟢: Vimo el dispositivo 2+ veces recientemente. Es real.
- **SOSPECHOSO** 🟠: Lo vimos una sola vez o hace poco. Podría ser real.
- **FANTASMA** 🔴: Hace 2+ minutos que no responde. Probablemente se apagó.
- **LOBBY** 💤: Lleva 4+ minutos sin actividad. Se movió a "zona de espera".

### Puntuación de riesgo (Risk Score):
Cada puerto abierto suma points:
- Puerto 23 (Telnet) = +35 puntos (muy peligroso)
- Puerto 445 (SMB - Windows) = +25 puntos
- Puerto 3389 (Escritorio remoto) = +22 puntos
- etc.

Si suma +60 → Rojo peligroso 🔴  
Si suma +30 → Naranja medio 🟠  
Si suma -30 → Seguro 🟢

---

## Archivo: `topology.py` — "El mapa de la red"

**Analogía:** Es como el _sistema de control de un edificio inteligente_. Mantiene:
- **Lista de todos los nodos** (dispositivos)
- **Conexiones entre ellos** (quién habla con quién)
- **Relaciones jerárquicas** (router → switch → hosts)
- **Alertas globales** (problemas detectados en la red)

### Métodos clave:

#### `agregar_o_actualizar(ip, mac, puertos)`
"Registra o actualiza la info de un dispositivo"
- Si vemos una IP nueva: la creamos
- Si ya existe: actualizamos su actividad
- Validamos que sea IP válida (no broadcast, no loopback)

#### `deducir_jerarquia()`
"Detecta automáticamente el orden del árbol de red"
- El router es quien responde al gateway
- Los switches son dispositivos con 10+ conexiones
- El resto son "hosts" normales

#### `registrar_hallazgos(ip, puertos)`
"Analiza puertos y genera alertas"
- Si veamos puerto 23 (Telnet): "ALERTA CRÍTICA — Telnet detectado"
- Si ves puerto 445 + 3389 juntos: "ALERTA CRÍTICA — Combinación peligrosa"

#### `limpiar_inactivos()`
"Rutina de mantenimiento cada 30s"
- Marca como FANTASMA si llevan 2 min sin responder
- Mueve a LOBBY si llevan 4 min
- Actualiza el "timeline" de cada dispositivo

---

# 🛠️ CARPETA: `tools/` — Las herramientas especializadas

## Archivo: `scanner.py` — "El explorador de la red"

**Analogía:** Es como un _detective que toca puertas y avisa si alguien responde_.

### ¿Qué hace?

Corre **3 hilos simultáneamente**:

#### 1. **Loop ARP** (cada 5 minutos)
- Grita en la red: "¿Quién eres? Soy 192.168.1.7"
- Todos los dispositivos responden con su MAC
- Descubre IPs nuevas

#### 2. **Worker nmap por nodo** (inmediato)
- Cuando se descubre una IP nueva: lanza `nmap` a esa IP
- Responde: ¿Qué puertos tiene abiertos?
- Intenta identificar qué servicio usa (SSH, HTTP, etc.)

#### 3. **Loop profundo** (cada 5 minutos)
- Re-escanea TODOS los nodos conocidos
- Detecta nuevos puertos, servicios updates
- Mantiene la información fresca

### Ejemplo:
```
[SCANNER] ARP sweep detecta 192.168.1.50
[SCANNER] Lanzando nmap a 192.168.1.50...
[SCANNER] Resultado: puertos 80,443 abiertos (HTTP,HTTPS)
[NODO] 192.168.1.50 tipo=servidor riesgo=bajo
```

---

## Archivo: `capture.py` — "Promiscuo — el chismoso pasivo"

**Analogía:** Un _abogado que escucha conversaciones de fondo sin participar_, para después anotar patrones.

### ¿Qué hace?

- Activa modo **promiscuo** en la tarjeta de red
- **Captura TODOS los paquetes** de la red (tráfico local + broadcast + extraño)
- Nota:
  - Quién habla con quién
  - Qué protocolo usa (ARP, TCP, UDP, ICMP)
  - Cuántos bytes se mueven
  - **NO modifica nada**, solo observa

### Watchdog automático:
- Si el hilo de captura muere → lo reinicia automáticamente
- Máximo 10 reintentospor sesión
- Garantiza 99% de uptime

---

## Archivo: `fingerprint.py` — "El identificador de dispositivos"

**Analogía:** Un _experto en criminología que dice "eso huele a iPhone"_ por detalles pequeños.

### ¿Qué identifica?

#### 1. **Fabricante (por MAC)**
- MAC = primeros 48 bits de la dirección física
- Base de datos OUI (Organizationally Unique Identifier)
- Ejemplo: `C0:25:E9:xx:xx:xx` = TP-Link

#### 2. **Sistema Operativo (por TTL)**
- **TTL 64** → Linux, Android, Mac
- **TTL 128** → Windows
- **TTL 255** → Routers/switches

#### 3. **Tipo de dispositivo (por puertos)**
- Puerto 554 (RTSP) → Probablemente cámara
- Puerto 9100 → Probablemente impresora
- Puerto 3306 (MySQL) → Probablemente servidor

---

## Archivo: `arsenal.py` — "Escaneos avanzados bajo demanda"

**Analogía:** Un _cirujano que tienes en tu bolsillo_ — llamas y hace análisis hiper-detallados.

### ¿Qué escaneos ofrece?

| Nombre | Tiempo | Qué detecta |
|--------|--------|----------|
| 🟢 Ping Check | 2s | ¿Sigue vivo? |
| ⚡ Quick Ports | 8s | Top 20 puertos más comunes |
| 🔍 Standard Scan | 30s | 1000 puertos estándar |
| 🏷 Service Versions | 45s | Versión exacta del software |
| 💻 OS Detection | 30s | Windows/Linux/Mac con precisión |
| 📜 Safe Scripts | 60s | Detalles de seguridad sin atacar |
| 🔴 Vuln Scan | 2 min | Detecta vulnerabilidades conocidas |

**Nota:** Cada escaneo corre en un **hilo separado** para no congelar la interfaz.

---

## Archivo: `exportar.py` — "Guardar para el futuro"

**Analogía:** Un _escriba que toma notas_ en diferentes formatos.

Exporta la topología a:
- **PNG**: Captura de pantalla del canvas
- **JSON**: Datos estructurados (importable a otros programas)
- **CSV**: Tabla para Excel/Calc

---

# 🖼️  CARPETA: `ui/` — La interfaz visual

## Archivo: `app.py` — "El director de orquesta"

Coordina TODO:
- Inicia scanner, captura, arsenal
- Crea las ventanas
- Ciclo de actualización cada 2 segundos
- Maneja eventos del usuario

## Archivo: `canvas.py` — "El lienzo de dibujo"

Dibuja **la topología en tiempo real**:
- **Nodos** = círculos (routers = hexágonos, scanners = triángulos)
- **Líneas** = conexiones entre dispositivos
- **Badges** = alertas de seguridad (🔴🟠🟡)
- **Clics** = seleccionar nodo para ver detalles

## Archivo: `panel.py` — "Panel derecho con detalles"

Muestra:
- Resumen: Total, confirmados, sospechosos, fantasmas
- **Detalle del nodo seleccionado**
- Puerto abiertos
- Conexiones externas
- Búsqueda + filtrado
- Lobby (nodos inactivos)

## Archivo: `panel_alertas.py` — "Panel izquierdo de seguridad"

Muestra:
- Alertas críticas de la red
- Estadísticas de tipos de dispositivo
- Risk score promedio
- Tarjetas agrupadas por IP

---

# 🔄 FLUJO COMPLETO: De nada a la pantalla

```
1. USUARIO PRESIONA "ESCANEAR"
   ↓
2. scanner.py LANZA 3 HILOS:
   • ARP sweep cada 5 min
   • nmap por nodo descubierto
   • re-escaneo profundo cada 5 min
   ↓
3. capture.py ESCUCHA pasivamente
   ↓
4. Los datos llegan a topology.py:
   • Se crea o actualiza Nodo
   • Se evalúan puertos → se generan alertas
   • Se detecta jerarquía (router/switch/host)
   ↓
5. canvas.py DIBUJA en pantalla
6. panel.py ACTUALIZA números
7. panel_alertas.py MUESTRA alertas críticas
   ↓
CADA 2 SEGUNDOS: ciclo_actualizacion() refresca TODO

```

---

# ⚠️ TABLA DE ERRORES COMUNES

| Error | Significa | Solución |
|-------|-----------|----------|
| Sin gateway | No encontró el router | Verifica que estés conectado a la red |
| ARP scan masivo | Alguien está probando IPs | Podría ser un scanner malicioso |
| Puerto 445 detectado | SMB (Windows compartido) | Desactiva si no lo necesitas |
| TTL muy bajo | Muchos saltos de red | No es host local, es externo |
| Risk score 100 | Felony en puerto | ⛔ Aísla ese dispositivo |

---

# 🎯 RESUMEN VISUAL

```
SCANNER         CAPTURE         FINGERPRINT
   ↓                ↓                ↓
  ARP sweep  →  Escucha pasiva  →  Identifica
  nmap by IP →  Nota tráfico    →  OS/Fabricante
  Re-escaneo →  Conecta hosts   →  Tipo dispositivo
               ↓
           TOPOLOGY
           (almacén central)
           ↓
       ALERTAS + JERARQUÍA
           ↓
    ┌──────┴───────────┐
    ↓                  ↓
  CANVAS           PANEL + ALERTS
  Dibujo real   Números y detalles
```

---

**Creado:** 2026-03-11  
**Proyecto:** TopoReveal v1.0  
**Propósito:** Comprensión general de la lógica del sistema
