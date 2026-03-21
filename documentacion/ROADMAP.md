# TopoReveal — Roadmap y Lista de Pendientes
_Última actualización: 2026-03-10_

---

## ✅ COMPLETADO

- Captura continua con scapy (modo promiscuo)
- Detección de gateway y subred
- Estados: confirmado / sospechoso / fantasma / lobby
- Timers: 3min → sospechoso, 5min → fantasma, 6min → lobby
- Lobby colapsable en panel
- Canvas adaptativo multi-fila para redes grandes (+90 nodos)
- Radio de nodos escalable según cantidad
- Log exportado al salir con resumen completo por host
- Detección ARP scan masivo con alerta [ALERTA]
- Router y IP local excluidos de alerta ARP scan
- Color naranja + icono ⚠ para nodo arp-scanner
- Etiquetas de protocolo sin superposición en líneas
- Contadores en panel: total / conf / sosp / ghost
- Conexiones externas por host en log y panel
- Filtro de subredes ajenas (192.168.88.x no dispara alertas)
- Detección evento TCP masivo → [EVENTO] en log
- Nodo local resaltado en canvas con doble anillo cian
- "Tu IP: x.x.x.x" visible en panel siempre
- Fingerprinting mejorado: MACs aleatorias detectadas como "Privada/Aleatoria"
- OUIs reales añadidos: Intel, Lenovo, Realtek (presentes en red universitaria)

---

## 🔴 BUGS CONOCIDOS ACTIVOS

- **0.0.0.0 como ARP scanner**: dispositivos en proceso DHCP sin IP aún disparan alerta. Filtrar IPs inválidas en el detector de ARP scan.
- **Switch falso por modo promiscuo**: el umbral de 10 conexiones aún puede dar falsos positivos en redes muy activas. Necesita señal adicional (puertos, fabricante) para confirmar que es switch real.
- **10.11.10.122 clasificado como "externo"**: es un servidor interno de otra subred de la misma universidad, no es internet. Necesitamos poder marcar rangos como "red local extendida".

---

## 🟡 EN PROGRESO / SIGUIENTE ITERACIÓN

### Fingerprinting
- [ ] Usar hostname via mDNS/NBNS para identificar dispositivos (nombres reales como "MacBook-de-Juan")
- [ ] Detectar tipo por patrones de tráfico: solo UDP multicast → IoT, mucho TCP externo → laptop activa
- [ ] Base de datos OUI más completa (actualmente ~30 fabricantes, necesitamos 200+)
- [ ] Mostrar fabricante real en panel cuando se identifica (Dell, Lenovo, etc.)

### Canvas / Visual
- [ ] Scroll en canvas para redes muy grandes (+100 nodos)
- [ ] Zoom in/out con rueda del ratón
- [ ] Agrupar nodos por subred cuando hay múltiples subredes (/22 universitaria)
- [ ] Click en nodo → abrir menú contextual con acciones (ping, nmap, info detallada)
- [ ] Animación visual cuando un nodo entra/sale del lobby
- [ ] Línea de conexión animada cuando hay tráfico activo entre dos nodos

### Panel
- [ ] Mostrar fabricante real en la lista de dispositivos (no solo "desconocido")
- [ ] Barra de búsqueda/filtro por IP, tipo o OS en la lista de dispositivos
- [ ] Ordenar lista por: actividad reciente / paquetes / IP
- [ ] Click en nodo del lobby → mostrar su historial (cuándo estuvo activo)

### Log
- [ ] Distinguir [EVENTO] de autenticación masiva (tipo 10.11.10.122 en tu red)
- [ ] Contador de eventos por tipo al final del resumen
- [ ] Mostrar hora de primera y última vez vista para cada host

---

## 🔵 FASE FUTURA — Arsenal de Herramientas

_Estas son las ideas más grandes. Se implementan después de que la base esté sólida._

### Por nodo (click derecho → menú)
- [ ] Ping con estadísticas (latencia promedio, pérdida de paquetes)
- [ ] Nmap básico: puertos abiertos del nodo seleccionado
- [ ] Nmap agresivo: OS detection + versiones de servicios
- [ ] Traceroute visual hacia ese nodo
- [ ] Historial de tráfico del nodo (línea de tiempo)

### Estadísticas globales
- [ ] Gráfico de actividad en tiempo real (paquetes/segundo)
- [ ] Top 5 hosts más activos
- [ ] Top 5 destinos externos más contactados
- [ ] Mapa de calor de conexiones (quién habla con quién)

### Detección de anomalías (inteligencia)
- [ ] Detectar host que cambia de MAC frecuentemente (MAC spoofing)
- [ ] Detectar nuevo dispositivo que aparece fuera de horario
- [ ] Detectar conexión a puerto inusual (ej: TCP 4444, 31337)
- [ ] Alertar si un host empieza a escanear puertos (port scan, no solo ARP)
- [ ] Detectar duplicados de IP (ARP spoofing / conflicto)

### Red extendida
- [ ] Soporte para múltiples subredes simultáneas (/22, /24, etc.)
- [ ] Identificar VLANs por comportamiento de tráfico
- [ ] Marcar rangos como "interna extendida" (como 10.11.x.x completo)

---

## 💡 IDEAS QUE SE PERDIERON EN LA CONVERSACIÓN Y SON VALIOSAS

_Estas surgieron en algún momento y no se implementaron:_

- **Identificar tu propio celular automáticamente**: si el programa detecta que una IP hace tráfico desde la misma MAC que el hotspot al que estás conectado, puede autoidentificarlo.
- **Plan de prueba estructurado por minutos**: cada sesión de test debería tener un protocolo (min 0-2 observar, min 2-5 navegar celular, min 5-7 apagar wifi, min 7-10 reconectar). Esto ayuda a validar cada feature.
- **Sesión de grabación**: grabar la pantalla durante una prueba completa para documentar comportamiento visual.
- **Comparar sesiones**: cargar dos archivos de log y ver qué cambió entre una sesión y otra (nuevos hosts, hosts desaparecidos, cambios de comportamiento).
- **Modo pasivo puro**: opción de correr sin hacer ARP scan inicial (solo escuchar). Útil para no levantar sospechas en redes auditadas.
- **Exportar topología como imagen**: guardar el canvas como PNG al salir, junto con el log.
- **Notificación de alerta**: cuando se detecta un ARP scanner, hacer un sonido o parpadeo visual, no solo texto en log.
- **Nombre de sesión**: al generar el log, pedir un nombre o contexto ("red universidad", "casa") para identificar mejor los archivos.
- **Historial de IPs**: guardar un archivo permanente con todas las MACs vistas alguna vez, para reconocer dispositivos conocidos en futuras sesiones.

---

## 📊 ESTADO ACTUAL DEL PROYECTO

```
Base funcional         ████████████████████  100% ✓
Captura continua       ████████████████████  100% ✓
Lobby / standby        ████████████████████  100% ✓
Canvas adaptativo      ████████████████████  100% ✓
Log exportado          ████████████████████  100% ✓
ARP scan detection     ████████████████████  100% ✓
Nodo local resaltado   ████████████████████  100% ✓
Fingerprinting OS      ██████████████░░░░░░   70% (MACs aleatorias = limitado)
Conexiones externas    ████████████████░░░░   80% ✓ verificado en universidad
Detección TCP masivo   ████████████████░░░░   80% (pendiente verificar en log)
Scroll / Zoom canvas   ░░░░░░░░░░░░░░░░░░░░    0% fase siguiente
Arsenal nmap           ░░░░░░░░░░░░░░░░░░░░    0% fase futura
Estadísticas           ░░░░░░░░░░░░░░░░░░░░    0% fase futura
Detección anomalías    ░░░░░░░░░░░░░░░░░░░░    0% fase futura

TOTAL ESTIMADO: ~75% del programa base
```

---

_Este archivo se actualiza en cada sesión de desarrollo._
