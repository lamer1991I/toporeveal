# 📖 ANÁLISIS COMENTADO DE CÓDIGO CRÍTICO
## Método: `actualizar_estado()` — El motor de decisión del nodo

---

## Localización
**Archivo:** `core/nodes.py`  
**Clase:** `Nodo`  
**Método:** `actualizar_estado()`  
**Líneas:** ~49-85

---

## ¿POR QUÉ ESTE CÓDIGO?

Este método es el **corazón del sistema**. Decide si un dispositivo es real, sospechoso o fake:
- Si devuelve `CONFIRMADO` → aparece en canvas normal 🟢
- Si devuelve `SOSPECHOSO` → aparece con color naranja 🟠
- Si devuelve `FANTASMA` → desaparece después de 4 min 💤

---

## CÓDIGO CON COMENTARIOS LINEALES

```python
def actualizar_estado(self):
    """
    Actualiza estado y retorna (anterior, nuevo) si hubo cambio, sino None.
    
    Este método corre cada 30 segundos en el loop principal (topology.limpiar_inactivos).
    Implementa la "máquina de estados" del nodo basado en tiempo de inactividad.
    
    Variables de referencia:
    - T_CONFIRMADO = 30 segundos (mínimo para estar activo)
    - T_SOSPECHOSO = 60 segundos (sin actividad = sospechoso)
    - T_FANTASMA = 2 minutos (probablemente se apagó)
    - T_LOBBY = 4 minutos (desaparece de pantalla)
    """
    
    # ============================================
    # PASO 1: GUARDAR EL ESTADO ANTERIOR
    # ============================================
    # Guardamos el estado anterior para detectar SI HUBO CAMBIO
    # Si el estado no cambió, retornamos None y no loggeamos nada
    anterior = self.estado
    en_lobby_anterior = self.en_lobby
    
    # ============================================
    # PASO 2: PROTECCIÓN PARA IP LOCAL
    # ============================================
    # Los nodos protegidos (típicamente TÚ, el equipo que ejecuta TopoReveal)
    # nunca se marcaran como inactivos, porque el equipo no llama a sí mismo
    # Esto evita falsos positivos
    if self.protegido:
        self.estado   = "confirmado"  # Siempre está "online"
        self.en_lobby = False         # Nunca entra en zona de espera
        return None                   # No hay cambio que reportar
    
    # ============================================
    # PASO 3: CALCULAR INACTIVIDAD
    # ============================================
    # segundos_sin_actividad() calcula: time.time() - self.ultimo_visto
    # Es decir: "¿Cuántos segundos hace que el último paquete?"
    # 
    # Ejemplo:
    # - Si ultimo_visto = 06:30:00 y ahora = 06:30:10 → 10 segundos sin ver
    # - Si ultimo_visto = 06:30:00 y ahora = 06:35:00 → 300 segundos sin ver
    segundos = self.segundos_sin_actividad()
    
    # ============================================
    # PASO 4: MÁQUINA DE ESTADOS — Orden es CRÍTICO
    # ============================================
    # Evaluamos en orden de severidad (más restrictivo primero)
    
    # REGLA 1: Si lleva 4 minutos sin responder → FANTASMA + LOBBY
    # El nodo está en "zona gris" — probablemente se apagó
    # Lo movemos a LOBBY para que no aparezca en canvas (evita clutter)
    if segundos >= T_LOBBY:  # T_LOBBY = 240 segundos (4 minutos)
        self.estado   = FANTASMA      # Estado semántico
        self.en_lobby = True          # Flag: "no lo dibujes en pantalla"
    
    # REGLA 2: Si lleva 2 minutos sin responder → FANTASMA (pero visible)
    # Es grave pero no tan seguro, todavía cabe en pantalla
    elif segundos >= T_FANTASMA:     # T_FANTASMA = 120 segundos (2 minutos)
        self.estado   = FANTASMA
        self.en_lobby = False         # Todavía visible en canvas
    
    # REGLA 3: Si lleva 1 minuto sin responder → SOSPECHOSO
    # Puede que se desconecte pronto, pero aún hay chances de que vuelva
    elif segundos >= T_SOSPECHOSO:   # T_SOSPECHOSO = 60 segundos
        self.estado   = SOSPECHOSO
        self.en_lobby = False
    
    # REGLA 4: Actividad reciente — posible confirmación
    else:
        # Si lo hemos visto 2+ veces en poco tiempo → es REAL
        # Primera vez podría ser un port scan falso o broadcast
        # Segunda vez confirma que responde activamente
        if self.veces_visto >= 2:     # veces_visto se incrementa en actualizar_actividad()
            self.estado = CONFIRMADO  # ✅ Estamos seguros
        else:
            self.estado = SOSPECHOSO   # ❓ Podría ser fake
        
        self.en_lobby = False  # Está activo, visible en pantalla
    
    # ============================================
    # PASO 5: DETECTAR CAMBIOS Y PREPARAR REPORTE
    # ============================================
    # Si algún estado cambió, preparamos un reporte para logging
    # Esto evita spam de logs (solo log cuando hay cambio)
    
    cambio_estado = (self.estado != anterior)  # ej: anterior=SOSPECHOSO, nuevo=CONFIRMADO
    entro_lobby   = (self.en_lobby and not en_lobby_anterior)  # Pasaje a zona gris
    salio_lobby   = (not self.en_lobby and en_lobby_anterior)  # Resurrección
    
    # Si hubo algún cambio relevante, lo reportamos como tupla
    # Si no hay cambio, retornamos None (silencio)
    if cambio_estado or entro_lobby or salio_lobby:
        # Tupla de 4 elementos para máxima info
        return (anterior, self.estado, self.en_lobby, en_lobby_anterior)
    
    return None  # Sin cambios, sin ruido
```

---

## DIAGRAMA DE FLUJO

```
                    ╔═══════════════════════╗
                    ║ actualizar_estado()   ║
                    ╚═════════════╤═════════╝
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
            ┌──────────────────┐  ┌──────────────────────────┐
            │ ¿Está protegido? │  │ NO → Calcular segundos   │
            │ (IP local)       │  │      sin actividad       │
            └────────┬─────────┘  └──────────┬───────────────┘
                     │                       │
                   SÍ│                       │NO
                     ▼                       │
            ┌──────────────────┐             │
            │ CONFIRMADO       │             │
            │ en_lobby=False   │             │
            │ return None      │             │
            └──────────────────┘             │
                                            ▼
                        ┌───────────────────────────────────┐
                        │ ¿segundos >= T_LOBBY (240)?      │
                        └───────────┬───────────────────────┘
                                    │
                        ┌───────────┴────────────┐
                        │SÍ                      │NO
                        ▼                        │
                  ┌──────────────┐              │
                  │ FANTASMA     │              │
                  │ en_lobby=Tru │              │
                  └──────────────┘              │
                                               ▼
                           ┌──────────────────────────────┐
                           │ ¿segundos >= T_FANTASMA?    │
                           │ (120s = 2 min)              │
                           └────────┬───────────────────┘
                                    │
                        ┌───────────┴────────────┐
                        │SÍ                      │NO
                        ▼                        │
                  ┌──────────────┐              │
                  │ FANTASMA     │              │
                  │ en_lobby=False │            │
                  └──────────────┘              │
                                               ▼
                           ┌──────────────────────────────┐
                           │ ¿segundos >= T_SOSPECHOSO?  │
                           │ (60s = 1 min)               │
                           └────────┬───────────────────┘
                                    │
                        ┌───────────┴────────────┐
                        │SÍ                      │NO
                        ▼                        │
                  ┌──────────────┐              │
                  │ SOSPECHOSO   │              │
                  │ en_lobby=False │            │
                  └──────────────┘              │
                                               ▼
                           ┌──────────────────────────────────┐
                           │ Actividad reciente              │
                           │ ¿veces_visto >= 2?              │
                           └────────┬───────────────────────┘
                                    │
                        ┌───────────┴────────────┐
                        │SÍ                      │NO
                        ▼                        ▼
                  ┌──────────────┐  ┌──────────────────┐
                  │ CONFIRMADO ✅│  │ SOSPECHOSO ❓     │
                  │ en_lobby=False  │ en_lobby=False   │
                  └──────────────┘  └──────────────────┘
                        │                    │
                        └──────────┬─────────┘
                                   ▼
                        ┌────────────────────┐
                        │ ¿Cambió estado?    │
                        │ ¿Entró/Salió lobby?│
                        └────────┬───────────┘
                                 │
                    ┌────────────┴────────────┐
                    │SÍ HUY CAMBIO            │NO CAMBIO
                    ▼                         ▼
         ┌──────────────────────┐  ┌─────────────────┐
         │ return (anterior,     │  │ return None     │
         │         nuevo,        │  │ (silencio, sin  │
         │         en_lobby,     │  │  log spam)      │
         │         en_lobby_ant) │  └─────────────────┘
         └──────────────────────┘
```

---

## EJEMPLO PRÁCTICO: LA VIDA DE UN NODO

### Momento 1: Se detecta por ARP (T=00:00:00)
```
Nodo(ip="192.168.1.50")
├─ veces_visto = 1
├─ ultimo_visto = 00:00:00
├─ estado = SOSPECHOSO (porque veces_visto < 2)
└─ en_lobby = False
```

### Momento 2: Se ve de nuevo a los 5 segundos (T=00:00:05)
```
# Llama actualizar_actividad()
├─ veces_visto = 2 ← CAMBIO
├─ ultimo_visto = 00:00:05
│
# Llama actualizar_estado()
├─ segundos = 5 (< 60)
├─ estado = CONFIRMADO ✅ ← ESTADO MEJORA
├─ en_lobby = False
└─ return ("sospechoso", "confirmado", False, False)
    ↓ → Se loguea: "[ESTADO] 192.168.1.50 | sospechoso -> confirmado"
```

### Momento 3: No responde por 1.5 minutos (T=00:01:35)
```
# actualizar_estado() detecta inactividad
├─ segundos = 95 (> 60, < 120)
├─ estado = SOSPECHOSO ← EMPEORA
├─ en_lobby = False
└─ return ("confirmado", "sospechoso", False, False)
    ↓ → Se loguea: "[ESTADO] 192.168.1.50 | confirmado -> sospechoso"
```

### Momento 4: No responde por 2.5 minutos (T=00:02:35)
```
# actualizar_estado() es grave
├─ segundos = 155 (> 120, < 240)
├─ estado = FANTASMA 🔴
├─ en_lobby = False (todavía visible)
└─ return ("sospechoso", "fantasma", False, False)
    ↓ → Se loguea: "[ESTADO] 192.168.1.50 | sospechoso -> fantasma"
```

### Momento 5: No responde por 5 minutos (T=00:05:00)
```
# actualizar_estado() lo mueve al limbo
├─ segundos = 300 (> 240)
├─ estado = FANTASMA
├─ en_lobby = True ← FLAG CRÍTICO
└─ return ("fantasma", "fantasma", True, False)
    ↓ → Se loguea: "[ESTADO] 192.168.1.50 | FANTASMA -> LOBBY (inactivo 5min)"
    ↓ → El canvas lo ESCONDE de pantalla
```

### Momento 6: ¡Responde de repente! (T=00:05:07)
```
# Llama actualizar_actividad() (paquete recibido)
├─ en_lobby = False ← RESURRECCIÓN
│
# Llama actualizar_estado()
├─ segundos = 7 (< 60) ← TIEMPO REINICIA
├─ veces_visto = 3
├─ estado = CONFIRMADO ✅
├─ en_lobby = False
└─ return ("fantasma", "confirmado", False, True)
    ↓ → Se loguea: "[ESTADO] 192.168.1.50 | LOBBY -> confirmado"
    ↓ → ¡Reaparece en canvas!
```

---

## BUGS QUE ESTE CÓDIGO EVITA

### ❌ BUG OLDSKOOL: "El nodo fantasma está en pantalla"
```python
# MAL (viejo):
estado = "fantasma"
# ... dibujar igual en canvas

# BIEN (ahora):
estado = "fantasma"
en_lobby = True  # ← Flag que dice "no lo dibujes"
# En canvas.py:
for nodo in nodos:
    if nodo.en_lobby: continue  # Skip
    dibuja(nodo)
```

### ❌ BUG: "¿Por qué parpadea el nodo entre confir/sospechoso?"
**Causa:** ARP replies intermitentes en redes WiFi fiesteras  
**Solución:** Requerimos 2+ apariciones para CONFIRMADO, no 1

### ❌ BUG: "El log está lleno, ¡NO SE ENTIENDE NADA!"
**Causa:** Logging cada segundo del estado (spam)  
**Solución:** `if cambio_estado or entro_lobby or salio_lobby` → solo log relevante

---

## PUNTOS CLAVE (RESUMIDO)

| Aspecto | Valor | Significado |
|---------|-------|-----------|
| **Protegido** | IP local | Nunca fantasma |
| **T_CONFIRMADO** | 30s | Tiempo "activo" mínimo |
| **T_SOSPECHOSO** | 60s | 1 min = sospecha |
| **T_FANTASMA** | 120s | 2 min = probablemente offline |
| **T_LOBBY** | 240s | 4 min = esconder de pantalla |
| **veces_visto >= 2** | Requisito | Para pasar de Sospechoso a Confirmado |
| **return None** | Sin cambio | No loguear (evita spam) |
| **return (tupla)** | Con cambio | Loguear estado nuevo |

---

## OPTIMIZACIÓN FUTURA

Ahora mismo los tiempos son **fijos**:
```python
T_CONFIRMADO = 30
T_SOSPECHOSO = 60
T_FANTASMA   = 120
T_LOBBY      = 240
```

**Idea mejorada:** Hacerlos **configurables** según tipo de red:
```python
# config.json
{
  "timeouts": {
    "wifi": {"confirmado": 30, "fantasma": 60, "lobby": 180},
    "ethernet": {"confirmado": 20, "fantasma": 120, "lobby": 300},
    "vpn": {"confirmado": 60, "fantasma": 300, "lobby": 600}
  }
}
```

---

**Creado:** 2026-03-11  
**Propósito:** Explicar la lógica central de states  
**Audiencia:** Desarrolladores/Power Users  
**Nivel:** Intermedio
