# 🎯 PLAN DE MEJORA Y ORIENTACIÓN ESTRATÉGICA
## TopoReveal — Hoja de Ruta para Evolucionar

---

## 📊 DIAGNÓSTICO ACTUAL (11-03-2026)

### ✅ Fortalezas identificadas:

1. **Arquitectura bien separada** — core/tools/ui están limpios y desacoplados
2. **Sistema de estados rico** — confirmado/sospechoso/fantasma/lobby es inteligente
3. **Risk scoring granular** — cada puerto tiene peso, hay combos críticos detectados
4. **Multi-threading robusto** — watchdog automático en captura, 3 scanners paralelos
5. **Base de datos OUI completa** — identifica 200+ fabricantes
6. **Fingerprinting multi-criterio** — MAC + TTL + puertos juntos
7. **UI atractiva** — Tkinter con colores temáticos, real-time actualización
8. **Exportación flexible** — PNG + JSON + CSV

### ⚠️ Debilidades/Áreas de mejora:

#### **Críticas (bloqueantes)**
- ❌ Errores de None en comparaciones (YA ARREGLADO ✅)
- ❌ Sin persistencia de datos (se pierden al cerrar)
- ❌ Sin autenticación/seguridad en API (si se hace API)
- ❌ Sin test suite

#### **Importantes**
- 🟡 Caché de OUI y TTL_OS es estática (sin actualizaciones)
- 🟡 Nmap tarda mucho en redes grandes (100+ nodos)
- 🟡 Sin configuración por usuario (parámetros hardcodeados)
- 🟡 Logs son solo texto plano (difícil analizar)
- 🟡 Sin alertas sonoras/notificaciones
- 🟡 Canvas se satura con 50+ nodos (sin scroll/zoom)

#### **Menores (nice-to-have)**
- 💙 Sin modo oscuro/claro seleccionable
- 💙 Sin español/inglés seleccionable (UI en inglés/español mixto)
- 💙 Sin historial de cambios de estado
- 💙 Sin integración con Slack/correo para alertas
- 💙 Sin API REST para integraciones
- 💙 Sin detección anti-spoofing

---

## 🚀 HOJA DE RUTA RECOMENDADA (Roadmap)

### **FASE 1: Estabilidad (1-2 semanas)**
```
Priority: ALTA
Tareas:
  1. ✅ Arreglar None comparisons (HECHO)
  2. Agregar test suite básico (unit tests para nodes.py)
  3. Logging a SQLite (en vez de .txt)
  4. Configuración por usuario (config.json)
  5. Validación de entrada en toda la UI
```

**Resultado esperado:** TopoReveal sin crashes, fácil de debug

---

### **FASE 2: Escalabilidad (2-3 semanas)**
```
Priority: MEDIA
Tareas:
  1. Implementar caché Redis (si capturas muchos flujos)
  2. Asincronía en nmap (ejecutar 5 parallelos, no 1)
  3. Compresión de datos en logs
  4. Paginación en UI (max 50 nodos visibles, scroll)
  5. Profiling de memoria con grandes redes
```

**Resultado esperado:** Maneja 500+ dispositivos sin lag

---

### **FASE 3: Inteligencia (3-4 semanas)**
```
Priority: MEDIA
Tareas:
  1. Machine Learning para detectar anomalías
     - ¿Es normal que este router tenga puerto 23?
     - ¿Es anormal este patrón de tráfico?
  2. Correlación de alertas (ejemplo: si X+Y+Z → CRÍTICO)
  3. Baseline histórico (compara hoy vs hace 1 week)
  4. Detección de cambios en topología (nuevo switch?)
  5. Predicción de fallos (este dispositivo se cae en X horas)
```

**Resultado esperado:** Alertas predictivas, no reactivas

---

### **FASE 4: Integración (2-3 semanas)**
```
Priority: BAJA
Tareas:
  1. API REST (Flask/FastAPI)
  2. Sistema de plugins (permitir custom scanners)
  3. Integración Slack/Discord/Telegram
  4. Integración Grafana (métricas históricas)
  5. Export a SIEM (Wazuh, Splunk)
```

**Resultado esperado:** TopoReveal se integra con tu stack DevOps

---

## 🏗️ ARQUITECTURA MEJORADA (Propuesta)

### Estructura de carpetas evolucionada:
```
toporeveal/
├── core/                 # Código fundamental
│   ├── nodes.py
│   ├── topology.py
│   └── scanner.py       # ← se podría mover aquí
│
├── tools/               # Herramientas externas
│   ├── scanner/
│   │   ├── arp_sweep.py
│   │   ├── nmap_worker.py
│   │   └── __init__.py
│   ├── capture/
│   │   ├── live.py
│   │   └── offline.py   # ← nuevo: cargar pcap
│   ├── fingerprint.py
│   ├── intel/           # ← nuevo: threat intel
│   │   ├── certs.py     # SSL certificates
│   │   ├── shodan.py    # integración externa
│   │   └── cvss.py      # puntuación de vulns
│   └── __init__.py
│
├── ui/                  # Interfaz de usuario
│   ├── app.py
│   ├── canvas.py
│   ├── panel.py
│   ├── panel_alertas.py
│   ├── dialogs/         # ← nuevo
│   │   ├── settings.py
│   │   ├── export_dialog.py
│   │   └── about.py
│   └── __init__.py
│
├── db/                  # ← NUEVO: persistencia
│   ├── models.py        # SQLAlchemy models
│   ├── queries.py       # Funciones de BD
│   └── migrations/      # Alembic (versionado)
│
├── api/                 # ← NUEVO: REST API
│   ├── server.py        # Flask/FastAPI
│   ├── routes.py
│   ├── auth.py
│   └── __init__.py
│
├── tests/               # ← NUEVO: test suite
│   ├── test_nodes.py
│   ├── test_topology.py
│   ├── test_scanner.py
│   └── fixtures/
│
├── config/              # ← NUEVO: configuración
│   ├── default.json
│   ├── production.json
│   └── secrets.example.json
│
├── scripts/             # ← NUEVO: utilities
│   ├── install_deps.sh
│   ├── run_tests.sh
│   ├── migrate_db.sh
│   └── analyze_logs.py
│
└── docs/                # ← NUEVO: documentación
    ├── README.md
    ├── ARCHITECTURE.md
    ├── API.md
    ├── INSTALL.md
    └── TROUBLESHOOT.md
```

---

## 🎯 PRIORIDADES INMEDIATAS (Próximas 2 semanas)

### **#1: Tests (D1-D3)**
```python
# tests/test_nodes.py
def test_nodo_confirmado_con_2_apariciones():
    """Si se ve 2+ veces, debe ser confirmado"""
    n = Nodo("192.168.1.1")
    n.veces_visto = 2
    n.actualizar_estado()
    assert n.estado == CONFIRMADO

def test_none_en_comparaciones():
    """No haya crashes al comparar None valores"""
    n = Nodo("192.168.1.1")
    n.severidad_max = None  # Esto pasaba antes
    # ... no debería haber erro
```

### **#2: Base de datos (D3-D7)**
```sql
-- sqlite schema
CREATE TABLE nodo (
    id INTEGER PRIMARY KEY,
    ip TEXT UNIQUE NOT NULL,
    mac TEXT,
    tipo TEXT,
    fabricante TEXT,
    primeiro_visto TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ultimo_visto TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    estado TEXT,
    risk_score INTEGER,
    puertos_abiertos JSON
);

CREATE TABLE hallazgo (
    id INTEGER PRIMARY KEY,
    nodo_ip TEXT,
    puerto INTEGER,
    servicio TEXT,
    severidad TEXT,
    timestamp TIMESTAMP,
    FOREIGN KEY (nodo_ip) REFERENCES nodo(ip)
);

CREATE TABLE evento (
    id INTEGER PRIMARY KEY,
    timestamp TIMESTAMP,
    tipo TEXT,  -- 'nodo_nuevo', 'estado_cambio', 'puerto_nuevo', 'alerta'
    mensaje TEXT,
    metadata JSON
);
```

### **#3: Config file (D1-D2)**
```json
{
  "scanner": {
    "intervalo_arp": 300,
    "intervalo_profundo": 300,
    "timeout_nodo": 8,
    "puertos_escanear": "22,80,443,445,3389,8080"
  },
  "capture": {
    "modo_promiscuo": true,
    "max_reinicios": 10
  },
  "ui": {
    "ancho_inicial": 1200,
    "alto_inicial": 750,
    "actualizar_cada_ms": 2000
  },
  "alertas": {
    "enabled": true,
    "sonido": true,
    "notificaciones": ["desktop", "syslog"]
  }
}
```

---

## 📈 MÉTRICAS DE ÉXITO

| Métrica | Actual | Meta (3 meses) |
|---------|--------|---|
| Dispositivos soportados | ~100 | 500+ |
| Tiempo startup | 5s | 2s |
| Porcentaje uptime | 98% | 99.9% |
| False positives | ~5% | <1% |
| Response time UI | 2s | <500ms |
| Test coverage | 0% | >80% |
| Documentación | 60% | 100% |

---

## 🤝 SUGERENCIAS DE DESARROLLO

### Si quieres **rápido win** (impacto alto, esfuerzo bajo):
1. Agregar config.json ← 30 min
2. Logs a SQLite ← 1 hora
3. Test para nodes.py ← 2 horas
4. Botón "Refrescr forzado" en UI ← 15 min

### Si quieres **escala** (impacto alto, esfuerzo alto):
1. API REST ← 1 semana
2. Multi-user + BD ← 2 semanas
3. Clustering (redes muy grandes) ← 1 semana

### Si quieres **inteligencia** (novedad, esfuerzo altísimo):
1. ML para anomalías ← 3 semanas
2. Integración threat intel ← 1 semana
3. Predicción de fallos ← 2 semanas

---

## 💡 IDEAS AVANZADAS (Futuro lejano)

- **Modo distribuido**: 10 rasp­berrys Pi escaneando cada uno su subred
- **Blockchain para logs inmutables**: legal chain of custody
- **AR Visualization**: ver red en augmented reality
- **Quantum-safe crypto**: anticiparse al futuro
- **Plugin marketplace**: comunidad de contribuidores

---

## 📋 CHECKLIST PARA SIGUIENTE SESIÓN

- [ ] Revisar code review de panel_alertas.py fix
- [ ] Crear primer test (test_nodes.py)
- [ ] Setup SQLite en topology.py
- [ ] Cargar config desde archivo (no hardcoded)
- [ ] Agregar logging a syslog
- [ ] Documentar cada método en docstrings
- [ ] Crear GitHub issues con el roadmap

---

**Última actualización:** 2026-03-11  
**Autor:** TopoReveal Dev Team  
**Estado:** 🟢 En Implementación
