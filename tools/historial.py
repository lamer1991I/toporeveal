"""
historial.py — Persistencia de sesiones y análisis diferencial en TopoReveal.

Guarda el estado de la red en SQLite para comparar entre sesiones y detectar:
  - Hosts nuevos (no estaban en la sesión anterior)
  - Hosts perdidos (estaban antes pero ya no se ven)
  - Cambios en el host (puertos nuevos, cambio de OS o tipo)
"""

import sqlite3
import os
import json
import pwd
from datetime import datetime

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [HISTORIAL] {msg}")

def _obtener_ruta_db():
    usuario = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
    try:
        home = pwd.getpwnam(usuario).pw_dir
    except Exception:
        home = os.path.expanduser("~")
    base = os.path.join(home, "Proyectos", "toporeveal")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "toporeveal_history.db")

class Historial:
    def __init__(self):
        self.ruta = _obtener_ruta_db()
        self._inicializar_db()

    def _inicializar_db(self):
        try:
            conn = sqlite3.connect(self.ruta)
            c = conn.cursor()
            # Tabla de sesiones
            c.execute('''CREATE TABLE IF NOT EXISTS sesiones
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          timestamp TEXT,
                          interfaz TEXT,
                          n_hosts INTEGER)''')
            # Tabla de hosts (último estado conocido)
            c.execute('''CREATE TABLE IF NOT EXISTS hosts
                         (ip TEXT PRIMARY KEY,
                          mac TEXT,
                          tipo TEXT,
                          fabricante TEXT,
                          sistema_op TEXT,
                          puertos TEXT,
                          risk_score INTEGER,
                          ultimo_visto TEXT)''')
            conn.commit()
            conn.close()
        except Exception as e:
            log(f"Error inicializando DB: {e}")

    def guardar_sesion(self, interfaz, nodos):
        """Guarda el estado actual de los nodos como 'último conocido'."""
        try:
            conn = sqlite3.connect(self.ruta)
            c = conn.cursor()
            
            # Registrar sesión
            timestamp = datetime.now().isoformat()
            c.execute("INSERT INTO sesiones (timestamp, interfaz, n_hosts) VALUES (?, ?, ?)",
                      (timestamp, interfaz, len(nodos)))
            
            # Actualizar tabla de hosts con el estado actual
            # Usamos REPLACE para que la IP sea la PK y siempre tengamos el estado más reciente
            for ip, nodo in nodos.items():
                puertos_json = json.dumps(list(nodo.puertos_abiertos))
                c.execute('''REPLACE INTO hosts 
                             (ip, mac, tipo, fabricante, sistema_op, puertos, risk_score, ultimo_visto)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                          (ip, nodo.mac, nodo.tipo, nodo.fabricante, nodo.sistema_op, 
                           puertos_json, getattr(nodo, "risk_score", 0), timestamp))
            
            conn.commit()
            conn.close()
            log(f"Sesión guardada en {self.ruta} ({len(nodos)} hosts)")
        except Exception as e:
            log(f"Error guardando sesión: {e}")

    def obtener_ultimo_estado(self):
        """Retorna un diccionario {ip: datos} con el estado de la sesión anterior."""
        historia = {}
        try:
            conn = sqlite3.connect(self.ruta)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM hosts")
            rows = c.fetchall()
            for row in rows:
                datos = dict(row)
                datos["puertos"] = json.loads(datos["puertos"])
                historia[datos["ip"]] = datos
            conn.close()
        except Exception as e:
            log(f"Error recuperando historial: {e}")
        return historia

def comparar_nodos(nodo_actual, datos_previos):
    """
    Compara un nodo actual con sus datos en la DB.
    Retorna una lista de cambios: ["NUEVO"], ["CAMBIO: puertos"], etc.
    """
    if not datos_previos:
        return ["NUEVO"]
    
    cambios = []
    
    # Comparar puertos
    puertos_actuales = sorted(list(nodo_actual.puertos_abiertos))
    puertos_previos = sorted(datos_previos.get("puertos", []))
    if puertos_actuales != puertos_previos:
        nuevos = [p for p in puertos_actuales if p not in puertos_previos]
        if nuevos:
            cambios.append(f"PUERTOS+")
        else:
            cambios.append(f"PUERTOS-")

    # Comparar Tipo/OS
    if nodo_actual.tipo != datos_previos.get("tipo"):
        cambios.append("TIPO")
    
    if nodo_actual.sistema_op != datos_previos.get("sistema_op") and \
       nodo_actual.sistema_op != "Desconocido":
        cambios.append("OS")
        
    return cambios
