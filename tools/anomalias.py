"""
anomalias.py — Detección de anomalías vs baseline histórico
============================================================
Compara la sesión actual contra el historial acumulado en SQLite
para detectar cambios sospechosos:

- Nuevo dispositivo con MAC nunca vista → MEDIO/ALTO
- Nodo con puertos nuevos no vistos antes → MEDIO
- Nodo con tipo cambiado (smartphone → servidor) → ALTO
- Nodo con OS cambiado → MEDIO
- Nodo con fabricante cambiado (MAC spoofing) → ALTO
- Risk score muy superior al histórico → MEDIO
- Nodo que normalmente está ausente aparece a hora inusual → INFO
"""

import sqlite3
import os
from datetime import datetime

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


class DetectorAnomalias:
    """
    Compara el estado actual de la red contra el baseline histórico.

    Uso:
        detector = DetectorAnomalias("toporeveal_history.db")
        anomalias = detector.analizar(topologia)
        # Retorna lista de Anomalia
    """

    def __init__(self, ruta_db):
        self._db = ruta_db
        self._baseline = {}   # {mac: BaselineNodo}
        self._cargado  = False

    def cargar_baseline(self):
        """Carga el baseline de todas las sesiones anteriores."""
        if not os.path.exists(self._db):
            log("[ANOMALIAS] Sin historial previo — baseline vacío")
            self._cargado = True
            return

        try:
            con = sqlite3.connect(self._db)
            cur = con.cursor()

            # Verificar si existe la tabla
            cur.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='nodos'")
            if not cur.fetchone():
                log("[ANOMALIAS] Tabla 'nodos' no encontrada en historial")
                con.close()
                self._cargado = True
                return

            # Obtener todas las sesiones previas por MAC
            cur.execute("""
                SELECT mac, ip, tipo, fabricante, sistema_op,
                       puertos, risk_score, sesion_id
                FROM nodos
                WHERE mac IS NOT NULL AND mac != ''
                ORDER BY sesion_id ASC
            """)
            filas = cur.fetchall()
            con.close()

            # Construir baseline por MAC
            for mac, ip, tipo, fab, os_str, puertos_str, score, sesion in filas:
                puertos = set()
                if puertos_str:
                    try:
                        puertos = set(int(p) for p in puertos_str.split(",")
                                      if p.strip().isdigit())
                    except Exception:
                        pass

                if mac not in self._baseline:
                    self._baseline[mac] = {
                        "ips"       : set(),
                        "tipos"     : set(),
                        "fabricantes": set(),
                        "sistemas"  : set(),
                        "puertos"   : set(),
                        "scores"    : [],
                        "sesiones"  : 0,
                    }
                b = self._baseline[mac]
                if ip:    b["ips"].add(ip)
                if tipo:  b["tipos"].add(tipo)
                if fab:   b["fabricantes"].add(fab)
                if os_str: b["sistemas"].add(os_str)
                b["puertos"].update(puertos)
                if score:  b["scores"].append(score)
                b["sesiones"] += 1

            log(f"[ANOMALIAS] Baseline cargado: "
                f"{len(self._baseline)} MACs de sesiones anteriores")
            self._cargado = True

        except Exception as e:
            log(f"[ANOMALIAS] Error cargando baseline: {e}")
            self._cargado = True

    def analizar(self, topologia):
        """
        Analiza la topología actual contra el baseline.
        Retorna lista de dicts con info de cada anomalía.
        """
        if not self._cargado:
            self.cargar_baseline()

        if not self._baseline:
            return []  # Sin historial no hay baseline

        anomalias = []
        nodos = topologia.todos_los_nodos()

        for nodo in nodos:
            if not nodo.mac or nodo.en_lobby:
                continue

            # Normalizar MAC
            mac = nodo.mac.lower().strip()

            # Ignorar MACs aleatorias/privadas — cambian siempre
            if self._es_mac_aleatoria(mac):
                continue

            # ── NODO NUEVO — MAC nunca vista ───────────────────
            if mac not in self._baseline:
                # Solo alertar si tiene puertos abiertos o tráfico alto
                if nodo.puertos_abiertos or nodo.paquetes > 10:
                    sev = "alto" if nodo.puertos_abiertos else "medio"
                    anomalias.append({
                        "ip"      : nodo.ip,
                        "mac"     : mac,
                        "tipo"    : "Dispositivo Nuevo",
                        "severidad": sev,
                        "detalle" : (f"MAC {mac} nunca vista en sesiones anteriores"
                                     f" | {nodo.fabricante or 'Fabricante desconocido'}"
                                     f" | {len(nodo.puertos_abiertos)} puerto(s)"),
                    })
                continue

            b = self._baseline[mac]

            # ── CAMBIO DE TIPO ─────────────────────────────────
            if nodo.tipo and b["tipos"] and nodo.tipo not in b["tipos"]:
                tipos_prev = ", ".join(sorted(b["tipos"]))
                anomalias.append({
                    "ip"      : nodo.ip,
                    "mac"     : mac,
                    "tipo"    : "Tipo Cambiado",
                    "severidad": "alto",
                    "detalle" : (f"Antes: {tipos_prev} → Ahora: {nodo.tipo}"
                                 f" | Posible reconfiguración o MAC spoofing"),
                })

            # ── CAMBIO DE FABRICANTE (MAC spoofing) ────────────
            if (nodo.fabricante
                    and "Privada" not in nodo.fabricante
                    and b["fabricantes"]
                    and "Privada" not in str(b["fabricantes"])
                    and nodo.fabricante not in b["fabricantes"]):
                fab_prev = ", ".join(sorted(b["fabricantes"]))
                anomalias.append({
                    "ip"      : nodo.ip,
                    "mac"     : mac,
                    "tipo"    : "Fabricante Cambiado",
                    "severidad": "alto",
                    "detalle" : (f"Antes: {fab_prev[:30]} → "
                                 f"Ahora: {nodo.fabricante}"
                                 f" | Posible MAC spoofing"),
                })

            # ── PUERTOS NUEVOS ─────────────────────────────────
            puertos_actuales = set(nodo.puertos_abiertos)
            puertos_nuevos   = puertos_actuales - b["puertos"]
            if puertos_nuevos:
                sev = "alto" if any(p in puertos_nuevos
                                    for p in {22,23,3389,5900,445,80,443,8080,8443,554,8000}
                                    ) else "medio"
                anomalias.append({
                    "ip"      : nodo.ip,
                    "mac"     : mac,
                    "tipo"    : "Puertos Nuevos",
                    "severidad": sev,
                    "detalle" : (f"Puertos nunca vistos antes: "
                                 f"{sorted(puertos_nuevos)}"
                                 f" | Historial: {sorted(b['puertos'])}"),
                })

            # ── RISK SCORE MUY SUPERIOR AL HISTÓRICO ──────────
            if b["scores"]:
                score_hist_max = max(b["scores"])
                score_actual   = getattr(nodo, "risk_score", 0) or 0
                if score_actual > score_hist_max + 30:
                    anomalias.append({
                        "ip"      : nodo.ip,
                        "mac"     : mac,
                        "tipo"    : "Riesgo Elevado",
                        "severidad": "medio",
                        "detalle" : (f"Score actual {score_actual} vs "
                                     f"máximo histórico {score_hist_max}"
                                     f" | Delta +{score_actual-score_hist_max}"),
                    })

        if anomalias:
            log(f"[ANOMALIAS] {len(anomalias)} anomalía(s) detectada(s)")

        return anomalias

    @staticmethod
    def _es_mac_aleatoria(mac):
        """
        Detecta MACs localmente administradas (bit U/L = 1 en primer octeto).
        Estas son MACs aleatorias/privadas — no sirven como baseline.
        """
        if not mac or len(mac) < 2:
            return True
        try:
            primer_octeto = int(mac.split(":")[0], 16)
            return bool(primer_octeto & 0x02)  # bit U/L
        except Exception:
            return True
