# 🐍 GUÍA COMPLETA PARA APRENDER PYTHON
## Desde CERO hasta entender TODO el código de TopoReveal

**Estado:** Para principiante absoluto  
**Objetivo:** Que entiendas línea-por-línea qué hace tu programa  
**Tiempo estimado:** 3-4 semanas (1-2 horas/día)

---

# 📋 TABLA DE CONTENIDOS

1. [NIVEL 1: CONCEPTOS BÁSICOS](#nivel-1-conceptos-básicos)
2. [NIVEL 2: ESTRUCTURAS DE DATOS](#nivel-2-estructuras-de-datos)
3. [NIVEL 3: FUNCIONES Y MÓDULOS](#nivel-3-funciones-y-módulos)
4. [NIVEL 4: PROGRAMACIÓN ORIENTADA A OBJETOS](#nivel-4-programación-orientada-a-objetos)
5. [NIVEL 5: MANEJO DE ERRORES](#nivel-5-manejo-de-errores)
6. [NIVEL 6: LIBRERÍAS EXTERNAS](#nivel-6-librerías-externas)
7. [NIVEL 7: CONCURRENCIA Y THREADING](#nivel-7-concurrencia-y-threading)
8. [NIVEL 8: CONCEPTOS AVANZADOS](#nivel-8-conceptos-avanzados)

---

# 🔴 NIVEL 1: CONCEPTOS BÁSICOS
## Lo primero que debes aprender (esta semana)

### 1.1 Variables y tipos de datos

**¿Qué es?** Un contenedor para guardar información

```python
# EJEMPLO DEL CÓDIGO DE TOPOREVEAL:
# Línea en: ui/panel.py
COLOR_FONDO = "#0d1117"  # Variable: guarda un COLOR (texto)
ANCHO_PANEL = 240         # Variable: guarda un NÚMERO

# Los tipos básicos en Python:
numero = 42               # int (número entero)
decimal = 3.14           # float (número decimal)
texto = "Hola"           # str (texto/string)
verdadero = True         # bool (verdadero/falso)
nada = None              # NoneType (sin valor)

# EN TU CÓDIGO:
# core/nodes.py - línea 11-18
self.ip = ip             # Guarda la IP (ej: "192.168.1.1")
self.mac = None          # Sin MAC al inicio
self.estado = SOSPECHOSO # Guarda el estado
self.veces_visto = 0     # Contador (número)
```

**Quiz:** ¿Qué tipo es `ip = "192.168.1.50"`?  
Respuesta: `str` (texto)

---

### 1.2 Impresión en pantalla

```python
# Syntax básico:
print("Hola")  # Imprime: Hola

# CON VARIABLES:
nombre = "192.168.1.1"
print("La IP es:", nombre)  # Imprime: La IP es: 192.168.1.1

# EN TU CÓDIGO:
# tools/scanner.py - línea 17-19
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    # Imprime: [14:30:45] [SCANNER] Se detectó nuevo host
```

---

### 1.3 Operadores aritméticos

```python
suma = 5 + 3          # 8
resta = 10 - 4        # 6
mult = 4 * 5          # 20
div = 20 / 4          # 5.0
potencia = 2 ** 3     # 8 (2 elevado a 3)
modulo = 10 % 3       # 1 (resto, no usado en TopoReveal)

# EN TU CÓDIGO:
# core/nodes.py - línea 50
T_FANTASMA = 2 * 60  # 2 minutos en segundos = 120
T_LOBBY = 4 * 60     # 4 minutos en segundos = 240
```

---

### 1.4 Comparaciones (=, ==, !=, <, >)

```python
# COMPARACIÓN: ¿Son iguales?
5 == 5          # True (sí, son iguales)
5 == 3          # False (no, no son iguales)
5 != 3          # True (sí, son diferentes)

# COMPARACIÓN: ¿Es mayor/menor?
5 > 3           # True
5 < 3           # False
5 >= 5          # True (mayor o igual)
5 <= 3          # False

# TEXTOS:
"hola" == "hola"       # True
"hola" == "Hola"       # False (mayúsculas importan)

# EN TU CÓDIGO:
# core/nodes.py - línea 62-67
if segundos >= T_FANTASMA:      # ¿Es >= 120?
    self.estado = FANTASMA      # Sí → cambiar estado
elif segundos >= T_SOSPECHOSO:  # ¿Es >= 60?
    self.estado = SOSPECHOSO    # Sí → cambiar estado
```

**CRUCIAL PARA TOPOREVEAL:** Se comparan tiempos y estados constantemente

---

### 1.5 Lógica booleana (AND, OR, NOT)

```python
# AND - AMBAS deben ser True
(5 > 3) and (3 > 1)    # True (ambas ciertas)
(5 > 3) and (3 > 5)    # False (una es falsa)

# OR - UNA debe ser True
(5 > 3) or (3 > 5)     # True (al menos una es cierta)
(1 > 3) or (2 > 5)     # False (ninguna es cierta)

# NOT - invierte
not True               # False
not False              # True
not (5 > 3)           # False (porque 5>3 es True)

# EN TU CÓDIGO:
# core/topology.py - línea 16-17
if not ip: return False        # Si NO hay IP, salir
if ip in IPS_INVALIDAS: return False  # Si está en lista invalida

# core/nodes.py - línea 35
if self.protegido:  # Si es protegido
    self.estado = "confirmado"  # Entonces confirmado
    return None
```

---

### 1.6 Asignación con condición (if/else)

```python
# SYNTAX:
if condicion:
    # Código si es True
else:
    # Código si es False

# EJEMPLO:
edad = 20
if edad >= 18:
    print("Eres adulto")
else:
    print("Eres menor")

# EN TU CÓDIGO:
# core/nodes.py - línea 62-75
segundos = self.segundos_sin_actividad()  # Calcular segundos
if segundos >= T_LOBBY:                   # ¿Muy inactivo?
    self.estado = FANTASMA
    self.en_lobby = True
elif segundos >= T_FANTASMA:              # ¿Medianamente inactivo?
    self.estado = FANTASMA
    self.en_lobby = False
elif segundos >= T_SOSPECHOSO:            # ¿Poco inactivo?
    self.estado = SOSPECHOSO
    self.en_lobby = False
else:                                      # ¿Activo?
    if self.veces_visto >= 2:             # ¿Lo vimos 2+ veces?
        self.estado = CONFIRMADO
    else:
        self.estado = SOSPECHOSO
    self.en_lobby = False
```

**CRÍTICO:** Este bloque decide si un dispositivo es real, fake o fantasma

---

### 1.7 Comentarios

```python
# Esto es un comentario (empiza con #)
# Python lo IGNORA, es solo para humanos

# EN TU CÓDIGO:
# core/nodes.py - línea 8
CONFIRMADO = "confirmado"  # Estado: dispositivo confirmado
SOSPECHOSO = "sospechoso"  # Estado: podría ser fake
FANTASMA   = "fantasma"    # Estado: probablemente offline
```

---

# 🟠 NIVEL 2: ESTRUCTURAS DE DATOS
## Colecciones para guardar múltiples valores (semana 1-2)

### 2.1 Listas (arrays)

**¿Qué es?** Un contenedor ordenado de múltiples valores

```python
# Crear lista:
frutas = ["manzana", "platano", "naranja"]

# Acceder (índice comienza en 0):
print(frutas[0])   # "manzana"
print(frutas[1])   # "platano"
print(frutas[-1])  # "naranja" (último elemento)

# Agregar:
frutas.append("uva")  # Ahora: ["manzana", "platano", "naranja", "uva"]

# Largo:
len(frutas)  # 4

# EN TU CÓDIGO:
# core/nodes.py - línea 27 y 50
self.puertos_abiertos = []     # Lista vacía, se llena después
self.hallazgos = []            # Lista de hallazgos/alertas

# Cuando se encuentra un puerto:
nodo.puertos_abiertos.append(80)   # Agregar puerto 80
nodo.puertos_abiertos.append(443)  # Agregar puerto 443
# Ahora: [80, 443]
```

---

### 2.2 Diccionarios (almacenamientos clave-valor)

**¿Qué es?** Pares de clave-valor, como un teléfono

```python
# Crear diccionario:
persona = {
    "nombre": "Juan",
    "edad": 30,
    "ciudad": "Madrid"
}

# Acceder:
print(persona["nombre"])  # "Juan"

# Modificar:
persona["edad"] = 31

# EN TU CÓDIGO:
# core/topology.py - línea 32
self.nodos = {}  # Diccionario vacío

# Agregar nodo:
self.nodos["192.168.1.1"] = Nodo("192.168.1.1")
self.nodos["192.168.1.50"] = Nodo("192.168.1.50")

# Acceder:
nodo = self.nodos.get("192.168.1.1")  # Obtener nodo por IP

# EN TU CÓDIGO (Colores):
# ui/panel.py - línea 5-14
COLOR_FONDO = "#0d1117"
COLOR_PANEL = "#161b22"
COLOR_TEXTO = "#e6edf3"
# Es como un diccionario visual

# Mejor ejemplo:
SEV_COLOR = {
    "info": "#58d6ff",
    "medio": "#f0e040",
    "alto": "#f0883e",
    "critico": "#da3633",
}
color = SEV_COLOR.get("critico")  # "#da3633"
```

---

### 2.3 Tuplas

**¿Qué es?** Como listas pero inmutables (no se pueden cambiar)

```python
# Crear tupla:
coordenadas = (10, 20)  # (x, y)
print(coordenadas[0])   # 10

# NO puedes hacer:
coordenadas[0] = 15  # ❌ ERROR

# EN TU CÓDIGO:
# core/topology.py - línea 40 y 102
self.enlaces = []  # Lista de tuplas (origin, destino, protocolo)

# Agregar enlace:
self.enlaces.append(("192.168.1.1", "192.168.1.50", "ARP"))

# Acceder:
for origen, destino, proto in self.enlaces:
    print(f"{origen} → {destino} [{proto}]")
```

---

### 2.4 Sets (conjuntos únicos)

**¿Qué es?** Una lista que NO PERMITE duplicados

```python
# Crear set:
numeros = {1, 2, 3, 3, 3}  # Se automáticamente elimina duplicados
print(numeros)  # {1, 2, 3}

# EN TU CÓDIGO:
# tools/scanner.py - línea 41
self._escaneados = set()  # Set de IPs ya escaneadas

# Agregar:
self._escaneados.add("192.168.1.1")

# Verificar si está:
if "192.168.1.50" in self._escaneados:
    print("Ya fue escaneado")
```

---

### 2.5 Operaciones comunes

```python
# EN TU CÓDIGO - Mucha iteración:

# VERIFICAR SI EXISTE:
if "192.168.1.1" in self.nodos:
    print("Existe")

# CONTAR ELEMENTOS:
total_nodos = len(self.nodos)

# FILTRAR LISTA:
nodos_visibles = [n for n in nodos if not n.en_lobby]
# ↑ Solo nodos que NO estén en lobby

# CONVERTIR LISTA A TUPLA:
resultado = tuple([80, 443])  # (80, 443)
```

---

# 🟡 NIVEL 3: FUNCIONES Y MÓDULOS
## Código reutilizable (semana 2)

### 3.1 Funciones básicas

**¿Qué es?** Bloque de código que hace UN trabajo específico

```python
# SYNTAX:
def nombre_funcion(parametro1, parametro2):
    # Código
    return resultado

# EJEMPLO:
def saludar(nombre):
    mensaje = f"Hola, {nombre}"
    return mensaje

# USAR:
resultado = saludar("Juan")  # "Hola, Juan"
print(resultado)

# EN TU CÓDIGO:
# tools/scanner.py - línea 17-19
def log(msg):  # Función: registra un mensaje
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    if _log_fn:
        try: _log_fn(msg)
        except: pass

# USAR:
log("[SCANNER] Detectado nuevo host")
# Imprime: [14:30:45] [SCANNER] Detectado nuevo host
```

---

### 3.2 Parámetros por defecto

```python
def aumentar(numero, cantidad=1):
    return numero + cantidad

aumentar(5)      # 6 (usa cantidad=1 por defecto)
aumentar(5, 10)  # 15 (usa cantidad=10)

# EN TU CÓDIGO:
# core/nodes.py - línea 46
def actualizar_actividad(self, bytes_paquete=0):
    # bytes_paquete es opcional, por defecto 0
    self.bytes_recibidos += bytes_paquete
```

---

### 3.3 Argumentos con nombre

```python
def crear_usuario(nombre, edad, ciudad):
    return f"{nombre}, {edad} años en {ciudad}"

# Posicional (orden importa):
crear_usuario("Juan", 30, "Madrid")

# Con nombre (orden NO importa):
crear_usuario(edad=30, nombre="Juan", ciudad="Madrid")

# EN TU CÓDIGO:
# tools/scanner.py - línea 45
threading.Thread(
    target=self._loop_arp,           # nombre del argumento=valor
    daemon=True,                      # nombre del argumento=valor
    name="scanner-arp"                # nombre del argumento=valor
).start()
```

---

### 3.4 Retorno múltiple

```python
def calcular(a, b):
    suma = a + b
    resta = a - b
    return suma, resta  # Retorna tupla

resultado = calcular(10, 5)  # (15, 5)
suma, resta = calcular(10, 5)  # Desempacar
print(suma)  # 15

# EN TU CÓDIGO:
# core/nodes.py - línea 49-82
def actualizar_estado(self):
    # ... código ...
    if cambio_estado or entro_lobby or salio_lobby:
        return (anterior, self.estado, self.en_lobby, en_lobby_anterior)
    return None
```

---

### 3.5 Módulos e imports

**¿Qué es?** Código Python en archivos separados

```python
# En archivo: helpers.py
def sumar(a, b):
    return a + b

# En archivo: main.py
from helpers import sumar  # Importar función
resultado = sumar(5, 3)   # 8

# O IMPORTAR COMPLETO:
import helpers
resultado = helpers.sumar(5, 3)

# EN TU CÓDIGO (INICIO DE CADA ARCHIVO):
# tools/scanner.py - línea 1-17
import subprocess      # Módulo de sistema operativo
import re             # Módulo de expresiones regulares
import threading      # Módulo de hilos
import time          # Módulo de tiempo
from datetime import datetime  # Importar clase específica

# core/topology.py - línea 1-7
import threading
import subprocess
from datetime import datetime
from core.nodes import (Nodo, CONFIRMADO, SOSPECHOSO, FANTASMA, ...)
# ↑ Importa desde archivo local core/nodes.py
```

---

# 🟢 NIVEL 4: PROGRAMACIÓN ORIENTADA A OBJETOS (OOP)
## Lo más importante para TopoReveal (semana 2-3)

### 4.1 Clases y objetos

**¿Qué es?** Un "molde" para crear objetos con características y acciones

```python
# DEFINIR CLASE:
class Perro:
    def __init__(self, nombre):  # Constructor
        self.nombre = nombre     # Atributo
        self.edad = 0
    
    def ladrar(self):            # Método (función dentro de clase)
        return f"{self.nombre} está ladrando"

# CREAR OBJETO (instancia):
mi_perro = Perro("Rex")
print(mi_perro.nombre)      # "Rex"
print(mi_perro.ladrar())    # "Rex está ladrando"

# EN TU CÓDIGO - LA CLASE MÁS IMPORTANTE:
# core/nodes.py - línea 11-42
class Nodo:
    def __init__(self, ip):           # Constructor
        self.ip = ip                  # Atributo: la IP
        self.mac = None               # Atributo: MAC address
        self.fabricante = "Desconocido"  # Atributo: quien fabrica
        self.tipo = "desconocido"     # Atributo: tipo de dispositivo
        self.estado = SOSPECHOSO      # Atributo: estado actual
        self.veces_visto = 0          # Atributo: contador
        self.puertos_abiertos = []    # Atributo: lista de puertos
        # ... más atributos ...
    
    def actualizar_actividad(self, bytes_paquete=0):  # Método
        self.ultimo_visto = time.time()
        self.veces_visto += 1
        self.paquetes += 1

# USAR:
nodo_router = Nodo("192.168.1.1")
nodo_router.tipo = "router"
nodo_router.actualizar_actividad(1500)  # Se vio, transmitió 1500 bytes
```

**VISUAL DEL NODO:**
```
┌─── OBJETO: Nodo("192.168.1.1") ─────┐
│ Atributos:                           │
│  • ip = "192.168.1.1"                │
│  • mac = "50:C7:BF:xx:xx:xx"         │
│  • tipo = "router"                   │
│  • estado = "confirmado"             │
│  • puertos_abiertos = [80, 443]      │
│  • veces_visto = 5                   │
│                                      │
│ Métodos:                             │
│  • actualizar_actividad()            │
│  • actualizar_estado()               │
│  • segundos_sin_actividad()          │
└──────────────────────────────────────┘
```

---

### 4.2 self - La "referencia a uno mismo"

```python
class Cuenta:
    def __init__(self, saldo):
        self.saldo = saldo  # self = "esta cuenta"
    
    def depositar(self, cantidad):
        self.saldo += cantidad  # self.saldo = saldo de esta cuenta

# CREAR DOS CUENTAS:
cuenta1 = Cuenta(100)
cuenta2 = Cuenta(500)

# DEPOSITAR EN CADA UNA:
cuenta1.depositar(50)  # self.saldo de cuenta1 = 150
cuenta2.depositar(50)  # self.saldo de cuenta2 = 550

# EN TU CÓDIGO:
# core/nodes.py - línea 46-51
def actualizar_actividad(self, bytes_paquete=0):
    self.ultimo_visto = time.time()      # self = este nodo
    self.veces_visto += 1                # self = este nodo
    self.paquetes += 1                   # self = este nodo
    self.bytes_recibidos += bytes_paquete
    self.en_lobby = False
```

---

### 4.3 Atributos y métodos

```python
class Persona:
    # ATRIBUTOS (características):
    color_piel = "blanca"      # Atributo de clase (compartido)
    
    def __init__(self, nombre):
        self.nombre = nombre   # Atributo de instancia (único)
        self.edad = 0
    
    # MÉTODOS (acciones):
    def cumpleaños(self):
        self.edad += 1
        return f"Feliz cumpleaños {self.nombre}"

persona1 = Persona("Juan")
print(persona1.nombre)        # "Juan" - ATRIBUTO
print(persona1.cumpleaños())  # "Feliz cumpleaños Juan" - MÉTODO

# EN TU CÓDIGO:
# core/nodes.py
# ATRIBUTOS:
self.ip = ip
self.mac = None
self.estado = SOSPECHOSO
self.veces_visto = 0

# MÉTODOS:
self.actualizar_actividad()
self.actualizar_estado()
self.segundos_sin_actividad()
```

---

### 4.4 `__init__` - El constructor

```python
class Robot:
    def __init__(self, nombre, bateria):  # Constructor (se llama al crear)
        self.nombre = nombre
        self.bateria = bateria
        print(f"Robot {nombre} creado")

# Cuando creas un objeto, se llama automáticamente:
robot1 = Robot("R2D2", 100)  # Imprime: Robot R2D2 creado
# ↑ Se ejecutó __init__ automáticamente

# EN TU CÓDIGO:
# core/nodes.py - línea 12-39
class Nodo:
    def __init__(self, ip):  # ← Se llama al hacer: Nodo("192.168.1.1")
        self.ip = ip
        self.mac = None
        # ... inicializar todos los atributos ...
        self.estado = SOSPECHOSO
        self.veces_visto = 0
        # etc.

# CREAR NODO:
nodo = Nodo("192.168.1.50")  # ← Llama a __init__ automáticamente
```

---

### 4.5 Herencia

**¿Qué es?** Una clase "hereda" de otra (como hijo de padre)

```python
# CLASE PADRE:
class Animal:
    def __init__(self, nombre):
        self.nombre = nombre
    
    def sonido(self):
        return "Sonido"

# CLASE HIJA (hereda de Animal):
class Perro(Animal):
    def sonido(self):  # SOBRESCRIBIR método
        return "Guau"

# USAR:
perro = Perro("Rex")
print(perro.nombre)  # "Rex" (heredada)
print(perro.sonido())  # "Guau" (sobrescrita)

# EN TU CÓDIGO:
# No hay herencia explícita, pero es fácil de agregar:
# Ejemplo de cómo sería:
# (Esto está en comentario, NO en tu código)
# class Router(Nodo):
#     def __init__(self, ip):
#         super().__init__(ip)  # Llamar constructor del padre
#         self.tipo = "router"
```

---

# 🟠-🔴 NIVEL 5: MANEJO DE ERRORES
## Try, except, finally (semana 3)

### 5.1 Try-Except básico

```python
# SYNTAX:
try:
    # Código que PODRÍA fallar
except TipoError:
    # Código si falla

# EJEMPLO:
try:
    numero = int("abc")  # Esto va a fallar
except ValueError:
    print("Eso no es un número")

# EN TU CÓDIGO (MUCHÍSIMO USADO):
# tools/scanner.py - línea 73-81
def _loop_arp(self):
    fallos_consecutivos = 0
    while not self._stop_event.is_set():
        try:
            red = self.obtener_red_local(self._interfaz)
            if red:
                self._red = red
                fallos_consecutivos = 0
                self._arp_scan(red)  # ← Podría fallar
        except Exception as e:  # ← Si falla, capturar
            log(f"[SCANNER] Error: {e}")
            fallos_consecutivos += 1
```

---

### 5.2 Múltiples except

```python
try:
    resultado = int(input("Número: "))
    print(10 / resultado)
except ValueError:
    print("Debes escribir un número")
except ZeroDivisionError:
    print("No puedes dividir por 0")
except Exception:  # Cualquier otro error
    print("Algo salió mal")

# EN TU CÓDIGO:
# core/topology.py - línea 73
try:
    r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=3)
except:
    return None  # Si falla, retornar None
```

---

### 5.3 Finally

```python
try:
    # Código
    resultado = 10 / 2
except:
    print("Error")
finally:
    # Código que SIEMPRE se ejecuta
    print("Limpieza")

# EN TU CÓDIGO:
# tools/capture.py (watchdog)
# Se cierraa conexiones en finally
```

---

# 🟡 NIVEL 6: LIBRERÍAS EXTERNAS
## Usar código de otros (semana 3)

### 6.1 Librerías estándar de Python

```python
# DATETIME: Para trabajar con fechas/horas
from datetime import datetime
ahora = datetime.now()
print(ahora.strftime('%H:%M:%S'))  # "14:30:45"

# EN TU CÓDIGO (LIGERÍSIMO):
# core/nodes.py - línea 1
import time
self.ultimo_visto = time.time()  # Tiempo actual en segundos

# tools/scanner.py - línea 1-3
from datetime import datetime
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    # Imprime: [14:30:45] [SCANNER] ...

# SUBPROCESS: Ejecutar comandos del sistema
import subprocess
resultado = subprocess.run(["ls", "-l"], capture_output=True, text=True)
print(resultado.stdout)

# EN TU CÓDIGO (MUCHO):
# tools/scanner.py - línea 85-92
r = subprocess.run(
    ["nmap", "-sn", self._red],  # Comando a ejecutar
    capture_output=True,          # Capturar output
    text=True,                    # Como texto
    timeout=300                   # Timeout
)
```

---

### 6.2 RE: Expresiones regulares

```python
import re

# Buscar patrón en texto:
texto = "Mi IP es 192.168.1.50"
patron = r"\d+\.\d+\.\d+\.\d+"  # Patrón de IP
match = re.search(patron, texto)
if match:
    print(match.group())  # "192.168.1.50"

# EN TU CÓDIGO:
# tools/scanner.py - línea 99-105
import re
puertos = ""
for match in re.finditer(r"(\d+)/open", output):
    puerto = int(match.group(1))
    puertos.append(puerto)
```

---

### 6.3 THREADING: Multihilo

```python
import threading

def worker():
    print("Trabajando...")

# Crear hilo:
hilo = threading.Thread(target=worker, daemon=True)
hilo.start()  # Iniciar

# EN TU CÓDIGO (CRÍTICO):
# tools/scanner.py - línea 48-50
threading.Thread(target=self._loop_arp,      daemon=True, name="scanner-arp").start()
threading.Thread(target=self._worker_nodos,  daemon=True, name="scanner-nodos").start()
threading.Thread(target=self._loop_profundo, daemon=True, name="scanner-profundo").start()
# ↑ Crea 3 hilos que corren EN PARALELO

# tools/capture.py - línea 35-50
self._hilo_watchdog = threading.Thread(
    target=self._watchdog, daemon=True, name="capture-watchdog")
self._hilo_watchdog.start()
# ↑ Crea hilo "watchdog" que vigila el principal
```

---

### 6.4 TKINTER: Interfaz gráfica

```python
import tkinter as tk

# Crear ventana:
ventana = tk.Tk()
ventana.title("Mi App")

# Crear botón:
boton = tk.Button(ventana, text="Haz click", command=lambda: print("Clickeado"))
boton.pack()

ventana.mainloop()  # Mostrar ventana

# EN TU CÓDIGO:
# ui/app.py - línea 1-5
import tkinter as tk
from tkinter import ttk, messagebox

class App:
    def __init__(self):
        self.ventana = tk.Tk()
        self.ventana.title("TopoReveal — Network Topology Viewer")
        self.ventana.configure(bg=COLOR_FONDO)
        self.ventana.geometry("1200x750")
```

---

# 🔴 NIVEL 7: CONCURRENCIA Y THREADING
## Código que corre EN PARALELO (semana 4)

### 7.1 Conceptos básicos

**¿Qué es?** Ejecutar múltiples cosas al mismo tiempo

```python
import threading
import time

def tarea1():
    for i in range(5):
        print("Tarea 1:", i)
        time.sleep(1)

def tarea2():
    for i in range(5):
        print("Tarea 2:", i)
        time.sleep(1)

# HILO 1 - Ejecutar tarea1 en paralelo:
hilo1 = threading.Thread(target=tarea1, daemon=True)
hilo1.start()

# HILO 2 - Ejecutar tarea2 en paralelo:
hilo2 = threading.Thread(target=tarea2, daemon=True)
hilo2.start()

# Ambas corren AL MISMO TIEMPO
# Sin threading: sería serial (primero tarea1, después tarea2)

# EN TU CÓDIGO - 3 HILOS EN PARALELO:
# tools/scanner.py línea 48-50
threading.Thread(target=self._loop_arp,      daemon=True).start()      # Hilo 1
threading.Thread(target=self._worker_nodos,  daemon=True).start()      # Hilo 2
threading.Thread(target=self._loop_profundo, daemon=True).start()      # Hilo 3
# Los 3 corren SIMULTÁNEAMENTE
```

---

### 7.2 Lock (Bloqueo para evitar conflictos)

```python
import threading

contador = 0
lock = threading.Lock()

def incrementar():
    global contador
    with lock:  # Bloquear acceso
        contador += 1
        print(f"Contador: {contador}")

# Sin lock: dos hilos podrían modificar al mismo tiempo (conflicto)
# Con lock: solo UNO accede a la vez

# EN TU CÓDIGO (MUCHO):
# core/topology.py - línea 30
self._lock = threading.Lock()

# Acceso seguro a nodos:
# core/topology.py - línea 53-58
with self._lock:
    if ip not in self.nodos:
        nodo_nuevo = Nodo(ip)
        self.nodos[ip] = nodo_nuevo
```

---

### 7.3 Event (Señal para controlar hilos)

```python
import threading

event = threading.Event()

def trabajador():
    while not event.is_set():  # Mientras event NO esté puesto
        print("Trabajando...")
        time.sleep(1)
    print("Me dijeron que pare")

# Crear hilo:
hilo = threading.Thread(target=trabajador, daemon=True)
hilo.start()

# Después...
event.set()  # Poner señal - el trabajador para

# EN TU CÓDIGO:
# tools/scanner.py - línea 38
self._stop_event = threading.Event()

# Usar:
while not self._stop_event.is_set():  # Mientras no digan "para"
    # Hacer trabajo
    self._arp_scan(red)

# Para detener:
self._stop_event.set()  # ← Lo paran
```

---

# 🟣 NIVEL 8: CONCEPTOS AVANZADOS
## Cosas complejas que usa tu código (semana 4)

### 8.1 List comprehensions (Sintaxis comprimida)

```python
# NORMAL:
numeros = []
for i in range(5):
    numeros.append(i * 2)
# Resultado: [0, 2, 4, 6, 8]

# COMPRIMIDO (list comprehension):
numeros = [i * 2 for i in range(5)]
# Mismo resultado, UNA línea

# EN TU CÓDIGO (COMÚN):
# core/topology.py - línea 86-87
nodos_visibles = [n for n in self.nodos.values() if not n.en_lobby]
# ↑ Obtener solo nodos que NO están en lobby

# ui/panel.py - línea 215
for nodo in sorted(nodos, key=lambda n: [int(x) for x in n.ip.split(".")]):
# ↑ Ordenar nodos por IP

# tools/scanner.py - línea 127
nuevos = [p for p in puertos if p not in nodo.puertos_abiertos]
# ↑ Obtener puertos nuevos (no en la lista anterior)
```

---

### 8.2 Lambda (Función anónima)

```python
# FUNCIÓN NORMAL:
def cuadrado(x):
    return x ** 2

# FUNCIÓN LAMBDA (comprimida):
cuadrado = lambda x: x ** 2

# USAR:
print(cuadrado(5))  # 25

# EN TU CÓDIGO (MUCHO):
# ui/panel.py - línea 215
sorted(nodos, key=lambda n: [int(x) for x in n.ip.split(".")])
# ↑ Lambda: toma nodo, retorna lista de números (para ordenar IPs)

# ui/panel_alertas.py - línea 322
ips_ord = sorted(por_ip.keys(), key=lambda ip: max(sevs) if sevs else 0)
# ↑ Lambda: toma IP, retorna su severidad máxima

# core/nodes.py - línea 316 (sorting hallazgos):
sorted(hallazgos, key=lambda h: orden.get(h.severidad, 0), reverse=True)
# ↑ Lambda: toma hallazgo, retorna número de severidad
```

---

### 8.3 Decoradores

```python
# DECORADOR: Función que modifica otra función
def decorador(funcion):
    def wrapper():
        print("Antes")
        funcion()
        print("Después")
    return wrapper

@decorador
def mi_funcion():
    print("En el medio")

mi_funcion()
# Imprime:
# Antes
# En el medio
# Después

# EN TU CÓDIGO:
# No hay decoradores explícitos, pero es patrón avanzado
```

---

### 8.4 Métodos especiales (`__nombre__`)

```python
class Persona:
    def __init__(self, nombre):
        self.nombre = nombre
    
    def __str__(self):  # ¿Cómo convertir a texto?
        return f"Persona({self.nombre})"
    
    def __repr__(self):  # ¿Cómo representar?
        return f"Persona('{self.nombre}')"
    
    def __len__(self):  # ¿Cuál es el largo?
        return len(self.nombre)

persona = Persona("Juan")
print(str(persona))   # "Persona(Juan)"
print(repr(persona))  # "Persona('Juan')"
print(len(persona))   # 4

# EN TU CÓDIGO:
# core/nodes.py - línea 84
def __repr__(self):
    return f"Nodo({self.ip}, {self.tipo}, {self.estado})"
```

---

### 8.5 Context managers (with statement)

```python
# PROBLEMA: Hay que acordarse de cerrar archivos
f = open("archivo.txt")
contenido = f.read()
f.close()  # ¡Hay que cerrar!

# SOLUCIÓN: Context manager (se cierra automáticamente)
with open("archivo.txt") as f:
    contenido = f.read()
# ↑ Se cierra automáticamente

# EN TU CÓDIGO:
# core/topology.py - línea 53-58
with self._lock:  # Bloquear
    # Acceso safe
    if ip not in self.nodos:
        self.nodos[ip] = Nodo(ip)
# ↑ Se desbloquea automáticamente al salir del with
```

---

### 8.6 f-strings (Interpolación de texto)

```python
nombre = "Juan"
edad = 30

# VIEJO:
print("Se llama " + nombre + " y tiene " + str(edad) + " años")

# NUEVO (f-string):
print(f"Se llama {nombre} y tiene {edad} años")

# CON EXPRESIONES:
print(f"Edad el próximo año: {edad + 1}")

# EN TU CÓDIGO (MUCHÍSIMO):
# tools/scanner.py - línea 19
print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
# ↑ Combina fecha con mensaje

# ui/panel.py - línea 229
self.lista.insert(tk.END, f"{prefijo} {nodo.ip:<16} {nodo.tipo}{riesgo}")
# ↑ Crea string con formato

# core/nodes.py - línea 118
h = Hallazgo(ip, puerto, nombre, sev)
```

---

### 8.7 Getters y setters (properties)

```python
class Persona:
    def __init__(self):
        self._edad = 0  # _ = privado
    
    @property  # Lectura
    def edad(self):
        return self._edad
    
    @edad.setter  # Escritura
    def edad(self, valor):
        if valor < 0:
            print("Error: edad negativa")
            return
        self._edad = valor

persona = Persona()
persona.edad = 30  # Usa el setter
print(persona.edad)  # Usa el getter

# EN TU CÓDIGO:
# No se usan properties, acceso directo:
nodo.estado = "confirmado"  # Acceso directo
nodo.veces_visto += 1       # Acceso directo
```

---

# 📊 MAPA VISUAL: DÓNDE OCURRE CADA CONCEPTO EN TU CÓDIGO

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESTRUCTURA DEL PROYECTO                       │
└─────────────────────────────────────────────────────────────────┘

MAIN.PY (Punto entrada)
  └─ Nivel 1: Variables, print
  └─ Nivel 3: Funciones (main, log)
  └─ Nivel 4: Clases (App)
  └─ Nivel 5: Try-except
  └─ Nivel 7: Threading (start scanner, capture)

CORE/ (El cerebro)
  ├─ nodes.py
  │   └─ Nivel 4: Clase Nodo (CRUCIAL)
  │   └─ Nivel 8: __repr__, __init__
  │   └─ Nivel 4: Métodos (actualizar_estado)
  │   └─ Nivel 1: If/else (máquina de estados)
  │  
  └─ topology.py
      └─ Nivel 4: Clase Topologia
      └─ Nivel 2: Diccionarios (self.nodos)
      └─ Nivel 7: Lock (thread safety)
      └─ Nivel 5: Try-except
      └─ Nivel 8: List comprehension

TOOLS/ (Las herramientas)
  ├─ scanner.py
  │   └─ Nivel 3: Funciones (log, _arp_scan, _nmap_nodo)
  │   └─ Nivel 6: subprocess (ejecutar nmap, arp)
  │   └─ Nivel 7: Threading (3 hilos paralelos)
  │   └─ Nivel 6: RE (parseador regex)
  │   └─ Nivel 8: Lambda (sorted)
  │
  ├─ capture.py
  │   └─ Nivel 7: Threading + watchdog
  │   └─ Nivel 5: Try-except
  │
  ├─ fingerprint.py
  │   └─ Nivel 3: Funciones
  │   └─ Nivel 2: Diccionarios (OUI_DB, TTL_OS)
  │
  ├─ arsenal.py
  │   └─ Nivel 3: Funciones (nmap scanning)
  │   └─ Nivel 6: subprocess
  │   └─ Nivel 7: Threading
  │
  └─ exportar.py
      └─ Nivel 3: Funciones (exportar PNG, JSON, CSV)

UI/ (La interfaz)
  ├─ app.py
  │   └─ Nivel 6: Tkinter
  │   └─ Nivel 4: Clase App
  │   └─ Nivel 7: Threading (ciclo actualización)
  │
  ├─ canvas.py
  │   └─ Nivel 6: Tkinter (Canvas)
  │   └─ Nivel 8: Lambda (sorted, key functions)
  │
  ├─ panel.py
  │   └─ Nivel 6: Tkinter (Frame, Label, Listbox)
  │   └─ Nivel 8: List comprehension
  │   └─ Nivel 8: Lambda (sorted)
  │
  └─ panel_alertas.py
      └─ Nivel 6: Tkinter
      └─ Nivel 8: Lambda (sorted)
      └─ Nivel 8: List comprehension
```

---

# 🧪 EJERCICIOS PARA PRACTICAR

## Ejercicio 1: Variables y tipos (NIVEL 1)
```python
# Crea variables:
mi_ip = "192.168.1.1"
mi_puerto = 80
activo = True

print(mi_ip)
print(mi_puerto)
print(activo)
print(type(mi_ip))
```

## Ejercicio 2: Listas (NIVEL 2)
```python
puertos = [22, 80, 443]
print(puertos[0])  # ¿22?
print(len(puertos))  # ¿3?

puertos.append(8080)
print(puertos)  # ¿[22, 80, 443, 8080]?
```

## Ejercicio 3: Diccionarios (NIVEL 2)
```python
dispositivo = {
    "ip": "192.168.1.50",
    "tipo": "router",
    "activo": True
}

print(dispositivo["ip"])
dispositivo["puerto"] = 80
print(dispositivo)
```

## Ejercicio 4: Funciones (NIVEL 3)
```python
def es_ip_valida(ip):
    partes = ip.split(".")
    if len(partes) == 4:
        return True
    return False

print(es_ip_valida("192.168.1.1"))  # True
print(es_ip_valida("192.168"))  # False
```

## Ejercicio 5: Clases (NIVEL 4)
```python
class Dispositivo:
    def __init__(self, ip, tipo):
        self.ip = ip
        self.tipo = tipo
        self.activo = False
    
    def activar(self):
        self.activo = True
        return f"{self.ip} está activo"

device = Dispositivo("192.168.1.1", "router")
print(device.activar())
```

---

# 📚 RECURSOS PARA APRENDER

## Libros recomendados
- "Python Crash Course" — Eric Matthes (mejor para principiantes)
- "Automate the Boring Stuff with Python" — Al Sweigart (gratis online)

## Sitios web
- python.org — Documentación oficial
- realpython.com — Tutoriales excelentes
- codecademy.com — Aprende interactivo

## Ver código
- Tu propio proyecto TopoReveal 😊
- GitHub.com — Busca proyectos Python

---

# ✅ CHECKLIST DE APRENDIZAJE

### Semana 1: Conceptos básicos
- [ ] Variables y tipos (int, str, bool, float)
- [ ] Operadores (=, ==, !=, <, >, and, or)
- [ ] If/else
- [ ] Print y f-strings
- [ ] Listas
- [ ] Diccionarios

### Semana 2: Funciones y estructuras
- [ ] Funciones y return
- [ ] Parámetros por defecto
- [ ] Módulos e imports
- [ ] Tuplas
- [ ] Sets

### Semana 3: OOP
- [ ] Clases y objetos
- [ ] `__init__` (constructor)
- [ ] Atributos y métodos
- [ ] `self`
- [ ] Try-except
- [ ] Librerías estándar (datetime, subprocess)

### Semana 4: Avanzado
- [ ] Threading
- [ ] Lock
- [ ] Event
- [ ] List comprehensions
- [ ] Lambda
- [ ] Métodos especiales (`__repr__`)

---

# 🎁 RESUMEN RÁPIDO

| Nivel | Concepto | Tu código | Importancia |
|-------|----------|-----------|-------------|
| 1 | Variables/tipos | DONDEQUIERA | ⭐⭐⭐⭐⭐ |
| 1 | If/else | DONDEQUIERA | ⭐⭐⭐⭐⭐ |
| 2 | Listas | nodes.py, topology.py | ⭐⭐⭐⭐⭐ |
| 2 | Diccionarios | topology.py, scanner.py | ⭐⭐⭐⭐⭐ |
| 3 | Funciones | DONDEQUIERA | ⭐⭐⭐⭐⭐ |
| 3 | Módulos/imports | INICIO DE CADA ARCHIVO | ⭐⭐⭐⭐⭐ |
| 4 | Clases | nodes.py, topology.py | ⭐⭐⭐⭐⭐ |
| 4 | Métodos | nodes.py, topology.py | ⭐⭐⭐⭐⭐ |
| 5 | Try-except | DONDEQUIERA | ⭐⭐⭐⭐ |
| 6 | subprocess | scanner.py | ⭐⭐⭐⭐ |
| 6 | Tkinter | ui/ | ⭐⭐⭐⭐ |
| 7 | Threading | scanner.py, capture.py | ⭐⭐⭐⭐ |
| 7 | Lock | topology.py | ⭐⭐⭐⭐ |
| 8 | List comprehension | UI files | ⭐⭐⭐ |
| 8 | Lambda | UI files | ⭐⭐⭐ |

---

**Documento creado:** 2026-03-13  
**Objetivo:** Aprender Python ya que participás con IA  
**Duración:** 3-4 semanas  
**Próximo paso:** Empieza por NIVEL 1, hazlos ejercicios
