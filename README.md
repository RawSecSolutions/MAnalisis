# Malware Analysis Lab

Laboratorio educativo de análisis de malware en Python, diseñado para ejecutarse en **Kali Linux**. Implementa desde cero los algoritmos y técnicas usados en análisis estático y dinámico de ejecutables, con documentación interna detallada en cada módulo.

---

## Arquitectura general

```
malware-analysis-lab/
├── main.py                    # CLI principal
├── requirements.txt
├── lab/
│   ├── pipeline.py            # Orquestador del flujo completo
│   ├── core/                  # Análisis estático
│   │   ├── hash_analysis.py   # SHA-256 + VirusTotal + MalwareBazaar
│   │   ├── entropy.py         # Entropía de Shannon (ventana deslizante)
│   │   ├── pe_analysis.py     # Metadatos PE con pefile
│   │   ├── packer_detector.py # Detección de packers (YARA + heurísticas)
│   │   ├── string_search.py   # Búsqueda multi-patrón (Aho-Corasick)
│   │   └── scoring.py         # Score de anomalía unificado
│   ├── dynamic/               # Análisis dinámico
│   │   ├── process_tree.py    # BFS sobre árbol de procesos
│   │   ├── network_monitor.py # Conexiones de red + detección DGA/beaconing
│   │   └── sandbox.py         # Orquestador de sandbox (strace + FS + red)
│   └── memory/
│       └── dump_analyzer.py   # Análisis de volcados de memoria
├── yara_rules/
│   ├── packers.yar            # Reglas YARA para packers conocidos
│   └── suspicious_strings.yar # Reglas YARA para familias de malware
├── tests/
│   ├── test_entropy.py
│   ├── test_string_search.py
│   ├── test_pe_analysis.py
│   └── test_scoring.py
└── samples/
    ├── benign/                # Muestras benignas para pruebas
    └── suspicious/            # NUNCA subir malware real al repo
```

---

## Flujo de análisis

```
┌──────────────────────────────────────────┐
│  1. Hash lookup (VT / MalwareBazaar)     │  ← Primer paso siempre
│     ¿Conocido malicioso? → STOP (70-80%) │
└──────────────────┬───────────────────────┘
                   │ desconocido / limpio
                   ▼
┌──────────────────────────────────────────┐
│  2. Metadatos PE (siempre, sin importar  │
│     si está empaquetado)                 │
│     - timestamp, secciones, imports      │
│     - anomalías → puntos de score        │
└──────────────────┬───────────────────────┘
                   ▼
┌──────────────────────────────────────────┐
│  3. Entropía de Shannon                  │
│     < 7.0 → análisis estático normal     │
│     ≥ 7.0 → probable packing             │
└──────────────┬───────────────────────────┘
          Alta │                Normal │
               ▼                       ▼
┌──────────────────────┐   ┌───────────────────────┐
│  5. Detección packer │   │  4. Aho-Corasick       │
│     UPX → unpack auto│   │     búsqueda de strings│
│     Complejo → dinámi│   │     maliciosos         │
└──────────┬───────────┘   └───────────────────────┘
           │
           ▼
┌──────────────────────────────────────────┐
│  6. Score final + recomendaciones        │
│     0-10: LIMPIO                         │
│     11-25: SOSPECHOSO                    │
│     26-50: PROBABLE MALWARE              │
│     51+:   MALWARE                       │
└──────────────────────────────────────────┘
```

---

## Instalación (Kali Linux)

### 1. Dependencias del sistema

```bash
sudo apt update
sudo apt install -y python3-pip tcpdump strace upx-ucl yara
```

### 2. Entorno Python

```bash
# Clonar el repositorio
git clone <repo-url>
cd malware-analysis-lab

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

### 3. Configurar API keys (opcional)

```bash
cp .env.example .env
# Editar .env con tu API key de VirusTotal
```

---

## Uso

### Pipeline completo

```bash
# Análisis estático completo
python main.py analyze /ruta/a/muestra.exe --verbose

# Con API key de VirusTotal
python main.py analyze muestra.exe --vt-key TU_CLAVE_AQUI

# Sin consultas a internet (modo offline)
python main.py analyze muestra.exe --no-intel

# Guardar informe en JSON
python main.py analyze muestra.exe --output informe.json
```

### Análisis individuales

```bash
# Solo hashes + threat intel
python main.py hash muestra.exe

# Entropía de Shannon
python main.py entropy muestra.exe

# Metadatos PE
python main.py pe muestra.exe

# Detección de packer
python main.py packer muestra.exe

# Búsqueda de strings maliciosos (Aho-Corasick)
python main.py strings muestra.exe
```

### Análisis dinámico (requiere VM aislada)

```bash
# Monitorear árbol de procesos de un PID (BFS)
python main.py monitor --pid 1234 --duration 30

# Snapshot de procesos del sistema
python main.py monitor

# Monitoreo de red
python main.py network --pid 1234

# Captura de tráfico con tcpdump (requiere root)
sudo python main.py network --capture --interface eth0 --duration 30
```

### Análisis de volcados de memoria

```bash
# Analizar un dump de memoria
python main.py memdump dump.bin

# Extraer PEs incrustados al directorio ./extracted/
python main.py memdump dump.bin --extract-pes ./extracted/
```

---

## Algoritmos implementados

### Aho-Corasick (búsqueda multi-patrón)

Busca simultáneamente N patrones en el binario en **O(n + m + z)** donde:
- `n` = tamaño del fichero
- `m` = suma de longitudes de patrones
- `z` = número de coincidencias

Mucho más eficiente que buscar cada patrón por separado O(n·k).

**Implementación:** `lab/core/string_search.py`

### Entropía de Shannon

Mide la aleatoriedad de los bytes:

```
H = -Σ p(x) · log₂(p(x))
```

- `< 4.0` → datos estructurados / texto
- `4.0–6.5` → binario normal
- `> 7.0` → cifrado / compresión / packing

**Implementación:** `lab/core/entropy.py`

### BFS sobre árbol de procesos

Descubre todos los procesos descendientes de un PID raíz en **O(V + E)**.
Detecta procesos sospechosos (cmd.exe, powershell, LOLBins) y calcula
la profundidad del árbol.

**Implementación:** `lab/dynamic/process_tree.py`

### Detección DGA (Domain Generation Algorithm)

Calcula la entropía del nombre de dominio y detecta patrones
(sin vocales, labels largos con números) para identificar dominios
generados algorítmicamente por C2.

**Implementación:** `lab/dynamic/network_monitor.py`

### Detección de beaconing

Analiza intervalos entre conexiones de red. Un coeficiente de variación
bajo (`CV < 0.2`) indica intervalos regulares → beaconing de C2.

**Implementación:** `lab/dynamic/network_monitor.py::detect_beaconing`

---

## Tests

```bash
# Ejecutar todos los tests
python -m pytest tests/ -v

# Con cobertura
pip install pytest-cov
python -m pytest tests/ -v --cov=lab --cov-report=html
```

---

## Estrategia completa para binarios empaquetados

| Situación | Acción |
|-----------|--------|
| Hash match en VT/MalwareBazaar | Veredicto inmediato |
| Entropía baja (< 7.0) | Análisis estático completo |
| UPX detectado | `upx -d archivo.exe` → análisis estático |
| Packer complejo (Themida, VMProtect) | Análisis dinámico en sandbox |
| En sandbox: proceso en ejecución | Memory dump → analizar con `memdump` |

---

## Advertencias de seguridad

- **NUNCA** ejecutar muestras de malware fuera de una VM aislada
- La sandbox (`SandboxRunner`) ejecuta el binario literalmente
- Usar snapshots de VM para restaurar después de cada análisis
- No conectar la VM de análisis a redes de producción
- Las capturas de red pueden contener datos sensibles

---

## Dependencias principales

| Librería | Uso |
|----------|-----|
| `pefile` | Parseo de cabeceras PE |
| `yara-python` | Reglas YARA para detección de packers |
| `psutil` | Monitoreo de procesos y red |
| `requests` | Consultas a VirusTotal / MalwareBazaar |

**Herramientas del sistema:**
- `tcpdump` — captura de tráfico de red
- `strace` — trazado de llamadas al sistema
- `upx` — desempaquetado automático de UPX
- `volatility` — análisis avanzado de dumps de memoria (externo)
