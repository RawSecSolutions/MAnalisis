# MAnalisis — Laboratorio de Análisis de Malware

> Creado y diseñado por **Emilio Castillo Schmidt** con [claude.ai](https://claude.ai)

Laboratorio educativo de análisis de malware en Python, diseñado para ejecutarse en **Kali Linux**. Implementa desde cero los algoritmos y técnicas usados en análisis estático y dinámico de ejecutables, con documentación interna detallada en cada módulo.

---

## Características principales

| Capacidad | Descripción |
|-----------|-------------|
| **Análisis estático** | Hashes, entropía de Shannon, metadatos PE, búsqueda Aho-Corasick, detección de packers |
| **Threat Intelligence** | Consultas a VirusTotal v3 y MalwareBazaar |
| **Análisis dinámico** | Monitoreo de procesos (BFS), red (DGA/beaconing), sandbox con strace |
| **Análisis de memoria** | Extracción de PEs incrustados, detección de shellcode, análisis de strings |
| **Scoring unificado** | Puntuación 0-999 con clasificación de riesgo y recomendaciones automáticas |
| **Detección de tipo de archivo** | Magic bytes para PE, ELF, Mach-O, DMG, ZIP, PDF — ajusta scoring por formato |

---

## Arquitectura del proyecto

```
MAnalisis/
├── main.py                        # CLI principal (argparse)
├── requirements.txt               # Dependencias Python
├── .env.example                   # Variables de entorno de ejemplo
├── .gitignore
├── lab/
│   ├── __init__.py
│   ├── pipeline.py                # Orquestador del flujo completo (6 etapas)
│   ├── core/                      # Módulos de análisis estático
│   │   ├── __init__.py
│   │   ├── hash_analysis.py       # MD5/SHA-1/SHA-256 + VirusTotal + MalwareBazaar
│   │   ├── entropy.py             # Entropía de Shannon (ventana deslizante)
│   │   ├── file_type.py           # Detección de tipo por magic bytes
│   │   ├── pe_analysis.py         # Metadatos PE con pefile + detección de anomalías
│   │   ├── packer_detector.py     # Detección de packers (YARA + heurísticas)
│   │   ├── string_search.py       # Búsqueda multi-patrón (Aho-Corasick)
│   │   └── scoring.py             # Score de anomalía unificado
│   ├── dynamic/                   # Módulos de análisis dinámico
│   │   ├── __init__.py
│   │   ├── process_tree.py        # BFS sobre árbol de procesos
│   │   ├── network_monitor.py     # Conexiones de red + detección DGA/beaconing
│   │   └── sandbox.py             # Orquestador de sandbox (strace + FS + red)
│   └── memory/                    # Análisis de volcados de memoria
│       ├── __init__.py
│       └── dump_analyzer.py       # Extracción de PEs + shellcode + strings
├── yara_rules/                    # Reglas YARA
│   ├── packers.yar                # 11 reglas para packers conocidos
│   └── suspicious_strings.yar     # 11 reglas para familias de malware
└── tests/                         # Suite de tests
    ├── __init__.py
    ├── test_entropy.py
    ├── test_file_type.py
    ├── test_pe_analysis.py
    ├── test_scoring.py
    └── test_string_search.py
```

---

## Flujo de análisis (pipeline de 6 etapas)

```
┌──────────────────────────────────────────┐
│  1. Hash + Threat Intel                  │
│     VT / MalwareBazaar                   │
│     ¿Conocido malicioso? → cortocircuito │
└──────────────────┬───────────────────────┘
                   │ desconocido / limpio
                   ▼
┌──────────────────────────────────────────┐
│  2. Metadatos PE                         │
│     Timestamp, secciones, imports        │
│     Anomalías → puntos de score          │
└──────────────────┬───────────────────────┘
                   ▼
┌──────────────────────────────────────────┐
│  3. Entropía de Shannon                  │
│     Global + por sección + ventanas      │
│     < 7.0 → normal   ≥ 7.0 → packing    │
└──────────────────┬───────────────────────┘
                   ▼
┌──────────────────────────────────────────┐
│  4. Aho-Corasick (strings maliciosos)    │
│     70+ patrones en 7 categorías         │
│     Lectura por chunks para archivos     │
│     grandes (>100 MB)                    │
└──────────────────┬───────────────────────┘
                   ▼
┌──────────────────────────────────────────┐
│  5. Detección de packer                  │
│     YARA + patrones EP + heurísticas     │
│     UPX → unpack automático              │
│     Complejo → análisis dinámico         │
└──────────────────┬───────────────────────┘
                   ▼
┌──────────────────────────────────────────┐
│  6. Score final + recomendaciones        │
│     Ajuste por tipo de archivo           │
│     0-10:  LIMPIO                        │
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
git clone https://github.com/RawSecSolutions/MAnalisis.git
cd MAnalisis

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
# Obtener en: https://www.virustotal.com/gui/my-apikey
```

---

## Uso

### Pipeline completo

```bash
# Análisis estático completo con verbose
python main.py analyze muestra.exe --verbose

# Con API key de VirusTotal
python main.py analyze muestra.exe --vt-key TU_CLAVE_AQUI

# Sin consultas a internet (modo offline)
python main.py analyze muestra.exe --no-intel

# Guardar informe en JSON
python main.py analyze muestra.exe --output informe.json

# Combinación completa
python main.py analyze muestra.exe --vt-key TU_CLAVE --verbose --output informe.json
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

# Monitoreo de red por PID
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

## Comandos disponibles

| Comando | Descripción |
|---------|-------------|
| `analyze` | Pipeline completo de 6 etapas (hash → PE → entropía → strings → packer → score) |
| `hash` | Cálculo de hashes + consulta a threat intel |
| `entropy` | Entropía de Shannon con ventana deslizante |
| `pe` | Extracción de metadatos PE |
| `packer` | Detección de packers |
| `strings` | Búsqueda Aho-Corasick de strings maliciosos |
| `memdump` | Análisis de volcados de memoria + extracción de PEs |
| `monitor` | Monitoreo de árbol de procesos (BFS en tiempo real) |
| `network` | Snapshot de conexiones / captura con tcpdump |

### Opciones globales

| Opción | Descripción |
|--------|-------------|
| `--vt-key` | API key de VirusTotal v3 |
| `--no-intel` | Modo offline (omitir consultas a threat intel) |
| `--verbose` | Mostrar progreso detallado |
| `--output` | Guardar informe en formato JSON |

---

## Algoritmos implementados

### Aho-Corasick (búsqueda multi-patrón)

Busca simultáneamente N patrones en el binario en **O(n + m + z)** donde:
- `n` = tamaño del fichero
- `m` = suma de longitudes de patrones
- `z` = número de coincidencias

Mucho más eficiente que buscar cada patrón por separado O(n·k). Implementa un trie con suffix links (función de fallo por BFS) y output links. Soporta lectura por chunks para archivos mayores a 100 MB.

**Implementación:** `lab/core/string_search.py`

### Entropía de Shannon

Mide la aleatoriedad de los bytes:

```
H = -Σ p(x) · log₂(p(x))    para cada valor de byte 0-255
```

| Rango | Interpretación |
|-------|---------------|
| `< 1.0` | Altamente estructurado (un solo valor dominante) |
| `1.0 – 4.0` | Datos estructurados / texto |
| `4.0 – 6.5` | Código binario normal |
| `> 7.0` | Cifrado / compresión / packing |

Incluye análisis global, por sección PE y por ventana deslizante (4 KB ventana, 2 KB stride por defecto).

**Implementación:** `lab/core/entropy.py`

### BFS sobre árbol de procesos

Descubre todos los procesos descendientes de un PID raíz en **O(V + E)**.
Detecta procesos sospechosos (cmd.exe, powershell, LOLBins, rutas temp, encoding base64) y calcula la profundidad del árbol. Dos modos: snapshot del sistema completo o monitoreo continuo.

**Implementación:** `lab/dynamic/process_tree.py`

### Detección DGA (Domain Generation Algorithm)

Heurísticas para identificar dominios generados algorítmicamente:
- Entropía del label ≥ 3.8 bits/carácter
- Labels largos (>20 caracteres) con 4+ dígitos consecutivos
- Labels sin vocales
- Sin coincidencia con prefijos legítimos

**Implementación:** `lab/dynamic/network_monitor.py`

### Detección de beaconing

Analiza intervalos entre conexiones de red. Un coeficiente de variación bajo (`CV < 0.2`) indica intervalos regulares → beaconing de C2.

**Implementación:** `lab/dynamic/network_monitor.py`

### Detección de tipo de archivo

Identificación por magic bytes para múltiples formatos: PE (MZ), ELF, Mach-O, DMG (koly trailer), ZIP, PDF. Ajusta el scoring para evitar falsos positivos en formatos comprimidos.

**Implementación:** `lab/core/file_type.py`

---

## Sistema de scoring

### Clasificación de riesgo

| Score | Clasificación | Acción recomendada |
|-------|--------------|-------------------|
| 0-10 | **LIMPIO** | Aparenta ser seguro, verificar en VT |
| 11-25 | **SOSPECHOSO** | Requiere revisión adicional |
| 26-50 | **PROBABLE MALWARE** | Indicadores fuertes, análisis en sandbox |
| 51+ | **MALWARE** | Alta confianza, NO ejecutar |

### Contribuciones al score

| Señal | Puntos |
|-------|--------|
| Hash en threat intel | +25 a +60 |
| Anomalías PE (10+ tipos) | +0 a +30 |
| Entropía > 7.5 | +15 |
| Entropía > 7.0 | +8 |
| Entropía > 6.5 | +3 |
| Secciones de alta entropía | +0 a +10 |
| Strings sospechosos (Aho-Corasick) | +0 a +20 (normalizado) |
| Packer complejo (Themida, VMProtect) | +15 |
| Packer común (UPX) | +5 |
| Otros packers | +8 |

El sistema ajusta automáticamente el score según el tipo de archivo detectado, reduciendo penalizaciones de entropía y packer para formatos comprimidos (ZIP, DMG, etc.).

---

## Reglas YARA

### `yara_rules/packers.yar` — 11 reglas

Detección de packers conocidos: UPX, ASPack, Themida/WinLicense, VMProtect, MPRESS, Petite, NsPack, PEBundle y heurística genérica.

### `yara_rules/suspicious_strings.yar` — 11 reglas

Detección de familias y comportamientos maliciosos:
- Robo de credenciales (LSASS, mimikatz)
- Reverse shell (cmd.exe, socket, C2)
- Ransomware (CryptEncrypt, bitcoin)
- Inyección de procesos (VirtualAllocEx, CreateRemoteThread)
- Persistencia en registro (HKLM\Run, RegSetValueEx)
- Keylogger (GetAsyncKeyState, SetWindowsHookEx)
- Anti-análisis (IsDebuggerPresent, VMware)
- Download & Execute (URLDownload + CreateProcess)
- PowerShell malicioso (-EncodedCommand, IEX, DownloadString)

---

## Categorías de strings maliciosos (Aho-Corasick)

El motor de búsqueda incluye **70+ patrones** organizados en 7 categorías:

| Categoría | Ejemplos |
|-----------|----------|
| **Red** | http://, socket, InternetOpen, WSAStartup |
| **Persistencia** | RegSetValueEx, HKEY_RUN, schtasks |
| **Inyección** | VirtualAllocEx, CreateRemoteThread, WriteProcessMemory |
| **Evasión** | IsDebuggerPresent, Sleep, NtQueryInformationProcess |
| **Robo de credenciales** | lsass, mimikatz, SAM, credential |
| **Ransomware** | CryptEncrypt, decrypt, bitcoin, .locked |
| **Indicadores C2** | cmd.exe, powershell, eval, /bin/sh |

---

## Estrategia para binarios empaquetados

| Situación | Acción |
|-----------|--------|
| Hash match en VT/MalwareBazaar | Veredicto inmediato (cortocircuito) |
| Entropía baja (< 7.0) | Análisis estático completo |
| UPX detectado | `upx -d archivo.exe` → análisis estático |
| Packer complejo (Themida, VMProtect) | Análisis dinámico en sandbox |
| Proceso en ejecución en sandbox | Memory dump → analizar con `memdump` |

---

## Tests

```bash
# Ejecutar todos los tests
python -m pytest tests/ -v

# Con cobertura
pip install pytest-cov
python -m pytest tests/ -v --cov=lab

# Reporte HTML de cobertura
python -m pytest tests/ -v --cov=lab --cov-report=html
```

Tests disponibles:
- `test_entropy.py` — Cálculo de entropía de Shannon
- `test_file_type.py` — Detección de tipo por magic bytes
- `test_pe_analysis.py` — Parseo de cabeceras PE
- `test_scoring.py` — Combinación de scores
- `test_string_search.py` — Búsqueda Aho-Corasick

---

## Dependencias

### Python (requirements.txt)

| Librería | Uso |
|----------|-----|
| `pefile` | Parseo de cabeceras PE |
| `yara-python` | Compilación y ejecución de reglas YARA |
| `psutil` | Monitoreo de procesos y conexiones de red |
| `requests` | Consultas HTTP a VirusTotal / MalwareBazaar |
| `colorama` | Colores en terminal (opcional) |
| `tabulate` | Formateo de tablas en terminal (opcional) |

### Herramientas del sistema (Kali Linux)

| Herramienta | Uso |
|-------------|-----|
| `tcpdump` | Captura de tráfico de red |
| `strace` | Trazado de llamadas al sistema |
| `upx-ucl` | Desempaquetado automático de binarios UPX |
| `yara` | Motor de reglas YARA |

---

## Variables de entorno

| Variable | Descripción | Default |
|----------|-------------|---------|
| `VT_API_KEY` | API key de VirusTotal v3 | — |
| `ENTROPY_THRESHOLD` | Umbral de entropía sospechosa | `7.0` |
| `NETWORK_INTERFACE` | Interfaz de red para tcpdump | `eth0` |

---

## Advertencias de seguridad

- **NUNCA** ejecutar muestras de malware fuera de una VM aislada
- La sandbox (`SandboxRunner`) ejecuta el binario literalmente — usar solo en entorno controlado
- Usar snapshots de VM para restaurar después de cada análisis
- No conectar la VM de análisis a redes de producción
- Las capturas de red y volcados de memoria pueden contener datos sensibles
- Los volcados de memoria deben adquirirse con herramientas externas (procdump, Volatility, etc.)

---

## Licencia

Proyecto educativo. Uso bajo responsabilidad del usuario.

---

> Creado y diseñado por **Emilio Castillo Schmidt** con [claude.ai](https://claude.ai)
