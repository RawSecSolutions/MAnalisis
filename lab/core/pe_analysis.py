"""
pe_analysis.py
==============
Análisis de metadatos de ejecutables PE (Portable Executable) usando pefile.

Qué extrae
----------
1. Cabeceras generales: arquitectura, timestamp de compilación, número de secciones.
2. Tabla de importaciones (IAT): funciones y DLLs importadas.
3. Secciones: nombre, tamaño raw vs virtual, entropía (calculada externamente).
4. Directorio de recursos: versión, metadatos.
5. Indicadores de anomalías:
   - Timestamp falso o en el futuro.
   - Secciones con nombres extraños o ratio raw/virtual anómalo.
   - Muy pocas imports (indicador de packing).
   - Presencia de secciones con nombres de packers conocidos.
   - Entry point fuera de la primera sección.

Uso
---
    from lab.core.pe_analysis import PEAnalyzer

    pe_analyzer = PEAnalyzer()
    report = pe_analyzer.analyze("sample.exe")
    print(report)
"""

import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constantes de referencia
# ---------------------------------------------------------------------------

# Secciones cuyo nombre delata el packer
PACKER_SECTION_NAMES = {
    ".upx0", ".upx1", ".upx2",
    "upx0",  "upx1",  "upx2",
    ".aspack", ".adata",
    ".themida", ".vmp0", ".vmp1", ".vmp2",
    ".mpress1", ".mpress2",
    ".petite",
    "pebundle",
    ".nsp0", ".nsp1", ".nsp2",
}

# Funciones de importación asociadas con packing / evasión
SUSPICIOUS_IMPORTS = {
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress",
    "VirtualAlloc", "VirtualAllocEx",
    "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    "SetWindowsHookEx",
    "RegSetValueEx",
    "CreateProcessA", "CreateProcessW",
    "ShellExecuteA", "ShellExecuteW",
    "WinExec",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpenA", "InternetConnectA",
    "WSAStartup", "socket", "connect",
}

# Máquinas / arquitecturas
MACHINE_TYPES = {
    0x014c: "x86 (i386)",
    0x0200: "Itanium",
    0x8664: "x64 (AMD64)",
    0x01c4: "ARM Thumb-2",
    0xaa64: "ARM64",
}


# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: int
    data: bytes = field(default=b"", repr=False)

    @property
    def is_packer_section(self) -> bool:
        return self.name.lower() in PACKER_SECTION_NAMES

    @property
    def virtual_raw_ratio(self) -> float:
        """Ratio virtual_size / raw_size. >3 es sospechoso (se descomprime en mem)."""
        return self.virtual_size / self.raw_size if self.raw_size > 0 else float("inf")

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)  # IMAGE_SCN_MEM_WRITE


@dataclass
class ImportEntry:
    dll: str
    functions: list[str] = field(default_factory=list)

    @property
    def suspicious_functions(self) -> list[str]:
        return [f for f in self.functions if f in SUSPICIOUS_IMPORTS]


@dataclass
class PEAnomalies:
    """Lista de anomalías detectadas con sus pesos para el score."""
    items: list[tuple[str, int]] = field(default_factory=list)  # (descripcion, peso)

    def add(self, description: str, weight: int = 1) -> None:
        self.items.append((description, weight))

    @property
    def total_score(self) -> int:
        return sum(w for _, w in self.items)

    @property
    def descriptions(self) -> list[str]:
        return [d for d, _ in self.items]


@dataclass
class PEReport:
    """Informe completo del análisis PE."""
    file_path: str
    is_pe: bool = False
    error: Optional[str] = None

    # Cabecera
    machine_type: str = "?"
    timestamp: Optional[datetime.datetime] = None
    timestamp_raw: int = 0
    num_sections: int = 0
    entry_point: int = 0
    image_base: int = 0
    subsystem: str = "?"

    # Secciones
    sections: list[PESection] = field(default_factory=list)

    # Importaciones
    imports: list[ImportEntry] = field(default_factory=list)

    # Anomalías
    anomalies: PEAnomalies = field(default_factory=PEAnomalies)

    @property
    def total_imports(self) -> int:
        return sum(len(imp.functions) for imp in self.imports)

    @property
    def all_suspicious_imports(self) -> list[str]:
        result = []
        for imp in self.imports:
            result.extend(imp.suspicious_functions)
        return result

    def __str__(self) -> str:
        if not self.is_pe:
            return f"=== PE Report ===\n  No es un PE válido: {self.error}"

        lines = [
            "=== PE Analysis Report ===",
            f"  Archivo        : {self.file_path}",
            f"  Arquitectura   : {self.machine_type}",
            f"  Timestamp      : {self.timestamp or 'N/A'} (raw={self.timestamp_raw})",
            f"  Secciones      : {self.num_sections}",
            f"  Entry Point    : 0x{self.entry_point:08X}",
            f"  Image Base     : 0x{self.image_base:016X}",
            f"  Total Imports  : {self.total_imports}",
            "",
            "  Secciones PE:",
        ]
        for s in self.sections:
            flags = []
            if s.is_packer_section:
                flags.append("PACKER")
            if s.virtual_raw_ratio > 3:
                flags.append(f"ratio={s.virtual_raw_ratio:.1f}x")
            if s.is_executable and s.is_writable:
                flags.append("RWX")
            flag_str = f"  [{', '.join(flags)}]" if flags else ""
            lines.append(
                f"    {s.name:<12} vsize={s.virtual_size:>8,}  "
                f"rsize={s.raw_size:>8,}{flag_str}"
            )

        if self.imports:
            lines.append("\n  DLLs importadas:")
            for imp in self.imports:
                susp = imp.suspicious_functions
                lines.append(f"    {imp.dll}  ({len(imp.functions)} funciones)")
                if susp:
                    lines.append(f"      ⚠ Sospechosas: {', '.join(susp)}")

        if self.anomalies.items:
            lines.append(f"\n  Anomalías detectadas (score={self.anomalies.total_score}):")
            for desc, weight in self.anomalies.items:
                lines.append(f"    [{weight:+d}] {desc}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Motor principal
# ---------------------------------------------------------------------------

class PEAnalyzer:
    """
    Analiza ejecutables PE y genera un informe de anomalías.

    Funciona aunque el contenido esté cifrado/empaquetado porque
    lee únicamente las cabeceras, que siempre están en texto claro.
    """

    SUSPICIOUS_RATIO_THRESHOLD = 3.0
    MIN_LEGITIMATE_IMPORTS     = 5

    def analyze(self, file_path: str | Path) -> PEReport:
        """
        Analiza el fichero PE y devuelve un PEReport.

        Parámetros
        ----------
        file_path : ruta al ejecutable.
        """
        if not PEFILE_AVAILABLE:
            report       = PEReport(file_path=str(file_path), is_pe=False)
            report.error = "pefile no está instalado. Ejecuta: pip install pefile"
            return report

        path   = Path(file_path)
        report = PEReport(file_path=str(file_path))

        try:
            pe = pefile.PE(str(path), fast_load=False)
        except pefile.PEFormatError as exc:
            report.is_pe = False
            report.error = str(exc)
            return report
        except Exception as exc:
            report.is_pe = False
            report.error = f"Error al parsear PE: {exc}"
            return report

        report.is_pe = True

        # ------------------------------------------------------------------
        # Cabecera FILE_HEADER
        # ------------------------------------------------------------------
        fh = pe.FILE_HEADER
        report.machine_type  = MACHINE_TYPES.get(fh.Machine, f"0x{fh.Machine:04X}")
        report.timestamp_raw = fh.TimeDateStamp
        report.num_sections  = fh.NumberOfSections

        try:
            report.timestamp = datetime.datetime.utcfromtimestamp(fh.TimeDateStamp)
        except (OSError, OverflowError, ValueError):
            report.anomalies.add("Timestamp inválido o fuera de rango", weight=2)

        # Timestamp futuro
        if report.timestamp and report.timestamp > datetime.datetime.utcnow():
            report.anomalies.add(
                f"Timestamp en el futuro: {report.timestamp}", weight=3
            )

        # Timestamp muy antiguo (año < 1995 = probablemente falso)
        if report.timestamp and report.timestamp.year < 1995:
            report.anomalies.add(
                f"Timestamp sospechosamente antiguo: {report.timestamp.year}", weight=2
            )

        # ------------------------------------------------------------------
        # Cabecera OPTIONAL_HEADER
        # ------------------------------------------------------------------
        oh = pe.OPTIONAL_HEADER
        report.entry_point = oh.AddressOfEntryPoint
        report.image_base  = oh.ImageBase

        subsystem_map = {
            1: "Native", 2: "GUI", 3: "Console",
            5: "OS/2 CUI", 7: "POSIX CUI", 9: "WinCE GUI",
        }
        report.subsystem = subsystem_map.get(oh.Subsystem, f"0x{oh.Subsystem:02X}")

        # ------------------------------------------------------------------
        # Secciones
        # ------------------------------------------------------------------
        ep_in_first_section = False

        for i, section in enumerate(pe.sections):
            try:
                name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            except Exception:
                name = "???"

            raw_data = section.get_data() or b""

            pe_section = PESection(
                name            = name,
                virtual_address = section.VirtualAddress,
                virtual_size    = section.Misc_VirtualSize,
                raw_size        = section.SizeOfRawData,
                characteristics = section.Characteristics,
                data            = raw_data,
            )
            report.sections.append(pe_section)

            # ¿EP en esta sección?
            va_start = section.VirtualAddress
            va_end   = va_start + section.Misc_VirtualSize
            if va_start <= report.entry_point < va_end:
                ep_in_first_section = (i == 0)

            # Anomalía: nombre de sección = packer conocido
            if pe_section.is_packer_section:
                report.anomalies.add(
                    f"Sección '{name}' coincide con nombre de packer conocido", weight=4
                )

            # Anomalía: ratio virtual/raw alto
            if pe_section.virtual_raw_ratio > self.SUSPICIOUS_RATIO_THRESHOLD:
                report.anomalies.add(
                    f"Sección '{name}' tiene ratio vsize/rsize = "
                    f"{pe_section.virtual_raw_ratio:.1f}x (>3 indica descompresión en memoria)",
                    weight=3,
                )

            # Anomalía: sección ejecutable Y escribible (RWX)
            if pe_section.is_executable and pe_section.is_writable:
                report.anomalies.add(
                    f"Sección '{name}' tiene permisos RWX (ejecutable + escribible)", weight=3
                )

            # Anomalía: nombre vacío o no imprimible
            if not name.strip() or any(ord(c) > 127 for c in name):
                report.anomalies.add(
                    f"Nombre de sección no ASCII: '{repr(name)}'", weight=2
                )

        # Entry point fuera de la primera sección
        if not ep_in_first_section and report.sections:
            report.anomalies.add(
                f"Entry point (0x{report.entry_point:X}) está fuera de la primera sección",
                weight=2,
            )

        # ------------------------------------------------------------------
        # Tabla de importaciones (IAT)
        # ------------------------------------------------------------------
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll = entry.dll.decode("utf-8", errors="replace")
                except Exception:
                    dll = "???"

                functions = []
                for imp in entry.imports:
                    if imp.name:
                        try:
                            functions.append(imp.name.decode("utf-8", errors="replace"))
                        except Exception:
                            functions.append("???")
                    elif imp.ordinal:
                        functions.append(f"ord_{imp.ordinal}")

                report.imports.append(ImportEntry(dll=dll, functions=functions))

        # Pocas importaciones → probable packing
        if report.total_imports < self.MIN_LEGITIMATE_IMPORTS:
            report.anomalies.add(
                f"Solo {report.total_imports} imports totales "
                f"(< {self.MIN_LEGITIMATE_IMPORTS} sugiere packing)",
                weight=4,
            )

        # Importaciones sospechosas
        for func in report.all_suspicious_imports:
            report.anomalies.add(
                f"Importación de alto riesgo: {func}", weight=2
            )

        pe.close()
        return report
