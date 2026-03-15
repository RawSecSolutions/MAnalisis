"""
dump_analyzer.py
================
Análisis de volcados de memoria (memory dumps) para extraer código
desempaquetado de binarios que se descomprimen en tiempo de ejecución.

Estrategia
----------
El malware empaquetado se descomprime a sí mismo en RAM antes de ejecutarse.
Un memory dump captura el proceso en ese estado "desempaquetado", permitiendo
aplicar análisis estático sobre el código real.

Fuentes de dumps
----------------
- procdump (Windows): procdump.exe -ma <pid> dump.dmp
- /proc/<pid>/mem  (Linux): lectura directa del espacio de memoria
- Volatility (Windows/Linux): vol.py -f imagen.raw --profile=... memdump
- LiME (Linux Kernel Module): adquisición de RAM completa

Este módulo procesa dumps ya obtenidos y aplica sobre ellos:
  1. Búsqueda de cabeceras PE (MZ magic) → extracción de PE incrustados.
  2. Análisis de strings con Aho-Corasick.
  3. Cálculo de entropía por bloques.
  4. Extracción de strings ASCII/Unicode legibles.
  5. Búsqueda de shellcode conocido (prólogos de función x86/x64).

Uso
---
    from lab.memory.dump_analyzer import MemoryDumpAnalyzer

    analyzer = MemoryDumpAnalyzer()
    report   = analyzer.analyze("dump.bin")
    print(report)
"""

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from lab.core.entropy       import EntropyAnalyzer
from lab.core.string_search import AhoCorasickSearcher, StringSearchReport


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

PE_MAGIC      = b"MZ"      # DOS header signature
PE_SIGNATURE  = b"PE\x00\x00"
ELF_MAGIC     = b"\x7fELF"
MAX_PE_SCAN   = 200 * 1024 * 1024  # 200 MB máximo a escanear

# Prólogos de función típicos (x86 / x64) para detectar shellcode
SHELLCODE_PROLOGUES = [
    b"\x55\x8b\xec",            # push ebp; mov ebp, esp  (x86)
    b"\x55\x89\xe5",            # push ebp; mov ebp, esp  (AT&T)
    b"\x48\x89\x5c\x24",        # mov [rsp+xx], rbx       (x64)
    b"\x40\x53\x48\x83\xec",    # push rbx; sub rsp, xx   (x64)
    b"\xfc\xe8",                 # cld; call (shellcode clásico)
    b"\x31\xc0\x50\x68",        # xor eax; push 0; push   (shellcode)
]

# Patrón de strings ASCII legibles (mínimo 4 chars imprimibles)
PRINTABLE_ASCII = re.compile(rb"[ -~]{4,}")
# Strings Unicode (UTF-16LE mínimo 4 chars)
UNICODE_PATTERN = re.compile(rb"(?:[ -~]\x00){4,}")


# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class EmbeddedPE:
    """PE incrustado encontrado en el dump de memoria."""
    offset: int
    size_estimate: int
    data: bytes = field(default=b"", repr=False)
    is_valid: bool = False
    machine_type: str = "?"
    num_sections: int = 0

    def __post_init__(self):
        if len(self.data) >= 4:
            self.is_valid = self.data[:2] == PE_MAGIC


@dataclass
class ShellcodeRegion:
    """Región con posible shellcode."""
    offset: int
    size: int
    prologue: bytes
    entropy: float


@dataclass
class ExtractedString:
    offset: int
    value: str
    encoding: str  # "ascii" o "unicode"


@dataclass
class MemoryDumpReport:
    """Informe completo del análisis del volcado de memoria."""
    dump_path: str
    dump_size: int
    embedded_pes:     list[EmbeddedPE]      = field(default_factory=list)
    shellcode_regions: list[ShellcodeRegion] = field(default_factory=list)
    extracted_strings: list[ExtractedString] = field(default_factory=list)
    string_report:    Optional[StringSearchReport] = None
    entropy_windows:  list[tuple[int, float]]      = field(default_factory=list)
    error: Optional[str] = None

    @property
    def high_entropy_regions(self) -> list[tuple[int, float]]:
        return [(off, ent) for off, ent in self.entropy_windows if ent >= 7.2]

    def __str__(self) -> str:
        lines = [
            "=== Memory Dump Analysis Report ===",
            f"  Dump         : {self.dump_path}",
            f"  Tamaño       : {self.dump_size:,} bytes",
            f"  PEs incrustados  : {len(self.embedded_pes)}",
            f"  Regiones shellcode: {len(self.shellcode_regions)}",
            f"  Strings extraídos: {len(self.extracted_strings)}",
            f"  Regiones alta entropía: {len(self.high_entropy_regions)}",
        ]
        if self.embedded_pes:
            lines.append("\n  PEs incrustados:")
            for pe in self.embedded_pes:
                valid = "✓ válido" if pe.is_valid else "✗ inválido"
                lines.append(
                    f"    0x{pe.offset:08X}  ~{pe.size_estimate:,} bytes  [{valid}]"
                    f"  arq={pe.machine_type}  secciones={pe.num_sections}"
                )
        if self.shellcode_regions:
            lines.append("\n  Regiones de shellcode:")
            for sc in self.shellcode_regions:
                lines.append(
                    f"    0x{sc.offset:08X}  {sc.size} bytes  "
                    f"entropía={sc.entropy:.3f}  "
                    f"prólogo={sc.prologue.hex()}"
                )
        if self.string_report:
            lines.append(
                f"\n  Análisis de strings (Aho-Corasick):\n"
                f"    Score: {self.string_report.total_score}  |  "
                f"{len(self.string_report.matches)} coincidencias"
            )
        if self.error:
            lines.append(f"\n  Error: {self.error}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Motor principal
# ---------------------------------------------------------------------------

class MemoryDumpAnalyzer:
    """
    Analiza volcados de memoria para extraer artefactos maliciosos.

    Parámetros
    ----------
    extract_pe    : buscar cabeceras PE incrustadas.
    extract_strings: extraer strings ASCII/Unicode legibles.
    detect_shellcode: buscar prólogos de shellcode conocidos.
    max_pe_size   : tamaño máximo a leer para cada PE incrustado.
    entropy_window: tamaño de ventana para análisis de entropía.
    """

    def __init__(
        self,
        extract_pe: bool = True,
        extract_strings: bool = True,
        detect_shellcode: bool = True,
        max_pe_size: int = 10 * 1024 * 1024,  # 10 MB por PE
        entropy_window: int = 4096,
    ):
        self.extract_pe      = extract_pe
        self.extract_strings = extract_strings
        self.detect_shellcode = detect_shellcode
        self.max_pe_size     = max_pe_size
        self.entropy_window  = entropy_window

        self._entropy_analyzer = EntropyAnalyzer(window_size=entropy_window)
        self._string_searcher  = AhoCorasickSearcher()

    # ------------------------------------------------------------------
    # Extracción de PEs incrustados
    # ------------------------------------------------------------------

    def _find_embedded_pes(self, data: bytes) -> list[EmbeddedPE]:
        """
        Busca firmas MZ en el dump y extrae los PEs incrustados.

        Algoritmo: búsqueda lineal de b"MZ" + verificación de la
        firma PE en el offset indicado por e_lfanew.
        """
        pes     = []
        offset  = 0

        while True:
            # Buscar "MZ" (firma DOS)
            idx = data.find(PE_MAGIC, offset)
            if idx == -1:
                break

            chunk = data[idx: idx + self.max_pe_size]

            # Verificar e_lfanew (offset a "PE\0\0") en bytes 0x3C-0x3F
            if len(chunk) >= 0x40:
                try:
                    e_lfanew = struct.unpack_from("<I", chunk, 0x3C)[0]
                    if e_lfanew < len(chunk) - 4:
                        pe_sig = chunk[e_lfanew: e_lfanew + 4]
                        if pe_sig == PE_SIGNATURE:
                            pe = self._parse_embedded_pe(chunk, idx, e_lfanew)
                            pes.append(pe)
                except struct.error:
                    pass

            offset = idx + 1

        return pes

    def _parse_embedded_pe(
        self, chunk: bytes, offset: int, e_lfanew: int
    ) -> EmbeddedPE:
        """Parsea cabecera básica de un PE incrustado."""
        pe = EmbeddedPE(
            offset         = offset,
            size_estimate  = len(chunk),
            data           = chunk[:min(512, len(chunk))],  # solo cabecera
            is_valid       = True,
        )

        # FILE_HEADER comienza en e_lfanew + 4 (después de "PE\0\0")
        fh_offset = e_lfanew + 4
        if len(chunk) >= fh_offset + 20:
            try:
                machine       = struct.unpack_from("<H", chunk, fh_offset)[0]
                num_sections  = struct.unpack_from("<H", chunk, fh_offset + 2)[0]
                machine_map   = {0x014c: "x86", 0x8664: "x64", 0x01c4: "ARM"}
                pe.machine_type  = machine_map.get(machine, f"0x{machine:04X}")
                pe.num_sections  = num_sections
            except struct.error:
                pass

        return pe

    # ------------------------------------------------------------------
    # Extracción de strings
    # ------------------------------------------------------------------

    def _extract_strings(self, data: bytes) -> list[ExtractedString]:
        """
        Extrae strings ASCII y Unicode legibles del dump.

        Útil cuando el malware ya se desempaquetó y el código real
        está visible en memoria.
        """
        strings: list[ExtractedString] = []

        # ASCII
        for match in PRINTABLE_ASCII.finditer(data):
            strings.append(ExtractedString(
                offset   = match.start(),
                value    = match.group().decode("ascii", errors="replace"),
                encoding = "ascii",
            ))

        # Unicode (UTF-16LE)
        for match in UNICODE_PATTERN.finditer(data):
            raw = match.group()
            # Decodificar cada par (byte, \x00)
            decoded = "".join(
                chr(raw[i]) for i in range(0, len(raw), 2)
                if raw[i + 1] == 0
            )
            strings.append(ExtractedString(
                offset   = match.start(),
                value    = decoded,
                encoding = "unicode",
            ))

        # Ordenar por offset
        strings.sort(key=lambda s: s.offset)
        return strings

    # ------------------------------------------------------------------
    # Detección de shellcode
    # ------------------------------------------------------------------

    def _detect_shellcode(self, data: bytes) -> list[ShellcodeRegion]:
        """
        Busca prólogos de shellcode conocidos en regiones ejecutables del dump.
        """
        regions: list[ShellcodeRegion] = []
        seen_offsets: set[int] = set()

        for prologue in SHELLCODE_PROLOGUES:
            offset = 0
            while True:
                idx = data.find(prologue, offset)
                if idx == -1:
                    break
                if idx not in seen_offsets:
                    # Calcular entropía del bloque de 256 bytes
                    block   = data[idx: idx + 256]
                    entropy = self._entropy_analyzer.shannon_entropy(block)
                    # Entropía alta → más probable que sea código real
                    if entropy >= 4.0:
                        regions.append(ShellcodeRegion(
                            offset   = idx,
                            size     = 256,
                            prologue = prologue,
                            entropy  = entropy,
                        ))
                        seen_offsets.add(idx)
                offset = idx + 1

        regions.sort(key=lambda r: r.offset)
        return regions

    # ------------------------------------------------------------------
    # Interfaz pública
    # ------------------------------------------------------------------

    def analyze(self, dump_path: str | Path) -> MemoryDumpReport:
        """
        Analiza un volcado de memoria completo.

        Parámetros
        ----------
        dump_path : ruta al fichero de dump.

        Retorna
        -------
        MemoryDumpReport con todos los artefactos encontrados.
        """
        path   = Path(dump_path)
        report = MemoryDumpReport(
            dump_path = str(path),
            dump_size = 0,
        )

        try:
            data = path.read_bytes()
        except OSError as exc:
            report.error = str(exc)
            return report

        report.dump_size = len(data)

        # Limitar a MAX_PE_SCAN para dumps grandes
        scan_data = data[:MAX_PE_SCAN]

        # 1. PEs incrustados
        if self.extract_pe:
            report.embedded_pes = self._find_embedded_pes(scan_data)

        # 2. Strings legibles
        if self.extract_strings:
            report.extracted_strings = self._extract_strings(scan_data)

        # 3. Shellcode
        if self.detect_shellcode:
            report.shellcode_regions = self._detect_shellcode(scan_data)

        # 4. Aho-Corasick sobre el dump completo
        try:
            self._string_searcher.build()
            report.string_report = self._string_searcher.search(
                scan_data,
                file_path = str(path),
            )
        except Exception as exc:
            report.error = f"Error en búsqueda de strings: {exc}"

        # 5. Análisis de entropía por ventanas
        try:
            entropy_report         = self._entropy_analyzer.analyze(
                path, use_sliding_window=True
            )
            report.entropy_windows = entropy_report.sliding_window
        except Exception:
            pass

        return report

    # ------------------------------------------------------------------
    # Extracción de PEs para análisis posterior
    # ------------------------------------------------------------------

    def extract_embedded_pe(
        self,
        dump_path: str | Path,
        pe_offset: int,
        output_path: str | Path,
    ) -> bool:
        """
        Extrae un PE incrustado del dump y lo guarda en disco
        para análisis estático posterior.

        Parámetros
        ----------
        dump_path  : ruta al dump de memoria.
        pe_offset  : offset del PE dentro del dump.
        output_path: ruta de salida para el PE extraído.

        Retorna True si la extracción fue exitosa.
        """
        try:
            data   = Path(dump_path).read_bytes()
            pe_data = data[pe_offset: pe_offset + self.max_pe_size]

            if not pe_data.startswith(PE_MAGIC):
                return False

            Path(output_path).write_bytes(pe_data)
            return True
        except OSError:
            return False
