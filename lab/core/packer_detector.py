"""
packer_detector.py
==================
Detección de empaquetadores (packers) mediante:

  1. Reglas YARA internas (sin necesidad de ficheros .yar externos).
  2. Heurísticas basadas en bytes mágicos del entry point.
  3. Detección de UPX por strings característicos.
  4. Identificación de otros packers por patrones de bytes.

Algoritmos
----------
- Coincidencia de patrones de bytes en el entry point: O(k) por regla.
- Búsqueda de strings fijos en el binario: O(n·m) naïve,
  optimizable con Aho-Corasick (ver string_search.py).

Uso
---
    from lab.core.packer_detector import PackerDetector

    detector = PackerDetector()
    result = detector.detect("sample.exe")
    print(result)
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# ---------------------------------------------------------------------------
# Reglas YARA integradas (string, no fichero externo)
# ---------------------------------------------------------------------------

YARA_RULES_SOURCE = r"""
rule UPX {
    meta:
        description = "Detecta binarios empaquetados con UPX"
        author      = "MalwareLab"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX2" ascii
        $upx_magic = { 55 50 58 21 }
    condition:
        any of them
}

rule ASPack {
    meta:
        description = "Detecta binarios empaquetados con ASPack"
    strings:
        $s1 = ".aspack" ascii nocase
        $s2 = ".adata"  ascii nocase
        $b1 = { 60 E8 ?? ?? ?? ?? }
    condition:
        any of them
}

rule Themida_WinLicense {
    meta:
        description = "Detecta protección Themida / WinLicense"
    strings:
        $s1 = ".themida" ascii nocase
        $s2 = "WinLicense" ascii
        $s3 = "Themida" ascii
    condition:
        any of them
}

rule VMProtect {
    meta:
        description = "Detecta protección VMProtect"
    strings:
        $s1 = ".vmp0" ascii nocase
        $s2 = ".vmp1" ascii nocase
        $s3 = "VMProtect" ascii
        $s4 = "vmp_begin" ascii
    condition:
        any of them
}

rule MPRESS {
    meta:
        description = "Detecta MPRESS packer"
    strings:
        $s1 = ".MPRESS1" ascii
        $s2 = ".MPRESS2" ascii
    condition:
        any of them
}

rule Petite {
    meta:
        description = "Detecta Petite packer"
    strings:
        $s1 = ".petite" ascii nocase
    condition:
        $s1
}

rule NsPack {
    meta:
        description = "Detecta NsPack packer"
    strings:
        $s1 = "NsPack" ascii
        $s2 = ".nsp0" ascii nocase
        $s3 = ".nsp1" ascii nocase
    condition:
        any of them
}

rule PEBundle {
    meta:
        description = "Detecta PEBundle packer"
    strings:
        $s1 = "PEBundle" ascii
        $s2 = "pebundle" ascii nocase
    condition:
        any of them
}

rule ExeStealth {
    meta:
        description = "Detecta ExeStealth packer"
    strings:
        $s1 = "eXeStealth" ascii
    condition:
        $s1
}

rule HighEntropySections {
    meta:
        description = "Posible contenido cifrado o comprimido (entrada PE con pocas imports)"
    strings:
        $getprocaddr    = "GetProcAddress" ascii
        $loadlibrary    = "LoadLibrary"    ascii
    condition:
        all of them
}
"""


# ---------------------------------------------------------------------------
# Patrones de bytes del Entry Point (sin YARA)
# ---------------------------------------------------------------------------

EP_PATTERNS: list[tuple[str, bytes]] = [
    ("UPX",    bytes([0x60, 0xBE])),                    # PUSHAD + MOV ESI
    ("UPX",    bytes([0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58])),  # PUSHAD CALL/POP
    ("ASPack", bytes([0x60, 0xE8, 0x72, 0x01, 0x00, 0x00])),
    ("Petite", bytes([0xB8, 0x00, 0x00, 0x00, 0x00, 0x68])),
]


# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class PackerMatch:
    packer: str
    method: str       # "yara", "ep_pattern", "string_search", "heuristic"
    confidence: str   # "high", "medium", "low"
    detail: str = ""


@dataclass
class PackerReport:
    file_path: str
    is_packed: bool
    matches: list[PackerMatch] = field(default_factory=list)
    can_auto_unpack: bool = False
    unpack_command: Optional[str] = None
    error: Optional[str] = None

    @property
    def packer_names(self) -> list[str]:
        return list({m.packer for m in self.matches})

    def __str__(self) -> str:
        lines = [
            "=== Packer Detection Report ===",
            f"  Archivo      : {self.file_path}",
            f"  Empaquetado  : {'SÍ' if self.is_packed else 'NO'}",
        ]
        if self.is_packed:
            lines.append(f"  Packers      : {', '.join(self.packer_names)}")
            lines.append(f"  Desempaquetado automático: {'SÍ' if self.can_auto_unpack else 'NO'}")
            if self.unpack_command:
                lines.append(f"  Comando      : {self.unpack_command}")
            lines.append("\n  Coincidencias detalladas:")
            for m in self.matches:
                lines.append(
                    f"    [{m.confidence.upper():6s}] {m.packer} via {m.method}: {m.detail}"
                )
        if self.error:
            lines.append(f"\n  Error: {self.error}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Motor principal
# ---------------------------------------------------------------------------

class PackerDetector:
    """
    Detecta empaquetadores en ejecutables PE.

    Combina reglas YARA (si disponibles) con heurísticas de bytes
    en el entry point y búsqueda de strings característicos.
    """

    def __init__(self):
        self._yara_rules = None
        if YARA_AVAILABLE:
            try:
                self._yara_rules = yara.compile(source=YARA_RULES_SOURCE)
            except Exception as exc:
                self._yara_rules = None
                self._yara_error = str(exc)

    # ------------------------------------------------------------------
    # YARA scan
    # ------------------------------------------------------------------

    def _scan_yara(self, data: bytes) -> list[PackerMatch]:
        if not self._yara_rules:
            return []
        matches = []
        try:
            for match in self._yara_rules.match(data=data):
                confidence = "high" if match.rule != "HighEntropySections" else "medium"
                matches.append(
                    PackerMatch(
                        packer     = match.rule,
                        method     = "yara",
                        confidence = confidence,
                        detail     = f"strings: {[str(s) for s in match.strings[:3]]}",
                    )
                )
        except Exception:
            pass
        return matches

    # ------------------------------------------------------------------
    # Entry point pattern matching
    # ------------------------------------------------------------------

    def _scan_ep_patterns(self, data: bytes, ep_offset: int) -> list[PackerMatch]:
        matches = []
        ep_bytes = data[ep_offset: ep_offset + 16]
        for packer, pattern in EP_PATTERNS:
            if ep_bytes.startswith(pattern):
                matches.append(
                    PackerMatch(
                        packer     = packer,
                        method     = "ep_pattern",
                        confidence = "high",
                        detail     = f"bytes EP: {ep_bytes[:8].hex()}",
                    )
                )
        return matches

    # ------------------------------------------------------------------
    # String heuristics (fallback sin YARA)
    # ------------------------------------------------------------------

    def _scan_strings(self, data: bytes) -> list[PackerMatch]:
        """Búsqueda de strings característicos de packers conocidos."""
        markers = {
            "UPX":     [b"UPX0", b"UPX1", b"UPX!"],
            "ASPack":  [b".aspack", b".adata"],
            "Themida": [b".themida", b"Themida", b"WinLicense"],
            "VMProtect": [b".vmp0", b".vmp1", b"VMProtect"],
            "MPRESS":  [b".MPRESS1", b".MPRESS2"],
            "NsPack":  [b"NsPack", b".nsp0"],
        }
        matches = []
        for packer, patterns in markers.items():
            for pat in patterns:
                if pat.lower() in data.lower():
                    matches.append(
                        PackerMatch(
                            packer     = packer,
                            method     = "string_search",
                            confidence = "medium",
                            detail     = f"string encontrado: {pat.decode(errors='replace')}",
                        )
                    )
                    break  # una coincidencia por packer es suficiente
        return matches

    # ------------------------------------------------------------------
    # Heurística PE: muy pocas imports
    # ------------------------------------------------------------------

    def _heuristic_few_imports(self, data: bytes) -> list[PackerMatch]:
        if not PEFILE_AVAILABLE:
            return []
        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            total_imports = 0
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    total_imports += len(entry.imports)
            pe.close()
            if total_imports < 5:
                return [
                    PackerMatch(
                        packer     = "UNKNOWN_PACKER",
                        method     = "heuristic",
                        confidence = "medium",
                        detail     = f"Solo {total_imports} funciones importadas (<5 sugiere packing)",
                    )
                ]
        except Exception:
            pass
        return []

    # ------------------------------------------------------------------
    # Interfaz pública
    # ------------------------------------------------------------------

    def detect(self, file_path: str | Path) -> PackerReport:
        """
        Detecta empaquetadores en el fichero dado.

        Parámetros
        ----------
        file_path : ruta al ejecutable PE.

        Retorna
        -------
        PackerReport con todos los matches y recomendaciones.
        """
        path   = Path(file_path)
        report = PackerReport(file_path=str(file_path), is_packed=False)

        try:
            data = path.read_bytes()
        except OSError as exc:
            report.error = str(exc)
            return report

        all_matches: list[PackerMatch] = []

        # 1. YARA
        all_matches.extend(self._scan_yara(data))

        # 2. Entry Point patterns (requiere pefile para calcular offset)
        ep_offset = self._get_ep_offset(data)
        if ep_offset is not None:
            all_matches.extend(self._scan_ep_patterns(data, ep_offset))

        # 3. String search (sin YARA / como confirmación)
        if not all_matches:
            all_matches.extend(self._scan_strings(data))

        # 4. Heurística de imports
        all_matches.extend(self._heuristic_few_imports(data))

        # Desduplicar por packer+método
        seen = set()
        unique: list[PackerMatch] = []
        for m in all_matches:
            key = (m.packer, m.method)
            if key not in seen:
                seen.add(key)
                unique.append(m)

        report.matches   = unique
        report.is_packed = len(unique) > 0

        # ¿Se puede desempaquetar automáticamente?
        upx_names = {"UPX"}
        if any(m.packer in upx_names for m in unique):
            report.can_auto_unpack = True
            report.unpack_command  = f"upx -d {path.name}"

        return report

    def _get_ep_offset(self, data: bytes) -> Optional[int]:
        if not PEFILE_AVAILABLE:
            return None
        try:
            pe        = pefile.PE(data=data, fast_load=True)
            ep_rva    = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_offset = pe.get_offset_from_rva(ep_rva)
            pe.close()
            return ep_offset
        except Exception:
            return None
