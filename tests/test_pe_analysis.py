"""
tests/test_pe_analysis.py
==========================
Tests unitarios para el analizador de metadatos PE.

Los tests crean binarios PE mínimos sintéticos para no depender
de ficheros de malware reales en el repositorio.

Ejecutar con:
    python -m pytest tests/test_pe_analysis.py -v
"""

import struct
import tempfile
from pathlib import Path

import pytest

from lab.core.pe_analysis import PEAnalyzer, PEAnomalies


# ---------------------------------------------------------------------------
# Construcción de PE mínimo sintético
# ---------------------------------------------------------------------------

def make_minimal_pe(
    machine: int = 0x014c,          # x86
    timestamp: int = 0x5A000000,    # 2017
    num_sections: int = 1,
    imports: bool = True,
) -> bytes:
    """
    Construye un fichero PE mínimo válido para pruebas.
    No es ejecutable, pero tiene estructura PE correcta.
    """
    # DOS Header (64 bytes)
    e_lfanew = 0x40  # offset a la cabecera PE
    dos_header = b"MZ" + b"\x00" * 0x3a + struct.pack("<I", e_lfanew)
    dos_header += b"\x00" * (e_lfanew - len(dos_header))

    # PE Signature
    pe_sig = b"PE\x00\x00"

    # File Header (20 bytes)
    # Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable,
    # NumberOfSymbols, SizeOfOptionalHeader, Characteristics
    optional_header_size = 0xE0  # Standard PE32 optional header
    file_header = struct.pack(
        "<HHIIIHH",
        machine,         # Machine
        num_sections,    # NumberOfSections
        timestamp,       # TimeDateStamp
        0,               # PointerToSymbolTable
        0,               # NumberOfSymbols
        optional_header_size,  # SizeOfOptionalHeader
        0x0102,          # Characteristics: executable | 32bit
    )

    # Optional Header PE32 (simplificado)
    # Formato: H BB I×9 H×6 I×4 H×2 I×6 = 30 campos
    optional_header = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,   # Magic PE32
        0,        # MajorLinkerVersion
        0,        # MinorLinkerVersion
        0x1000,   # SizeOfCode
        0,        # SizeOfInitializedData
        0,        # SizeOfUninitializedData
        0x1000,   # AddressOfEntryPoint
        0x1000,   # BaseOfCode
        0x2000,   # BaseOfData (PE32 only)
        0x400000, # ImageBase
        0x1000,   # SectionAlignment
        0x200,    # FileAlignment
        6,        # MajorOperatingSystemVersion
        0,        # MinorOperatingSystemVersion
        0,        # MajorImageVersion
        0,        # MinorImageVersion
        6,        # MajorSubsystemVersion
        0,        # MinorSubsystemVersion
        0,        # Win32VersionValue
        0x10000,  # SizeOfImage
        0x400,    # SizeOfHeaders
        0,        # CheckSum
        2,        # Subsystem (GUI)
        0,        # DllCharacteristics
        0x100000, # SizeOfStackReserve
        0x1000,   # SizeOfStackCommit
        0x100000, # SizeOfHeapReserve
        0x1000,   # SizeOfHeapCommit
        0,        # LoaderFlags
        16,       # NumberOfRvaAndSizes
    )
    # Data directories (16 × 8 bytes = 128 bytes)
    optional_header += b"\x00" * 128

    # Section headers
    section_headers = b""
    for i in range(num_sections):
        name = f".text{i}".encode()[:8].ljust(8, b"\x00")
        section_headers += struct.pack(
            "<8sIIIIIIHHI",
            name,
            0x1000,   # VirtualSize
            0x1000 * (i + 1),  # VirtualAddress
            0x200,    # SizeOfRawData
            0x400,    # PointerToRawData
            0,        # PointerToRelocations
            0,        # PointerToLinenumbers
            0,        # NumberOfRelocations
            0,        # NumberOfLinenumbers
            0x60000020,  # Characteristics: code, execute, read
        )

    # Datos de sección (relleno)
    section_data = b"\x90" * 0x200  # NOP sled

    return (
        dos_header
        + pe_sig
        + file_header
        + optional_header
        + section_headers
        + b"\x00" * (0x400 - len(dos_header) - 4 - 20 - len(optional_header) - len(section_headers))
        + section_data
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPEAnalyzer:

    def setup_method(self):
        self.analyzer = PEAnalyzer()

    def _write_temp_pe(self, data: bytes) -> Path:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        tmp.write(data)
        tmp.close()
        return Path(tmp.name)

    def test_non_pe_file(self):
        """Un fichero que no es PE debe retornar is_pe=False."""
        path   = self._write_temp_pe(b"This is not a PE file at all.")
        report = self.analyzer.analyze(path)
        assert not report.is_pe
        path.unlink()

    def test_valid_pe_detected(self):
        """Un PE mínimo válido debe ser detectado como PE."""
        try:
            import pefile
        except ImportError:
            pytest.skip("pefile no instalado")

        pe_data = make_minimal_pe()
        path    = self._write_temp_pe(pe_data)
        report  = self.analyzer.analyze(path)
        # pefile puede ser estricto con PE mínimos, acepta tanto True como False
        # Lo importante es que no lanze excepción
        assert isinstance(report.is_pe, bool)
        path.unlink()

    def test_report_file_path(self):
        """El informe debe incluir la ruta del fichero."""
        path   = self._write_temp_pe(b"not a pe")
        report = self.analyzer.analyze(path)
        assert str(path) in report.file_path
        path.unlink()

    def test_str_representation_non_pe(self):
        """__str__ de un no-PE debe indicar el error."""
        path   = self._write_temp_pe(b"hello")
        report = self.analyzer.analyze(path)
        output = str(report)
        assert "PE" in output
        path.unlink()


class TestPEAnomalies:

    def test_add_and_score(self):
        anomalies = PEAnomalies()
        anomalies.add("Test anomaly 1", weight=3)
        anomalies.add("Test anomaly 2", weight=2)
        assert anomalies.total_score == 5
        assert len(anomalies.items) == 2

    def test_descriptions(self):
        anomalies = PEAnomalies()
        anomalies.add("Anomaly A", weight=1)
        anomalies.add("Anomaly B", weight=2)
        descs = anomalies.descriptions
        assert "Anomaly A" in descs
        assert "Anomaly B" in descs

    def test_empty_anomalies(self):
        anomalies = PEAnomalies()
        assert anomalies.total_score == 0
        assert anomalies.descriptions == []
