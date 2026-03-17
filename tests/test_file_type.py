"""
tests/test_file_type.py
========================
Tests para detección de tipo de archivo y ajuste de scoring por formato.

Ejecutar con:
    python -m pytest tests/test_file_type.py -v
"""

import tempfile
import os

import pytest
from unittest.mock import MagicMock

from lab.core.file_type import detect_file_type, FileType
from lab.core.scoring import AnomalyScorer, _discount, ScoreContribution


# ---------------------------------------------------------------------------
# Tests de detect_file_type
# ---------------------------------------------------------------------------

class TestDetectFileType:

    def _write_tmp(self, header: bytes, suffix: str = ".bin") -> str:
        f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        f.write(header)
        # Pad to at least 512 bytes for DMG trailer tests
        f.write(b"\x00" * max(0, 512 - len(header)))
        f.close()
        return f.name

    def test_pe_magic(self):
        path = self._write_tmp(b"MZ" + b"\x00" * 14)
        try:
            assert detect_file_type(path) == FileType.PE
        finally:
            os.unlink(path)

    def test_elf_magic(self):
        path = self._write_tmp(b"\x7fELF" + b"\x00" * 12)
        try:
            assert detect_file_type(path) == FileType.ELF
        finally:
            os.unlink(path)

    def test_macho_magic_64(self):
        path = self._write_tmp(b"\xcf\xfa\xed\xfe" + b"\x00" * 12)
        try:
            assert detect_file_type(path) == FileType.MACHO
        finally:
            os.unlink(path)

    def test_zip_magic(self):
        path = self._write_tmp(b"PK\x03\x04" + b"\x00" * 12)
        try:
            assert detect_file_type(path) == FileType.ZIP
        finally:
            os.unlink(path)

    def test_pdf_magic(self):
        path = self._write_tmp(b"%PDF-1.4" + b"\x00" * 8)
        try:
            assert detect_file_type(path) == FileType.PDF
        finally:
            os.unlink(path)

    def test_dmg_by_trailer(self):
        """DMG files have a 'koly' signature in the last 512 bytes."""
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        f.write(b"\x00" * 1024)  # random data
        f.seek(-512, 2)
        f.write(b"\x00" * 100 + b"koly" + b"\x00" * 408)
        f.close()
        try:
            assert detect_file_type(f.name) == FileType.DMG
        finally:
            os.unlink(f.name)

    def test_dmg_by_extension(self):
        path = self._write_tmp(b"\x00" * 16, suffix=".dmg")
        try:
            assert detect_file_type(path) == FileType.DMG
        finally:
            os.unlink(path)

    def test_unknown_file(self):
        path = self._write_tmp(b"\x01\x02\x03\x04" * 4, suffix=".xyz")
        try:
            assert detect_file_type(path) == FileType.UNKNOWN
        finally:
            os.unlink(path)

    def test_empty_file(self):
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        f.close()
        try:
            assert detect_file_type(f.name) == FileType.UNKNOWN
        finally:
            os.unlink(f.name)

    def test_extension_fallback_exe(self):
        """Unknown magic but .exe extension should return PE."""
        path = self._write_tmp(b"\x00" * 16, suffix=".exe")
        try:
            assert detect_file_type(path) == FileType.PE
        finally:
            os.unlink(path)

    def test_extension_fallback_apk(self):
        """APK files are ZIP-based."""
        path = self._write_tmp(b"\x00" * 16, suffix=".apk")
        try:
            assert detect_file_type(path) == FileType.ZIP
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Tests de _discount helper
# ---------------------------------------------------------------------------

class TestDiscount:

    def test_discount_applies_factor(self):
        contribs = [
            ScoreContribution(source="Entropía", points=15, reason="alta"),
            ScoreContribution(source="Packer detectado", points=5, reason="UPX"),
        ]
        _discount(contribs, "Entropía", factor=0.2)
        assert contribs[0].points == 3  # round(15 * 0.2)
        assert "ajustado ×0.2" in contribs[0].reason
        # Packer should be untouched
        assert contribs[1].points == 5

    def test_discount_zero_removes_points(self):
        contribs = [
            ScoreContribution(source="Packer detectado", points=5, reason="UPX"),
        ]
        _discount(contribs, "Packer detectado", factor=0.0)
        assert contribs[0].points == 0

    def test_discount_no_match(self):
        contribs = [
            ScoreContribution(source="Strings sospechosos", points=9, reason="net"),
        ]
        _discount(contribs, "Entropía", factor=0.2)
        assert contribs[0].points == 9  # unchanged


# ---------------------------------------------------------------------------
# Tests de scoring ajustado por file_type
# ---------------------------------------------------------------------------

class TestScoringFileTypeAdjustment:

    def setup_method(self):
        self.scorer = AnomalyScorer()

    def _make_entropy_report(self, entropy: float = 7.8):
        er = MagicMock()
        er.overall_entropy = entropy
        er.high_entropy_sections = []
        return er

    def _make_packer_report(self, names=None):
        pr = MagicMock()
        pr.is_packed = True
        pr.packer_names = names or ["UPX"]
        pr.can_auto_unpack = True
        pr.unpack_command = "upx -d sample"
        return pr

    def _make_string_report(self, total_score=27):
        sr = MagicMock()
        sr.total_score = total_score
        sr.by_category = {"network": [MagicMock(severity=3)]}
        return sr

    def test_pe_no_discount(self):
        """PE files should NOT get any discount."""
        report = self.scorer.score(
            entropy_report=self._make_entropy_report(7.8),
            packer_report=self._make_packer_report(),
            string_report=self._make_string_report(),
            file_type=FileType.PE,
        )
        # No "Ajuste formato" contribution should exist
        sources = [c.source for c in report.contributions]
        assert "Ajuste formato" not in sources

    def test_unknown_no_discount(self):
        """Unknown file type should NOT get any discount."""
        report = self.scorer.score(
            entropy_report=self._make_entropy_report(7.8),
            file_type=FileType.UNKNOWN,
        )
        sources = [c.source for c in report.contributions]
        assert "Ajuste formato" not in sources

    def test_dmg_reduces_entropy(self):
        """DMG entropy contribution should be reduced to 20%."""
        report_pe = self.scorer.score(
            entropy_report=self._make_entropy_report(7.8),
            file_type=FileType.PE,
        )
        report_dmg = self.scorer.score(
            entropy_report=self._make_entropy_report(7.8),
            file_type=FileType.DMG,
        )
        assert report_dmg.total_score < report_pe.total_score

    def test_dmg_packer_zeroed(self):
        """DMG packer contribution should be zeroed out."""
        report = self.scorer.score(
            packer_report=self._make_packer_report(),
            file_type=FileType.DMG,
        )
        packer_contribs = [
            c for c in report.contributions if c.source.startswith("Packer")
        ]
        for c in packer_contribs:
            assert c.points == 0

    def test_zip_strings_halved(self):
        """ZIP string contribution should be halved."""
        report_pe = self.scorer.score(
            string_report=self._make_string_report(60),
            file_type=FileType.PE,
        )
        report_zip = self.scorer.score(
            string_report=self._make_string_report(60),
            file_type=FileType.ZIP,
        )
        assert report_zip.total_score < report_pe.total_score

    def test_dmg_fl_studio_scenario(self):
        """
        Reproduce el escenario de FL Studio .dmg:
        Entropía ~8.0 (+15), Strings genéricos (+9), Packer UPX (+5) = 29 antes.
        Con ajuste DMG debería ser ~8 o menos → LIMPIO.
        """
        report = self.scorer.score(
            entropy_report=self._make_entropy_report(8.0),
            string_report=self._make_string_report(27),  # → 9 pts base
            packer_report=self._make_packer_report(["UPX"]),
            file_type=FileType.DMG,
        )
        assert report.total_score <= 10, (
            f"Expected LIMPIO (≤10) for DMG, got {report.total_score}"
        )
        assert report.risk_level == "LIMPIO"

    def test_adjustment_note_present(self):
        """Non-PE files should have an explanatory note in contributions."""
        report = self.scorer.score(
            entropy_report=self._make_entropy_report(7.5),
            file_type=FileType.DMG,
        )
        sources = [c.source for c in report.contributions]
        assert "Ajuste formato" in sources

    def test_file_type_as_string(self):
        """file_type can be passed as a string value."""
        report = self.scorer.score(
            entropy_report=self._make_entropy_report(7.8),
            file_type="dmg",
        )
        sources = [c.source for c in report.contributions]
        assert "Ajuste formato" in sources

    def test_elf_gets_discount(self):
        """ELF files should also get packer/strings discount (not PE)."""
        report = self.scorer.score(
            packer_report=self._make_packer_report(),
            string_report=self._make_string_report(),
            file_type=FileType.ELF,
        )
        sources = [c.source for c in report.contributions]
        assert "Ajuste formato" in sources
