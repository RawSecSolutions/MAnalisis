"""
tests/test_scoring.py
======================
Tests unitarios para el sistema de puntuación de anomalías.

Ejecutar con:
    python -m pytest tests/test_scoring.py -v
"""

import pytest
from lab.core.scoring import AnomalyScorer, ScoringReport, classify_score


class TestClassifyScore:

    def test_limpio(self):
        label, _ = classify_score(0)
        assert label == "LIMPIO"
        label, _ = classify_score(10)
        assert label == "LIMPIO"

    def test_sospechoso(self):
        label, _ = classify_score(11)
        assert label == "SOSPECHOSO"
        label, _ = classify_score(25)
        assert label == "SOSPECHOSO"

    def test_probable_malware(self):
        label, _ = classify_score(26)
        assert label == "PROBABLE MALWARE"
        label, _ = classify_score(50)
        assert label == "PROBABLE MALWARE"

    def test_malware(self):
        label, _ = classify_score(51)
        assert label == "MALWARE"
        label, _ = classify_score(100)
        assert label == "MALWARE"


class TestAnomalyScorer:

    def setup_method(self):
        self.scorer = AnomalyScorer()

    def test_no_reports_gives_zero_score(self):
        report = self.scorer.score()
        assert report.total_score == 0
        assert report.risk_level == "LIMPIO"

    def test_malicious_hash_gives_high_score(self):
        """Un hash conocido malicioso debe dar score alto."""
        from unittest.mock import MagicMock
        from lab.core.hash_analysis import ThreatIntelResult, HashReport

        ti_result = ThreatIntelResult(
            service      = "VirusTotal",
            found        = True,
            malicious    = True,
            detections   = 40,
            total_engines= 70,
        )
        hash_report = HashReport(
            file_path  = "test.exe",
            md5        = "a" * 32,
            sha1       = "b" * 40,
            sha256     = "c" * 64,
            file_size  = 1000,
            threat_intel = [ti_result],
        )
        report = self.scorer.score(hash_report=hash_report)
        assert report.total_score >= 50
        assert report.risk_level == "MALWARE"

    def test_high_entropy_adds_points(self):
        """Entropía alta debe incrementar el score."""
        from unittest.mock import MagicMock

        entropy_report = MagicMock()
        entropy_report.overall_entropy    = 7.8
        entropy_report.high_entropy_sections = []

        report = self.scorer.score(entropy_report=entropy_report)
        assert report.total_score >= 10

    def test_packed_binary_adds_points(self):
        """Packer detectado debe incrementar el score."""
        from unittest.mock import MagicMock

        packer_report = MagicMock()
        packer_report.is_packed      = True
        packer_report.packer_names   = ["UPX"]
        packer_report.can_auto_unpack = True
        packer_report.unpack_command  = "upx -d sample.exe"

        report = self.scorer.score(packer_report=packer_report)
        assert report.total_score > 0

    def test_themida_higher_than_upx(self):
        """Themida debe dar score mayor que UPX."""
        from unittest.mock import MagicMock

        def make_packer(names):
            p = MagicMock()
            p.is_packed = True
            p.packer_names = names
            p.can_auto_unpack = False
            p.unpack_command = None
            return p

        report_upx     = self.scorer.score(packer_report=make_packer(["UPX"]))
        report_themida = self.scorer.score(packer_report=make_packer(["Themida"]))
        assert report_themida.total_score > report_upx.total_score

    def test_contributions_listed(self):
        """El informe debe incluir las contribuciones al score."""
        from unittest.mock import MagicMock

        entropy_report = MagicMock()
        entropy_report.overall_entropy = 7.5
        entropy_report.high_entropy_sections = []

        report = self.scorer.score(entropy_report=entropy_report)
        assert len(report.contributions) > 0

    def test_str_representation(self):
        report = self.scorer.score()
        output = str(report)
        assert "VEREDICTO" in output
        assert "Score" in output

    def test_recommendations_included(self):
        """Debe incluir recomendaciones según el contexto."""
        from unittest.mock import MagicMock

        packer_report = MagicMock()
        packer_report.is_packed = True
        packer_report.packer_names = ["Themida"]
        packer_report.can_auto_unpack = False
        packer_report.unpack_command = None

        report = self.scorer.score(packer_report=packer_report)
        assert len(report.recommendations) > 0
