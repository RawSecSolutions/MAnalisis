"""
tests/test_entropy.py
=====================
Tests unitarios para el módulo de cálculo de entropía.

Ejecutar con:
    python -m pytest tests/test_entropy.py -v
    python -m pytest tests/ -v
"""

import math
import tempfile
from pathlib import Path

import pytest

from lab.core.entropy import EntropyAnalyzer, classify_entropy


# ---------------------------------------------------------------------------
# Tests de clasificación
# ---------------------------------------------------------------------------

class TestClassifyEntropy:

    def test_muy_baja(self):
        assert classify_entropy(0.0) == "muy_baja"
        assert classify_entropy(0.5) == "muy_baja"

    def test_baja(self):
        assert classify_entropy(1.0) == "baja"
        assert classify_entropy(3.5) == "baja"

    def test_normal(self):
        assert classify_entropy(4.0) == "normal"
        assert classify_entropy(6.0) == "normal"

    def test_sospechosa(self):
        assert classify_entropy(6.5) == "sospechosa"
        assert classify_entropy(7.0) == "sospechosa"

    def test_alta(self):
        assert classify_entropy(7.2) == "alta"
        assert classify_entropy(7.9) == "alta"


# ---------------------------------------------------------------------------
# Tests del motor de entropía
# ---------------------------------------------------------------------------

class TestShannonEntropy:

    def setup_method(self):
        self.analyzer = EntropyAnalyzer()

    def test_empty_data(self):
        """Datos vacíos → entropía 0."""
        assert self.analyzer.shannon_entropy(b"") == 0.0

    def test_all_same_bytes(self):
        """Todos los bytes iguales → entropía 0."""
        data = b"\x00" * 1000
        assert self.analyzer.shannon_entropy(data) == 0.0

    def test_two_values_equal_prob(self):
        """Dos valores con probabilidad 0.5 cada uno → entropía 1.0."""
        data = bytes([0, 1] * 500)
        entropy = self.analyzer.shannon_entropy(data)
        assert abs(entropy - 1.0) < 0.001

    def test_uniform_distribution(self):
        """
        256 bytes distintos en distribución uniforme → entropía máxima = 8.0.
        """
        data    = bytes(range(256)) * 4  # cada byte aparece 4 veces
        entropy = self.analyzer.shannon_entropy(data)
        assert abs(entropy - 8.0) < 0.001

    def test_text_lower_entropy(self):
        """Texto ASCII normal tiene entropía entre 3.5 y 5.5."""
        text    = b"Hello, this is a normal text with repeated characters. " * 50
        entropy = self.analyzer.shannon_entropy(text)
        assert 3.5 < entropy < 6.0

    def test_random_like_bytes_high_entropy(self):
        """Bytes con distribución uniforme → entropía alta."""
        import os
        data    = bytes(range(256)) * 100
        entropy = self.analyzer.shannon_entropy(data)
        assert entropy > 7.9


# ---------------------------------------------------------------------------
# Tests del analizador de ficheros
# ---------------------------------------------------------------------------

class TestEntropyAnalyzer:

    def setup_method(self):
        self.analyzer = EntropyAnalyzer(window_size=256, window_step=128)

    def _make_temp_file(self, content: bytes) -> Path:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        tmp.write(content)
        tmp.close()
        return Path(tmp.name)

    def test_analyze_all_zeros(self):
        path   = self._make_temp_file(b"\x00" * 4096)
        report = self.analyzer.analyze(path)
        assert report.overall_entropy == 0.0
        assert report.classification == "muy_baja"
        assert not report.is_suspicious
        path.unlink()

    def test_analyze_uniform_bytes(self):
        path   = self._make_temp_file(bytes(range(256)) * 16)
        report = self.analyzer.analyze(path)
        assert report.overall_entropy > 7.9
        assert report.is_suspicious
        path.unlink()

    def test_analyze_sliding_window(self):
        # Fichero: mitad ceros (entropía 0) + mitad uniforme (entropía 8)
        half    = 2048
        content = b"\x00" * half + bytes(range(256)) * (half // 256)
        path    = self._make_temp_file(content)
        report  = self.analyzer.analyze(path, use_sliding_window=True)
        # Debe haber ventanas con entropía alta y baja
        entropies = [e for _, e in report.sliding_window]
        assert any(e > 6.0 for e in entropies), "Debe detectar ventanas de alta entropía"
        assert any(e < 1.0 for e in entropies), "Debe detectar ventanas de baja entropía"
        path.unlink()

    def test_report_str(self):
        path   = self._make_temp_file(b"hello world" * 100)
        report = self.analyzer.analyze(path)
        output = str(report)
        assert "Entropy Report" in output
        assert "bits" in output
        path.unlink()

    def test_file_size_in_report(self):
        content = b"A" * 1024
        path    = self._make_temp_file(content)
        report  = self.analyzer.analyze(path)
        assert report.file_size == 1024
        path.unlink()


# ---------------------------------------------------------------------------
# Tests de rendimiento básico
# ---------------------------------------------------------------------------

class TestEntropyPerformance:

    def test_large_file_performance(self):
        """El análisis de 1 MB no debería tardar más de 1 segundo."""
        import time
        analyzer = EntropyAnalyzer(window_size=4096, window_step=2048)
        data     = bytes(range(256)) * (1024 * 4)  # ~1 MB

        start = time.perf_counter()
        entropy = analyzer.shannon_entropy(data)
        elapsed = time.perf_counter() - start

        assert elapsed < 1.0, f"Demasiado lento: {elapsed:.3f}s"
        assert entropy > 7.9
