"""
tests/test_string_search.py
============================
Tests unitarios para el motor Aho-Corasick.

Ejecutar con:
    python -m pytest tests/test_string_search.py -v
"""

import pytest
from lab.core.string_search import AhoCorasickSearcher, _AhoCorasickNode


# ---------------------------------------------------------------------------
# Tests del autómata
# ---------------------------------------------------------------------------

class TestAhoCorasickBuild:

    def test_build_empty_patterns(self):
        searcher = AhoCorasickSearcher()
        searcher.build(patterns=[])
        assert searcher._built

    def test_build_single_pattern(self):
        searcher = AhoCorasickSearcher()
        searcher.build(patterns=[("hello", "test", 1)])
        assert searcher._built

    def test_build_multiple_patterns(self):
        searcher = AhoCorasickSearcher()
        patterns = [("abc", "cat1", 1), ("def", "cat2", 2), ("abcdef", "cat3", 3)]
        searcher.build(patterns=patterns)
        assert searcher._built


class TestAhoCorasickSearch:

    def setup_method(self):
        self.searcher = AhoCorasickSearcher(case_insensitive=False)

    def test_no_match(self):
        self.searcher.build(patterns=[("xyz", "test", 1)])
        report = self.searcher.search(b"hello world")
        assert len(report.matches) == 0

    def test_single_match(self):
        self.searcher.build(patterns=[("hello", "greet", 3)])
        report = self.searcher.search(b"hello world")
        assert len(report.matches) == 1
        assert report.matches[0].pattern == "hello"

    def test_multiple_patterns_found(self):
        self.searcher.build(patterns=[
            ("cat", "animal", 1),
            ("dog", "animal", 1),
            ("fish", "animal", 1),
        ])
        data   = b"I have a cat and a dog but no fish"
        report = self.searcher.search(data, deduplicate=False)
        patterns_found = {m.pattern for m in report.matches}
        assert "cat"  in patterns_found
        assert "dog"  in patterns_found
        assert "fish" in patterns_found

    def test_overlapping_patterns(self):
        """Aho-Corasick debe detectar patrones que se solapan."""
        self.searcher.build(patterns=[
            ("abc",    "t1", 1),
            ("abcdef", "t2", 2),
            ("def",    "t3", 3),
        ])
        data   = b"abcdef"
        report = self.searcher.search(data, deduplicate=False)
        patterns_found = {m.pattern for m in report.matches}
        # Todos deben ser detectados
        assert "abc"    in patterns_found
        assert "abcdef" in patterns_found
        assert "def"    in patterns_found

    def test_case_insensitive(self):
        searcher = AhoCorasickSearcher(case_insensitive=True)
        searcher.build(patterns=[("GetProcAddress", "api", 3)])
        data   = b"GETPROCADDRESS in binary"
        report = searcher.search(data)
        assert len(report.matches) == 1

    def test_case_sensitive(self):
        searcher = AhoCorasickSearcher(case_insensitive=False)
        searcher.build(patterns=[("GetProcAddress", "api", 3)])
        data   = b"GETPROCADDRESS in binary"
        report = searcher.search(data)
        assert len(report.matches) == 0

    def test_offset_correctness(self):
        """El offset debe apuntar al inicio del patrón."""
        self.searcher.build(patterns=[("needle", "test", 1)])
        haystack = b"find the needle in the haystack"
        report   = self.searcher.search(haystack, deduplicate=False)
        assert len(report.matches) == 1
        offset = report.matches[0].offset
        assert haystack[offset: offset + 6] == b"needle"

    def test_deduplication(self):
        """Con deduplicate=True, solo debe aparecer una vez por patrón."""
        self.searcher.build(patterns=[("abc", "t", 1)])
        data   = b"abc abc abc abc"
        report_dedup  = self.searcher.search(data, deduplicate=True)
        report_all    = self.searcher.search(data, deduplicate=False)
        assert len(report_dedup.matches) == 1
        assert len(report_all.matches)   == 4

    def test_severity_ordering(self):
        """Matches deben estar ordenados por severidad descendente."""
        self.searcher.build(patterns=[
            ("low",  "cat", 1),
            ("high", "cat", 5),
            ("mid",  "cat", 3),
        ])
        data   = b"high mid low"
        report = self.searcher.search(data)
        if len(report.matches) >= 2:
            assert report.matches[0].severity >= report.matches[1].severity

    def test_score_aggregation(self):
        self.searcher.build(patterns=[
            ("cmd.exe",   "c2", 3),
            ("powershell", "c2", 3),
        ])
        data   = b"cmd.exe powershell"
        report = self.searcher.search(data)
        assert report.total_score == 6


# ---------------------------------------------------------------------------
# Tests con patrones de malware reales
# ---------------------------------------------------------------------------

class TestMalwarePatterns:

    def setup_method(self):
        self.searcher = AhoCorasickSearcher(case_insensitive=True)
        self.searcher.build()  # carga ALL_PATTERNS

    def test_detects_network_strings(self):
        data   = b"WSAStartup socket connect URLDownloadToFile"
        report = self.searcher.search(data)
        cats   = set(report.by_category.keys())
        assert "network" in cats

    def test_detects_injection_strings(self):
        data   = b"VirtualAllocEx WriteProcessMemory CreateRemoteThread"
        report = self.searcher.search(data)
        cats   = set(report.by_category.keys())
        assert "injection" in cats

    def test_detects_ransomware_strings(self):
        data   = b"CryptEncrypt Your files have been encrypted ransom bitcoin"
        report = self.searcher.search(data)
        cats   = set(report.by_category.keys())
        assert "ransomware" in cats

    def test_clean_binary_low_score(self):
        """Un texto sin strings maliciosos debe tener score bajo."""
        data   = b"Hello World. This is a clean test file with no malicious content."
        report = self.searcher.search(data)
        assert report.total_score < 10


# ---------------------------------------------------------------------------
# Tests de rendimiento
# ---------------------------------------------------------------------------

class TestAhoCorasickPerformance:

    def test_large_text_performance(self):
        """Búsqueda en 1 MB debe completarse en < 2 segundos."""
        import time
        searcher = AhoCorasickSearcher()
        searcher.build()

        data  = b"A" * (512 * 1024) + b"GetProcAddress VirtualAllocEx" + b"B" * (512 * 1024 - 30)
        start = time.perf_counter()
        searcher.search(data)
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, f"Aho-Corasick demasiado lento: {elapsed:.3f}s"

    def test_many_patterns_build_time(self):
        """Construir el autómata con 100 patrones debe ser rápido."""
        import time
        patterns = [(f"pattern_{i}", "test", 1) for i in range(100)]
        searcher = AhoCorasickSearcher()

        start = time.perf_counter()
        searcher.build(patterns=patterns)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.1, f"Build demasiado lento: {elapsed:.3f}s"
