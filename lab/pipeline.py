"""
pipeline.py
===========
Pipeline completo de análisis de malware que orquesta todos los módulos
en el orden óptimo según los resultados de cada fase.

Flujo de decisión
-----------------

    ┌─────────────────────────────────┐
    │  1. Hash lookup (VT/MalwareBazaar)│
    │     ¿Hash conocido malicioso?    │
    └──────┬────────────────┬──────────┘
           │ SÍ             │ NO / desconocido
           ▼                ▼
      VEREDICTO       ┌─────────────────────┐
      MALICIOSO       │ 2. Análisis PE       │
                      │    metadata         │
                      └──────┬──────────────┘
                             ▼
                      ┌─────────────────────┐
                      │ 3. Entropía global  │
                      │    ¿Alta (>7.0)?    │
                      └──────┬──────────────┘
                     Alta    │ Normal
                      │      ▼
                      │  ┌───────────────────┐
                      │  │ 4. Aho-Corasick   │
                      │  │    string search  │
                      │  └───────────────────┘
                      ▼
               ┌─────────────────────┐
               │ 5. Detección packer │
               │    ¿UPX? → unpack   │
               │    ¿Complejo? → din │
               └──────┬──────────────┘
                      │
                      ▼
               ┌─────────────────────┐
               │ 6. Score final      │
               │    + recomendaciones│
               └─────────────────────┘

Uso
---
    from lab.pipeline import MalwareAnalysisPipeline

    pipeline = MalwareAnalysisPipeline(vt_api_key="...")
    result   = pipeline.analyze("muestra.exe")
    print(result.full_report())
"""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .core.hash_analysis   import HashAnalyzer, HashReport
from .core.entropy         import EntropyAnalyzer, EntropyReport
from .core.pe_analysis     import PEAnalyzer, PEReport
from .core.packer_detector import PackerDetector, PackerReport
from .core.string_search   import AhoCorasickSearcher, StringSearchReport
from .core.scoring         import AnomalyScorer, ScoringReport
from .core.file_type       import detect_file_type, FileType


# ---------------------------------------------------------------------------
# Resultado del pipeline
# ---------------------------------------------------------------------------

@dataclass
class PipelineResult:
    """Resultado completo del análisis de malware."""
    file_path: str
    analysis_time: float = 0.0

    hash_report:    Optional[HashReport]         = None
    entropy_report: Optional[EntropyReport]      = None
    pe_report:      Optional[PEReport]           = None
    packer_report:  Optional[PackerReport]       = None
    string_report:  Optional[StringSearchReport] = None
    scoring_report: Optional[ScoringReport]      = None

    file_type:      str = "unknown"

    # Flags de control del flujo
    short_circuit:  bool = False    # True si el hash fue suficiente
    skip_static:    bool = False    # True si entropía alta y no desempaquetado
    errors: list[str] = field(default_factory=list)

    def full_report(self) -> str:
        """Imprime el informe completo de todas las fases."""
        separator = "\n" + "─" * 50 + "\n"
        parts = [
            "╔══════════════════════════════════════════════════╗",
            "║         MALWARE ANALYSIS LAB - INFORME           ║",
            "╚══════════════════════════════════════════════════╝",
            f"  Archivo: {self.file_path}",
            f"  Tipo de archivo: {self.file_type}",
            f"  Tiempo de análisis: {self.analysis_time:.2f}s",
        ]

        if self.hash_report:
            parts.append(separator + str(self.hash_report))
        if self.pe_report:
            parts.append(separator + str(self.pe_report))
        if self.entropy_report:
            parts.append(separator + str(self.entropy_report))
        if self.packer_report:
            parts.append(separator + str(self.packer_report))
        if self.string_report:
            parts.append(separator + str(self.string_report))
        if self.scoring_report:
            parts.append(separator + str(self.scoring_report))
        if self.errors:
            parts.append(separator + "ERRORES:\n" + "\n".join(f"  - {e}" for e in self.errors))

        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Pipeline principal
# ---------------------------------------------------------------------------

class MalwareAnalysisPipeline:
    """
    Orquesta el análisis completo de una muestra de malware.

    Parámetros
    ----------
    vt_api_key          : clave API de VirusTotal.
    entropy_threshold   : entropía a partir de la cual se considera packing.
    skip_strings_if_packed : omitir Aho-Corasick si el archivo está empaquetado.
    query_threat_intel  : realizar consultas a threat intel (requiere internet).
    """

    ENTROPY_SUSPICIOUS = 7.0

    def __init__(
        self,
        vt_api_key: Optional[str] = None,
        entropy_threshold: float = 7.0,
        skip_strings_if_packed: bool = False,
        query_threat_intel: bool = True,
    ):
        self.vt_api_key             = vt_api_key
        self.entropy_threshold      = entropy_threshold
        self.skip_strings_if_packed = skip_strings_if_packed
        self.query_threat_intel     = query_threat_intel

        # Inicializar módulos
        self._hash_analyzer    = HashAnalyzer(vt_api_key=vt_api_key)
        self._entropy_analyzer = EntropyAnalyzer()
        self._pe_analyzer      = PEAnalyzer()
        self._packer_detector  = PackerDetector()
        self._string_searcher  = AhoCorasickSearcher()
        self._scorer           = AnomalyScorer()

        # Pre-construir el autómata Aho-Corasick una sola vez
        self._string_searcher.build()

    # ------------------------------------------------------------------
    # Análisis completo
    # ------------------------------------------------------------------

    def analyze(
        self,
        file_path: str | Path,
        verbose: bool = False,
    ) -> PipelineResult:
        """
        Ejecuta el pipeline completo de análisis estático.

        Parámetros
        ----------
        file_path : ruta al fichero a analizar.
        verbose   : imprimir progreso en tiempo real.

        Retorna
        -------
        PipelineResult con todos los informes.
        """
        start   = time.perf_counter()
        path    = Path(file_path)
        result  = PipelineResult(file_path=str(path))

        if not path.exists():
            result.errors.append(f"Fichero no encontrado: {path}")
            return result

        def log(msg: str) -> None:
            if verbose:
                print(f"  [pipeline] {msg}")

        # ----------------------------------------------------------
        # Detección de tipo de archivo
        # ----------------------------------------------------------
        file_type = detect_file_type(path)
        result.file_type = file_type.value
        log(f"Tipo de archivo detectado: {file_type.value}")

        # ----------------------------------------------------------
        # FASE 1: Hash + Threat Intelligence
        # ----------------------------------------------------------
        log("Fase 1: Calculando hashes y consultando threat intel...")
        try:
            result.hash_report = self._hash_analyzer.analyze(
                path,
                query_vt = self.query_threat_intel and bool(self.vt_api_key),
                query_mb = self.query_threat_intel,
            )

            # Short-circuit: si hay detección positiva en threat intel
            if result.hash_report.is_known_malicious:
                log("Hash encontrado como MALICIOSO. Short-circuit activado.")
                result.short_circuit = True
        except Exception as exc:
            result.errors.append(f"Fase 1 (hash): {exc}")

        # ----------------------------------------------------------
        # FASE 2: Metadatos PE (siempre, independiente del contenido)
        # ----------------------------------------------------------
        log("Fase 2: Analizando metadatos PE...")
        try:
            result.pe_report = self._pe_analyzer.analyze(path)
        except Exception as exc:
            result.errors.append(f"Fase 2 (PE): {exc}")

        # ----------------------------------------------------------
        # FASE 3: Entropía
        # ----------------------------------------------------------
        log("Fase 3: Calculando entropía...")
        try:
            # Pasar secciones al analizador de entropía si el PE es válido
            pe_sections = None
            if result.pe_report and result.pe_report.is_pe:
                pe_sections = [
                    {"name": s.name, "data": s.data}
                    for s in result.pe_report.sections
                ]

            result.entropy_report = self._entropy_analyzer.analyze(
                path,
                pe_sections        = pe_sections,
                use_sliding_window = True,
            )

            high_entropy = (
                result.entropy_report.overall_entropy >= self.entropy_threshold
            )
            if high_entropy:
                log(
                    f"Entropía alta ({result.entropy_report.overall_entropy:.3f}). "
                    "Probable packing."
                )
        except Exception as exc:
            result.errors.append(f"Fase 3 (entropía): {exc}")

        # ----------------------------------------------------------
        # FASE 4: Aho-Corasick string search
        # (se ejecuta incluso con alta entropía para detectar strings del packer)
        # ----------------------------------------------------------
        high_entropy = (
            result.entropy_report is not None
            and result.entropy_report.overall_entropy >= self.entropy_threshold
        )
        should_skip = self.skip_strings_if_packed and high_entropy

        if not should_skip:
            log("Fase 4: Búsqueda de strings con Aho-Corasick...")
            try:
                result.string_report = self._string_searcher.search_file(
                    str(path),
                    deduplicate = True,
                )
            except Exception as exc:
                result.errors.append(f"Fase 4 (strings): {exc}")
        else:
            log("Fase 4: Omitida (alta entropía + skip_strings_if_packed=True)")

        # ----------------------------------------------------------
        # FASE 5: Detección de packer
        # ----------------------------------------------------------
        log("Fase 5: Detectando packer...")
        try:
            result.packer_report = self._packer_detector.detect(path)
            if result.packer_report.is_packed:
                log(
                    f"Packer detectado: {', '.join(result.packer_report.packer_names)}"
                )
                if result.packer_report.can_auto_unpack:
                    log(
                        f"Desempaquetado automático disponible: "
                        f"{result.packer_report.unpack_command}"
                    )
        except Exception as exc:
            result.errors.append(f"Fase 5 (packer): {exc}")

        # ----------------------------------------------------------
        # FASE 6: Score final
        # ----------------------------------------------------------
        log("Fase 6: Calculando score de anomalía...")
        try:
            result.scoring_report = self._scorer.score(
                hash_report    = result.hash_report,
                pe_report      = result.pe_report,
                entropy_report = result.entropy_report,
                string_report  = result.string_report,
                packer_report  = result.packer_report,
                file_type      = file_type,
            )
        except Exception as exc:
            result.errors.append(f"Fase 6 (scoring): {exc}")

        result.analysis_time = time.perf_counter() - start
        log(f"Análisis completado en {result.analysis_time:.2f}s")
        return result

    # ------------------------------------------------------------------
    # Análisis de dump de memoria
    # ------------------------------------------------------------------

    def analyze_memory_dump(
        self,
        dump_path: str | Path,
        verbose: bool = False,
    ) -> "PipelineResult":
        """
        Analiza un volcado de memoria para extraer código desempaquetado.

        Parámetros
        ----------
        dump_path : ruta al fichero de dump (.bin, .dmp, .raw).
        """
        from .memory.dump_analyzer import MemoryDumpAnalyzer

        start  = time.perf_counter()
        path   = Path(dump_path)
        result = PipelineResult(file_path=str(path))

        if verbose:
            print(f"  [pipeline] Analizando dump de memoria: {path}")

        try:
            dump_analyzer  = MemoryDumpAnalyzer()
            dump_report    = dump_analyzer.analyze(path)

            # Reusar el string_report del dump
            if dump_report.string_report:
                result.string_report = dump_report.string_report

            # Score basado en strings del dump
            result.scoring_report = self._scorer.score(
                string_report = result.string_report,
            )
        except Exception as exc:
            result.errors.append(f"Memory dump analysis: {exc}")

        result.analysis_time = time.perf_counter() - start
        return result
