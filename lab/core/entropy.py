"""
entropy.py
==========
Cálculo de entropía de Shannon para detectar cifrado, compresión o empaquetado.

Teoría
------
La entropía de Shannon mide la aleatoriedad de una secuencia de bytes.
Se calcula como:

    H = -Σ p(x) · log₂(p(x))   para cada byte x con probabilidad p(x) > 0

Rango: 0 (todos los bytes iguales) → 8 (distribución perfectamente uniforme).

Umbrales prácticos
------------------
  < 1.0   →  Texto muy simple (relleno de ceros, NUL padding)
  1.0–4.0 →  Texto legible / datos estructurados
  4.0–6.5 →  Binario normal (código compilado)
  6.5–7.2 →  Posible compresión ligera o cifrado parcial
  > 7.2   →  Alta probabilidad de cifrado / compresión / packing

Uso
---
    from lab.core.entropy import EntropyAnalyzer

    ea = EntropyAnalyzer()
    report = ea.analyze("sample.exe")
    print(report)
"""

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Umbrales y clasificaciones
# ---------------------------------------------------------------------------

ENTROPY_THRESHOLDS = {
    "muy_baja":   (0.0, 1.0),
    "baja":       (1.0, 4.0),
    "normal":     (4.0, 6.5),
    "sospechosa": (6.5, 7.2),
    "alta":       (7.2, 8.01),
}


def classify_entropy(value: float) -> str:
    for label, (lo, hi) in ENTROPY_THRESHOLDS.items():
        if lo <= value < hi:
            return label
    return "alta"


# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class SectionEntropy:
    """Entropía de una sección PE específica."""
    name: str
    entropy: float
    size: int
    classification: str = ""

    def __post_init__(self):
        self.classification = classify_entropy(self.entropy)


@dataclass
class EntropyReport:
    """Informe completo de entropía del fichero."""
    file_path: str
    file_size: int
    overall_entropy: float
    classification: str
    is_suspicious: bool
    section_entropies: list[SectionEntropy] = field(default_factory=list)
    # Entropía por ventana deslizante (offset, entropy)
    sliding_window: list[tuple[int, float]] = field(default_factory=list)

    @property
    def high_entropy_sections(self) -> list[SectionEntropy]:
        return [s for s in self.section_entropies if s.entropy >= 7.2]

    def __str__(self) -> str:
        alert = " ⚠ SOSPECHOSO" if self.is_suspicious else ""
        lines = [
            "=== Entropy Report ===",
            f"  Archivo        : {self.file_path}",
            f"  Tamaño         : {self.file_size:,} bytes",
            f"  Entropía total : {self.overall_entropy:.4f} bits  [{self.classification}]{alert}",
        ]
        if self.section_entropies:
            lines.append("  Secciones PE:")
            for s in self.section_entropies:
                flag = " <-- ALTA" if s.entropy >= 7.2 else ""
                lines.append(
                    f"    {s.name:<12} {s.entropy:.4f}  ({s.size:,} bytes){flag}"
                )
        if self.sliding_window:
            lines.append(
                f"  Ventanas altas : "
                f"{sum(1 for _, e in self.sliding_window if e >= 7.2)} / "
                f"{len(self.sliding_window)}"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Motor de cálculo
# ---------------------------------------------------------------------------

class EntropyAnalyzer:
    """
    Calcula la entropía de Shannon de un fichero completo y por bloques.

    Parámetros
    ----------
    window_size  : int
        Tamaño de la ventana deslizante en bytes (0 = desactivado).
    window_step  : int
        Paso entre ventanas consecutivas (stride).
    suspicious_threshold : float
        Umbral a partir del cual se marca el archivo como sospechoso.
    """

    def __init__(
        self,
        window_size: int = 4096,
        window_step: int = 2048,
        suspicious_threshold: float = 7.0,
    ):
        self.window_size           = window_size
        self.window_step           = window_step
        self.suspicious_threshold  = suspicious_threshold

    # ------------------------------------------------------------------
    # Cálculo de entropía (núcleo)
    # ------------------------------------------------------------------

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """
        Calcula la entropía de Shannon de un bloque de bytes.

        Complejidad: O(n) donde n = len(data).
        """
        if not data:
            return 0.0

        # Tabla de frecuencias: O(n)
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        total   = len(data)
        entropy = 0.0

        # Σ -p·log₂(p): O(256) → constante
        for count in freq:
            if count > 0:
                p        = count / total
                entropy -= p * math.log2(p)

        return entropy

    # ------------------------------------------------------------------
    # Análisis por ventana deslizante
    # ------------------------------------------------------------------

    def sliding_window_entropy(
        self, data: bytes
    ) -> list[tuple[int, float]]:
        """
        Calcula la entropía en ventanas deslizantes sobre el fichero.

        Útil para localizar regiones cifradas dentro de un binario
        que en promedio tiene entropía normal.

        Retorna: lista de (offset_inicio, entropia)
        """
        results = []
        size    = len(data)
        offset  = 0

        while offset + self.window_size <= size:
            window  = data[offset: offset + self.window_size]
            entropy = self.shannon_entropy(window)
            results.append((offset, entropy))
            offset += self.window_step

        return results

    # ------------------------------------------------------------------
    # Interfaz pública
    # ------------------------------------------------------------------

    def analyze(
        self,
        file_path: str | Path,
        pe_sections: Optional[list[dict]] = None,
        use_sliding_window: bool = True,
    ) -> EntropyReport:
        """
        Analiza la entropía de un fichero.

        Parámetros
        ----------
        file_path         : ruta al fichero.
        pe_sections       : lista de dicts {name, data} con secciones PE
                            (proviene de PEAnalyzer). Si se proporciona,
                            se calcula la entropía por sección.
        use_sliding_window: calcular entropía por ventana deslizante.

        Retorna
        -------
        EntropyReport
        """
        path = Path(file_path)
        data = path.read_bytes()
        size = len(data)

        # Entropía global
        overall    = self.shannon_entropy(data)
        class_name = classify_entropy(overall)
        suspicious = overall >= self.suspicious_threshold

        # Entropía por sección PE (si se proporcionan)
        section_entropies: list[SectionEntropy] = []
        if pe_sections:
            for sec in pe_sections:
                sec_data    = sec.get("data", b"")
                sec_entropy = self.shannon_entropy(sec_data) if sec_data else 0.0
                section_entropies.append(
                    SectionEntropy(
                        name    = sec.get("name", "?"),
                        entropy = sec_entropy,
                        size    = len(sec_data),
                    )
                )
            # Si alguna sección es alta, el fichero es sospechoso
            if any(s.entropy >= self.suspicious_threshold for s in section_entropies):
                suspicious = True

        # Ventana deslizante
        windows: list[tuple[int, float]] = []
        if use_sliding_window and size <= 50 * 1024 * 1024:  # máx 50 MB
            windows = self.sliding_window_entropy(data)

        return EntropyReport(
            file_path         = str(file_path),
            file_size         = size,
            overall_entropy   = overall,
            classification    = class_name,
            is_suspicious     = suspicious,
            section_entropies = section_entropies,
            sliding_window    = windows,
        )
