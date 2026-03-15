"""
scoring.py
==========
Sistema de puntuación de anomalías que combina los resultados de todos los
módulos de análisis estático en un veredicto unificado.

Escala de riesgo
----------------
  0–10   →  LIMPIO        (bajo riesgo)
 11–25   →  SOSPECHOSO    (requiere revisión adicional)
 26–50   →  PROBABLE MALWARE
 51+     →  MALWARE (alta confianza)

Ponderaciones por módulo
------------------------
  Threat intel (hash match en BD maliciosa) : peso máximo (50 pts)
  PE anomalías (imports, secciones, etc.)   : hasta 30 pts
  Entropía alta                              : hasta 15 pts
  Strings sospechosos (Aho-Corasick)        : hasta 20 pts
  Packer detectado                          : hasta 15 pts

Uso
---
    from lab.core.scoring import AnomalyScorer

    scorer  = AnomalyScorer()
    verdict = scorer.score(
        hash_report    = hash_report,
        pe_report      = pe_report,
        entropy_report = entropy_report,
        string_report  = string_report,
        packer_report  = packer_report,
    )
    print(verdict)
"""

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Niveles de riesgo
# ---------------------------------------------------------------------------

RISK_LEVELS = [
    (0,  10, "LIMPIO",           "Verde  "),
    (11, 25, "SOSPECHOSO",       "Amarillo"),
    (26, 50, "PROBABLE MALWARE", "Naranja"),
    (51, 999,"MALWARE",          "Rojo   "),
]


def classify_score(score: int) -> tuple[str, str]:
    for lo, hi, label, color in RISK_LEVELS:
        if lo <= score <= hi:
            return label, color
    return "MALWARE", "Rojo"


# ---------------------------------------------------------------------------
# Contribuciones al score
# ---------------------------------------------------------------------------

@dataclass
class ScoreContribution:
    source: str
    points: int
    reason: str


@dataclass
class ScoringReport:
    total_score: int
    risk_level: str
    color: str
    contributions: list[ScoreContribution] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [
            "╔══════════════════════════════════════════╗",
            f"║  VEREDICTO FINAL: {self.risk_level:<23}║",
            f"║  Score total   : {self.total_score:<24}║",
            "╚══════════════════════════════════════════╝",
            "",
            "  Contribuciones al score:",
        ]
        for c in sorted(self.contributions, key=lambda x: -x.points):
            lines.append(f"    [{c.points:+3d}]  {c.source}: {c.reason}")

        if self.recommendations:
            lines.append("\n  Recomendaciones:")
            for r in self.recommendations:
                lines.append(f"    → {r}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Scorer principal
# ---------------------------------------------------------------------------

class AnomalyScorer:
    """
    Combina resultados de análisis estático en un score de maliciosidad.

    Acepta objetos de los módulos core (hash, PE, entropía, strings, packer)
    y los pondera para producir un veredicto unificado.
    """

    def score(
        self,
        hash_report=None,
        pe_report=None,
        entropy_report=None,
        string_report=None,
        packer_report=None,
    ) -> ScoringReport:
        """
        Calcula el score de anomalía combinando todos los reportes.

        Cualquier parámetro puede ser None si ese análisis no se realizó.
        """
        contributions: list[ScoreContribution] = []
        total = 0
        recommendations: list[str] = []

        # ------------------------------------------------------------------
        # 1. Threat Intelligence (mayor peso)
        # ------------------------------------------------------------------
        if hash_report is not None:
            for result in hash_report.threat_intel:
                if result.found and result.malicious:
                    pts = min(60, 25 + result.detections)
                    contributions.append(ScoreContribution(
                        source=f"Threat Intel ({result.service})",
                        points=pts,
                        reason=(
                            f"Detectado como malicioso: "
                            f"{result.detections}/{result.total_engines} motores"
                        ),
                    ))
                    total += pts
                    recommendations.append(
                        f"Hash encontrado en {result.service}. NO ejecutar."
                    )

        # ------------------------------------------------------------------
        # 2. PE Anomalías
        # ------------------------------------------------------------------
        if pe_report is not None and pe_report.is_pe:
            pe_score = min(30, pe_report.anomalies.total_score)
            if pe_score > 0:
                contributions.append(ScoreContribution(
                    source="Análisis PE",
                    points=pe_score,
                    reason=(
                        f"{len(pe_report.anomalies.items)} anomalías: "
                        f"{'; '.join(pe_report.anomalies.descriptions[:3])}"
                    ),
                ))
                total += pe_score

            if pe_report.total_imports < 5:
                recommendations.append(
                    "Menos de 5 imports: probable packing. "
                    "Considera análisis dinámico."
                )

        # ------------------------------------------------------------------
        # 3. Entropía
        # ------------------------------------------------------------------
        if entropy_report is not None:
            ent = entropy_report.overall_entropy
            if ent >= 7.5:
                pts = 15
                reason = f"Entropía global {ent:.3f} (probable cifrado/packing)"
                recommendations.append(
                    "Entropía muy alta: contenido cifrado o comprimido. "
                    "Identifica el packer antes del análisis estático."
                )
            elif ent >= 7.0:
                pts = 8
                reason = f"Entropía global {ent:.3f} (posible compresión)"
            elif ent >= 6.5:
                pts = 3
                reason = f"Entropía global {ent:.3f} (ligeramente alta)"
            else:
                pts = 0
                reason = f"Entropía global {ent:.3f} (normal)"

            if pts > 0:
                contributions.append(ScoreContribution(
                    source="Entropía",
                    points=pts,
                    reason=reason,
                ))
                total += pts

            # Secciones con alta entropía
            high_sections = entropy_report.high_entropy_sections
            if high_sections:
                sec_pts = min(10, len(high_sections) * 3)
                contributions.append(ScoreContribution(
                    source="Entropía (secciones)",
                    points=sec_pts,
                    reason=(
                        f"{len(high_sections)} secciones con entropía ≥ 7.2: "
                        f"{', '.join(s.name for s in high_sections)}"
                    ),
                ))
                total += sec_pts

        # ------------------------------------------------------------------
        # 4. Strings sospechosos (Aho-Corasick)
        # ------------------------------------------------------------------
        if string_report is not None:
            str_score = min(20, string_report.total_score // 3)
            if str_score > 0:
                top_cats = sorted(
                    string_report.by_category.items(),
                    key=lambda x: -sum(m.severity for m in x[1]),
                )[:3]
                reason = "Categorías: " + ", ".join(c for c, _ in top_cats)
                contributions.append(ScoreContribution(
                    source="Strings sospechosos",
                    points=str_score,
                    reason=reason,
                ))
                total += str_score

                # Recomendaciones específicas por categoría
                cats = set(string_report.by_category.keys())
                if "injection" in cats:
                    recommendations.append(
                        "Strings de inyección detectados: monitorizar acceso a procesos."
                    )
                if "credential_theft" in cats:
                    recommendations.append(
                        "Strings de robo de credenciales: posible ladrón de contraseñas."
                    )
                if "ransomware" in cats:
                    recommendations.append(
                        "Strings relacionados con ransomware detectados."
                    )
                if "c2_indicators" in cats:
                    recommendations.append(
                        "Indicadores de C2 detectados: capturar tráfico de red."
                    )

        # ------------------------------------------------------------------
        # 5. Packer detectado
        # ------------------------------------------------------------------
        if packer_report is not None and packer_report.is_packed:
            packer_names = packer_report.packer_names
            high_risk_packers = {"Themida", "VMProtect", "UNKNOWN_PACKER"}
            if any(p in high_risk_packers for p in packer_names):
                pts = 15
            elif "UPX" in packer_names:
                pts = 5
            else:
                pts = 8

            contributions.append(ScoreContribution(
                source="Packer detectado",
                points=pts,
                reason=f"Packers: {', '.join(packer_names)}",
            ))
            total += pts

            if packer_report.can_auto_unpack:
                recommendations.append(
                    f"Desempaquetar con: {packer_report.unpack_command}"
                )
            else:
                recommendations.append(
                    f"Packer complejo ({', '.join(packer_names)}): "
                    "usar análisis dinámico en sandbox."
                )

        # ------------------------------------------------------------------
        # Score final y recomendaciones generales
        # ------------------------------------------------------------------
        if total == 0:
            contributions.append(ScoreContribution(
                source="Análisis estático",
                points=0,
                reason="Sin anomalías detectadas",
            ))
            recommendations.append("Archivo aparentemente limpio. Verificar con VT.")

        risk_level, color = classify_score(total)

        if total >= 26 and not any("análisis dinámico" in r for r in recommendations):
            recommendations.append(
                "Score alto: considera análisis dinámico en sandbox aislada."
            )

        return ScoringReport(
            total_score     = total,
            risk_level      = risk_level,
            color           = color,
            contributions   = contributions,
            recommendations = list(dict.fromkeys(recommendations)),  # dedup ordenado
        )
