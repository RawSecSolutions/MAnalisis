"""
hash_analysis.py
================
Cálculo de hashes criptográficos y consulta contra bases de datos
de inteligencia de amenazas (VirusTotal, MalwareBazaar, Abuse.ch).

Algoritmos utilizados
---------------------
- MD5, SHA-1, SHA-256  →  identificadores únicos del fichero
- Lookup en APIs REST  →  correlación con muestras conocidas

Flujo
-----
1. Leer el fichero en bloques (streaming) para no cargar binarios grandes.
2. Calcular los tres hashes en un solo pase.
3. Consultar cada servicio de inteligencia de amenazas.
4. Devolver un resultado unificado con el veredicto.

Uso
---
    from lab.core.hash_analysis import HashAnalyzer

    analyzer = HashAnalyzer(vt_api_key="TU_CLAVE")
    result = analyzer.analyze("muestra.exe")
    print(result)
"""

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests


# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class ThreatIntelResult:
    """Resultado de la consulta a un servicio de inteligencia de amenazas."""
    service: str
    found: bool
    malicious: Optional[bool] = None
    detections: int = 0
    total_engines: int = 0
    tags: list[str] = field(default_factory=list)
    permalink: Optional[str] = None
    raw: dict = field(default_factory=dict)


@dataclass
class HashReport:
    """Informe completo del análisis de hashes."""
    file_path: str
    md5: str
    sha1: str
    sha256: str
    file_size: int
    threat_intel: list[ThreatIntelResult] = field(default_factory=list)

    @property
    def is_known_malicious(self) -> bool:
        """True si al menos un servicio reporta el archivo como malicioso."""
        return any(r.malicious for r in self.threat_intel if r.found)

    @property
    def verdict(self) -> str:
        if not self.threat_intel:
            return "UNKNOWN (no threat intel queried)"
        if self.is_known_malicious:
            detections = max(
                (r.detections for r in self.threat_intel if r.found and r.malicious),
                default=0,
            )
            return f"MALICIOUS ({detections} detecciones)"
        if any(r.found for r in self.threat_intel):
            return "CLEAN (conocido, no malicioso)"
        return "NOT FOUND (muestra no vista antes)"

    def __str__(self) -> str:
        lines = [
            "=== Hash Analysis Report ===",
            f"  Archivo  : {self.file_path}",
            f"  Tamaño   : {self.file_size:,} bytes",
            f"  MD5      : {self.md5}",
            f"  SHA-1    : {self.sha1}",
            f"  SHA-256  : {self.sha256}",
            f"  Veredicto: {self.verdict}",
        ]
        for r in self.threat_intel:
            status = "ENCONTRADO" if r.found else "NO ENCONTRADO"
            lines.append(f"\n  [{r.service}] {status}")
            if r.found and r.malicious is not None:
                lines.append(
                    f"    Detecciones : {r.detections}/{r.total_engines}"
                )
            if r.tags:
                lines.append(f"    Tags        : {', '.join(r.tags)}")
            if r.permalink:
                lines.append(f"    URL         : {r.permalink}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Motor principal
# ---------------------------------------------------------------------------

class HashAnalyzer:
    """
    Calcula hashes y consulta servicios de threat intelligence.

    Parámetros
    ----------
    vt_api_key : str, opcional
        Clave API de VirusTotal v3.
    mb_api_key : str, opcional
        Clave API de MalwareBazaar (actualmente no requerida para lookups).
    chunk_size : int
        Tamaño del bloque de lectura en bytes (por defecto 8 MB).
    timeout : int
        Tiempo máximo de espera para cada petición HTTP (segundos).
    """

    VT_BASE          = "https://www.virustotal.com/api/v3/files"
    MB_BASE          = "https://mb-api.abuse.ch/api/v1/"
    ABUSECH_BASE     = "https://bazaar.abuse.ch/api/"

    def __init__(
        self,
        vt_api_key: Optional[str] = None,
        mb_api_key: Optional[str] = None,
        chunk_size: int = 8 * 1024 * 1024,
        timeout: int = 15,
    ):
        self.vt_api_key  = vt_api_key
        self.mb_api_key  = mb_api_key
        self.chunk_size  = chunk_size
        self.timeout     = timeout

    # ------------------------------------------------------------------
    # Hash calculation
    # ------------------------------------------------------------------

    def compute_hashes(self, file_path: str | Path) -> tuple[str, str, str, int]:
        """
        Lee el fichero en bloques y calcula MD5, SHA-1, SHA-256 en un pase.

        Complejidad: O(n) en el tamaño del fichero, memoria O(chunk_size).

        Retorna
        -------
        (md5, sha1, sha256, file_size)
        """
        path    = Path(file_path)
        md5     = hashlib.md5()
        sha1    = hashlib.sha1()
        sha256  = hashlib.sha256()
        size    = 0

        with open(path, "rb") as fh:
            while chunk := fh.read(self.chunk_size):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                size += len(chunk)

        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), size

    # ------------------------------------------------------------------
    # Threat intelligence lookups
    # ------------------------------------------------------------------

    def _query_virustotal(self, sha256: str) -> ThreatIntelResult:
        """
        Consulta VirusTotal v3 API.

        Endpoint: GET /api/v3/files/{sha256}
        Requiere cabecera x-apikey.
        """
        if not self.vt_api_key:
            return ThreatIntelResult(
                service="VirusTotal", found=False,
                raw={"error": "API key no configurada"}
            )

        headers = {"x-apikey": self.vt_api_key}
        url     = f"{self.VT_BASE}/{sha256}"

        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)

            if resp.status_code == 404:
                return ThreatIntelResult(service="VirusTotal", found=False, raw={})

            resp.raise_for_status()
            data  = resp.json()
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            total     = sum(stats.values())
            tags      = attrs.get("tags", [])
            permalink = f"https://www.virustotal.com/gui/file/{sha256}"

            return ThreatIntelResult(
                service="VirusTotal",
                found=True,
                malicious=malicious > 0,
                detections=malicious,
                total_engines=total,
                tags=tags,
                permalink=permalink,
                raw=attrs,
            )

        except requests.RequestException as exc:
            return ThreatIntelResult(
                service="VirusTotal", found=False,
                raw={"error": str(exc)}
            )

    def _query_malwarebazaar(self, sha256: str) -> ThreatIntelResult:
        """
        Consulta MalwareBazaar (Abuse.ch).

        API pública, no requiere autenticación para lookups por hash.
        Endpoint: POST https://mb-api.abuse.ch/api/v1/  con query=get_info
        """
        try:
            resp = requests.post(
                self.MB_BASE,
                data={"query": "get_info", "hash": sha256},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get("query_status") == "hash_not_found":
                return ThreatIntelResult(service="MalwareBazaar", found=False, raw=data)

            entry = data.get("data", [{}])[0]
            tags  = entry.get("tags", []) or []
            sig   = entry.get("signature", "")
            if sig:
                tags.insert(0, sig)

            return ThreatIntelResult(
                service="MalwareBazaar",
                found=True,
                malicious=True,          # Todo en MalwareBazaar es malicioso por definición
                detections=1,
                total_engines=1,
                tags=tags,
                permalink=f"https://bazaar.abuse.ch/sample/{sha256}/",
                raw=entry,
            )

        except requests.RequestException as exc:
            return ThreatIntelResult(
                service="MalwareBazaar", found=False,
                raw={"error": str(exc)}
            )

    # ------------------------------------------------------------------
    # Interfaz pública
    # ------------------------------------------------------------------

    def analyze(
        self,
        file_path: str | Path,
        query_vt: bool = True,
        query_mb: bool = True,
    ) -> HashReport:
        """
        Análisis completo: hashes + threat intelligence.

        Parámetros
        ----------
        file_path : ruta al fichero a analizar.
        query_vt  : consultar VirusTotal (requiere api_key).
        query_mb  : consultar MalwareBazaar (gratis).

        Retorna
        -------
        HashReport con todos los resultados.
        """
        md5, sha1, sha256, size = self.compute_hashes(file_path)

        intel_results: list[ThreatIntelResult] = []

        if query_vt:
            intel_results.append(self._query_virustotal(sha256))
            time.sleep(0.5)  # Evitar rate-limit de VT free tier (4 req/min)

        if query_mb:
            intel_results.append(self._query_malwarebazaar(sha256))

        return HashReport(
            file_path=str(file_path),
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            file_size=size,
            threat_intel=intel_results,
        )
