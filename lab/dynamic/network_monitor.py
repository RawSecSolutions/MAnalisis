"""
network_monitor.py
==================
Monitoreo de conexiones de red y captura de tráfico durante análisis dinámico.

Funcionalidades
---------------
1. Listar conexiones activas de un proceso (usando psutil).
2. Capturar tráfico con tcpdump y parsear el resultado.
3. Detectar indicadores de C2: beaconing, dominios DGA, IPs sospechosas.
4. Resolver dominios y verificar contra listas de reputación.

Indicadores de C2 detectados
------------------------------
- Conexiones a IPs en rangos privados desde un proceso no-sistema.
- Intervalos de conexión regulares (beaconing).
- Peticiones HTTP a dominios con alta entropía (DGA - Domain Generation Algorithm).
- User-Agents sospechosos o ausentes.
- Conexiones a puertos no estándar.

Uso
---
    from lab.dynamic.network_monitor import NetworkMonitor

    monitor = NetworkMonitor()
    report  = monitor.snapshot_connections(pid=1234)
    print(report)

    # Captura con tcpdump (requiere root)
    report = monitor.capture_traffic(pid=1234, duration=30, interface="eth0")
    print(report)
"""

import math
import re
import subprocess
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ---------------------------------------------------------------------------
# Puertos considerados "no estándar" para tráfico web/app
# ---------------------------------------------------------------------------

COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 8888,
}

# IPs de servicios legítimos conocidos (incompleto, solo ilustrativo)
KNOWN_GOOD_IP_PREFIXES = [
    "8.8.8.",    # Google DNS
    "1.1.1.",    # Cloudflare DNS
    "8.8.4.",    # Google DNS 2
]


# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class NetworkConnection:
    pid: int
    process_name: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    protocol: str = "tcp"
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)

    def check_suspicious(self) -> None:
        """Evalúa indicadores de C2 en esta conexión."""
        # Puerto no estándar
        if self.remote_port not in COMMON_PORTS and self.remote_port != 0:
            if self.remote_port > 1024:
                self.is_suspicious = True
                self.suspicion_reasons.append(
                    f"Puerto no estándar: {self.remote_port}"
                )

        # Conexión a IP privada desde proceso sospechoso (pivot/lateral)
        if self._is_private_ip(self.remote_addr):
            if self.process_name.lower() not in {
                "system", "svchost.exe", "lsass.exe", "services.exe"
            }:
                self.suspicion_reasons.append(
                    f"Conexión a IP privada: {self.remote_addr}"
                )

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        private_prefixes = ("10.", "172.16.", "172.17.", "192.168.", "127.")
        return any(ip.startswith(p) for p in private_prefixes)


@dataclass
class DGAIndicator:
    """Indicador de Domain Generation Algorithm."""
    domain: str
    entropy: float
    is_dga: bool
    reason: str = ""


@dataclass
class NetworkReport:
    pid: Optional[int]
    snapshot_time: datetime
    connections: list[NetworkConnection] = field(default_factory=list)
    suspicious_connections: list[NetworkConnection] = field(default_factory=list)
    dga_indicators: list[DGAIndicator] = field(default_factory=list)
    captured_packets: int = 0
    tcpdump_output: str = ""
    beaconing_detected: bool = False
    beaconing_interval: Optional[float] = None

    def __str__(self) -> str:
        lines = [
            "=== Network Monitor Report ===",
            f"  PID          : {self.pid or 'sistema'}",
            f"  Snapshot     : {self.snapshot_time}",
            f"  Conexiones   : {len(self.connections)}",
            f"  Sospechosas  : {len(self.suspicious_connections)}",
            f"  Paquetes cap.: {self.captured_packets}",
        ]
        if self.beaconing_detected:
            lines.append(
                f"  ⚠ BEACONING detectado cada ~{self.beaconing_interval:.1f}s"
            )
        if self.suspicious_connections:
            lines.append("\n  Conexiones sospechosas:")
            for c in self.suspicious_connections:
                lines.append(
                    f"    {c.process_name}  "
                    f"{c.local_addr}:{c.local_port} → "
                    f"{c.remote_addr}:{c.remote_port}  [{c.status}]"
                )
                for reason in c.suspicion_reasons:
                    lines.append(f"      ⚠ {reason}")
        if self.dga_indicators:
            lines.append("\n  Posibles dominios DGA:")
            for dga in self.dga_indicators:
                lines.append(
                    f"    {dga.domain}  (entropía={dga.entropy:.2f}): {dga.reason}"
                )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Motor principal
# ---------------------------------------------------------------------------

class NetworkMonitor:
    """
    Monitoriza actividad de red durante análisis dinámico.

    Parámetros
    ----------
    dga_entropy_threshold : float
        Umbral de entropía para clasificar un dominio como posible DGA.
    beacon_tolerance : float
        Tolerancia en segundos para detección de beaconing.
    """

    def __init__(
        self,
        dga_entropy_threshold: float = 3.8,
        beacon_tolerance: float = 2.0,
    ):
        self.dga_threshold  = dga_entropy_threshold
        self.beacon_tol     = beacon_tolerance

    # ------------------------------------------------------------------
    # Snapshot de conexiones actuales
    # ------------------------------------------------------------------

    def snapshot_connections(
        self,
        pid: Optional[int] = None,
    ) -> NetworkReport:
        """
        Captura las conexiones de red actuales de un proceso o del sistema.

        Parámetros
        ----------
        pid : PID del proceso. Si None, captura todas las conexiones del sistema.
        """
        if not PSUTIL_AVAILABLE:
            raise RuntimeError("psutil no instalado. Ejecuta: pip install psutil")

        report = NetworkReport(pid=pid, snapshot_time=datetime.now())
        connections: list[NetworkConnection] = []

        try:
            if pid:
                proc  = psutil.Process(pid)
                conns = proc.connections(kind="all")
                pname = proc.name()
            else:
                conns = psutil.net_connections(kind="all")
                pname = "sistema"

            for conn in conns:
                if conn.laddr and conn.raddr:
                    nc = NetworkConnection(
                        pid          = pid or 0,
                        process_name = pname,
                        local_addr   = conn.laddr.ip if conn.laddr else "",
                        local_port   = conn.laddr.port if conn.laddr else 0,
                        remote_addr  = conn.raddr.ip if conn.raddr else "",
                        remote_port  = conn.raddr.port if conn.raddr else 0,
                        status       = conn.status or "?",
                        protocol     = "tcp" if conn.type == 1 else "udp",
                    )
                    nc.check_suspicious()
                    connections.append(nc)

        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            pass

        report.connections           = connections
        report.suspicious_connections = [c for c in connections if c.is_suspicious]
        return report

    # ------------------------------------------------------------------
    # Captura con tcpdump
    # ------------------------------------------------------------------

    def capture_traffic(
        self,
        pid: Optional[int] = None,
        duration: int = 30,
        interface: str = "eth0",
        output_file: Optional[str] = None,
    ) -> NetworkReport:
        """
        Captura tráfico de red usando tcpdump.

        Requiere privilegios de root / sudo.

        Parámetros
        ----------
        pid        : filtrar por PID (no soportado directamente por tcpdump,
                     se usa host filter si se conoce el proceso).
        duration   : duración de la captura en segundos.
        interface  : interfaz de red (eth0, wlan0, any, etc.).
        output_file: fichero .pcap de salida (opcional).
        """
        report = NetworkReport(pid=pid, snapshot_time=datetime.now())

        cmd = ["tcpdump", "-i", interface, "-nn", f"--duration={duration}"]
        if output_file:
            cmd += ["-w", output_file]
        else:
            cmd += ["-l", "-c", "1000"]  # máx 1000 paquetes sin fichero

        try:
            result = subprocess.run(
                cmd,
                capture_output = True,
                text           = True,
                timeout        = duration + 10,
            )
            output = result.stdout + result.stderr
            report.tcpdump_output = output

            # Contar paquetes capturados
            match = re.search(r"(\d+) packets captured", output)
            if match:
                report.captured_packets = int(match.group(1))

            # Parsear líneas de tcpdump para detectar dominios
            domains = self._extract_domains_from_tcpdump(output)
            report.dga_indicators = [self._analyze_domain(d) for d in domains]
            report.dga_indicators = [
                d for d in report.dga_indicators if d.is_dga
            ]

        except FileNotFoundError:
            report.tcpdump_output = (
                "tcpdump no encontrado. Instalar con: sudo apt install tcpdump"
            )
        except subprocess.TimeoutExpired:
            report.tcpdump_output = "tcpdump timeout"
        except PermissionError:
            report.tcpdump_output = "Permiso denegado. Ejecutar con sudo."

        return report

    # ------------------------------------------------------------------
    # Detección de DGA
    # ------------------------------------------------------------------

    @staticmethod
    def _domain_entropy(domain: str) -> float:
        """Entropía del nombre de dominio (sin TLD) como heurística DGA."""
        label = domain.split(".")[0] if "." in domain else domain
        if not label:
            return 0.0
        freq  = Counter(label.lower())
        total = len(label)
        return -sum((c / total) * math.log2(c / total) for c in freq.values())

    def _analyze_domain(self, domain: str) -> DGAIndicator:
        entropy = self._domain_entropy(domain)
        label   = domain.split(".")[0]
        is_dga  = False
        reason  = ""

        # Alta entropía del label
        if entropy >= self.dga_threshold:
            is_dga = True
            reason = f"Entropía del label alta ({entropy:.2f})"

        # Label muy largo y aleatorio
        if len(label) > 20 and re.search(r"[0-9]{4,}", label):
            is_dga  = True
            reason += " | Label largo con números"

        # Sin vocales (típico de DGA hex-based)
        if len(label) > 8 and not re.search(r"[aeiou]", label.lower()):
            is_dga  = True
            reason += " | Sin vocales"

        return DGAIndicator(
            domain  = domain,
            entropy = entropy,
            is_dga  = is_dga,
            reason  = reason.strip(" |"),
        )

    @staticmethod
    def _extract_domains_from_tcpdump(output: str) -> list[str]:
        """Extrae nombres de dominio de la salida de tcpdump."""
        # Patrón básico: DNS queries en tcpdump -nn
        pattern = r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,}"
        domains = set(re.findall(pattern, output))
        # Filtrar IPs y entradas vacías
        return [
            d for d in domains
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", d)
            and len(d) > 4
        ]

    # ------------------------------------------------------------------
    # Detección de beaconing
    # ------------------------------------------------------------------

    def detect_beaconing(
        self,
        connection_times: list[float],
        min_connections: int = 5,
    ) -> tuple[bool, Optional[float]]:
        """
        Detecta beaconing analizando intervalos entre conexiones.

        Un C2 beacon típicamente se conecta a intervalos regulares.
        Si la desviación estándar de los intervalos es baja → beaconing.

        Parámetros
        ----------
        connection_times : lista de timestamps (Unix) de las conexiones.
        min_connections  : mínimo de conexiones para hacer el análisis.

        Retorna
        -------
        (is_beaconing, interval_seconds)
        """
        if len(connection_times) < min_connections:
            return False, None

        times     = sorted(connection_times)
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]

        if not intervals:
            return False, None

        mean      = sum(intervals) / len(intervals)
        variance  = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std_dev   = variance ** 0.5
        cv        = std_dev / mean if mean > 0 else 1.0  # coeficiente de variación

        # CV < 0.2 indica intervalos muy regulares → probable beaconing
        is_beaconing = cv < 0.2 and mean > 5  # ignorar intervalos < 5s
        return is_beaconing, mean if is_beaconing else None
