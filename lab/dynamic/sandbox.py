"""
sandbox.py
==========
Orquestador de análisis dinámico en sandbox aislada.

Estrategia de análisis dinámico
--------------------------------
1. Detonar el binario en un entorno controlado (VM / namespace Linux).
2. Monitorizar simultáneamente:
   a. Árbol de procesos (BFS) con ProcessTreeMonitor.
   b. Conexiones y tráfico de red con NetworkMonitor.
   c. Ficheros creados/modificados con inotify o polling de filesystem.
   d. Llamadas al sistema con strace (Linux).
3. Registrar todos los eventos con timestamps.
4. Producir un informe de comportamiento unificado.

ADVERTENCIA
-----------
Este módulo ejecuta el binario analizado. Solo úsalo en una VM
completamente aislada sin acceso a red real o a datos sensibles.

Uso
---
    from lab.dynamic.sandbox import SandboxRunner

    runner = SandboxRunner(
        timeout=60,
        network_interface="eth0",
    )
    report = runner.run("sample.exe")
    print(report)
"""

import os
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from .process_tree    import BFSProcessAnalyzer, ProcessTreeReport
from .network_monitor import NetworkMonitor, NetworkReport


# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class FileSystemEvent:
    timestamp: float
    event_type: str      # "created", "modified", "deleted"
    path: str
    is_suspicious: bool = False

    @property
    def suspicion_reason(self) -> str:
        ext = Path(self.path).suffix.lower()
        if ext in {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".com"}:
            return f"Fichero ejecutable: {ext}"
        if "startup" in self.path.lower() or "autorun" in self.path.lower():
            return "Posible persistencia"
        if "\\temp\\" in self.path.lower():
            return "Fichero en directorio temporal"
        return ""


@dataclass
class SyscallEvent:
    timestamp: float
    syscall: str
    args: str
    pid: int
    return_value: str = ""


@dataclass
class SandboxReport:
    """Informe completo del análisis dinámico en sandbox."""
    sample_path: str
    start_time: datetime
    end_time: Optional[datetime] = None
    exit_code: Optional[int]     = None
    timed_out: bool               = False

    process_report: Optional[ProcessTreeReport] = None
    network_report: Optional[NetworkReport]     = None
    fs_events:      list[FileSystemEvent]        = field(default_factory=list)
    syscall_events: list[SyscallEvent]           = field(default_factory=list)
    strace_output:  str                          = ""
    error:          Optional[str]                = None

    @property
    def suspicious_files_created(self) -> list[FileSystemEvent]:
        return [
            e for e in self.fs_events
            if e.event_type == "created" and e.suspicion_reason
        ]

    @property
    def duration_seconds(self) -> float:
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    def __str__(self) -> str:
        status = "TIMEOUT" if self.timed_out else f"exit={self.exit_code}"
        lines = [
            "=== Sandbox Analysis Report ===",
            f"  Muestra       : {self.sample_path}",
            f"  Inicio        : {self.start_time}",
            f"  Duración      : {self.duration_seconds:.1f}s  [{status}]",
            f"  Eventos FS    : {len(self.fs_events)}",
            f"  Eventos red   : "
            f"{len(self.network_report.connections) if self.network_report else 0}",
        ]
        if self.process_report:
            lines.append(
                f"  Procesos      : {self.process_report.total_processes} "
                f"(sospechosos: {len(self.process_report.suspicious_nodes)})"
            )
        if self.suspicious_files_created:
            lines.append("\n  Ficheros sospechosos creados:")
            for e in self.suspicious_files_created:
                lines.append(f"    {e.path}  [{e.suspicion_reason}]")
        if self.network_report and self.network_report.suspicious_connections:
            lines.append("\n  Conexiones de red sospechosas:")
            for c in self.network_report.suspicious_connections:
                lines.append(
                    f"    {c.remote_addr}:{c.remote_port}  [{c.status}]"
                )
        if self.error:
            lines.append(f"\n  Error: {self.error}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orquestador
# ---------------------------------------------------------------------------

class SandboxRunner:
    """
    Ejecuta y monitoriza un binario en sandbox.

    SOLO usar en VM aislada.

    Parámetros
    ----------
    timeout          : segundos máximos de ejecución.
    network_interface: interfaz para tcpdump.
    capture_network  : capturar tráfico (requiere root).
    capture_strace   : usar strace para syscalls (requiere Linux).
    watch_paths      : directorios a monitorizar para eventos FS.
    """

    def __init__(
        self,
        timeout: int = 60,
        network_interface: str = "eth0",
        capture_network: bool = False,
        capture_strace: bool = True,
        watch_paths: Optional[list[str]] = None,
    ):
        self.timeout           = timeout
        self.network_interface = network_interface
        self.capture_network   = capture_network
        self.capture_strace    = capture_strace
        self.watch_paths       = watch_paths or ["/tmp", "/var/tmp"]

    # ------------------------------------------------------------------
    # Monitoreo de filesystem (polling simple)
    # ------------------------------------------------------------------

    def _snapshot_filesystem(self, paths: list[str]) -> dict[str, float]:
        """Captura snapshot de ficheros en las rutas dadas."""
        snapshot: dict[str, float] = {}
        for base in paths:
            base_path = Path(base)
            if not base_path.exists():
                continue
            try:
                for p in base_path.rglob("*"):
                    if p.is_file():
                        try:
                            snapshot[str(p)] = p.stat().st_mtime
                        except OSError:
                            pass
            except PermissionError:
                pass
        return snapshot

    def _diff_filesystem(
        self,
        before: dict[str, float],
        after: dict[str, float],
    ) -> list[FileSystemEvent]:
        events = []
        ts     = time.time()

        # Nuevos ficheros
        for path in set(after) - set(before):
            ev = FileSystemEvent(
                timestamp  = ts,
                event_type = "created",
                path       = path,
                is_suspicious = bool(FileSystemEvent(0, "created", path).suspicion_reason),
            )
            ev.is_suspicious = bool(ev.suspicion_reason)
            events.append(ev)

        # Ficheros modificados
        for path in set(after) & set(before):
            if after[path] != before[path]:
                events.append(FileSystemEvent(
                    timestamp  = ts,
                    event_type = "modified",
                    path       = path,
                ))

        # Ficheros eliminados
        for path in set(before) - set(after):
            events.append(FileSystemEvent(
                timestamp  = ts,
                event_type = "deleted",
                path       = path,
            ))

        return events

    # ------------------------------------------------------------------
    # strace
    # ------------------------------------------------------------------

    def _run_with_strace(self, cmd: list[str], timeout: int) -> tuple[str, int]:
        """Ejecuta el comando bajo strace y captura las syscalls."""
        strace_cmd = [
            "strace", "-f",               # seguir procesos hijos
            "-e", "trace=network,process,file",
            "-tt",                         # timestamps
            "-s", "256",                   # tamaño de strings
        ] + cmd

        try:
            result = subprocess.run(
                strace_cmd,
                capture_output = True,
                text           = True,
                timeout        = timeout,
            )
            return result.stderr, result.returncode
        except FileNotFoundError:
            return "strace no disponible. Instalar con: sudo apt install strace", -1
        except subprocess.TimeoutExpired:
            return "TIMEOUT", -1

    # ------------------------------------------------------------------
    # Interfaz pública
    # ------------------------------------------------------------------

    def run(self, sample_path: str | Path) -> SandboxReport:
        """
        Ejecuta el análisis dinámico completo.

        ADVERTENCIA: Ejecuta el binario. Solo en VM aislada.

        Parámetros
        ----------
        sample_path : ruta al binario a analizar.
        """
        path   = Path(sample_path)
        report = SandboxReport(
            sample_path = str(path),
            start_time  = datetime.now(),
        )

        if not path.exists():
            report.error = f"Fichero no encontrado: {path}"
            return report

        # Snapshot inicial del filesystem
        fs_before = self._snapshot_filesystem(self.watch_paths)

        # Inicializar monitores
        process_analyzer = BFSProcessAnalyzer() if PSUTIL_AVAILABLE else None
        net_monitor      = NetworkMonitor()

        # Hilo de monitoreo de red (snapshot antes de la ejecución)
        net_report_before = net_monitor.snapshot_connections()

        # Ejecutar la muestra
        timed_out     = False
        strace_output = ""
        exit_code     = None
        sample_pid    = None

        try:
            if self.capture_strace and os.name == "posix":
                # Con strace
                strace_out, exit_code = self._run_with_strace(
                    [str(path)], self.timeout
                )
                strace_output = strace_out
            else:
                # Sin strace
                proc = subprocess.Popen(
                    [str(path)],
                    stdout = subprocess.DEVNULL,
                    stderr = subprocess.DEVNULL,
                )
                sample_pid = proc.pid
                try:
                    exit_code = proc.wait(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    timed_out = True
                    exit_code = -1

        except PermissionError:
            report.error = "Permiso denegado al ejecutar la muestra."
            return report
        except OSError as exc:
            report.error = f"Error al ejecutar: {exc}"
            return report

        report.end_time     = datetime.now()
        report.exit_code    = exit_code
        report.timed_out    = timed_out
        report.strace_output = strace_output

        # Snapshot posterior del filesystem
        fs_after       = self._snapshot_filesystem(self.watch_paths)
        report.fs_events = self._diff_filesystem(fs_before, fs_after)

        # Análisis del árbol de procesos (snapshot post-ejecución)
        if process_analyzer and sample_pid:
            try:
                report.process_report = process_analyzer.analyze_system_snapshot()
            except Exception:
                pass

        # Snapshot posterior de red
        report.network_report = net_monitor.snapshot_connections()

        return report
