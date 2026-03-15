"""
process_tree.py
===============
Monitoreo de árbol de procesos con BFS (Breadth-First Search) para detectar
procesos hijos creados por malware durante análisis dinámico.

Algoritmo BFS sobre árbol de procesos
--------------------------------------
El árbol de procesos es un grafo dirigido acíclico (DAG) donde cada nodo
es un proceso y los arcos representan relaciones padre→hijo.

BFS permite:
  1. Descubrir todos los procesos descendientes de un PID raíz.
  2. Detectar comportamientos anómalos: spawning de cmd.exe, powershell,
     procesos ocultos, o procesos en ubicaciones sospechosas.
  3. Calcular la "profundidad" de cada proceso (distancia al raíz).

Complejidad BFS: O(V + E) donde V = procesos, E = relaciones padre-hijo.

Uso
---
    from lab.dynamic.process_tree import BFSProcessAnalyzer

    analyzer = BFSProcessAnalyzer()

    # Monitorear durante N segundos
    report = analyzer.monitor_pid(pid=1234, duration_seconds=30)
    print(report)

    # Analizar snapshot actual del sistema
    report = analyzer.analyze_system_snapshot()
    print(report)
"""

import os
import time
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constantes de detección
# ---------------------------------------------------------------------------

SUSPICIOUS_PROCESS_NAMES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "msiexec.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "schtasks.exe", "at.exe",
    "net.exe", "netsh.exe", "sc.exe",
    "reg.exe", "regedit.exe",
}

SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\", "\\appdata\\roaming\\",
    "\\appdata\\local\\temp\\", "%temp%", "%appdata%",
    "\\users\\public\\", "c:\\windows\\temp\\",
]

LOLBINS = {  # Living-off-the-land binaries frecuentemente abusados
    "mshta.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "cmstp.exe",
    "msiexec.exe", "rundll32.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe",
}


# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class ProcessNode:
    pid: int
    name: str
    cmdline: str
    exe_path: str
    ppid: int
    create_time: float
    status: str
    depth: int = 0
    children: list["ProcessNode"] = field(default_factory=list)
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)

    def check_suspicious(self) -> None:
        """Evalúa si el proceso es sospechoso."""
        name_lower = self.name.lower()
        path_lower = self.exe_path.lower()

        if name_lower in SUSPICIOUS_PROCESS_NAMES:
            self.is_suspicious = True
            self.suspicion_reasons.append(f"Nombre sospechoso: {self.name}")

        if name_lower in LOLBINS:
            self.is_suspicious = True
            self.suspicion_reasons.append(f"LOLBin detectado: {self.name}")

        for keyword in SUSPICIOUS_PATH_KEYWORDS:
            if keyword in path_lower:
                self.is_suspicious = True
                self.suspicion_reasons.append(f"Ruta sospechosa: {self.exe_path}")
                break

        if self.cmdline and (
            "-enc" in self.cmdline.lower() or
            "-encodedcommand" in self.cmdline.lower() or
            "base64" in self.cmdline.lower()
        ):
            self.is_suspicious = True
            self.suspicion_reasons.append("Argumento de comando codificado en base64")


@dataclass
class ProcessTreeReport:
    root_pid: int
    snapshot_time: datetime
    all_nodes: list[ProcessNode] = field(default_factory=list)
    suspicious_nodes: list[ProcessNode] = field(default_factory=list)
    max_depth: int = 0
    total_processes: int = 0

    def __str__(self) -> str:
        lines = [
            "=== Process Tree Report (BFS) ===",
            f"  PID raíz     : {self.root_pid}",
            f"  Snapshot     : {self.snapshot_time}",
            f"  Procesos     : {self.total_processes}",
            f"  Profundidad  : {self.max_depth}",
            f"  Sospechosos  : {len(self.suspicious_nodes)}",
        ]
        if self.suspicious_nodes:
            lines.append("\n  Procesos sospechosos:")
            for node in self.suspicious_nodes:
                lines.append(
                    f"    PID={node.pid} [{node.name}] depth={node.depth}"
                )
                for reason in node.suspicion_reasons:
                    lines.append(f"      ⚠ {reason}")
        return "\n".join(lines)

    def print_tree(self, node: Optional[ProcessNode] = None, prefix: str = "") -> str:
        """Renderiza el árbol de procesos en ASCII."""
        if node is None:
            roots = [n for n in self.all_nodes if n.depth == 0]
            return "\n".join(self.print_tree(r, "") for r in roots)

        flag = " ⚠" if node.is_suspicious else ""
        lines = [f"{prefix}[{node.pid}] {node.name}{flag}"]
        for i, child in enumerate(node.children):
            is_last  = i == len(node.children) - 1
            new_pref = prefix + ("└── " if is_last else "├── ")
            sub_pref = prefix + ("    " if is_last else "│   ")
            sub_lines = self.print_tree(child, new_pref).split("\n")
            lines.extend(sub_lines)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Monitor de procesos con BFS
# ---------------------------------------------------------------------------

class BFSProcessAnalyzer:
    """
    Analiza el árbol de procesos usando BFS.

    Puede operar en dos modos:
    1. Snapshot: captura instantánea del estado del sistema.
    2. Monitor: sigue un PID durante N segundos registrando nuevos hijos.
    """

    def __init__(self):
        if not PSUTIL_AVAILABLE:
            raise RuntimeError(
                "psutil no está instalado. Ejecuta: pip install psutil"
            )

    # ------------------------------------------------------------------
    # Snapshot del sistema completo
    # ------------------------------------------------------------------

    def analyze_system_snapshot(
        self,
        root_pid: Optional[int] = None,
    ) -> ProcessTreeReport:
        """
        Captura el árbol de procesos actual del sistema.

        Parámetros
        ----------
        root_pid : PID raíz. Si None, usa el PID 1 (init/systemd) o
                   el proceso monitoreado.
        """
        all_procs: dict[int, ProcessNode] = {}

        # Recopilar todos los procesos del sistema
        for proc in psutil.process_iter(
            ["pid", "name", "cmdline", "exe", "ppid", "create_time", "status"]
        ):
            try:
                info = proc.info
                node = ProcessNode(
                    pid         = info["pid"],
                    name        = info.get("name", "?") or "?",
                    cmdline     = " ".join(info.get("cmdline") or []),
                    exe_path    = info.get("exe") or "",
                    ppid        = info.get("ppid") or 0,
                    create_time = info.get("create_time") or 0.0,
                    status      = info.get("status") or "?",
                )
                node.check_suspicious()
                all_procs[node.pid] = node
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Construir árbol
        for pid, node in all_procs.items():
            parent = all_procs.get(node.ppid)
            if parent and parent.pid != pid:
                parent.children.append(node)

        # BFS desde root_pid
        start_pid = root_pid or 1
        start_node = all_procs.get(start_pid)

        if start_node is None:
            # Fallback: usar el proceso actual
            start_pid  = os.getpid()
            start_node = all_procs.get(start_pid)

        bfs_nodes     = []
        suspicious    = []
        max_depth     = 0

        if start_node:
            queue = deque([(start_node, 0)])
            visited = set()

            while queue:
                node, depth = queue.popleft()
                if node.pid in visited:
                    continue
                visited.add(node.pid)

                node.depth = depth
                max_depth  = max(max_depth, depth)
                bfs_nodes.append(node)

                if node.is_suspicious:
                    suspicious.append(node)

                for child in node.children:
                    if child.pid not in visited:
                        queue.append((child, depth + 1))

        return ProcessTreeReport(
            root_pid        = start_pid,
            snapshot_time   = datetime.now(),
            all_nodes       = bfs_nodes,
            suspicious_nodes= suspicious,
            max_depth       = max_depth,
            total_processes = len(bfs_nodes),
        )

    # ------------------------------------------------------------------
    # Monitor continuo de un PID específico
    # ------------------------------------------------------------------

    def monitor_pid(
        self,
        pid: int,
        duration_seconds: int = 30,
        poll_interval: float = 0.5,
    ) -> ProcessTreeReport:
        """
        Monitoriza un proceso durante `duration_seconds` segundos,
        registrando todos los procesos hijos que crea.

        Usa BFS periódico para descubrir nuevos descendientes.

        Parámetros
        ----------
        pid              : PID del proceso a monitorizar.
        duration_seconds : cuánto tiempo monitorizar.
        poll_interval    : intervalo entre polls (segundos).
        """
        all_pids_seen: dict[int, ProcessNode] = {}
        start_time = time.time()

        try:
            root_proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            raise ValueError(f"PID {pid} no existe")

        # BFS periódico
        while time.time() - start_time < duration_seconds:
            try:
                # Obtener todos los hijos recursivamente
                children = root_proc.children(recursive=True)
                for proc in [root_proc] + children:
                    if proc.pid not in all_pids_seen:
                        try:
                            info = proc.as_dict(
                                attrs=["pid","name","cmdline","exe","ppid",
                                       "create_time","status"]
                            )
                            node = ProcessNode(
                                pid         = info["pid"],
                                name        = info.get("name","?") or "?",
                                cmdline     = " ".join(info.get("cmdline") or []),
                                exe_path    = info.get("exe") or "",
                                ppid        = info.get("ppid") or 0,
                                create_time = info.get("create_time") or 0.0,
                                status      = info.get("status") or "?",
                            )
                            node.check_suspicious()
                            all_pids_seen[node.pid] = node
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

            time.sleep(poll_interval)

        # Construir árbol de lo observado
        for pid_k, node in all_pids_seen.items():
            parent = all_pids_seen.get(node.ppid)
            if parent and parent.pid != pid_k:
                if node not in parent.children:
                    parent.children.append(node)

        # BFS final para asignar profundidades
        root_node  = all_pids_seen.get(pid)
        bfs_nodes  = []
        suspicious = []
        max_depth  = 0

        if root_node:
            queue   = deque([(root_node, 0)])
            visited = set()
            while queue:
                node, depth = queue.popleft()
                if node.pid in visited:
                    continue
                visited.add(node.pid)
                node.depth = depth
                max_depth  = max(max_depth, depth)
                bfs_nodes.append(node)
                if node.is_suspicious:
                    suspicious.append(node)
                for child in node.children:
                    if child.pid not in visited:
                        queue.append((child, depth + 1))

        return ProcessTreeReport(
            root_pid        = pid,
            snapshot_time   = datetime.now(),
            all_nodes       = bfs_nodes,
            suspicious_nodes= suspicious,
            max_depth       = max_depth,
            total_processes = len(bfs_nodes),
        )


# ---------------------------------------------------------------------------
# Alias de conveniencia
# ---------------------------------------------------------------------------
ProcessTreeMonitor = BFSProcessAnalyzer
