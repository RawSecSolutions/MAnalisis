#!/usr/bin/env python3
"""
main.py
=======
CLI principal del Malware Analysis Lab.

Uso básico
----------
    # Análisis estático completo
    python main.py analyze sample.exe

    # Con clave VirusTotal
    python main.py analyze sample.exe --vt-key TU_CLAVE_AQUI

    # Solo hash + threat intel
    python main.py hash sample.exe

    # Solo entropía
    python main.py entropy sample.exe

    # Solo PE metadata
    python main.py pe sample.exe

    # Solo detección de packer
    python main.py packer sample.exe

    # Solo búsqueda de strings (Aho-Corasick)
    python main.py strings sample.exe

    # Análisis de volcado de memoria
    python main.py memdump dump.bin

    # Monitoreo de proceso en tiempo real
    python main.py monitor --pid 1234 --duration 30

    # Captura de red
    python main.py network --pid 1234

Opciones globales
-----------------
    --vt-key    : API key de VirusTotal
    --verbose   : mostrar progreso
    --no-intel  : omitir consultas a threat intel (modo offline)
    --output    : guardar informe en fichero JSON
"""

import argparse
import json
import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuración desde variables de entorno
# ---------------------------------------------------------------------------

def get_env_key(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


# ---------------------------------------------------------------------------
# Comandos
# ---------------------------------------------------------------------------

def cmd_analyze(args) -> int:
    """Pipeline de análisis completo."""
    from lab.pipeline import MalwareAnalysisPipeline

    pipeline = MalwareAnalysisPipeline(
        vt_api_key         = args.vt_key or get_env_key("VT_API_KEY"),
        query_threat_intel = not args.no_intel,
    )

    print(f"\n[*] Analizando: {args.file}")
    result = pipeline.analyze(args.file, verbose=args.verbose)
    print(result.full_report())

    if args.output:
        _save_json(result, args.output)

    if result.scoring_report:
        score = result.scoring_report.total_score
        # Exit code refleja el nivel de riesgo
        if score >= 51:
            return 3   # MALWARE
        elif score >= 26:
            return 2   # PROBABLE MALWARE
        elif score >= 11:
            return 1   # SOSPECHOSO
    return 0


def cmd_hash(args) -> int:
    """Solo análisis de hashes + threat intel."""
    from lab.core.hash_analysis import HashAnalyzer

    analyzer = HashAnalyzer(
        vt_api_key=args.vt_key or get_env_key("VT_API_KEY")
    )
    report = analyzer.analyze(
        args.file,
        query_vt = not args.no_intel,
        query_mb = not args.no_intel,
    )
    print(report)
    return 0


def cmd_entropy(args) -> int:
    """Análisis de entropía."""
    from lab.core.entropy import EntropyAnalyzer

    analyzer = EntropyAnalyzer()
    report   = analyzer.analyze(args.file, use_sliding_window=True)
    print(report)
    return 0


def cmd_pe(args) -> int:
    """Análisis de metadatos PE."""
    from lab.core.pe_analysis import PEAnalyzer

    analyzer = PEAnalyzer()
    report   = analyzer.analyze(args.file)
    print(report)
    return 0


def cmd_packer(args) -> int:
    """Detección de packer."""
    from lab.core.packer_detector import PackerDetector

    detector = PackerDetector()
    report   = detector.detect(args.file)
    print(report)
    if report.is_packed and report.can_auto_unpack:
        print(f"\n[!] Para desempaquetar:\n    {report.unpack_command}")
    return 0


def cmd_strings(args) -> int:
    """Búsqueda de strings con Aho-Corasick."""
    from lab.core.string_search import AhoCorasickSearcher

    searcher = AhoCorasickSearcher()
    searcher.build()
    report = searcher.search_file(args.file, deduplicate=not args.all)
    print(report)
    return 0


def cmd_memdump(args) -> int:
    """Análisis de volcado de memoria."""
    from lab.memory.dump_analyzer import MemoryDumpAnalyzer

    analyzer = MemoryDumpAnalyzer()
    report   = analyzer.analyze(args.file)
    print(report)

    if args.extract_pes and report.embedded_pes:
        out_dir = Path(args.extract_pes)
        out_dir.mkdir(parents=True, exist_ok=True)
        for i, pe in enumerate(report.embedded_pes):
            if pe.is_valid:
                out_path = out_dir / f"extracted_pe_{i:03d}_0x{pe.offset:08X}.bin"
                success  = analyzer.extract_embedded_pe(
                    args.file, pe.offset, str(out_path)
                )
                if success:
                    print(f"  [*] PE extraído: {out_path}")
    return 0


def cmd_monitor(args) -> int:
    """Monitoreo de árbol de procesos con BFS."""
    from lab.dynamic.process_tree import BFSProcessAnalyzer

    analyzer = BFSProcessAnalyzer()

    if args.pid:
        print(f"\n[*] Monitorizando PID {args.pid} durante {args.duration}s...")
        report = analyzer.monitor_pid(
            pid              = args.pid,
            duration_seconds = args.duration,
        )
    else:
        print("\n[*] Capturando snapshot del sistema...")
        report = analyzer.analyze_system_snapshot()

    print(report)
    print("\n  Árbol de procesos:")
    print(report.print_tree())
    return 0


def cmd_network(args) -> int:
    """Monitoreo de red."""
    from lab.dynamic.network_monitor import NetworkMonitor

    monitor = NetworkMonitor()
    report  = monitor.snapshot_connections(pid=args.pid)
    print(report)

    if args.capture:
        print(f"\n[*] Capturando tráfico en {args.interface} durante {args.duration}s...")
        capture_report = monitor.capture_traffic(
            pid       = args.pid,
            duration  = args.duration,
            interface = args.interface,
        )
        print(capture_report)
    return 0


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def _save_json(result, output_path: str) -> None:
    """Guarda el resultado en formato JSON (simplificado)."""
    data = {
        "file_path":     result.file_path,
        "analysis_time": result.analysis_time,
        "score":         result.scoring_report.total_score if result.scoring_report else 0,
        "risk_level":    result.scoring_report.risk_level  if result.scoring_report else "?",
        "errors":        result.errors,
    }
    if result.hash_report:
        data["hashes"] = {
            "md5":    result.hash_report.md5,
            "sha1":   result.hash_report.sha1,
            "sha256": result.hash_report.sha256,
        }
    Path(output_path).write_text(json.dumps(data, indent=2, default=str))
    print(f"\n[*] Informe guardado en: {output_path}")


# ---------------------------------------------------------------------------
# Parser de argumentos
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog        = "malware-lab",
        description = "Malware Analysis Lab - Herramienta educativa para Kali Linux",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
Ejemplos:
  python main.py analyze sample.exe --verbose
  python main.py analyze sample.exe --vt-key API_KEY --output report.json
  python main.py hash sample.exe --no-intel
  python main.py pe sample.exe
  python main.py packer sample.exe
  python main.py strings sample.exe
  python main.py entropy sample.exe
  python main.py memdump dump.bin --extract-pes ./extracted/
  python main.py monitor --pid 1234 --duration 60
  python main.py network --capture --interface eth0 --duration 30
        """,
    )

    # Opciones globales — definidas tanto en el parser padre como en cada
    # subparser para que funcionen antes o después del subcomando.
    global_opts = {
        "--vt-key":   dict(default="",    help="API key de VirusTotal v3"),
        "--no-intel": dict(action="store_true", help="Modo offline (sin consultas)"),
        "--verbose":  dict(action="store_true", help="Mostrar progreso detallado"),
        "--output":   dict(default="",    help="Guardar informe en JSON"),
    }

    for flag, kw in global_opts.items():
        parser.add_argument(flag, **kw)

    subparsers = parser.add_subparsers(dest="command", required=True)

    def _add_global(sub):
        """Añade las opciones globales a un subparser."""
        for flag, kw in global_opts.items():
            sub.add_argument(flag, **kw)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Pipeline de análisis completo")
    p_analyze.add_argument("file", help="Fichero a analizar")
    _add_global(p_analyze)

    # hash
    p_hash = subparsers.add_parser("hash", help="Hashes + threat intelligence")
    p_hash.add_argument("file", help="Fichero a analizar")
    _add_global(p_hash)

    # entropy
    p_entropy = subparsers.add_parser("entropy", help="Análisis de entropía")
    p_entropy.add_argument("file", help="Fichero a analizar")
    _add_global(p_entropy)

    # pe
    p_pe = subparsers.add_parser("pe", help="Metadatos PE")
    p_pe.add_argument("file", help="Fichero PE a analizar")
    _add_global(p_pe)

    # packer
    p_packer = subparsers.add_parser("packer", help="Detección de packer")
    p_packer.add_argument("file", help="Fichero a analizar")
    _add_global(p_packer)

    # strings
    p_strings = subparsers.add_parser("strings", help="Búsqueda de strings (Aho-Corasick)")
    p_strings.add_argument("file", help="Fichero a analizar")
    p_strings.add_argument("--all", action="store_true", help="No deduplicar (todas las ocurrencias)")
    _add_global(p_strings)

    # memdump
    p_memdump = subparsers.add_parser("memdump", help="Análisis de volcado de memoria")
    p_memdump.add_argument("file", help="Fichero de dump")
    p_memdump.add_argument("--extract-pes", default="", metavar="DIR",
                           help="Directorio para extraer PEs incrustados")
    _add_global(p_memdump)

    # monitor
    p_monitor = subparsers.add_parser("monitor", help="Monitoreo de árbol de procesos (BFS)")
    p_monitor.add_argument("--pid",      type=int, default=0, help="PID a monitorizar (0=sistema)")
    p_monitor.add_argument("--duration", type=int, default=30, help="Segundos de monitoreo")
    _add_global(p_monitor)

    # network
    p_network = subparsers.add_parser("network", help="Monitoreo de red")
    p_network.add_argument("--pid",       type=int, default=0,     help="PID a filtrar (0=todos)")
    p_network.add_argument("--capture",   action="store_true",     help="Capturar con tcpdump")
    p_network.add_argument("--interface", default="eth0",          help="Interfaz de red")
    p_network.add_argument("--duration",  type=int, default=30,    help="Segundos de captura")
    _add_global(p_network)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

COMMANDS = {
    "analyze": cmd_analyze,
    "hash":    cmd_hash,
    "entropy": cmd_entropy,
    "pe":      cmd_pe,
    "packer":  cmd_packer,
    "strings": cmd_strings,
    "memdump": cmd_memdump,
    "monitor": cmd_monitor,
    "network": cmd_network,
}


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    handler = COMMANDS.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por el usuario.")
        return 130
    except Exception as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
