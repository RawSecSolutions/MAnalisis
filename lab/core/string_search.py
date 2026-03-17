"""
string_search.py
================
Motor de búsqueda de strings sospechosos en binarios usando el algoritmo
Aho-Corasick.

Algoritmo Aho-Corasick
-----------------------
Permite buscar simultáneamente múltiples patrones en un texto en tiempo
O(n + m + z), donde:
  n = longitud del texto
  m = suma de longitudes de todos los patrones
  z = número total de coincidencias

Es drásticamente más eficiente que buscar cada patrón por separado
(que sería O(n·k) con k patrones).

Pasos:
  1. Construir el trie de los patrones (prefijos compartidos).
  2. Calcular la función de fallo (suffix links) con BFS.
  3. Calcular los output links para coincidencias en sufijos.
  4. Recorrer el texto una sola vez usando el autómata resultante.

Uso
---
    from lab.core.string_search import AhoCorasickSearcher

    searcher = AhoCorasickSearcher()
    searcher.build()            # carga patrones maliciosos por defecto
    results = searcher.search(data)
    for match in results:
        print(match)
"""

from collections import deque
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Diccionario de patrones con categorías y severidad
# ---------------------------------------------------------------------------

MALWARE_PATTERNS: dict[str, list[tuple[str, int]]] = {
    "network": [
        ("http://",         3), ("https://",        3),
        ("ftp://",          2), ("socket",           2),
        ("connect",         2), ("WSAStartup",       3),
        ("InternetOpen",    3), ("URLDownloadToFile",4),
        ("WinHttpOpen",     3), ("curl_easy_init",   2),
        ("recv",            2), ("send",             2),
    ],
    "persistence": [
        ("RegSetValueEx",   4), ("RegCreateKey",     3),
        ("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 5),
        ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",              5),
        ("schtasks",        4), ("at ",              2),
        ("startup",         2), ("autorun",          4),
    ],
    "injection": [
        ("VirtualAllocEx",  4), ("WriteProcessMemory",4),
        ("CreateRemoteThread",5),("NtUnmapViewOfSection",5),
        ("ZwUnmapViewOfSection",5),("SetWindowsHookEx",3),
        ("OpenProcess",     3), ("NtCreateThreadEx", 4),
        ("RtlCreateUserThread",4),
    ],
    "evasion": [
        ("IsDebuggerPresent",3),("CheckRemoteDebuggerPresent",3),
        ("NtQueryInformationProcess",3),
        ("GetTickCount",    2), ("timeGetTime",      2),
        ("Sleep",           1), ("VirtualProtect",   3),
        ("NtSetInformationThread",3),
        ("OutputDebugString",2),
    ],
    "credential_theft": [
        ("lsass",           5), ("SAM",              4),
        ("SECURITY",        3), ("mimikatz",         5),
        ("sekurlsa",        5), ("logonpasswords",   5),
        ("wce",             3), ("fgdump",           4),
        ("hashdump",        4), ("CryptAcquireContext",3),
    ],
    "ransomware": [
        ("CryptEncrypt",    4), ("BCryptEncrypt",    4),
        ("AES",             2), ("RSA",              2),
        ("Your files",      4), ("decrypt",          3),
        ("ransom",          4), ("bitcoin",          3),
        (".locked",         4), (".encrypted",       4),
        ("How to recover",  4),
    ],
    "c2_indicators": [
        ("cmd.exe",         3), ("powershell",       3),
        ("base64",          2), ("eval(",            3),
        ("exec(",           2), ("subprocess",       2),
        ("shell32",         2), ("ShellExecute",     3),
        ("WScript.Shell",   4), ("Invoke-Expression",4),
    ],
    "suspicious_paths": [
        ("%TEMP%",          2), ("%APPDATA%",        2),
        ("\\Temp\\",        2), ("\\AppData\\",      2),
        ("C:\\Windows\\Temp",3),("C:\\Users\\",      1),
    ],
    "packers_strings": [
        ("UPX0",            3), ("UPX1",             3),
        ("Themida",         4), ("VMProtect",        4),
        ("ASPack",          3), ("MPRESS",           3),
    ],
}

# Aplanar a lista de (patrón, categoría, severidad)
ALL_PATTERNS: list[tuple[str, str, int]] = [
    (pattern, category, severity)
    for category, items in MALWARE_PATTERNS.items()
    for pattern, severity in items
]


# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class StringMatch:
    pattern: str
    category: str
    severity: int
    offset: int
    context: bytes = field(default=b"", repr=False)

    @property
    def context_str(self) -> str:
        return self.context.decode("latin-1", errors="replace")


@dataclass
class StringSearchReport:
    file_path: str
    total_size: int
    matches: list[StringMatch] = field(default_factory=list)
    patterns_searched: int = 0

    @property
    def by_category(self) -> dict[str, list[StringMatch]]:
        result: dict[str, list[StringMatch]] = {}
        for m in self.matches:
            result.setdefault(m.category, []).append(m)
        return result

    @property
    def total_score(self) -> int:
        return sum(m.severity for m in self.matches)

    @property
    def unique_patterns(self) -> set[str]:
        return {m.pattern for m in self.matches}

    def __str__(self) -> str:
        lines = [
            "=== String Search Report (Aho-Corasick) ===",
            f"  Archivo     : {self.file_path}",
            f"  Tamaño      : {self.total_size:,} bytes",
            f"  Patrones    : {self.patterns_searched} buscados",
            f"  Coincidencias: {len(self.matches)} encontradas",
            f"  Score total : {self.total_score}",
        ]
        by_cat = self.by_category
        if by_cat:
            lines.append("\n  Por categoría:")
            for cat, items in sorted(by_cat.items()):
                score = sum(m.severity for m in items)
                lines.append(f"    [{score:3d}] {cat}: {len(items)} hits")
                for m in items[:5]:  # mostrar máx 5 por categoría
                    lines.append(
                        f"          +0x{m.offset:08X}  '{m.pattern}'  "
                        f"(sev={m.severity})"
                    )
                if len(items) > 5:
                    lines.append(f"          ... y {len(items) - 5} más")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Nodo del Trie / autómata de Aho-Corasick
# ---------------------------------------------------------------------------

class _AhoCorasickNode:
    __slots__ = ("children", "fail", "output")

    def __init__(self):
        self.children: dict[int, "_AhoCorasickNode"] = {}
        self.fail: Optional["_AhoCorasickNode"] = None
        # Lista de (patrón, categoría, severidad) que terminan aquí
        self.output: list[tuple[str, str, int]] = []


# ---------------------------------------------------------------------------
# Motor Aho-Corasick
# ---------------------------------------------------------------------------

class AhoCorasickSearcher:
    """
    Buscador multi-patrón basado en Aho-Corasick.

    Parámetros
    ----------
    case_insensitive : bool
        Si True, la búsqueda ignora mayúsculas/minúsculas.
    context_bytes : int
        Número de bytes de contexto alrededor de cada coincidencia.
    """

    def __init__(
        self,
        case_insensitive: bool = True,
        context_bytes: int = 32,
    ):
        self.case_insensitive = case_insensitive
        self.context_bytes    = context_bytes
        self._root: Optional[_AhoCorasickNode] = None
        self._patterns: list[tuple[str, str, int]] = []
        self._built = False

    # ------------------------------------------------------------------
    # Construcción del autómata
    # ------------------------------------------------------------------

    def add_patterns(
        self,
        patterns: list[tuple[str, str, int]]
    ) -> None:
        """
        Agrega patrones al diccionario.

        patterns : lista de (string_patron, categoria, severidad)
        """
        self._patterns.extend(patterns)
        self._built = False

    def build(self, patterns: Optional[list[tuple[str, str, int]]] = None) -> None:
        """
        Construye el autómata Aho-Corasick.

        Si se pasa `patterns`, reemplaza los patrones actuales.
        Si no, usa los patrones cargados con add_patterns() o ALL_PATTERNS.

        Complejidad: O(m) donde m = suma de longitudes de todos los patrones.
        """
        if patterns is not None:
            self._patterns = patterns
        elif not self._patterns:
            self._patterns = ALL_PATTERNS

        root = _AhoCorasickNode()

        # Fase 1: Construir el trie
        for raw_pattern, category, severity in self._patterns:
            pattern = raw_pattern.lower() if self.case_insensitive else raw_pattern
            node    = root
            for byte in pattern.encode("latin-1", errors="replace"):
                node = node.children.setdefault(byte, _AhoCorasickNode())
            node.output.append((raw_pattern, category, severity))

        # Fase 2: Calcular suffix links (función de fallo) con BFS
        queue = deque()
        root.fail = root

        for child in root.children.values():
            child.fail = root
            queue.append(child)

        while queue:
            current = queue.popleft()
            for byte, child in current.children.items():
                # Buscar el suffix link del padre
                fail_node = current.fail
                while fail_node is not root and byte not in fail_node.children:
                    fail_node = fail_node.fail
                child.fail = fail_node.children.get(byte, root)
                if child.fail is child:
                    child.fail = root
                # Propagar outputs del nodo de fallo (output links)
                child.output = child.output + child.fail.output
                queue.append(child)

        self._root  = root
        self._built = True

    # ------------------------------------------------------------------
    # Búsqueda
    # ------------------------------------------------------------------

    def _search_bytes(
        self, data: bytes, file_path: str = ""
    ) -> list[StringMatch]:
        """
        Ejecuta el autómata sobre los datos y retorna coincidencias.

        Complejidad: O(n + z) donde n = len(data), z = número de matches.
        """
        if not self._built:
            self.build()

        if self.case_insensitive:
            search_data = data.lower()
        else:
            search_data = data

        root    = self._root
        node    = root
        matches = []

        for i, byte in enumerate(search_data):
            # Seguir el autómata (con suffix links ante fallos)
            while node is not root and byte not in node.children:
                node = node.fail
            node = node.children.get(byte, root)

            # Registrar coincidencias en este nodo
            for raw_pattern, category, severity in node.output:
                pat_len = len(raw_pattern)
                offset  = i - pat_len + 1
                # Contexto alrededor de la coincidencia
                ctx_start = max(0, offset - self.context_bytes)
                ctx_end   = min(len(data), offset + pat_len + self.context_bytes)
                context   = data[ctx_start:ctx_end]

                matches.append(
                    StringMatch(
                        pattern  = raw_pattern,
                        category = category,
                        severity = severity,
                        offset   = offset,
                        context  = context,
                    )
                )

        return matches

    # ------------------------------------------------------------------
    # Interfaz pública
    # ------------------------------------------------------------------

    def search(
        self,
        data: bytes,
        file_path: str = "<memory>",
        deduplicate: bool = True,
    ) -> StringSearchReport:
        """
        Busca todos los patrones en `data`.

        Parámetros
        ----------
        data        : bytes del fichero o volcado de memoria.
        file_path   : ruta para el informe.
        deduplicate : si True, reporta solo la primera ocurrencia por patrón.

        Retorna
        -------
        StringSearchReport
        """
        if not self._built:
            self.build()

        matches = self._search_bytes(data, file_path)

        if deduplicate:
            seen    = set()
            unique  = []
            for m in matches:
                if m.pattern not in seen:
                    seen.add(m.pattern)
                    unique.append(m)
            matches = unique

        # Ordenar por severidad descendente
        matches.sort(key=lambda m: (-m.severity, m.offset))

        return StringSearchReport(
            file_path         = file_path,
            total_size        = len(data),
            matches           = matches,
            patterns_searched = len(self._patterns),
        )

    def search_file_chunked(
        self,
        file_path: str,
        deduplicate: bool = True,
        chunk_size_mb: int = 64,
    ) -> StringSearchReport:
        """
        Lee el fichero en bloques y ejecuta la búsqueda Aho-Corasick
        sobre cada bloque con solapamiento para no perder coincidencias
        que caigan en la frontera entre chunks.

        Parámetros
        ----------
        chunk_size_mb : tamaño de cada bloque de lectura (MB).
        """
        from pathlib import Path

        if not self._built:
            self.build()

        path       = Path(file_path)
        total_size = path.stat().st_size
        chunk_size = chunk_size_mb * 1024 * 1024

        # El solapamiento debe cubrir el patrón más largo para no
        # perder coincidencias en la frontera entre chunks.
        max_pat_len = max(len(p.encode("latin-1", errors="replace"))
                         for p, _, _ in self._patterns) if self._patterns else 0
        overlap     = max_pat_len + self.context_bytes

        all_matches: list[StringMatch] = []
        processed   = 0

        with open(path, "rb") as fh:
            while processed < total_size:
                # Retroceder `overlap` bytes para cubrir la frontera,
                # excepto en el primer chunk.
                read_start = max(0, processed - overlap)
                fh.seek(read_start)
                to_read = chunk_size + (processed - read_start)
                chunk   = fh.read(to_read)

                if not chunk:
                    break

                chunk_matches = self._search_bytes(chunk, file_path)

                # Ajustar offsets al offset absoluto del fichero y
                # descartar matches del solapamiento ya procesado.
                base_offset   = read_start
                frontier      = processed - read_start  # inicio de datos nuevos

                for m in chunk_matches:
                    abs_offset = m.offset + base_offset
                    # Solo aceptar coincidencias que empiezan en la zona nueva
                    # (o en el primer chunk donde todo es nuevo).
                    if processed == 0 or m.offset >= frontier:
                        all_matches.append(
                            StringMatch(
                                pattern  = m.pattern,
                                category = m.category,
                                severity = m.severity,
                                offset   = abs_offset,
                                context  = m.context,
                            )
                        )

                processed = read_start + len(chunk)

        if deduplicate:
            seen   = set()
            unique = []
            for m in all_matches:
                if m.pattern not in seen:
                    seen.add(m.pattern)
                    unique.append(m)
            all_matches = unique

        all_matches.sort(key=lambda m: (-m.severity, m.offset))

        return StringSearchReport(
            file_path         = str(file_path),
            total_size        = total_size,
            matches           = all_matches,
            patterns_searched = len(self._patterns),
        )

    def search_file(
        self,
        file_path: str,
        deduplicate: bool = True,
        max_size_mb: int = 100,
    ) -> StringSearchReport:
        """
        Lee el fichero y ejecuta la búsqueda.

        Para ficheros pequeños (≤ max_size_mb) carga todo en memoria.
        Para ficheros grandes usa lectura por bloques (chunked search).

        Parámetros
        ----------
        max_size_mb : umbral a partir del cual se activa chunked search (MB).
        """
        from pathlib import Path
        path = Path(file_path)
        size = path.stat().st_size

        if size > max_size_mb * 1024 * 1024:
            return self.search_file_chunked(
                file_path, deduplicate=deduplicate
            )

        data = path.read_bytes()
        return self.search(data, file_path=str(file_path), deduplicate=deduplicate)
