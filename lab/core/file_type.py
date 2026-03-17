"""
file_type.py
============
Detección de tipo de archivo por magic bytes (sin dependencias externas).

Uso
---
    from lab.core.file_type import detect_file_type, FileType

    ft = detect_file_type("muestra.dmg")
    # ft == FileType.DMG
"""

from enum import Enum
from pathlib import Path


class FileType(str, Enum):
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    DMG = "dmg"
    ZIP = "zip"
    PDF = "pdf"
    UNKNOWN = "unknown"


# Magic bytes → FileType (checked in order)
_MAGIC_TABLE: list[tuple[bytes, int, FileType]] = [
    # (magic, offset, file_type)
    (b"\x7fELF",                   0, FileType.ELF),
    (b"MZ",                        0, FileType.PE),
    (b"\xcf\xfa\xed\xfe",         0, FileType.MACHO),  # Mach-O 64-bit
    (b"\xce\xfa\xed\xfe",         0, FileType.MACHO),  # Mach-O 32-bit
    (b"\xfe\xed\xfa\xcf",         0, FileType.MACHO),  # Mach-O 64 big-endian
    (b"\xfe\xed\xfa\xce",         0, FileType.MACHO),  # Mach-O 32 big-endian
    (b"\xca\xfe\xba\xbe",         0, FileType.MACHO),  # Universal binary
    (b"PK\x03\x04",               0, FileType.ZIP),
    (b"%PDF",                      0, FileType.PDF),
]

# DMG "koly" trailer signature (last 512 bytes)
_DMG_KOLY = b"koly"

# Formats that are inherently compressed (high entropy is normal)
COMPRESSED_FORMATS = frozenset({FileType.DMG, FileType.ZIP, FileType.PDF})

# Only PE has meaningful packer/PE analysis
PE_ONLY_FORMATS = frozenset({FileType.PE})


def detect_file_type(path: str | Path) -> FileType:
    """
    Detecta el tipo de archivo por magic bytes.

    Fallback: usa la extensión del archivo si no se reconocen los magic bytes.
    """
    path = Path(path)

    try:
        with open(path, "rb") as f:
            header = f.read(16)
    except (OSError, IOError):
        return FileType.UNKNOWN

    if not header:
        return FileType.UNKNOWN

    # Check magic bytes
    for magic, offset, file_type in _MAGIC_TABLE:
        end = offset + len(magic)
        if len(header) >= end and header[offset:end] == magic:
            return file_type

    # DMG: check for "koly" trailer
    try:
        file_size = path.stat().st_size
        if file_size >= 512:
            with open(path, "rb") as f:
                f.seek(-512, 2)
                trailer = f.read(512)
                if _DMG_KOLY in trailer:
                    return FileType.DMG
    except (OSError, IOError):
        pass

    # Fallback: extension
    ext = path.suffix.lower()
    _EXT_MAP = {
        ".exe": FileType.PE,
        ".dll": FileType.PE,
        ".sys": FileType.PE,
        ".scr": FileType.PE,
        ".elf": FileType.ELF,
        ".dmg": FileType.DMG,
        ".zip": FileType.ZIP,
        ".apk": FileType.ZIP,
        ".jar": FileType.ZIP,
        ".docx": FileType.ZIP,
        ".xlsx": FileType.ZIP,
        ".pptx": FileType.ZIP,
        ".pdf": FileType.PDF,
        ".app": FileType.MACHO,
    }
    return _EXT_MAP.get(ext, FileType.UNKNOWN)
