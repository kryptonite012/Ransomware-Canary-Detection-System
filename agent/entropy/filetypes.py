"""File-type knowledge used for entropy baselines and header (magic) checks.

Encrypted output is statistically indistinguishable from random data, which is
also what well-compressed formats look like.  Entropy alone therefore cannot
separate "a JPEG" from "an encrypted JPEG".  What *does* separate them is
structure: a JPEG starts with ``FF D8 FF``; once encrypted, the header is gone.
Each category below records whether high entropy is expected and which header
signatures are valid, so the analyzer can make file-type-aware decisions.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FileCategory:
    name: str
    expected_high_entropy: bool  # naturally compressed / encrypted container
    typical_max_entropy: float  # rough upper bound for healthy files of this type
    text_like: bool = False


CATEGORIES: dict[str, FileCategory] = {
    "text": FileCategory("text", False, 6.0, text_like=True),
    "source": FileCategory("source", False, 6.0, text_like=True),
    "data": FileCategory("data", False, 6.5, text_like=True),
    "office_ooxml": FileCategory("office_ooxml", True, 8.0),
    "office_legacy": FileCategory("office_legacy", False, 7.0),
    "pdf": FileCategory("pdf", True, 8.0),
    "image": FileCategory("image", True, 8.0),
    "image_raw": FileCategory("image_raw", False, 7.5),
    "archive": FileCategory("archive", True, 8.0),
    "audio_video": FileCategory("audio_video", True, 8.0),
    "database": FileCategory("database", False, 7.5),
    "executable": FileCategory("executable", False, 7.5),
    "encrypted": FileCategory("encrypted", True, 8.0),
    "unknown": FileCategory("unknown", False, 8.0),
}

EXTENSION_CATEGORY: dict[str, str] = {}


def _register(category: str, *exts: str) -> None:
    for e in exts:
        EXTENSION_CATEGORY[e] = category


_register("text", ".txt", ".log", ".md", ".rst", ".rtf", ".ini", ".cfg", ".conf", ".tex", ".srt", ".nfo")
_register(
    "source", ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".c", ".h", ".cpp", ".hpp", ".cs", ".go", ".rs",
    ".rb", ".php", ".sh", ".ps1", ".bat", ".html", ".htm", ".css", ".scss", ".sql", ".kt", ".swift", ".lua",
)
_register("data", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".toml", ".ics", ".vcf", ".svg")
_register("office_ooxml", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".odp", ".epub")
_register("office_legacy", ".doc", ".xls", ".ppt", ".msg", ".pst")
_register("pdf", ".pdf")
_register("image", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".avif", ".jxl")
_register("image_raw", ".bmp", ".tif", ".tiff", ".psd", ".raw", ".cr2", ".nef", ".dng", ".ico")
_register("archive", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst", ".lz4", ".jar", ".apk", ".whl")
_register(
    "audio_video", ".mp3", ".mp4", ".m4a", ".m4v", ".mkv", ".avi", ".mov", ".wmv", ".flac", ".ogg", ".opus",
    ".webm", ".aac",
)
_register("database", ".sqlite", ".sqlite3", ".db", ".mdb", ".accdb", ".dbf")
_register("executable", ".exe", ".dll", ".so", ".dylib", ".sys", ".msi", ".bin", ".o", ".class")
_register("encrypted", ".gpg", ".pgp", ".asc", ".kdbx", ".age", ".p12", ".pfx")

# Header signatures: extension -> list of (offset, bytes).
MAGIC: dict[str, list[tuple[int, bytes]]] = {
    ".zip": [(0, b"PK\x03\x04"), (0, b"PK\x05\x06")],
    ".pdf": [(0, b"%PDF")],
    ".png": [(0, b"\x89PNG\r\n\x1a\n")],
    ".jpg": [(0, b"\xff\xd8\xff")],
    ".jpeg": [(0, b"\xff\xd8\xff")],
    ".gif": [(0, b"GIF87a"), (0, b"GIF89a")],
    ".webp": [(8, b"WEBP")],
    ".gz": [(0, b"\x1f\x8b")],
    ".tgz": [(0, b"\x1f\x8b")],
    ".bz2": [(0, b"BZh")],
    ".xz": [(0, b"\xfd7zXZ\x00")],
    ".7z": [(0, b"7z\xbc\xaf\x27\x1c")],
    ".rar": [(0, b"Rar!\x1a\x07")],
    ".zst": [(0, b"\x28\xb5\x2f\xfd")],
    ".mp3": [(0, b"ID3"), (0, b"\xff\xfb"), (0, b"\xff\xf3"), (0, b"\xff\xf2")],
    ".mp4": [(4, b"ftyp")],
    ".m4a": [(4, b"ftyp")],
    ".m4v": [(4, b"ftyp")],
    ".mov": [(4, b"ftyp"), (4, b"moov"), (4, b"wide"), (4, b"mdat")],
    ".heic": [(4, b"ftyp")],
    ".avif": [(4, b"ftyp")],
    ".mkv": [(0, b"\x1a\x45\xdf\xa3")],
    ".webm": [(0, b"\x1a\x45\xdf\xa3")],
    ".flac": [(0, b"fLaC")],
    ".ogg": [(0, b"OggS")],
    ".opus": [(0, b"OggS")],
    ".sqlite": [(0, b"SQLite format 3\x00")],
    ".sqlite3": [(0, b"SQLite format 3\x00")],
    ".exe": [(0, b"MZ")],
    ".dll": [(0, b"MZ")],
    ".sys": [(0, b"MZ")],
    ".so": [(0, b"\x7fELF")],
    ".bmp": [(0, b"BM")],
    ".tif": [(0, b"II*\x00"), (0, b"MM\x00*")],
    ".tiff": [(0, b"II*\x00"), (0, b"MM\x00*")],
    ".psd": [(0, b"8BPS")],
    ".doc": [(0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")],
    ".xls": [(0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")],
    ".ppt": [(0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")],
    ".msg": [(0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")],
    ".kdbx": [(0, b"\x03\xd9\xa2\x9a")],
    ".class": [(0, b"\xca\xfe\xba\xbe")],
}
for _ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".odp", ".epub", ".jar",
             ".apk", ".whl"):
    MAGIC[_ext] = MAGIC[".zip"]

MAX_MAGIC_BYTES = 32


def extension_of(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def category_for(path: str) -> FileCategory:
    return CATEGORIES[EXTENSION_CATEGORY.get(extension_of(path), "unknown")]


def check_magic(path: str, header: bytes) -> bool | None:
    """True if header matches a known signature, False if it does not,
    None if the extension has no registered signature."""
    sigs = MAGIC.get(extension_of(path))
    if not sigs:
        return None
    for offset, sig in sigs:
        if header[offset: offset + len(sig)] == sig:
            return True
    return False


def looks_like_text(sample: bytes) -> bool:
    """Heuristic: decodable as UTF-8/UTF-16 text with few control characters."""
    if not sample:
        return True
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            sample.decode("utf-16")
            return True
        except UnicodeDecodeError:
            return False
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError as exc:
        # Allow a multibyte character truncated at the end of the sample.
        if exc.start < len(sample) - 4:
            return False
        text = sample[: exc.start].decode("utf-8", errors="ignore")
    if not text:
        return False
    control = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\r\n\f\v")
    return control / len(text) < 0.02
