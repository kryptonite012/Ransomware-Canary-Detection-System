"""Synthetic content generators for canary files.

Canary files must look plausible to an attacker's bulk-encryption loop (correct
extension, realistic size, valid file structure) while containing ONLY
synthetic data.  They never contain real credentials, keys, personal data or
anything sensitive - that is a hard requirement: a decoy that leaks real
secrets is worse than no decoy.

The generators produce deterministic-but-randomized content seeded per file so
that each deployment is unique (an attacker cannot fingerprint canaries by a
fixed hash) yet reproducible for testing.
"""
from __future__ import annotations

import io
import random
import struct
import zipfile
from datetime import datetime, timedelta, timezone

_FIRST = ["Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Sam", "Jamie", "Avery", "Quinn",
          "Drew", "Reese", "Skyler", "Cameron", "Devon", "Harper", "Rowan", "Sage", "Blair", "Elliot"]
_LAST = ["Mercer", "Castellano", "Whitfield", "Ashby", "Thornton", "Delgado", "Okafor", "Bianchi",
         "Nystrom", "Vasquez", "Lindqvist", "Harrington", "Fontaine", "Underwood", "Marchetti"]
_DEPT = ["Finance", "Operations", "Engineering", "Legal", "Marketing", "Facilities", "Research"]
_CITY = ["Rivermouth", "Oakhaven", "Fairport", "Westbridge", "Elmford", "Northgate", "Stonebury"]

NOTE = (
    "SENTINEL CANARY FILE - DO NOT MODIFY\n"
    "This is a decoy file deployed by PROJECT SENTINEL to detect unauthorized\n"
    "encryption or tampering. It contains only synthetic, non-sensitive data.\n"
)


def _rng(seed: str | None) -> random.Random:
    return random.Random(seed) if seed is not None else random.Random()


def _rows(rng: random.Random, n: int) -> list[tuple]:
    base = datetime(2021, 1, 1, tzinfo=timezone.utc)
    out = []
    for i in range(n):
        out.append((
            1000 + i,
            f"{rng.choice(_FIRST)} {rng.choice(_LAST)}",
            rng.choice(_DEPT),
            rng.choice(_CITY),
            (base + timedelta(days=rng.randint(0, 1400))).date().isoformat(),
            round(rng.uniform(42_000, 180_000), 2),
            f"REF-{rng.randint(100000, 999999)}",
        ))
    return out


def generate_txt(seed: str | None = None) -> bytes:
    rng = _rng(seed)
    lines = [NOTE, "", "BACKUP INDEX (synthetic)", "=" * 40]
    for rid, name, dept, city, date, amount, ref in _rows(rng, rng.randint(60, 140)):
        lines.append(f"{ref}  {date}  {dept:<12} {name:<24} {city:<12} snapshot={amount}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def generate_csv(seed: str | None = None) -> bytes:
    rng = _rng(seed)
    out = io.StringIO()
    out.write("# " + NOTE.replace("\n", " ").strip() + "\n")
    out.write("record_id,full_name,department,location,start_date,salary_band,reference\n")
    for row in _rows(rng, rng.randint(120, 400)):
        out.write(",".join(str(c) for c in row) + "\n")
    return out.getvalue().encode("utf-8")


def _ooxml(seed: str | None, kind: str) -> bytes:
    """Produce a minimal but structurally valid OOXML (zip) document."""
    rng = _rng(seed)
    buf = io.BytesIO()
    body = "\n".join(f"{r[6]} {r[1]} {r[2]} {r[5]}" for r in _rows(rng, rng.randint(50, 200)))
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/></Types>')
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://purpose/doc" Target="content.xml"/></Relationships>')
        z.writestr("docProps/core.xml", f"<!-- {NOTE} -->")
        z.writestr("content.xml", f"<!-- {kind} synthetic canary -->\n<data>\n{body}\n</data>")
    return buf.getvalue()


def generate_docx(seed: str | None = None) -> bytes:
    return _ooxml(seed, "wordprocessing")


def generate_xlsx(seed: str | None = None) -> bytes:
    return _ooxml(seed, "spreadsheet")


def generate_pdf(seed: str | None = None) -> bytes:
    """A small, valid PDF (header, objects, xref, trailer)."""
    rng = _rng(seed)
    text = f"PROJECT SENTINEL synthetic canary  ref {rng.randint(100000, 999999)}"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\nBT /F1 12 Tf 72 720 Td (%s) Tj ET\nendstream"
        % (len(text) + 40, text.encode("latin-1", "replace")),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + obj + b"\nendobj\n"
    xref_pos = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref_pos)
    return bytes(out)


GENERATORS = {
    "txt": generate_txt, "csv": generate_csv, "docx": generate_docx,
    "xlsx": generate_xlsx, "pdf": generate_pdf,
}

_EXT_TO_KIND = {".txt": "txt", ".csv": "csv", ".docx": "docx", ".xlsx": "xlsx", ".pdf": "pdf",
                ".log": "txt", ".doc": "docx", ".xls": "xlsx"}


def kind_for_name(name: str) -> str:
    import os
    return _EXT_TO_KIND.get(os.path.splitext(name)[1].lower(), "txt")


def generate_for_name(name: str, seed: str | None = None) -> tuple[str, bytes]:
    kind = kind_for_name(name)
    return kind, GENERATORS[kind](seed)


# Guard: make sure a generator never emits an obvious secret-looking token.
_FORBIDDEN = (b"BEGIN PRIVATE KEY", b"BEGIN RSA", b"password=", b"api_key", b"aws_secret",
              b"-----BEGIN")


def assert_no_secrets(content: bytes) -> None:
    low = content.lower()
    for token in _FORBIDDEN:
        if token.lower() in low:
            raise ValueError(f"canary content contains forbidden token {token!r}")
