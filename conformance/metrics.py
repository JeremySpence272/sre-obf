"""Diagnostics and narrow recovery contracts, not a universal hardness score."""
from __future__ import annotations

import hashlib
import re

CANARY = 0x13579BDF
FOLDABLE = 0x6B12C9A7


def contains_integer(text: str, value: int, width: int = 32) -> bool:
    # Recognize signed decimal/hex spellings modulo the known fixture width.
    # Exclude identifiers, addresses embedded in labels, and floating literals.
    pattern = r"(?<![\w.])(-?(?:0x[0-9a-fA-F]+|[0-9]+))(?:[uUlL]*)(?![\w.])"
    mask = (1 << width) - 1
    return any((int(token, 16 if "0x" in token else 10) & mask) == value
               for token in re.findall(pattern, text))


def normalize_c(text: str) -> str:
    # Names/spacing are incidental; constants, casts, comparisons and signedness
    # must survive. This is a diagnostic fingerprint, not semantic equivalence.
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    names = {}
    def replace(match):
        name = match.group(0)
        return names.setdefault(name, f"v{len(names)}")
    text = re.sub(r"\b(?:local|uVar|iVar|bVar|cVar|lVar|pVar|param)_?\w*\b",
                  replace, text)
    return re.sub(r"\s+", " ", text).strip()


def c_metrics(text: str) -> dict:
    normalized = normalize_c(text)
    return {"bytes": len(text.encode()), "normalized_sha256":
            hashlib.sha256(normalized.encode()).hexdigest(),
            "canary_recovered": contains_integer(text, CANARY),
            "goto_count": len(re.findall(r"\bgoto\b", text)),
            "switch_count": len(re.findall(r"\bswitch\b", text))}


def flattening_ran(report: dict) -> bool:
    return any(p.get("id") == "flattening" and p.get("status") == "ran"
               and p.get("changed") is True
               for fn in report.get("functions", [])
               for p in fn.get("passes", []))
