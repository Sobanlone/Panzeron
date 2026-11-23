"""Masking. Ultrimater stores and displays masked values only; raw sensitive values are never persisted."""
from __future__ import annotations

import re

_GENERIC_ORG_WORDS = {"high", "school", "middle", "elementary", "secondary", "university", "college",
                      "academy", "institute", "of", "the", "and"}


def _mask_token(tok: str) -> str:
    return tok[0] + "***" if tok else tok


def mask_value(kind: str, raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if kind == "email":
        local, _, domain = raw.partition("@")
        return f"{local[:1]}***@{domain}" if domain else _mask_token(raw)
    if kind in ("phone", "card", "national_id", "iban"):
        digits = re.sub(r"[^0-9A-Za-z]", "", raw)
        return "*" * max(len(digits) - 4, 0) + digits[-4:]
    if kind == "username":
        u = raw.lstrip("@")
        return "@" + u[:2] + "***"
    if kind == "person_name":
        return " ".join(_mask_token(t) for t in raw.split())
    if kind == "org":
        return " ".join(t if t.lower() in _GENERIC_ORG_WORDS else _mask_token(t) for t in raw.split())
    if kind == "credential":
        return raw[:4] + "…" + f"[{len(raw)} chars]"
    if kind == "location":
        m = re.match(r"\s*(-?\d+\.\d+)\s*[,;]\s*(-?\d+\.\d+)", raw)
        if m:  # coarsen coordinates (~11 km) so the stored value cannot pinpoint a place
            return f"~{float(m.group(1)):.1f}°, {float(m.group(2)):.1f}° (rounded)"
        return " ".join(_mask_token(t) for t in raw.split())
    if kind == "url":
        m = re.match(r"(?i)(https?://[^/\s?#]+)", raw)
        return (m.group(1) + "/…") if m else raw[:40]
    if kind in ("file", "message"):
        return raw
    return raw[:2] + "***"
