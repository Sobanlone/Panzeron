"""UI preferences: the single source of truth for what the appearance system accepts.

Values end up inside CSS and DOM attributes, so everything is validated against a strict whitelist here (and mirrored in
the front end). Unknown keys are dropped, out-of-range numbers are clamped, colours must be #rrggbb. Nothing else gets through.
"""
from __future__ import annotations

import re
from typing import Any

DEFAULTS: dict[str, Any] = {
    "accent": "#4169e1",         # royal blue
    "bg": "royal",               # royal | midnight | ocean | emerald | crimson | graphite | solid
    "pureBlack": False,          # true black base (OLED)
    "fx": "auto",                # auto | full | lite (glass quality)
    "blur": 22,                  # glass blur radius, px
    "glass": 50,                 # glass opacity/tint, 0-100
    "sheen": True,               # pointer-following highlight
    "density": "comfortable",    # compact | comfortable | spacious
    "width": "default",          # focused | default | full
    "sidebar": "expanded",       # expanded | compact
    "font": "system",            # system | humanist | serif | mono
    "textSize": "default",       # small | default | large | xl
    "anim": True,                # interface animations
    "sound": True,               # interface sound effects
}
ENUMS: dict[str, set[str]] = {
    "bg": {"royal", "midnight", "ocean", "emerald", "crimson", "graphite", "solid"},
    "fx": {"auto", "full", "lite"},
    "density": {"compact", "comfortable", "spacious"},
    "width": {"focused", "default", "full"},
    "sidebar": {"expanded", "compact"},
    "font": {"system", "humanist", "serif", "mono"},
    "textSize": {"small", "default", "large", "xl"},
}
BOOLS = {"pureBlack", "sheen", "anim", "sound"}
RANGES = {"blur": (0, 40), "glass": (0, 100)}
HEX = re.compile(r"^#[0-9a-fA-F]{6}$")


def sanitize(raw: Any) -> tuple[dict[str, Any], list[str]]:
    """Returns (clean full preference set, list of keys that were rejected or unknown)."""
    clean = dict(DEFAULTS)
    rejected: list[str] = []
    if not isinstance(raw, dict):
        return clean, ["<not an object>"]
    for key, val in raw.items():
        if key not in DEFAULTS:
            rejected.append(key)
        elif key in ENUMS:
            if isinstance(val, str) and val in ENUMS[key]:
                clean[key] = val
            else:
                rejected.append(key)
        elif key in BOOLS:
            if isinstance(val, bool):
                clean[key] = val
            else:
                rejected.append(key)
        elif key in RANGES:
            lo, hi = RANGES[key]
            if isinstance(val, (int, float)) and not isinstance(val, bool) and val == val:
                clean[key] = int(min(hi, max(lo, round(val))))
            else:
                rejected.append(key)
        elif key == "accent":
            if isinstance(val, str) and HEX.match(val):
                clean[key] = val.lower()
            else:
                rejected.append(key)
    return clean, rejected
