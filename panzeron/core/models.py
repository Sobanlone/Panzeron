"""Core schema. Every module emits these types; this is what lets the graph connect them.

Invariants enforced in code (not by convention):
  1. A Finding must carry at least one Evidence item.
  2. A Finding's tier is the WEAKEST tier among its evidence (computed, never set by callers).
  3. Evidence produced by AI ("ai:" prefix) can never be tiered above AI_ASSESSED.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable

from .masking import mask_value


class InvariantError(ValueError):
    """Raised when a schema invariant would be violated."""


class EvidenceTier(str, Enum):
    VERIFIED = "verified"        # deterministic and reproducible
    DERIVED = "derived"          # deterministic rule applied to verified facts
    AI_ASSESSED = "ai_assessed"  # model judgement, always shown with its reasoning
    SPECULATIVE = "speculative"  # hypothesis, always labelled as such


class Confidence(str, Enum):  # ordinal on purpose: we do not have calibrated probabilities
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Module(str, Enum):
    SHIELD = "shield"
    VISION = "vision"
    SENTINEL = "sentinel"
    INFERENCE = "inference"


TIER_RANK = {EvidenceTier.VERIFIED: 0, EvidenceTier.DERIVED: 1,
             EvidenceTier.AI_ASSESSED: 2, EvidenceTier.SPECULATIVE: 3}
SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
                 Severity.HIGH: 3, Severity.CRITICAL: 4}


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def weakest_tier(tiers: Iterable[EvidenceTier]) -> EvidenceTier:
    tiers = list(tiers)
    if not tiers:
        raise InvariantError("cannot compute a tier without evidence")
    return max(tiers, key=lambda t: TIER_RANK[t])


def cap_ai_tier(tier: EvidenceTier) -> EvidenceTier:
    """AI output can never be VERIFIED or DERIVED."""
    return tier if TIER_RANK[tier] >= TIER_RANK[EvidenceTier.AI_ASSESSED] else EvidenceTier.AI_ASSESSED


@dataclass
class Evidence:
    description: str
    source_ref: str      # e.g. "screenshot.png @ OCR line 4", "EXIF:GPSLatitude"
    produced_by: str     # e.g. "regex:email", "sig:EICAR", "rule:R-003", "ai:ollama/qwen2.5:3b"
    tier: EvidenceTier

    def __post_init__(self) -> None:
        self.tier = EvidenceTier(self.tier)
        if self.produced_by.startswith("ai:"):
            self.tier = cap_ai_tier(self.tier)

    def to_dict(self) -> dict[str, Any]:
        return {"description": self.description, "source_ref": self.source_ref,
                "produced_by": self.produced_by, "tier": self.tier.value}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Evidence":
        return cls(d["description"], d["source_ref"], d["produced_by"], EvidenceTier(d["tier"]))


@dataclass
class Entity:
    id: str
    kind: str            # file|url|email|phone|username|location|org|person_name|credential|...
    display_masked: str  # the ONLY representation that is persisted or displayed
    value_hash: str      # salted hash, used for cross-finding matching only
    subtype: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "display_masked": self.display_masked,
                "value_hash": self.value_hash, "subtype": self.subtype}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Entity":
        return cls(d["id"], d["kind"], d["display_masked"], d["value_hash"], d.get("subtype", ""))


def normalise_value(kind: str, raw: str) -> str:
    raw = raw.strip()
    if kind in ("phone", "card", "national_id", "iban"):
        return re.sub(r"[^0-9A-Za-z]", "", raw).upper()
    if kind in ("email", "username", "org", "person_name", "url"):
        return re.sub(r"\s+", " ", raw.lower().lstrip("@"))
    if kind == "location":
        m = re.match(r"\s*(-?\d+\.\d+)\s*[,;]\s*(-?\d+\.\d+)", raw)
        if m:  # match GPS values across sources at ~1 km granularity
            return f"{float(m.group(1)):.2f},{float(m.group(2)):.2f}"
        return re.sub(r"\s+", " ", raw.lower())
    return raw


def make_entity(kind: str, raw: str, salt: bytes, subtype: str = "") -> Entity:
    """Build an Entity. The raw value is hashed (salted) and masked; it is not kept."""
    norm = normalise_value(kind, raw)
    digest = hashlib.sha256(salt + b"\x00" + kind.encode() + b"\x00" + norm.encode("utf-8")).hexdigest()
    return Entity(id=f"ent_{digest[:16]}", kind=kind, display_masked=mask_value(kind, raw),
                  value_hash=digest, subtype=subtype)


@dataclass
class Finding:
    module: Module
    title: str
    severity: Severity
    confidence: Confidence
    explanation: str
    evidence: list[Evidence]
    source: str                                  # human label of where it was found
    entities: list[Entity] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    source_path: str | None = None               # local path if the source is a file
    id: str = field(default_factory=lambda: new_id("fnd"))
    status: str = "open"                         # open | resolved | false_positive
    false_positive_reported: bool = False
    created_at: str = field(default_factory=now_iso)
    category: str = ""                           # machine-readable sub-type, e.g. "pii.email"
    tier: EvidenceTier = field(init=False)

    def __post_init__(self) -> None:
        self.module = Module(self.module)
        self.severity = Severity(self.severity)
        self.confidence = Confidence(self.confidence)
        if not self.evidence:
            raise InvariantError("a Finding must have at least one Evidence item")
        self.tier = weakest_tier(e.tier for e in self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "module": self.module.value, "title": self.title,
            "severity": self.severity.value, "confidence": self.confidence.value,
            "tier": self.tier.value, "explanation": self.explanation,
            "evidence": [e.to_dict() for e in self.evidence],
            "entities": [e.to_dict() for e in self.entities],
            "recommended_actions": list(self.recommended_actions),
            "source": self.source, "source_path": self.source_path,
            "status": self.status, "false_positive_reported": self.false_positive_reported,
            "created_at": self.created_at, "category": self.category,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            module=Module(d["module"]), title=d["title"], severity=Severity(d["severity"]),
            confidence=Confidence(d["confidence"]), explanation=d["explanation"],
            evidence=[Evidence.from_dict(e) for e in d["evidence"]],
            source=d["source"], entities=[Entity.from_dict(e) for e in d.get("entities", [])],
            recommended_actions=d.get("recommended_actions", []),
            source_path=d.get("source_path"), id=d["id"], status=d.get("status", "open"),
            false_positive_reported=d.get("false_positive_reported", False),
            created_at=d.get("created_at", now_iso()), category=d.get("category", ""),
        )


@dataclass
class Edge:
    src: str
    dst: str
    relation: str
    derived_by: str      # rule id, so every edge can be explained and audited
    tier: EvidenceTier

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "relation": self.relation,
                "derived_by": self.derived_by, "tier": self.tier.value}
