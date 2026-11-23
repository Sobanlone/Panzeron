"""Ultrimater INFERENCE: contextual exposure reasoning over findings from other modules.

Principles
  * Rules (not a language model) DISCOVER relationships; they are deterministic and auditable.
  * Every edge records the rule that produced it. Co-occurrence is DERIVED; "this could identify someone"
    is SPECULATIVE and labelled as a hypothesis. Nothing here ever claims a person was identified.
  * Entities are matched through salted hashes, so the raw values are never needed (or stored).
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from ..core.models import (Confidence, Edge, Entity, Evidence, EvidenceTier as T, Finding, Module, Severity,
                           SEVERITY_RANK)

# Transparent, published weights (heuristic, not calibrated probabilities)
QUASI_WEIGHTS = {"person_name": 3, "id_document": 4, "national_id": 4, "location": 3, "dob": 3,
                 "org": 2, "username": 2, "phone": 2, "email": 1}
RISK_BANDS = [(8, Severity.HIGH, Confidence.MEDIUM), (5, Severity.MEDIUM, Confidence.MEDIUM)]
IDENTITY_KINDS = {"person_name", "username", "org", "email", "phone"}
FORMULA = ("Identifiability score = sum of weights of DISTINCT categories present "
           "(name 3, ID 4, location 3, birth date 3, institution 2, username 2, phone 2, email 1). "
           "≥8 high, 5–7 medium, <5 not reported. This is a heuristic, not a probability.")


def _fid(rule: str, *parts: str) -> str:
    return "inf_" + hashlib.sha256((rule + "|" + "|".join(sorted(parts))).encode()).hexdigest()[:12]


@dataclass
class Graph:
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": self.nodes, "edges": [e.to_dict() for e in self.edges], "formula": FORMULA}


def _kind_of_source(source: str, findings: list[Finding]) -> str:
    if any(f.module == Module.SENTINEL for f in findings):
        return "message"
    return "file"


class _UnionFind:
    def __init__(self) -> None:
        self.p: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: str, b: str) -> None:
        self.p[self.find(a)] = self.find(b)


def run_inference(findings: list[Finding]) -> tuple[list[Finding], Graph]:
    """Pure function: open findings in, (inference findings, graph) out. Deterministic ids allow re-runs."""
    base = [f for f in findings if f.module != Module.INFERENCE and f.status == "open"]
    by_source: dict[str, list[Finding]] = defaultdict(list)
    for f in base:
        by_source[f.source].append(f)

    ent_info: dict[str, Entity] = {}
    ent_sources: dict[str, set[str]] = defaultdict(set)
    ent_findings: dict[str, set[str]] = defaultdict(set)
    for f in base:
        for e in f.entities:
            if e.kind in ("file",):
                continue
            ent_info[e.id] = e
            ent_sources[e.id].add(f.source)
            ent_findings[e.id].add(f.id)
        if f.category.startswith("pii.id_document") or f.category == "pii.national_id":
            pass

    g = Graph()
    uf = _UnionFind()
    # nodes: sources, entities, threat indicators
    for src, fs in by_source.items():
        g.nodes.append({"id": f"src:{src}", "label": src, "kind": _kind_of_source(src, fs), "finding_ids": [f.id for f in fs]})
        uf.find(f"src:{src}")
    for eid, e in ent_info.items():
        g.nodes.append({"id": eid, "label": e.display_masked, "kind": "entity", "entity_kind": e.kind,
                        "finding_ids": sorted(ent_findings[eid])})
        for src in ent_sources[eid]:
            g.edges.append(Edge(f"src:{src}", eid, "contains", "extractor", T.VERIFIED))
            uf.union(f"src:{src}", eid)
    for f in base:
        if f.module in (Module.SHIELD, Module.SENTINEL):
            nid = f"fnd:{f.id}"
            g.nodes.append({"id": nid, "label": f.title, "kind": "threat_indicator", "severity": f.severity.value,
                            "tier": f.tier.value, "finding_ids": [f.id]})
            g.edges.append(Edge(f"src:{f.source}", nid, "flagged_by", f"module:{f.module.value}", f.tier))
        elif f.category.startswith("meta.") or f.category in ("pii.credential", "pii.id_document", "pii.card"):
            nid = f"fnd:{f.id}"
            g.nodes.append({"id": nid, "label": f.title, "kind": "privacy_finding", "severity": f.severity.value,
                            "tier": f.tier.value, "finding_ids": [f.id]})
            g.edges.append(Edge(f"src:{f.source}", nid, "flagged_by", f"module:{f.module.value}", f.tier))

    out: list[Finding] = []

    # R-001: same entity in two or more distinct sources
    for eid, srcs in ent_sources.items():
        if len(srcs) >= 2:
            e = ent_info[eid]
            ev = [Evidence(f"Entity {e.display_masked} ({e.kind}) appears in '{s}'", s, "rule:R-001", T.DERIVED) for s in sorted(srcs)]
            ev.append(Evidence("Matched by comparing salted hashes; raw values were not compared or stored.", "inference", "rule:R-001", T.DERIVED))
            sev = Severity.MEDIUM if e.kind in ("username", "email", "phone", "person_name") else Severity.LOW
            f = Finding(Module.INFERENCE, f"Same {e.kind.replace('_', ' ')} appears in {len(srcs)} places", sev, Confidence.HIGH,
                        f"The {e.kind.replace('_', ' ')} {e.display_masked} was found in {len(srcs)} separate sources. "
                        "Reusing one identifier lets anyone who sees both sources connect them. "
                        "This is a factual match, not a claim about who you are.",
                        ev, ", ".join(sorted(srcs)), [e], [f"Use different {e.kind.replace('_', ' ')}s in unrelated places",
                                                          "Remove it from the source where it is not needed"],
                        id=_fid("R-001", eid), category="inference.reuse")
            out.append(f)
            g.nodes.append({"id": f.id, "label": f.title, "kind": "inference", "severity": f.severity.value, "tier": f.tier.value, "finding_ids": [f.id]})
            g.edges.append(Edge(f.id, eid, "involves", "rule:R-001", f.tier))

    # component analysis for R-002 / R-004 / R-005
    comps: dict[str, list[str]] = defaultdict(list)
    for src in by_source:
        comps[uf.find(f"src:{src}")].append(src)
    for root, srcs in comps.items():
        ents = {eid for eid in ent_info if any(s in srcs for s in ent_sources[eid])}
        if not ents:
            continue
        kinds: dict[str, Entity] = {}
        for eid in sorted(ents):
            kinds.setdefault(ent_info[eid].kind, ent_info[eid])
        for fnd in (f for s in srcs for f in by_source[s]):
            if fnd.category == "pii.id_document":
                kinds.setdefault("id_document", Entity("n/a", "id_document", "identity-document cues", "", ""))
        score = sum(QUASI_WEIGHTS.get(k, 0) for k in kinds)
        parts = " + ".join(f"{k.replace('_', ' ')} {QUASI_WEIGHTS[k]}" for k in kinds if k in QUASI_WEIGHTS)
        scope = f"{len(srcs)} linked source(s): {', '.join(sorted(srcs))}"
        band = next(((s, c) for t, s, c in RISK_BANDS if score >= t), None)
        involved = sorted(e.id for e in kinds.values() if e.id != "n/a")
        if band and len([k for k in kinds if k in QUASI_WEIGHTS]) >= 3:
            sev, conf = band
            ev = [Evidence(f"{k.replace('_', ' ')} present: {e.display_masked}", scope, "rule:R-002", T.DERIVED) for k, e in kinds.items() if k in QUASI_WEIGHTS]
            ev.append(Evidence(f"Score {score} = {parts}", "inference", "rule:R-002", T.DERIVED))
            ev.append(Evidence("HYPOTHESIS: this combination of details could narrow down who the information is about. "
                               "Ultrimater has not identified, looked up or verified anyone.", "inference", "hypothesis:H-001", T.SPECULATIVE))
            f = Finding(Module.INFERENCE, "Combined details could make you identifiable", sev, conf,
                        f"Individually these details reveal little, but together they cover {len([k for k in kinds if k in QUASI_WEIGHTS])} "
                        f"identifying categories across {scope}. A person who sees all of them could potentially work out more about you "
                        "than any single item shows. The presence of each detail is verified; the risk itself is a hypothesis.",
                        ev, ", ".join(sorted(srcs)), [e for e in kinds.values() if e.id != "n/a"],
                        ["Remove or blur the highest-weight details (name, location, ID) from shared material",
                         "Avoid pairing your real name with your school, location and username in the same place",
                         "Review which of these sources are public"], id=_fid("R-002", *involved, *srcs), category="inference.combination")
            out.append(f)
            g.nodes.append({"id": f.id, "label": f.title, "kind": "inference", "severity": f.severity.value, "tier": f.tier.value, "finding_ids": [f.id]})
            for i in involved:
                g.edges.append(Edge(f.id, i, "involves", "rule:R-002", T.SPECULATIVE))

        # R-004 credential + identity in the same linked component
        cred = [e for e in ents if ent_info[e].kind == "credential"]
        ident = [e for e in ents if ent_info[e].kind in IDENTITY_KINDS]
        if cred and ident:
            ev = [Evidence(f"Credential present: {ent_info[c].display_masked}", scope, "rule:R-004", T.DERIVED) for c in cred]
            ev += [Evidence(f"Identity detail present: {ent_info[i].display_masked}", scope, "rule:R-004", T.DERIVED) for i in ident[:4]]
            out.append(Finding(Module.INFERENCE, "Secret exposed next to identifying details", Severity.CRITICAL, Confidence.HIGH,
                               "A credential and information that says whose it is appear together. Anyone who finds this can both "
                               "use the secret and know who to target.", ev, ", ".join(sorted(srcs)), [ent_info[c] for c in cred + ident[:3]],
                               ["Rotate or revoke the credential immediately", "Remove it from the source and any shared copies"],
                               id=_fid("R-004", *cred, *srcs), category="inference.credential_identity"))
            g.nodes.append({"id": out[-1].id, "label": out[-1].title, "kind": "inference", "severity": "critical", "tier": out[-1].tier.value, "finding_ids": [out[-1].id]})
            for c in cred:
                g.edges.append(Edge(out[-1].id, c, "involves", "rule:R-004", out[-1].tier))

        # R-005 location + identity
        loc = [e for e in ents if ent_info[e].kind == "location"]
        if loc and ident and not any(o.category == "inference.location_identity" and set(srcs) & set(o.source.split(", ")) for o in out):
            ev = [Evidence(f"Location present: {ent_info[l].display_masked}", scope, "rule:R-005", T.DERIVED) for l in loc]
            ev += [Evidence(f"Identity detail present: {ent_info[i].display_masked}", scope, "rule:R-005", T.DERIVED) for i in ident[:3]]
            ev.append(Evidence("HYPOTHESIS: the location could be where the person described by these details lives, studies or spends time. "
                               "This is not verified.", "inference", "hypothesis:H-002", T.SPECULATIVE))
            out.append(Finding(Module.INFERENCE, "Location appears alongside identifying details", Severity.HIGH, Confidence.MEDIUM,
                               "Location data and identity details appear in the same linked material. Even a rounded location can "
                               "matter when paired with a name, school or username.", ev, ", ".join(sorted(srcs)),
                               [ent_info[l] for l in loc] + [ent_info[i] for i in ident[:3]],
                               ["Strip location metadata before sharing", "Avoid sharing images taken at home or school"],
                               id=_fid("R-005", *loc, *srcs), category="inference.location_identity"))
            g.nodes.append({"id": out[-1].id, "label": out[-1].title, "kind": "inference", "severity": "high", "tier": out[-1].tier.value, "finding_ids": [out[-1].id]})
            for l in loc:
                g.edges.append(Edge(out[-1].id, l, "involves", "rule:R-005", T.SPECULATIVE))

        # R-003 targeted message: a flagged message shares identity details with other (non-message) sources
        msgs = [s for s in srcs if any(f.module == Module.SENTINEL for f in by_source[s])]
        files = [s for s in srcs if s not in msgs]
        if msgs and files:
            for m in msgs:
                m_ents = {e.id for f in by_source[m] if f.module == Module.SENTINEL for e in f.entities if e.kind in IDENTITY_KINDS}
                shared = [e for e in m_ents if ent_sources[e] & set(files)]
                if shared:
                    ev = [Evidence(f"{ent_info[e].display_masked} ({ent_info[e].kind}) appears in the message AND in "
                                   f"{', '.join(sorted(ent_sources[e] & set(files)))}", m, "rule:R-003", T.DERIVED) for e in shared]
                    ev.append(Evidence("HYPOTHESIS: the sender may have gathered these details from material like your files. "
                                       "They could also come from elsewhere (public profiles, a data breach); Ultrimater cannot tell.",
                                       "inference", "hypothesis:H-003", T.SPECULATIVE))
                    f = Finding(Module.INFERENCE, "Suspicious message uses details that also appear in your files", Severity.HIGH, Confidence.MEDIUM,
                                "A message flagged as suspicious mentions details that also appear in your own files. Personalised scams "
                                "(spear-phishing) are more convincing and more dangerous than generic ones.",
                                ev, m, [ent_info[e] for e in shared],
                                ["Treat the message as targeted: do not reply or click", "Reduce how much of this detail is public",
                                 "Warn the people named in it"], id=_fid("R-003", m, *shared), category="inference.targeted")
                    out.append(f)
                    g.nodes.append({"id": f.id, "label": f.title, "kind": "inference", "severity": "high", "tier": f.tier.value, "finding_ids": [f.id]})
                    g.edges.append(Edge(f.id, f"src:{m}", "involves", "rule:R-003", T.DERIVED))
                    for e in shared:
                        g.edges.append(Edge(f.id, e, "involves", "rule:R-003", T.SPECULATIVE))

        # R-006 flagged file that also holds personal data
        for s in srcs:
            shield = [f for f in by_source[s] if f.module == Module.SHIELD and SEVERITY_RANK[f.severity] >= SEVERITY_RANK[Severity.MEDIUM]]
            priv = [f for f in by_source[s] if f.module == Module.VISION]
            if shield and priv:
                ev = [Evidence(f"Shield: {shield[0].title}", s, "rule:R-006", T.DERIVED),
                      Evidence(f"Vision: {priv[0].title}", s, "rule:R-006", T.DERIVED)]
                out.append(Finding(Module.INFERENCE, "File flagged by Shield also contains personal data", Severity.MEDIUM, Confidence.MEDIUM,
                                   "A file with security indicators also contains personal information, so handling it carelessly has both risks.",
                                   ev, s, [], ["Resolve the Shield finding first", "Do not share this file"], id=_fid("R-006", s), category="inference.threat_privacy"))

    return out, g
