"""Deterministic sensitive-information detection (regex + checksum validators).

Limitations (also in docs/LIMITATIONS.md): no NER model, so person names and organisations are only detected
from labelled patterns ("Name:", "my name is", "... High School"). That is a conscious trade-off for
explainability: every hit can point to the exact rule that produced it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Hit:
    kind: str          # email|phone|card|national_id|iban|credential|username|person_name|org|location|dob|id_document|identifier|confidential
    subtype: str       # more specific label, e.g. "aws_access_key"
    start: int
    end: int
    raw: str           # transient: used to build masked entities and redactions, never stored
    confidence: str    # low|medium|high
    rule: str          # e.g. "regex:email" or "luhn:card"
    note: str = ""


def luhn_ok(digits: str) -> bool:
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in rearranged)
    return int(num) % 97 == 1


def ssn_ok(s: str) -> bool:
    a, g, n = s.split("-")
    return a not in ("000", "666") and not a.startswith("9") and g != "00" and n != "0000"


_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
_CNIC = re.compile(r"(?<!\d)\d{5}-\d{7}-\d(?!\d)")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
_PHONE = re.compile(r"(?<![\w.])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{2,4}[\s.-]\d{3,4}[\s.-]?\d{3,4}(?![\w])|(?<![\w.])\+\d{10,14}(?!\w)")
_GPS = re.compile(r"(?<![\d.])(-?\d{1,2}\.\d{3,})\s*[,;]\s*(-?\d{1,3}\.\d{3,})(?![\d.])")
_ADDRESS = re.compile(r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Boulevard|Blvd)\b\.?")
_USER_AT = re.compile(r"(?<![\w@./])@([A-Za-z0-9_.]{3,30})\b(?!\.[a-z]{2,}\b)")
_USER_LABEL = re.compile(r"(?i:\b(?:user(?:name)?|handle|login|insta(?:gram)?|twitter|tiktok)\b)\s*[:=]\s*@?([A-Za-z0-9_.-]{3,30})")
_ORG = re.compile(r"\b((?:[A-Z][\w'&-]+[ \t]+){1,4}(?:High School|Middle School|Elementary School|Secondary School|Academy|University|College|Institute|School))\b|\b(University of (?:[A-Z][\w'-]+)(?: [A-Z][\w'-]+){0,2})\b")
_NAME_LABEL = re.compile(r"(?i:\b(?:full name|student name|patient name|employee name|name)\b)[ \t]*[:=][ \t]*([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){0,3})")
_NAME_INTRO = re.compile(r"(?i:\bmy name is\b)\s+([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){0,2})")
# Badges and event passes print a role label above (or beside) the person's name instead of "Name:".
_NAME_ROLE = re.compile(
    r"(?im)\b(?:team[ \t]+lead(?:er)?|participant|attendee|delegate|exhibitor|student|speaker|presenter|"
    r"panelist|cardholder|issued[ \t]+to|member|representative|contestant|player|author|prepared[ \t]+by|"
    r"submitted[ \t]+by)\b[ \t]*[:.\-]?[ \t]*(?:\r?\n[ \t]*)?([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){0,3})")
_NAME_ROLE_CAPS = re.compile(
    r"(?m)\b(?:TEAM[ \t]+LEAD(?:ER)?|PARTICIPANT|ATTENDEE|DELEGATE|EXHIBITOR|STUDENT|SPEAKER|PRESENTER|"
    r"PANELIST|CARDHOLDER|MEMBER|REPRESENTATIVE|CONTESTANT|PLAYER|AUTHOR)\b[ \t]*[:.\-]?[ \t]*"
    r"(?:\r?\n[ \t]*)?([A-Z][A-Z'.-]+(?:[ \t]+[A-Z][A-Z'.-]+){0,3})")
# Non-government identifiers printed on badges, tickets and forms (team code, badge number, ...).
_CODE_LABEL = re.compile(
    r"(?i)\b(?:team[ \t]+code|badge[ \t]*(?:no|number|id)?|(?:id|reg(?:istration)?|roll|ticket)[ \t]*(?:no|number|code)|"
    r"employee[ \t]*(?:id|no)|member[ \t]*(?:id|no)|event[ \t]+pass)\b[ \t]*[:#\-]?[ \t]*"
    r"(?:\r?\n[ \t]*)?([A-Z0-9][A-Z0-9\-/]{2,20})\b")
_DOB = re.compile(r"(?i:\b(?:date of birth|dob|d\.o\.b|born on)\b)\s*[:\-]?\s*(\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{2}-\d{2})")
_MRZ = re.compile(r"P<[A-Z]{3}[A-Z<]{5,39}\s*\n?\s*[A-Z0-9<]{9}\d[A-Z<]{3}\d{6}")
_PLACEHOLDER = re.compile(r"^(?:[*x•.]+|<.*>|\{.*\}|your[_-]?\w*|changeme|password|example|redacted)$", re.I)

_CRED_PATTERNS = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "high"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "high"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"), "high"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "medium"),
]
_CRED_ASSIGN = re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*[\"']?([^\s\"']{6,})")

_ID_CUES = ["passport", "driver licen", "driving licen", "national id", "identity card", "id card", "date of birth",
            "nationality", "place of birth", "date of issue", "date of expiry", "expiry date", "cnic", "licence no",
            "license no", "surname", "given names", "social security"]
_CONF_MARKERS = re.compile(r"(?i)\b(strictly confidential|confidential|internal use only|not for distribution|privileged and confidential|do not share|attorney[- ]client)\b")
# Event badges / lanyards share a small vocabulary; two of these together is strong evidence of a badge layout.
_BADGE_CUES = re.compile(r"(?i)\b(team[ \t]+code|team[ \t]+lead(?:er)?|participant|attendee|delegate|exhibitor|"
                         r"event[ \t]+pass|lanyard|badge)\b")
_CAPS_STOP = {"TEAM", "CODE", "SCHOOL", "TABLE", "BADGE", "EVENT", "PASS", "HALL", "ROOM", "DATE", "TIME",
              "NAME", "LEAD", "LEADER", "MEMBER", "STUDENT", "SPEAKER", "SPONSOR", "NATIONAL", "INTERNATIONAL"}


def _caps_name_ok(raw: str) -> bool:
    """All-caps role labels are noisy in OCR; require a real two-word name and reject layout words."""
    toks = raw.split()
    if not 2 <= len(toks) <= 4:
        return False
    if any(t in _CAPS_STOP or any(ch.isdigit() for ch in t) for t in toks):
        return False
    return all(2 <= len(t) <= 20 for t in toks)


_PRIORITY = {"credential": 0, "card": 1, "iban": 1, "national_id": 1, "email": 2, "location": 3, "phone": 4,
             "identifier": 5, "dob": 5, "person_name": 6, "org": 6, "username": 7, "id_document": 8, "confidential": 8}


def detect(text: str) -> list[Hit]:
    hits: list[Hit] = []

    for m in _EMAIL.finditer(text):
        hits.append(Hit("email", "", m.start(), m.end(), m.group(), "high", "regex:email"))
    for m in _CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if luhn_ok(digits):
            hits.append(Hit("card", "payment_card", m.start(), m.end(), m.group(), "high", "luhn:card",
                            "Passes the Luhn checksum used by payment cards"))
    for m in _CNIC.finditer(text):
        hits.append(Hit("national_id", "cnic_format", m.start(), m.end(), m.group(), "medium", "regex:cnic",
                        "Matches the 5-7-1 digit format of a Pakistani CNIC; format match only"))
    for m in _SSN.finditer(text):
        if ssn_ok(m.group()):
            hits.append(Hit("national_id", "us_ssn_format", m.start(), m.end(), m.group(), "medium", "regex:ssn",
                            "Matches the US SSN format and range rules; format match only"))
    for m in _IBAN.finditer(text):
        if iban_ok(m.group()):
            hits.append(Hit("iban", "iban", m.start(), m.end(), m.group(), "high", "mod97:iban",
                            "Passes the IBAN mod-97 checksum"))
    for name, rx, conf in _CRED_PATTERNS:
        for m in rx.finditer(text):
            hits.append(Hit("credential", name, m.start(), m.end(), m.group(), conf, f"regex:{name}"))
    for m in _CRED_ASSIGN.finditer(text):
        val = m.group(2)
        if not _PLACEHOLDER.match(val):
            hits.append(Hit("credential", "labelled_secret", m.start(2), m.end(2), val, "medium", "regex:labelled_secret",
                            f"Value follows the label '{m.group(1)}'"))
    for m in _GPS.finditer(text):
        lat, lon = float(m.group(1)), float(m.group(2))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            hits.append(Hit("location", "gps_coordinates", m.start(), m.end(), m.group(), "high", "regex:gps",
                            "Latitude/longitude pair within valid ranges"))
    for m in _ADDRESS.finditer(text):
        hits.append(Hit("location", "street_address", m.start(), m.end(), m.group(), "medium", "regex:address"))
    for m in _PHONE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 10 <= len(digits) <= 15:
            hits.append(Hit("phone", "", m.start(), m.end(), m.group().strip(), "medium", "regex:phone"))
    for m in _DOB.finditer(text):
        hits.append(Hit("dob", "date_of_birth", m.start(1), m.end(1), m.group(1), "medium", "regex:dob",
                        "Date following a 'date of birth' style label"))
    for rx, rule in ((_NAME_LABEL, "regex:name_label"), (_NAME_INTRO, "regex:name_intro")):
        for m in rx.finditer(text):
            hits.append(Hit("person_name", "", m.start(1), m.end(1), m.group(1), "medium", rule,
                            "Name found after a label; no NER model is used"))
    for m in _NAME_ROLE.finditer(text):
        hits.append(Hit("person_name", "role_label", m.start(1), m.end(1), m.group(1), "medium", "regex:role_name",
                        "Name printed under a role label (badge / event pass layout)"))
    for m in _NAME_ROLE_CAPS.finditer(text):
        if _caps_name_ok(m.group(1)):
            hits.append(Hit("person_name", "role_label_caps", m.start(1), m.end(1), m.group(1), "low", "regex:role_name_caps",
                            "All-caps name under a role label; OCR casing is unreliable"))
    for m in _CODE_LABEL.finditer(text):
        label = m.group(0).replace(m.group(1), "", 1).strip(" :#-\t\r\n")
        hits.append(Hit("identifier", "labelled_code", m.start(1), m.end(1), m.group(1), "medium", "regex:labelled_code",
                        f"Code follows the label '{label}'"))
    for m in _ORG.finditer(text):
        g = m.group(1) or m.group(2)
        s = m.start(1) if m.group(1) else m.start(2)
        hits.append(Hit("org", "school_or_institution", s, s + len(g), g, "medium", "regex:institution"))
    for m in _USER_AT.finditer(text):
        hits.append(Hit("username", "handle", m.start(1) - 1, m.end(1), m.group(1), "medium", "regex:handle"))
    for m in _USER_LABEL.finditer(text):
        hits.append(Hit("username", "labelled_username", m.start(1), m.end(1), m.group(1), "medium", "regex:username_label"))

    for m in _MRZ.finditer(text):
        hits.append(Hit("id_document", "passport_mrz", m.start(), m.end(), m.group(), "high", "regex:mrz",
                        "Machine-readable zone pattern of a passport"))
    low = text.lower()
    cues = sorted({c for c in _ID_CUES if c in low})
    if len(cues) >= 2 and not any(h.subtype == "passport_mrz" for h in hits):
        conf = "medium" if len(cues) >= 3 else "low"
        hits.append(Hit("id_document", "id_document_cues", 0, 0, ", ".join(cues), conf, "rule:id-cues",
                        f"{len(cues)} identity-document phrases present: {', '.join(cues)}"))
    badge_cues = sorted({m.group(1).lower() for m in _BADGE_CUES.finditer(text)})
    team_pair = any(c.startswith("team lead") for c in badge_cues) and "team code" in badge_cues
    if (team_pair or len(badge_cues) >= 3) and not any(h.subtype in ("passport_mrz", "event_badge") for h in hits):
        hits.append(Hit("id_document", "event_badge", 0, 0, ", ".join(badge_cues), "medium", "rule:badge-cues",
                        f"Event-badge layout cues present: {', '.join(badge_cues)}"))
    for m in _CONF_MARKERS.finditer(text):
        hits.append(Hit("confidential", "confidentiality_marker", m.start(), m.end(), m.group(), "medium", "regex:confidential"))

    return _resolve_overlaps(hits)


def _resolve_overlaps(hits: list[Hit]) -> list[Hit]:
    """Keep the highest-priority, longest hit where spans overlap (e.g. a card number also looks like a phone)."""
    zero = [h for h in hits if h.start == h.end]
    spans = sorted((h for h in hits if h.start != h.end),
                   key=lambda h: (_PRIORITY.get(h.kind, 9), -(h.end - h.start), h.start))
    kept: list[Hit] = []
    for h in spans:
        if all(h.end <= k.start or h.start >= k.end for k in kept):
            kept.append(h)
    out = sorted(kept, key=lambda h: h.start) + zero
    seen, dedup = set(), []
    for h in out:  # drop exact duplicates (e.g. same email repeated is still reported once per location)
        key = (h.kind, h.start, h.end)
        if key not in seen:
            seen.add(key)
            dedup.append(h)
    return dedup


def redact_text(text: str, hits: list[Hit]) -> str:
    """Return a redacted COPY of the text. Original is untouched."""
    out, last = [], 0
    for h in sorted((h for h in hits if h.start != h.end), key=lambda h: h.start):
        if h.start < last:
            continue
        out.append(text[last:h.start])
        out.append("█" * max(len(h.raw), 4))
        last = h.end
    out.append(text[last:])
    return "".join(out)
