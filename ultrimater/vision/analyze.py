"""Ultrimater VISION: turns extracted content into explainable Findings. Never modifies originals."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.models import (Confidence, Entity, Evidence, EvidenceTier as T, Finding, Module, Severity, make_entity)
from . import pii
from .extract import Extracted, PIL_OK, extract, tesseract_cmd

try:
    from PIL import Image, ImageDraw, ImageOps
except Exception:  # pragma: no cover
    pass

WHY = {
    "email": ("Email address", Severity.LOW, "Email addresses are used to find your accounts, send targeted phishing, and link profiles.",
              ["Remove or blur the address before sharing", "Use a separate address for public profiles"]),
    "phone": ("Phone number", Severity.MEDIUM, "Phone numbers enable SIM-swap attempts, spam and scam calls, and account recovery attacks.",
              ["Redact the number before sharing", "Avoid posting it publicly"]),
    "card": ("Payment card number", Severity.CRITICAL, "A valid card number can be used for fraud, especially with an expiry date or CVV nearby.",
             ["Do not share this file", "Contact your bank if it was shared", "Redact before storing"]),
    "iban": ("Bank account number (IBAN)", Severity.HIGH, "An IBAN can be used to initiate unauthorised direct debits or targeted payment fraud.",
             ["Redact before sharing", "Share only with trusted payees"]),
    "national_id": ("National identity number", Severity.HIGH, "Identity numbers are a key ingredient of identity theft.",
                    ["Do not share this file", "Redact the number", "Store identity documents encrypted"]),
    "credential": ("Exposed credential or secret", Severity.CRITICAL, "Anyone who sees this can act as you or your service. Exposed secrets are exploited automatically within minutes of public exposure.",
                   ["Rotate/revoke the secret NOW", "Remove it from the file and from any shared history", "Use a secrets manager"]),
    "username": ("Username / handle", Severity.LOW, "Usernames let people link your accounts across sites and find more about you.",
                 ["Avoid reusing the same handle everywhere", "Crop or blur handles in screenshots"]),
    "person_name": ("Personal name", Severity.LOW, "A name on its own is weakly identifying, but it becomes much stronger combined with a school, location or username.",
                    ["Consider whether the name needs to be visible"]),
    "org": ("School / institution", Severity.LOW, "A school or employer narrows who you are to a small group of people.",
            ["Consider removing institution names from public posts"]),
    "location": ("Location information", Severity.MEDIUM, "Locations reveal where you live, study or travel and can enable stalking or burglary.",
                 ["Remove location data before sharing", "Disable geotagging in your camera app"]),
    "dob": ("Date of birth", Severity.MEDIUM, "Dates of birth are used to verify identity and are hard to change once leaked.",
            ["Redact it", "Share only the year if the date is not required"]),
    "id_document": ("Possible identity document", Severity.HIGH, "Identity documents carry many identifiers at once and are prime targets for identity fraud.",
                    ["Do not share images of ID documents unless required", "If required, add a watermark with the purpose and date"]),
    "confidential": ("Confidentiality marker", Severity.MEDIUM, "The document says it is confidential; sharing it may breach an agreement or policy.",
                     ["Check who is authorised to receive this document"]),
}
_CONF_MAP = {"low": Confidence.LOW, "medium": Confidence.MEDIUM, "high": Confidence.HIGH}
_SEV_BUMP = {"credential": {"private_key": Severity.CRITICAL}, "location": {"gps_coordinates": Severity.HIGH}}


@dataclass
class AnalysisReport:
    source: str
    kind: str
    chars_analysed: int
    findings: list[Finding]
    notes: list[str] = field(default_factory=list)
    ocr_mean_conf: float | None = None
    redaction_available: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "kind": self.kind, "chars_analysed": self.chars_analysed,
                "notes": self.notes, "ocr_mean_confidence": self.ocr_mean_conf,
                "redaction_available": self.redaction_available,
                "findings": [f.to_dict() for f in self.findings]}


def _ref(ex: Extracted, name: str, h: pii.Hit, text: str) -> str:
    if ex.kind == "text" or ex.kind == "docx" or ex.kind == "pdf":
        line = text.count("\n", 0, h.start) + 1
        return f"{name} @ line {line}"
    if ex.kind == "image":
        return f"{name} @ OCR text offset {h.start}"
    return name


def analyze_text(text: str, source: str, salt: bytes, path: str | None = None, kind: str = "text",
                 ex: Extracted | None = None) -> list[Finding]:
    """Group hits by kind into findings. Each finding lists evidence per occurrence."""
    ex = ex or Extracted(kind=kind, text=text)
    groups: dict[str, list[pii.Hit]] = defaultdict(list)
    for h in pii.detect(text):
        groups[h.kind].append(h)
    findings = []
    for kind_name, hs in groups.items():
        title, sev, why, actions = WHY[kind_name]
        subs = {h.subtype for h in hs}
        for st in subs:
            sev = _SEV_BUMP.get(kind_name, {}).get(st, sev)
        conf = min((_CONF_MAP[h.confidence] for h in hs), key=lambda c: list(Confidence).index(c))
        ents: list[Entity] = []
        seen_ids = set()
        for h in hs:
            if h.kind == "id_document":
                continue
            e = make_entity(h.kind, h.raw, salt, h.subtype)
            if e.id not in seen_ids:
                seen_ids.add(e.id)
                ents.append(e)
        evid = []
        for h in hs:
            masked = make_entity(h.kind, h.raw, salt, h.subtype).display_masked if h.kind != "id_document" else h.raw
            desc = f"{h.subtype.replace('_', ' ') or h.kind}: {masked}" + (f" — {h.note}" if h.note else "")
            tier = T.DERIVED if h.rule.startswith("rule:") else T.VERIFIED
            evid.append(Evidence(desc, _ref(ex, source, h, text), h.rule, tier))
        count = len(hs)
        findings.append(Finding(
            Module.VISION, f"{title}{'s' if count > 1 else ''} found ({count})" if count > 1 else f"{title} found",
            sev, conf, f"{why} Found {count} occurrence{'s' if count > 1 else ''} in {source}.",
            evid, source, ents, actions, path, category=f"pii.{kind_name}"))
    return findings


def analyze_extracted(ex: Extracted, source: str, salt: bytes, path: str | None = None) -> AnalysisReport:
    findings = analyze_text(ex.text, source, salt, path, ex.kind, ex)
    gps = ex.exif.get("gps")
    if gps:
        raw = f"{gps[0]}, {gps[1]}"
        ent = make_entity("location", raw, salt, "exif_gps")
        findings.append(Finding(
            Module.VISION, "Image contains embedded GPS location", Severity.HIGH, Confidence.HIGH,
            "The photo's metadata records exactly where it was taken. Anyone who receives the original file can read this. "
            "Many platforms strip it, but messaging apps, email and file sharing often do not.",
            [Evidence(f"EXIF GPS latitude/longitude present (shown rounded: {ent.display_masked})", f"{source} @ EXIF:GPS",
                      "exif:gps", T.VERIFIED)],
            source, [ent], ["Create an EXIF-stripped copy before sharing", "Turn off camera geotagging"], path,
            category="meta.exif_gps"))
    ident = [(k, ex.exif[k]) for k in ("Make", "Model", "BodySerialNumber", "CameraOwnerName", "Artist", "HostComputer", "Software")
             if k in ex.exif]
    if ident:
        ents = []
        for k in ("Artist", "CameraOwnerName"):
            if k in ex.exif:
                ents.append(make_entity("person_name", ex.exif[k], salt, f"exif_{k.lower()}"))
        serial = "BodySerialNumber" in ex.exif
        findings.append(Finding(
            Module.VISION, "Image metadata identifies the device or author",
            Severity.MEDIUM if (serial or ents) else Severity.LOW, Confidence.HIGH,
            "Device model, serial numbers and author fields can link photos to the same person or device.",
            [Evidence(f"EXIF {k} is set" + (f" ({ex.exif[k]})" if k in ("Make", "Model", "Software") else ""), f"{source} @ EXIF:{k}",
                      "exif:field", T.VERIFIED) for k, _ in ident],
            source, ents, ["Create an EXIF-stripped copy before sharing"], path, category="meta.exif_device"))
    if ex.doc_props:
        ents = [make_entity("person_name", v, salt, f"docprop_{k}") for k, v in ex.doc_props.items()]
        findings.append(Finding(
            Module.VISION, "Document properties reveal author name", Severity.LOW, Confidence.HIGH,
            "Word documents store the author and last editor in hidden properties that travel with the file.",
            [Evidence(f"Document property '{k}' is set", f"{source} @ docProps/core.xml", "docx:core-props", T.VERIFIED)
             for k in ex.doc_props], source, ents, ["Remove document properties before sharing"], path, category="meta.doc_props"))
    notes = list(ex.notes)
    redaction = ex.kind in ("text",) or (ex.kind == "image" and bool(ex.ocr_words))
    return AnalysisReport(source, ex.kind, len(ex.text), findings, notes, ex.ocr_mean_conf, redaction)


def analyze_file(path: str | Path, salt: bytes, tesseract_path: str = "", display_name: str | None = None) -> AnalysisReport:
    p = Path(path)
    ex = extract(p, tesseract_path)
    return analyze_extracted(ex, display_name or p.name, salt, str(p))


# ---- safe copies (originals are never modified) ------------------------------------------------------------
def redact_to_copy(src: Path, out_dir: Path, salt: bytes, tesseract_path: str = "") -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    ex = extract(src, tesseract_path)
    if ex.kind == "text":
        dest = _unique(out_dir, f"{src.stem}.redacted{src.suffix}")
        dest.write_text(pii.redact_text(ex.text, pii.detect(ex.text)), encoding="utf-8")
        return dest
    if ex.kind == "image":
        if not ex.ocr_words:
            raise ValueError("No OCR text available, so image redaction cannot be performed.")
        # Build per-line text with word offsets so a PII span can be mapped back to word boxes
        lines: dict[tuple[int, int, int], list] = defaultdict(list)
        for w in ex.ocr_words:
            lines[w.line_key].append(w)
        with Image.open(src) as im:
            im = ImageOps.exif_transpose(im).convert("RGB")
        draw = ImageDraw.Draw(im)
        boxes = 0
        for words in lines.values():
            text, spans = "", []
            for w in words:
                start = len(text)
                text += w.text + " "
                spans.append((start, start + len(w.text), w))
            for h in pii.detect(text):
                if h.start == h.end:
                    continue
                for s, e, w in spans:
                    if s < h.end and e > h.start:
                        draw.rectangle([w.left - 2, w.top - 2, w.left + w.width + 2, w.top + w.height + 2], fill=(0, 0, 0))
                        boxes += 1
        dest = _unique(out_dir, f"{src.stem}.redacted.png")
        im.save(dest)
        if boxes == 0:
            raise ValueError("No sensitive text was located in the image; no redacted copy was written.")
        dest.with_suffix(".txt").write_text(f"Redacted copy of {src.name}: {boxes} region(s) blacked out. "
                                            "Redaction is based on OCR; text OCR missed is NOT redacted. Review before sharing.")
        return dest
    raise ValueError(f"Redaction is not supported for {ex.kind} files.")


def strip_exif_copy(src: Path, out_dir: Path) -> Path:
    if not PIL_OK:
        raise RuntimeError("Pillow is required to strip metadata")
    out_dir.mkdir(parents=True, exist_ok=True)
    with Image.open(src) as im:
        fmt = (im.format or "PNG").upper()
        im = ImageOps.exif_transpose(im)  # keep visual orientation, then drop metadata
        clean = Image.new(im.mode, im.size)
        clean.paste(im)
        dest = _unique(out_dir, f"{src.stem}.nometadata{src.suffix}")
        kwargs = {"quality": 95} if fmt in ("JPEG", "JPG") else {}
        clean.save(dest, format=fmt if fmt != "JPG" else "JPEG", **kwargs)
    return dest


def _unique(d: Path, name: str) -> Path:
    p = d / name
    i = 1
    while p.exists():
        p = d / f"{Path(name).stem}-{i}{Path(name).suffix}"
        i += 1
    return p
