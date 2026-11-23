"""Local content extraction: image metadata (EXIF), OCR, PDF text, DOCX text and properties.

Everything degrades gracefully: when OCR / PDF tooling is missing the report says so explicitly instead of
pretending a file was fully analysed.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

try:
    from PIL import Image, ExifTags
    PIL_OK = True
except Exception:  # pragma: no cover - depends on environment
    PIL_OK = False

try:
    import pytesseract
    PYTESSERACT_OK = True
except Exception:  # pragma: no cover
    PYTESSERACT_OK = False

TEXT_EXTS = {".txt", ".md", ".csv", ".log", ".json", ".eml", ".msg", ".ini", ".cfg", ".env", ".yaml", ".yml", ".html", ".htm"}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".webp"}
MAX_TEXT_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 60_000_000


@dataclass
class OcrWord:
    text: str
    left: int
    top: int
    width: int
    height: int
    conf: float
    line_key: tuple[int, int, int]


@dataclass
class Extracted:
    kind: str                                   # text | image | pdf | docx | unsupported
    text: str = ""
    exif: dict[str, Any] = field(default_factory=dict)       # parsed metadata of interest
    ocr_words: list[OcrWord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)           # limitations that affected this analysis
    ocr_mean_conf: float | None = None
    doc_props: dict[str, str] = field(default_factory=dict)


def tesseract_cmd(configured: str = "") -> str | None:
    if configured and Path(configured).exists():
        return configured
    found = shutil.which("tesseract")
    if found:
        return found
    for cand in (r"C:\Program Files\Tesseract-OCR\tesseract.exe", r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"):
        if Path(cand).exists():
            return cand
    return None


def ocr_status(configured: str = "") -> dict[str, Any]:
    cmd = tesseract_cmd(configured)
    ok = bool(PIL_OK and PYTESSERACT_OK and cmd)
    reason = None
    if not PIL_OK:
        reason = "Pillow is not installed"
    elif not PYTESSERACT_OK:
        reason = "pytesseract is not installed"
    elif not cmd:
        reason = "Tesseract OCR engine not found (install it or set its path in Settings)"
    return {"available": ok, "engine": "tesseract" if ok else None, "reason": reason, "path": cmd}


def _dms_to_deg(v: Any, ref: str) -> float | None:
    try:
        d, m, s = (float(x) for x in v)
    except Exception:
        return None
    deg = d + m / 60 + s / 3600
    return -deg if ref in ("S", "W") else deg


def read_exif(path: Path) -> dict[str, Any]:
    """Return metadata of privacy interest: GPS, device, serial, timestamps, author, software."""
    out: dict[str, Any] = {}
    if not PIL_OK:
        return out
    with Image.open(path) as img:
        exif = img.getexif()
        if not exif:
            return out
        tagmap = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
        try:
            tagmap.update({ExifTags.TAGS.get(k, k): v for k, v in exif.get_ifd(0x8769).items()})
        except Exception:
            pass
        for k in ("Make", "Model", "Software", "Artist", "Copyright", "DateTimeOriginal", "DateTime",
                  "BodySerialNumber", "CameraOwnerName", "LensSerialNumber", "HostComputer"):
            if k in tagmap and str(tagmap[k]).strip():
                out[k] = str(tagmap[k]).strip().strip("\x00")
        try:
            gps = exif.get_ifd(0x8825)
        except Exception:
            gps = {}
        if gps:
            lat = _dms_to_deg(gps.get(2), gps.get(1, "N")) if gps.get(2) else None
            lon = _dms_to_deg(gps.get(4), gps.get(3, "E")) if gps.get(4) else None
            if lat is not None and lon is not None:
                out["gps"] = (round(lat, 6), round(lon, 6))
    return out


def ocr_image(path: Path, configured_tesseract: str = "") -> tuple[list[OcrWord], float | None, list[str]]:
    st = ocr_status(configured_tesseract)
    if not st["available"]:
        return [], None, [f"OCR unavailable: {st['reason']}. Text inside this image was NOT analysed."]
    pytesseract.pytesseract.tesseract_cmd = st["path"]
    with Image.open(path) as img:
        if img.width * img.height > MAX_IMAGE_PIXELS:
            return [], None, ["Image too large for OCR safety limit; text was NOT analysed."]
        rgb = img.convert("RGB")
        data = pytesseract.image_to_data(rgb, output_type=pytesseract.Output.DICT, timeout=60)
    words, confs = [], []
    for i, t in enumerate(data["text"]):
        t = (t or "").strip()
        if not t:
            continue
        c = float(data["conf"][i]) if str(data["conf"][i]).lstrip("-").replace(".", "").isdigit() else -1
        words.append(OcrWord(t, data["left"][i], data["top"][i], data["width"][i], data["height"][i], c,
                             (data["block_num"][i], data["par_num"][i], data["line_num"][i])))
        if c >= 0:
            confs.append(c)
    mean = round(sum(confs) / len(confs), 1) if confs else None
    return words, mean, []


def words_to_text(words: list[OcrWord]) -> str:
    lines: dict[tuple[int, int, int], list[str]] = {}
    for w in words:
        lines.setdefault(w.line_key, []).append(w.text)
    return "\n".join(" ".join(ws) for ws in lines.values())


def pdf_text(path: Path) -> tuple[str, list[str]]:
    try:
        import fitz  # PyMuPDF
        with fitz.open(path) as doc:
            return "\n".join(p.get_text() for p in doc), []
    except ImportError:
        pass
    except Exception as e:
        return "", [f"PDF could not be parsed: {e}"]
    exe = shutil.which("pdftotext")
    if exe:
        try:
            cp = subprocess.run([exe, "-layout", str(path), "-"], capture_output=True, timeout=60,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return cp.stdout.decode("utf-8", "replace"), []
        except (OSError, subprocess.TimeoutExpired) as e:
            return "", [f"pdftotext failed: {e}"]
    return "", ["PDF text extraction unavailable (install PyMuPDF: pip install pymupdf). The PDF was NOT analysed."]


def docx_extract(path: Path) -> tuple[str, dict[str, str], list[str]]:
    ns_w = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    ns_dc = "{http://purl.org/dc/elements/1.1/}"
    ns_cp = "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}"
    try:
        with zipfile.ZipFile(path) as z:
            if z.getinfo("word/document.xml").file_size > 20 * 1024 * 1024:
                return "", {}, ["DOCX content too large; not analysed."]
            root = ET.fromstring(z.read("word/document.xml"))
            paras = ["".join(t.text or "" for t in p.iter(f"{ns_w}t")) for p in root.iter(f"{ns_w}p")]
            props: dict[str, str] = {}
            if "docProps/core.xml" in z.namelist():
                core = ET.fromstring(z.read("docProps/core.xml"))
                for tag, key in ((f"{ns_dc}creator", "author"), (f"{ns_cp}lastModifiedBy", "last_modified_by")):
                    el = core.find(tag)
                    if el is not None and (el.text or "").strip():
                        props[key] = el.text.strip()
            return "\n".join(paras), props, []
    except (zipfile.BadZipFile, KeyError, ET.ParseError) as e:
        return "", {}, [f"DOCX could not be parsed: {e}"]


def extract(path: Path, configured_tesseract: str = "") -> Extracted:
    ext = path.suffix.lower()
    if ext in IMAGE_EXTS:
        ex = Extracted("image")
        try:
            ex.exif = read_exif(path)
        except Exception as e:
            ex.notes.append(f"Image metadata could not be read: {e}")
        try:
            ex.ocr_words, ex.ocr_mean_conf, notes = ocr_image(path, configured_tesseract)
            ex.notes += notes
            ex.text = words_to_text(ex.ocr_words)
        except Exception as e:
            ex.notes.append(f"OCR failed: {e}")
        return ex
    if ext == ".pdf":
        text, notes = pdf_text(path)
        return Extracted("pdf", text=text, notes=notes)
    if ext == ".docx":
        text, props, notes = docx_extract(path)
        return Extracted("docx", text=text, doc_props=props, notes=notes)
    if ext in TEXT_EXTS or ext == "":
        raw = path.read_bytes()[:MAX_TEXT_BYTES]
        ex = Extracted("text", text=raw.decode("utf-8", "replace"))
        if path.stat().st_size > MAX_TEXT_BYTES:
            ex.notes.append("File larger than 5 MB; only the first 5 MB was analysed.")
        return ex
    return Extracted("unsupported", notes=[f"File type '{ext}' is not supported for privacy analysis."])
