"""A scanner reads hostile files. These tests throw garbage, truncated and mutated data at every parser and require:
(1) no exception ever escapes, and (2) nothing takes unreasonable time (catches regex backtracking / ReDoS)."""
import io, os, random, struct, tempfile, time, unittest, zipfile
from pathlib import Path
from panzeron.shield import containers, pe as pelib
from panzeron.shield.scanner import Scanner, inspect_content
from panzeron.vision import pii
from panzeron.sentinel import analyzer as sn
from tests.helpers import SALT
from tests.test_shield2 import build_pe

RNG = random.Random(20261109)
EXTS = [".exe", ".dll", ".ps1", ".bat", ".js", ".vbs", ".lnk", ".php", ".pdf", ".txt", ".docx", ".zip", ".doc", ".html", ".py", ".jpg", ""]
LIMIT = 3.0


def rbytes(n): return bytes(RNG.getrandbits(8) for _ in range(n))
def mutate(data, flips=8):
    b = bytearray(data)
    for _ in range(flips):
        if b: b[RNG.randrange(len(b))] = RNG.getrandbits(8)
    if RNG.random() < 0.5 and b: del b[RNG.randrange(len(b)):]          # also truncate
    return bytes(b)
def timed(fn, *a):
    t = time.perf_counter(); r = fn(*a); return r, time.perf_counter() - t


class FuzzTests(unittest.TestCase):
    def test_random_bytes_through_every_content_inspector(self):
        for i in range(250):
            data = rbytes(RNG.choice([0, 1, 2, 16, 64, 500, 4000, 40000]))
            if RNG.random() < 0.4: data = RNG.choice([b"MZ", b"PK\x03\x04", b"%PDF", b"\xd0\xcf\x11\xe0", b"{\\rtf", b"\x7fELF"]) + data
            name = f"f{i}{RNG.choice(EXTS)}"
            _, dt = timed(inspect_content, name, data, None, SALT, "0" * 64); self.assertLess(dt, LIMIT, name)

    def test_mutated_pe_files_never_crash_the_parser(self):
        good = build_pe({"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"], "user32.dll": ["MessageBoxW"]})
        self.assertIsNotNone(pelib.parse(good))
        for _ in range(600):
            m = mutate(good, RNG.choice([1, 4, 16, 64]))
            info = pelib.parse(m, len(m))
            if info: pelib.assess(info, len(m))
            inspect_content("m.exe", m, None, SALT, "0" * 64)

    def test_mutated_and_truncated_archives(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("a.txt", b"hello" * 50); z.writestr("invoice.pdf", b"MZ" + b"\x90" * 100); z.writestr("n/inner.zip", b"PK\x05\x06" + b"\0" * 18)
        good = b.getvalue()
        for _ in range(400):
            m = mutate(good, RNG.choice([1, 3, 10]))
            containers.inspect_zip(io.BytesIO(m), "x.zip", None, SALT, lambda n, d, p, s, sha, depth=0: inspect_content(n, d, p, s, sha, depth=depth))
            containers.inspect_ole(RNG.choice([b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b""]) + m, "x.doc", None, SALT)

    def test_garbage_text_through_privacy_and_phishing_analysers(self):
        for _ in range(150):
            text = rbytes(RNG.choice([10, 200, 5000])).decode("latin-1")
            pii.detect(text); sn.analyze(text, SALT)

    def test_scanning_a_directory_of_hostile_files_completes_and_reports(self):
        d = Path(tempfile.mkdtemp())
        names = ["", "a" * 120, "ünï©ødé.txt", "with space.exe", "dots...", "x.pdf.exe", "CON.txt" if os.name != "nt" else "okay.txt"]
        for i, n in enumerate(names):
            if not n: continue
            try: (d / n).write_bytes(rbytes(RNG.choice([0, 10, 3000, 70000])))
            except OSError: pass
        (d / "zero.exe").write_bytes(b""); (d / "trunc.zip").write_bytes(b"PK\x03\x04" + rbytes(30)); (d / "broken.docx").write_bytes(b"PK\x03\x04junk")
        res, _ = Scanner(SALT, workers=3).scan(str(d)); self.assertEqual(res.status, "completed"); self.assertFalse(res.enumerating)


class PathologicalInputTests(unittest.TestCase):
    """Inputs crafted to make a backtracking regex explode. Each must finish quickly."""
    CASES = {
        "long run of letters": "a" * 200_000,
        "long run of digits": "1" * 200_000,
        "digit-dash pairs": "1-" * 100_000,
        "digit-space pairs": "1 " * 100_000,
        "many at signs": "@" * 100_000,
        "email-like then fail": "a" * 100_000 + "@" + "b." * 30_000,
        "title-case words": "Alpha Beta " * 30_000,
        "school-like words": ("Riverside " * 40_000) + "Universit",
        "dots and slashes": "a./" * 70_000,
        "colon equals labels": "password = " * 20_000,
        "http repeats": "http://" * 30_000,
        "nested brackets": "(" * 50_000 + "a" + ")" * 50_000,
        "base64-ish": "QUJD" * 60_000,
        "spaces": " " * 200_000,
        "newlines": "\n" * 200_000,
        "dear repeats": "Dear " * 40_000,
    }

    def test_privacy_detector_is_linear_enough(self):
        for label, text in self.CASES.items():
            _, dt = timed(pii.detect, text); self.assertLess(dt, LIMIT, f"pii.detect too slow on '{label}': {dt:.1f}s")

    def test_phishing_analyser_is_linear_enough(self):
        for label, text in self.CASES.items():
            _, dt = timed(sn.analyze, text, SALT); self.assertLess(dt, LIMIT, f"sentinel too slow on '{label}': {dt:.1f}s")

    def test_rule_engine_is_linear_enough(self):
        for label, text in self.CASES.items():
            for ext in (".txt", ".ps1", ".php", ".lnk", ".sh"):
                _, dt = timed(inspect_content, "t" + ext, text.encode("utf-8", "ignore"), None, SALT, "0" * 64); self.assertLess(dt, LIMIT, f"rules too slow on '{label}' ({ext}): {dt:.1f}s")
