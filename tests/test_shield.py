import tempfile, unittest, hashlib
from pathlib import Path
from panzeron.shield.scanner import *
from panzeron.shield.quarantine import QuarantineVault, ConfirmationRequired, QuarantineError
from panzeron.shield import defender
from tests.helpers import SALT, new_app


def titles(name, data, sha="0"):
    return [f.title for f in inspect_content(name, data, None, SALT, sha)]


class ShieldTests(unittest.TestCase):
    def test_eicar_detected_in_memory(self):  # never written to disk: Defender would delete it
        r = inspect_content("x.txt", EICAR, None, SALT, "0")
        self.assertEqual(r[0].category, "shield.signature"); self.assertEqual(r[0].tier.value, "verified")
        self.assertEqual(hashlib.sha256(EICAR).hexdigest(), EICAR_SHA256)

    def test_known_hash_list(self):
        self.assertTrue(any(f.category == "shield.hash" for f in inspect_content("renamed.bin", b"other", None, SALT, EICAR_SHA256)))

    def test_false_positive_traps_not_flagged(self):
        self.assertEqual(titles("virus.exe", b"just some harmless text"), [])
        self.assertEqual(titles("invoice.pdf.exe", b"hello"), [])
        self.assertEqual(titles("free_crack_keygen.zip", b"PK\x03\x04 nothing"), [])

    def test_disguised_executable(self):
        self.assertIn("Executable content with a non-executable extension", titles("cat.jpg", b"MZ" + b"\0" * 80))

    def test_pe_parse_and_packer_indicator(self):
        import struct
        pe = bytearray(b"MZ" + b"\0" * 62); pe[0x3C:0x40] = struct.pack("<I", 0x40)
        pe += b"PE\0\0" + struct.pack("<HHIIIHH", 0x14c, 1, 0, 0, 0, 0, 0x102)
        pe += b"UPX0".ljust(8, b"\0") + struct.pack("<IIII", 100, 0, 0, 0) + b"\0" * 16
        parsed = parse_pe(bytes(pe)); self.assertEqual(parsed["sections"][0]["name"], b"UPX0")
        fs = inspect_content("setup.exe", bytes(pe), None, SALT, "0")
        self.assertEqual(fs[0].severity.value, "low"); self.assertEqual(fs[0].confidence.value, "low")

    def test_script_needs_two_indicators(self):
        one = b"Invoke-WebRequest http://x"; two = b"powershell -w hidden; (New-Object Net.WebClient).DownloadString('x')"
        self.assertEqual(titles("a.ps1", one), [])
        self.assertEqual(len(titles("a.ps1", two)), 1)
        self.assertEqual(titles("a.txt", two), [])   # not a script extension

    def test_scan_directory_exclusions_and_errors(self):
        d = Path(tempfile.mkdtemp())
        (d / "bad.txt").write_bytes(b"x " + PANZERON_MARKER); (d / "ok.txt").write_text("fine")
        (d / "skip.txt").write_bytes(PANZERON_MARKER)
        res, fs = Scanner(SALT).scan(str(d)); self.assertEqual((res.files_scanned, len(fs)), (3, 2))
        ex = [{"kind": "path", "pattern": str(d / "skip.txt")}]
        res, fs = Scanner(SALT, ex).scan(str(d)); self.assertEqual((res.files_excluded, len(fs)), (1, 1))
        res, _ = Scanner(SALT, max_file_mb=1).scan(str(d / "ok.txt")); self.assertEqual(res.status, "completed")
        res, _ = Scanner(SALT).scan(str(d / "nope")); self.assertEqual(res.status, "failed")

    def test_signature_across_chunk_boundary(self):
        d = Path(tempfile.mkdtemp()); p = d / "big.bin"
        p.write_bytes(b"A" * (CHUNK - 10) + PANZERON_MARKER + b"B" * 100)
        self.assertEqual(len(Scanner(SALT).scan(str(p))[1]), 1)

    def test_hash_exclusion(self):
        d = Path(tempfile.mkdtemp()); p = d / "a.txt"; p.write_bytes(PANZERON_MARKER)
        h = hashlib.sha256(PANZERON_MARKER).hexdigest()
        self.assertEqual(Scanner(SALT, [{"kind": "hash", "pattern": h}]).scan(str(d))[0].files_excluded, 1)


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.app = new_app(); self.d = Path(tempfile.mkdtemp()); self.f = self.d / "sample.bin"
        self.f.write_bytes(b"payload" * 1000); self.sha = hashlib.sha256(self.f.read_bytes()).hexdigest()

    def test_requires_confirmation_and_changes_nothing(self):
        with self.assertRaises(ConfirmationRequired): self.app.vault.quarantine(str(self.f), None, confirm=False)
        self.assertTrue(self.f.exists())

    def test_roundtrip_is_byte_identical(self):
        q = self.app.vault.quarantine(str(self.f), None, confirm=True)
        self.assertFalse(self.f.exists())
        with self.assertRaises(ConfirmationRequired): self.app.vault.restore(q["id"], confirm=False)
        self.app.vault.restore(q["id"], confirm=True)
        self.assertEqual(hashlib.sha256(self.f.read_bytes()).hexdigest(), self.sha)

    def test_restore_never_overwrites(self):
        q = self.app.vault.quarantine(str(self.f), None, confirm=True); self.f.write_text("new file")
        with self.assertRaises(QuarantineError): self.app.vault.restore(q["id"], confirm=True)
        self.assertEqual(self.f.read_text(), "new file")

    def test_vault_tamper_blocks_restore(self):
        q = self.app.vault.quarantine(str(self.f), None, confirm=True)
        Path(self.app.vault.list()[0]["vault_path"]).write_bytes(b"tampered")
        with self.assertRaises(QuarantineError): self.app.vault.restore(q["id"], confirm=True)


class DefenderTests(unittest.TestCase):
    def test_unavailable_off_windows_is_not_zero(self):
        if defender._is_windows(): self.skipTest("Windows")
        s = defender.status(); self.assertFalse(s["available"]); self.assertIn("reason", s)

    def test_parses_defender_json_when_windows(self):
        from unittest import mock
        out = '{"AMServiceEnabled":true,"AntivirusEnabled":true,"RealTimeProtectionEnabled":false,"AntivirusSignatureVersion":"1.2"}'
        cp = mock.Mock(returncode=0, stdout=out, stderr="")
        with mock.patch.object(defender, "_is_windows", return_value=True), mock.patch.object(defender, "_ps", return_value=cp):
            s = defender.status()
        self.assertTrue(s["available"]); self.assertIs(s["realtime_protection"], False)  # False is reported, not hidden
