import unittest
from panzeron.core.models import *
from panzeron.core.masking import mask_value
from panzeron.core.audit import AuditLog
from tests.helpers import SALT, new_app


class CoreTests(unittest.TestCase):
    def test_finding_requires_evidence(self):
        with self.assertRaises(InvariantError):
            Finding(Module.SHIELD, "t", Severity.LOW, Confidence.LOW, "x", [], "s")

    def test_tier_is_weakest_evidence(self):
        ev = [Evidence("a", "r", "x", EvidenceTier.VERIFIED), Evidence("b", "r", "rule", EvidenceTier.DERIVED)]
        self.assertEqual(Finding(Module.VISION, "t", Severity.LOW, Confidence.LOW, "x", ev, "s").tier, EvidenceTier.DERIVED)

    def test_ai_evidence_can_never_be_verified(self):
        self.assertEqual(Evidence("d", "r", "ai:ollama", EvidenceTier.VERIFIED).tier, EvidenceTier.AI_ASSESSED)
        self.assertEqual(Evidence("d", "r", "ai:ollama", EvidenceTier.DERIVED).tier, EvidenceTier.AI_ASSESSED)

    def test_roundtrip(self):
        f = Finding(Module.VISION, "t", Severity.LOW, Confidence.LOW, "x", [Evidence("a", "r", "p", EvidenceTier.VERIFIED)], "s",
                    [make_entity("email", "a@b.com", SALT)])
        self.assertEqual(Finding.from_dict(f.to_dict()).to_dict(), f.to_dict())

    def test_entities_match_across_sources_but_hide_raw(self):
        a, b = make_entity("username", "@Maya_K", SALT), make_entity("username", "maya_k", SALT)
        self.assertEqual(a.id, b.id)
        self.assertNotIn("maya_k", str(a.to_dict()).lower().replace("ma***", ""))
        self.assertNotEqual(a.id, make_entity("username", "maya_k", b"other" * 7).id)  # salt matters

    def test_masking(self):
        self.assertEqual(mask_value("email", "jane@x.com"), "j***@x.com")
        self.assertTrue(mask_value("card", "4111 1111 1111 1111").endswith("1111"))
        self.assertNotIn("4111 1111", mask_value("card", "4111 1111 1111 1111"))
        self.assertIn("rounded", mask_value("location", "47.6062, -122.3321"))

    def test_audit_chain_detects_tampering(self):
        app = new_app()
        a = AuditLog(app.db)
        for i in range(3):
            a.append("t", "e", {"i": i})
        self.assertTrue(a.verify()["ok"])
        app.db.execute("UPDATE audit_log SET payload='{\"i\": 99}' WHERE seq=2")
        v = a.verify()
        self.assertFalse(v["ok"]); self.assertEqual(v["first_broken_seq"], 2)

    def test_resolved_status_survives_rerun(self):
        app = new_app()
        f = Finding(Module.VISION, "t", Severity.LOW, Confidence.LOW, "x", [Evidence("a", "r", "p", EvidenceTier.VERIFIED)], "s", id="inf_fixed")
        app.db.save_finding(f); app.db.set_finding_status("inf_fixed", "resolved")
        app.db.save_finding(Finding(Module.VISION, "t", Severity.LOW, Confidence.LOW, "x", [Evidence("a", "r", "p", EvidenceTier.VERIFIED)], "s", id="inf_fixed"))
        self.assertEqual(app.db.get_finding("inf_fixed").status, "resolved")
