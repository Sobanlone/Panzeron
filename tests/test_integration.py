import json, tempfile, threading, time, unittest, urllib.error, urllib.request
from pathlib import Path
from ultrimater import demo
from ultrimater.api.server import create_server
from ultrimater.core.models import Module
from ultrimater.inference.engine import run_inference
from ultrimater.shield.quarantine import ConfirmationRequired
from ultrimater.response.service import ActionError
from tests.helpers import new_app


def wait_scan(app, sid):
    for _ in range(100):
        s = app.scan_status(sid)
        if s and s["status"] != "running": return s
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


class InferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = new_app(); cls.summary = demo.load_demo(cls.app); wait_scan(cls.app, cls.summary["scan_id"])
        cls.inf, cls.graph = run_inference(cls.app.db.list_findings())
        cls.cats = {f.category for f in cls.inf}

    def test_expected_rules_fire(self):
        for c in ("inference.reuse", "inference.combination", "inference.credential_identity", "inference.targeted"):
            self.assertIn(c, self.cats)

    def test_hypotheses_are_labelled_speculative_never_verified(self):
        comb = next(f for f in self.inf if f.category == "inference.combination")
        self.assertEqual(comb.tier.value, "speculative")
        self.assertTrue(any(e.description.startswith("HYPOTHESIS") for e in comb.evidence))
        self.assertTrue(all(f.tier.value in ("derived", "speculative") for f in self.inf))   # inference never claims 'verified'

    def test_every_edge_names_its_rule_and_references_real_nodes(self):
        ids = {n["id"] for n in self.graph.nodes}
        for e in self.graph.edges:
            self.assertTrue(e.derived_by); self.assertIn(e.src, ids); self.assertIn(e.dst, ids)

    def test_no_raw_values_in_graph(self):
        blob = json.dumps(self.graph.to_dict())
        for raw in ("maya.khan@example.com", "maya_k_art", "415 555 0132", "AKIAIOSFODNN7EXAMPLE", "Sunflower-2026"): self.assertNotIn(raw, blob)

    def test_inference_ids_are_stable_across_runs(self):
        again, _ = run_inference(self.app.db.list_findings())
        self.assertEqual({f.id for f in again}, {f.id for f in self.inf})

    def test_no_links_without_shared_entities(self):
        a = new_app(); a.analyze_pasted_text("Name: Alice Brown\nemail alice@one.org", "a.txt"); a.analyze_pasted_text("Name: Carl Dunn\nemail carl@two.org", "b.txt")
        inf, _ = run_inference(a.db.list_findings()); self.assertEqual([f for f in inf if f.category == "inference.reuse"], [])

    def test_resolved_findings_leave_the_graph(self):
        for f in self.app.db.list_findings(module="sentinel"): self.app.db.set_finding_status(f.id, "resolved")
        inf, _ = run_inference(self.app.db.list_findings()); self.assertNotIn("inference.targeted", {f.category for f in inf})


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.app = new_app(); self.d = Path(tempfile.mkdtemp())
        from ultrimater.shield.scanner import ULTRIMATER_MARKER
        self.f = self.d / "marker.txt"; self.f.write_bytes(ULTRIMATER_MARKER)
        wait_scan(self.app, self.app.start_scan(str(self.d))["scan_id"])
        self.finding = self.app.db.list_findings(module="shield")[0]

    def test_quarantine_needs_confirmation_then_restore(self):
        with self.assertRaises(ConfirmationRequired): self.app.response.execute("quarantine_file", self.finding.id, confirm=False)
        self.assertTrue(self.f.exists())
        self.app.response.execute("quarantine_file", self.finding.id, confirm=True)
        self.assertFalse(self.f.exists()); self.assertEqual(self.app.db.get_finding(self.finding.id).status, "resolved")
        q = self.app.vault.list()[0]; self.app.response.restore_quarantined(q["id"], confirm=True)
        self.assertTrue(self.f.exists()); self.assertEqual(self.app.db.get_finding(self.finding.id).status, "open")

    def test_actions_are_audited_and_chain_valid(self):
        self.app.response.execute("report_false_positive", self.finding.id, confirm=False)
        self.assertEqual(self.app.db.get_finding(self.finding.id).status, "false_positive")
        self.assertTrue(any(e["event"] == "action.report_false_positive" for e in self.app.audit.entries()))
        self.assertTrue(self.app.audit.verify()["ok"]); self.assertEqual(self.app.response.history()[0]["type"], "report_false_positive")

    def test_exclusion_then_rescan_skips(self):
        self.app.response.execute("add_exclusion", self.finding.id, confirm=True)
        res = wait_scan(self.app, self.app.start_scan(str(self.d))["scan_id"]); self.assertEqual(res["files_excluded"], 1)

    def test_reassess_resolves_when_file_is_clean(self):
        self.f.write_text("now clean"); r = self.app.response.execute("reassess", self.finding.id, confirm=False)
        self.assertEqual(r["detail"]["result"], "no_longer_detected"); self.assertEqual(self.app.db.get_finding(self.finding.id).status, "resolved")

    def test_unavailable_action_rejected(self):
        with self.assertRaises(ActionError): self.app.response.execute("redact_copy", self.finding.id, confirm=True)


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = new_app(); cls.srv, cls.tok = create_server(cls.app, 0); cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()

    def call(self, m, p, body=None, tok=None, headers=None, raw=None):
        h = {"X-Session-Token": self.tok if tok is None else tok, **(headers or {})}
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{p}", method=m, headers=h, data=raw if raw is not None else (json.dumps(body).encode() if body is not None else None))
        try:
            with urllib.request.urlopen(r) as x: return x.status, json.loads(x.read() or b"{}")
        except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")

    def test_auth_and_host(self):
        self.assertEqual(self.call("GET", "/api/status", tok="nope")[0], 401)
        self.assertEqual(self.call("GET", "/api/status", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.call("POST", "/api/scan", {"path": "/"}, headers={"Sec-Fetch-Site": "cross-site"})[0], 403)

    def test_status_is_honest(self):
        s = self.call("GET", "/api/status")[1]
        self.assertFalse(s["monitoring"]["realtime"]); self.assertIn("available", s["defender"])

    def test_validation_and_errors(self):
        self.assertEqual(self.call("POST", "/api/sentinel/analyze", {"text": ""})[0], 400)
        self.assertEqual(self.call("POST", "/api/scan", {"path": "/definitely/not/here"})[0], 400)
        self.assertEqual(self.call("POST", "/api/scan", raw=b"{bad json")[0], 400)
        self.assertEqual(self.call("PUT", "/api/settings", {"nope": 1})[0], 400)
        self.assertEqual(self.call("PUT", "/api/settings", {"max_scan_file_mb": "big"})[0], 400)
        self.assertEqual(self.call("GET", "/api/nothing")[0], 404)

    def test_upload_sanitises_filename_and_analyses(self):
        s, r = self.call("POST", "/api/vision/upload", raw=b"mail me: a@b.com", headers={"X-Filename": "../../evil name.txt"})
        self.assertEqual(s, 200); self.assertEqual(r["source"], "evil name.txt"); self.assertTrue(any(f["category"] == "pii.email" for f in r["findings"]))

    def test_confirmation_flow_over_http(self):
        d = Path(tempfile.mkdtemp()); (d / "m.txt").write_bytes(b"ULTRIMATER-TEST-MARKER-HARMLESS-V1")
        sid = self.call("POST", "/api/scan", {"path": str(d)})[1]["scan_id"]; wait_scan(self.app, sid)
        fid = self.call("GET", "/api/findings?module=shield")[1]["findings"][0]["id"]
        s, r = self.call("POST", f"/api/findings/{fid}/action", {"type": "quarantine_file"}); self.assertEqual((s, r["error"]), (409, "confirmation_required"))
        self.assertTrue((d / "m.txt").exists())

    def test_static_ui_gets_token_but_traversal_blocked(self):
        r = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/"); body = r.read().decode()
        self.assertIn(self.tok, body); self.assertNotIn("__SESSION_TOKEN__", body)
        with self.assertRaises(urllib.error.HTTPError) as c: urllib.request.urlopen(f"http://127.0.0.1:{self.port}/..%2f..%2fapp.py")
        self.assertEqual(c.exception.code, 404)

    def test_cors_not_enabled(self):
        r = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/")
        self.assertIsNone(r.headers.get("Access-Control-Allow-Origin"))
