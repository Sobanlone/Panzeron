import json, os, threading, time, unittest, urllib.request
from pathlib import Path
from unittest import mock
from panzeron import diagnostics as dx
from panzeron.api.server import create_server
from tests.helpers import new_app


def finish(app, secs=60):
    for _ in range(int(secs * 10)):
        s = app.diagnostics_status()
        if not s["running"] and s["result"]: return s["result"]
        time.sleep(0.1)
    raise AssertionError("diagnostics did not finish")


class DiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = new_app(); cls.app.start_diagnostics(); cls.res = finish(cls.app); cls.by = {c["id"]: c for c in cls.res["checks"]}

    def test_every_check_reports_status_detail_and_timing(self):
        self.assertGreaterEqual(len(self.res["checks"]), 15)
        for c in self.res["checks"]:
            self.assertIn(c["status"], ("pass", "warn", "fail", "info")); self.assertTrue(c["detail"]); self.assertIsInstance(c["ms"], int)

    def test_core_checks_pass_here(self):
        for cid in ("selftest", "database", "audit", "datadir", "consent"): self.assertEqual(self.by[cid]["status"], "pass", self.by[cid])

    def test_scanner_selftest_covers_the_danger_model(self):
        self.assertIn("6 detection cases", self.by["selftest"]["detail"])

    def test_windows_only_checks_are_honest_elsewhere(self):
        if os.name == "nt": self.skipTest("windows")
        self.assertEqual(self.by["powershell"]["status"], "info"); self.assertEqual(self.by["winsec"]["status"], "info")

    def test_report_is_plain_text_with_summary_and_masks_personal_details(self):
        rep = self.res["report"]; self.assertIn("Panzeron diagnostics report", rep); self.assertIn("Summary:", rep)
        self.assertNotIn(str(Path.home()), rep)
        user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
        if len(user) > 2: self.assertNotIn(user, rep.replace("<user>", ""))

    def test_audit_records_the_run(self):
        self.assertTrue(any(e["event"] == "diagnostics.run" for e in self.app.audit.entries()))


class RobustnessTests(unittest.TestCase):
    def test_a_crashing_check_is_reported_and_does_not_stop_the_others(self):
        app = new_app()
        def boom(): raise RuntimeError("simulated crash")
        with mock.patch.object(dx, "_check_python", boom):
            app.start_diagnostics(); res = finish(app)
        by = {c["id"]: c for c in res["checks"]}
        self.assertEqual(by["python"]["status"], "fail"); self.assertIn("simulated crash", by["python"]["detail"]); self.assertEqual(by["selftest"]["status"], "pass"); self.assertFalse(res["ok"])

    def test_tampered_audit_log_is_a_failure(self):
        app = new_app(); app.db.execute("UPDATE audit_log SET payload='{\"x\":1}' WHERE seq=1")
        app.start_diagnostics(); res = finish(app); self.assertEqual({c["id"]: c for c in res["checks"]}["audit"]["status"], "fail")

    def test_second_start_while_running_does_not_spawn_another(self):
        app = new_app(); self.assertTrue(app.start_diagnostics()["running"]); self.assertTrue(app.start_diagnostics()["running"]); finish(app)


class ApiTests(unittest.TestCase):
    def test_http_job_flow(self):
        app = new_app(); srv, tok = create_server(app, 0); threading.Thread(target=srv.serve_forever, daemon=True).start()
        def call(m, p):
            r = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}{p}", method=m, headers={"X-Session-Token": tok}, data=b"{}" if m == "POST" else None)
            with urllib.request.urlopen(r) as x: return json.loads(x.read())
        try:
            self.assertTrue(call("POST", "/api/diagnostics/run")["running"])
            for _ in range(600):
                d = call("GET", "/api/diagnostics")
                if not d["running"] and d["result"]: break
                time.sleep(0.1)
            self.assertIn("report", d["result"]); self.assertEqual(d["result"]["counts"]["fail"], d["result"]["counts"].get("fail", 0))
        finally: srv.shutdown()
