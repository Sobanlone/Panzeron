import threading, time, unittest
from unittest import mock
from ultrimater.core.cache import BackgroundCache
from ultrimater.core.audit import AuditLog
from ultrimater.shield import defender
from tests.helpers import new_app


class CacheTests(unittest.TestCase):
    def test_get_never_blocks_on_a_slow_lookup(self):
        c = BackgroundCache(lambda: (time.sleep(1.0), "v")[1], ttl=60)
        t = time.perf_counter(); v, busy = c.get(); self.assertLess(time.perf_counter() - t, 0.2)
        self.assertIsNone(v); self.assertTrue(busy)
        time.sleep(1.2); self.assertEqual(c.get()[0], "v")

    def test_single_flight_no_pileup_of_lookups(self):
        calls = []
        c = BackgroundCache(lambda: (calls.append(1), time.sleep(0.4), "v")[2], ttl=60)
        ts = [threading.Thread(target=c.get) for _ in range(25)]; [t.start() for t in ts]; [t.join() for t in ts]
        time.sleep(0.6); self.assertEqual(len(calls), 1)      # 25 concurrent requests -> ONE PowerShell-equivalent call

    def test_stale_value_served_while_refreshing_and_errors_keep_old_value(self):
        state = {"n": 0}
        def fn():
            state["n"] += 1
            if state["n"] == 2: raise RuntimeError("boom")
            return state["n"]
        c = BackgroundCache(fn, ttl=0.4); c.get(wait=1); self.assertEqual(c.get()[0], 1)
        time.sleep(0.5); c.get(); time.sleep(0.15)            # refresh #2 fails
        self.assertEqual(c.get()[0], 1); self.assertIn("boom", c.last_error or "")
        self.assertEqual(state["n"], 2)                       # and it did NOT immediately retry


class StatusLatencyTests(unittest.TestCase):
    def test_status_returns_fast_even_when_defender_is_slow(self):
        with mock.patch.object(defender, "snapshot", lambda: (time.sleep(2.5), {"status": {"available": False, "reason": "x"}, "products": {}, "detections": {}})[1]):
            app = new_app()
            t = time.perf_counter(); s = app.status(); app.summary(); took = time.perf_counter() - t
        self.assertLess(took, 1.0); self.assertTrue(s["defender"]["checking"])      # honest "checking", not a fake value
        self.assertIsNone(s["defender"]["available"])
        time.sleep(2.8); self.assertFalse(app.defender_info()["checking"])

    def test_repeated_status_calls_do_not_respawn_probes(self):
        calls = []
        with mock.patch.object(defender, "snapshot", lambda: (calls.append(1), {"status": {"available": False, "reason": "x"}, "products": {}, "detections": {}})[1]):
            app = new_app(); time.sleep(0.3)
            for _ in range(20): app.status()
        self.assertEqual(len(calls), 1)

    def test_powershell_calls_hide_their_console_window(self):
        with mock.patch.object(defender, "NO_WINDOW", 0x08000000), mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="{}", stderr="")
            defender._ps("Get-Date")
        self.assertEqual(run.call_args.kwargs["creationflags"], 0x08000000)


class AuditIncrementalTests(unittest.TestCase):
    def test_incremental_check_is_cheap_and_catches_new_tampering(self):
        app = new_app(); a = AuditLog(app.db)
        for i in range(50): a.append("t", "e", {"i": i})
        self.assertTrue(a.verify_incremental()["ok"])
        a.append("t", "e", {"i": 51}); self.assertTrue(a.verify_incremental()["ok"])
        app.db.execute("UPDATE audit_log SET payload='{}' WHERE seq=(SELECT MAX(seq) FROM audit_log)")
        a2 = AuditLog(app.db)                                  # a fresh checker, like a restart
        self.assertFalse(a2.verify_incremental()["ok"]); self.assertFalse(a2.verify()["ok"])
