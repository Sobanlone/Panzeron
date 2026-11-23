import json, threading, unittest, urllib.parse, urllib.request
from ultrimater.api.server import create_server
from ultrimater.core.models import Confidence, Evidence, EvidenceTier, Finding, Module, Severity
from tests.helpers import new_app

SEVS = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def seed(app, n=120):
    for i in range(n):
        app.db.save_finding(Finding(Module.SHIELD if i % 2 else Module.VISION, f"Finding {i} {'phishing' if i % 7 == 0 else 'plain'}", SEVS[i % 5], Confidence.LOW, "x",
                                    [Evidence("e", "r", "p", EvidenceTier.VERIFIED)], f"folder/src{i % 9}.txt"))


class SearchTests(unittest.TestCase):
    def setUp(self): self.app = new_app(); seed(self.app)

    def test_text_search_matches_title_and_source(self):
        r = self.app.search_findings(q="phishing"); self.assertEqual(r["total"], 18)
        self.assertEqual(self.app.search_findings(q="src3")["total"], len([i for i in range(120) if i % 9 == 3]))

    def test_filters_combine_and_counts_ignore_the_severity_filter(self):
        r = self.app.search_findings(severities=["critical", "high"], modules=["shield"])
        self.assertTrue(all(i["severity"] in ("critical", "high") and i["module"] == "shield" for i in r["items"]))
        self.assertEqual(sum(r["counts"]["severity"].values()), self.app.search_findings(modules=["shield"])["total"])   # chip counts stay visible while filtering

    def test_sort_by_severity_then_paginate_without_gaps_or_repeats(self):
        seen, order = [], ["critical", "high", "medium", "low", "info"]
        for off in range(0, 120, 25):
            seen += [(i["id"], i["severity"]) for i in self.app.search_findings(offset=off, limit=25)["items"]]
        self.assertEqual(len(seen), 120); self.assertEqual(len({s[0] for s in seen}), 120)
        ranks = [order.index(s[1]) for s in seen]; self.assertEqual(ranks, sorted(ranks))

    def test_hostile_search_text_is_inert(self):
        for q in ("100%_x", "'; DROP TABLE findings;--", "\\", "%", "_" * 500, "\u0000"):
            self.app.search_findings(q=q)
        self.assertEqual(self.app.db.query("SELECT COUNT(*) n FROM findings")[0]["n"], 120)
        self.assertEqual(self.app.search_findings(q="%")["total"], 0)               # a literal percent, not a wildcard

    def test_limit_is_capped_and_bad_sort_falls_back(self):
        self.assertLessEqual(len(self.app.search_findings(limit=100000)["items"]), 120); self.assertEqual(self.app.search_findings(sort="'; --")["total"], 120)


class BulkTests(unittest.TestCase):
    def setUp(self): self.app = new_app(); seed(self.app)

    def test_bulk_by_ids_and_by_filter_are_status_only_and_reversible(self):
        ids = [f["id"] for f in self.app.search_findings(limit=5)["items"]]
        self.assertEqual(self.app.bulk_status("resolve", ids, None)["changed"], 5); self.assertEqual(self.app.search_findings()["total"], 115)
        still_open = self.app.search_findings(q="phishing")["total"]; self.assertGreater(still_open, 0)
        self.assertEqual(self.app.bulk_status("false_positive", None, {"q": "phishing", "status": "open"})["changed"], still_open)   # by filter, not by ids
        self.assertEqual(self.app.search_findings(q="phishing")["total"], 0)
        closed = self.app.search_findings(status="closed")["total"]; self.assertEqual(closed, 5 + still_open)
        self.assertEqual(self.app.bulk_status("reopen", None, {"status": "closed"})["changed"], closed); self.assertEqual(self.app.search_findings()["total"], 120)   # fully reversible

    def test_bulk_validation_and_audit(self):
        with self.assertRaises(ValueError): self.app.bulk_status("delete", ["x"], None)
        self.app.bulk_status("resolve", [f["id"] for f in self.app.search_findings(limit=2)["items"]], None)
        self.assertTrue(any(e["event"] == "findings.bulk_resolve" for e in self.app.audit.entries())); self.assertTrue(self.app.audit.verify()["ok"])


class SearchApiTests(unittest.TestCase):
    def test_http_search_and_bulk(self):
        app = new_app(); seed(app, 60); srv, tok = create_server(app, 0); threading.Thread(target=srv.serve_forever, daemon=True).start()
        def call(m, p, body=None):
            r = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}{p}", method=m, headers={"X-Session-Token": tok}, data=json.dumps(body).encode() if body is not None else None)
            with urllib.request.urlopen(r) as x: return json.loads(x.read())
        try:
            r = call("GET", "/api/findings/search?" + urllib.parse.urlencode({"q": "phishing", "severity": "critical,high,medium,low,info", "limit": "5", "sort": "newest"}))
            self.assertEqual(len(r["items"]), 5); self.assertEqual(r["total"], 9)
            self.assertEqual(call("POST", "/api/findings/bulk", {"action": "resolve", "filter": {"q": "phishing"}})["changed"], 9)
            self.assertEqual(call("GET", "/api/findings/search?q=phishing")["total"], 0)
        finally: srv.shutdown()
