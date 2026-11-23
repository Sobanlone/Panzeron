"""Gmail protection against a local stand-in for Google (no network): consent is enforced, the OAuth flow uses PKCE and checks `state`,
only the read-only scope is requested, no mail is ever modified, bodies/subjects are never stored, and disconnect revokes and deletes."""
import base64
import json
import threading
import time
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests.helpers import new_app
from panzeron.connectors import gmail
from panzeron.shield.quarantine import ConsentRequired

b64 = lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
PHISH = {"id": "m1", "internalDate": str(int(time.time() * 1000)), "payload": {"mimeType": "multipart/alternative", "headers": [
    {"name": "From", "value": "PayPal Support <help@paypa1-secure-login.xyz>"}, {"name": "Reply-To", "value": "x@other-mail.ru"},
    {"name": "Authentication-Results", "value": "mx.google.com; spf=fail dkim=none dmarc=fail"}, {"name": "Subject", "value": "SECRETSUBJECT"}],
    "parts": [{"mimeType": "text/plain", "body": {"data": b64("URGENT: your account will be suspended. Verify your account now: http://paypa1-secure-login.xyz/verify/account?token=SECRETBODYTOKEN")}}]}}
FINE = {"id": "m2", "internalDate": str(int(time.time() * 1000)), "payload": {"mimeType": "text/plain", "headers": [
    {"name": "From", "value": "Mum <mum@example.com>"}, {"name": "Authentication-Results", "value": "spf=pass dkim=pass dmarc=pass"}],
    "body": {"data": b64("Dinner on Sunday? Bring the good bread.")}}}


class Google:
    """Minimal fake of the OAuth + Gmail endpoints. Records every request so tests can assert on what was asked."""
    def __init__(self):
        self.log = []; self.codes = {}; outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _send(self, obj, code=200):
                b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0)); form = urllib.parse.parse_qs(self.rfile.read(n).decode())
                outer.log.append(("POST", self.path, {k: v[0] for k, v in form.items()}, self.command))
                if self.path == "/token":
                    if form.get("grant_type") == ["authorization_code"]:
                        if form["code"][0] not in outer.codes: return self._send({"error_description": "bad code"}, 400)
                        return self._send({"access_token": "AT1", "refresh_token": "RT1", "expires_in": 3600, "scope": gmail.SCOPE})
                    return self._send({"access_token": "AT2", "expires_in": 3600})
                if self.path == "/revoke": return self._send({})
                self._send({}, 404)
            def do_GET(self):
                outer.log.append(("GET", self.path, {}, self.headers.get("Authorization")))
                if self.headers.get("Authorization", "").split(" ")[-1] not in ("AT1", "AT2"): return self._send({}, 401)
                if self.path.startswith("/gmail/v1/users/me/profile"): return self._send({"emailAddress": "me@gmail.com"})
                if self.path.startswith("/gmail/v1/users/me/messages?"): return self._send({"messages": [{"id": "m1"}, {"id": "m2"}]})
                if self.path.startswith("/gmail/v1/users/me/messages/m1"): return self._send(PHISH)
                if self.path.startswith("/gmail/v1/users/me/messages/m2"): return self._send(FINE)
                self._send({}, 404)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def endpoints(self):
        return {"auth": self.base + "/auth", "token": self.base + "/token", "revoke": self.base + "/revoke", "api": self.base}


class GmailTests(unittest.TestCase):
    def setUp(self):
        self.g = Google(); self.app = new_app()
        self.app.gmail = gmail.GmailGuard(self.app.db, self.app.audit, self.app.salt, self.app.paths.home, self.g.endpoints(), interval=0.3, first_delay=0.05)
        self.app.gmail.run_first_check = False
        self.opened = []; self.app.gmail.open_url = self.opened.append
        self.app.gmail_access("configure", "123-abc.apps.googleusercontent.com", "GOCSPX-secret")

    def connect(self, automatic=False):
        self.app.gmail_access("connect", automatic=automatic, consent=True)
        url = self.opened[-1]; q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        self.g.codes["CODE1"] = True
        cb = q["redirect_uri"][0] + "?" + urllib.parse.urlencode({"code": "CODE1", "state": q["state"][0]})
        urllib.request.urlopen(cb, timeout=5).read()
        return q

    def test_nothing_happens_without_permission(self):
        with self.assertRaises(ConsentRequired) as c: self.app.gmail_access("connect", consent=False)
        d = c.exception.details
        self.assertEqual(d["scope"], "gmail"); self.assertTrue(any("read-only" in p.lower() for p in d["promises"]))
        self.assertEqual(self.opened, []); self.assertFalse(self.app.gmail_status()["connected"])
        with self.assertRaises(ConsentRequired): self.app.gmail.check()
        self.assertEqual(self.g.log, [])                                   # Google was never contacted

    def test_client_id_is_validated_and_secret_is_not_stored_in_the_database(self):
        with self.assertRaises(ValueError): self.app.gmail_access("configure", "not-a-client-id")
        self.assertNotIn("GOCSPX-secret", json.dumps(self.app.db.query("SELECT value FROM settings")))
        self.assertNotIn("GOCSPX-secret", (self.app.paths.home / "gmail.secret").read_text())    # at rest it is encoded/encrypted, never plain

    def test_oauth_is_read_only_pkce_and_state_checked(self):
        q = self.connect()
        self.assertEqual(q["scope"], [gmail.SCOPE]); self.assertTrue(gmail.SCOPE.endswith("gmail.readonly"))
        self.assertEqual(q["code_challenge_method"], ["S256"]); self.assertTrue(q["redirect_uri"][0].startswith("http://127.0.0.1:"))
        ex = next(l for l in self.g.log if l[1] == "/token" and l[2].get("grant_type") == "authorization_code")[2]
        self.assertTrue(ex["code_verifier"]); self.assertEqual(ex["client_secret"], "GOCSPX-secret")
        st = self.app.gmail_status()
        self.assertTrue(st["connected"]); self.assertEqual(st["account"], "me@gmail.com")

    def test_wrong_state_is_rejected(self):
        self.app.gmail_access("connect", consent=True)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.opened[-1]).query); self.g.codes["C"] = True
        urllib.request.urlopen(q["redirect_uri"][0] + "?code=C&state=WRONG", timeout=5).read()
        self.assertFalse(self.app.gmail_status()["connected"]); self.assertIn("did not match", self.app.gmail_status()["error"])

    def test_check_flags_phishing_and_stores_no_mail_content(self):
        self.connect(); s = self.app.gmail.check()
        self.assertEqual((s["messages_screened"], s["flagged"]), (2, 1))
        fs = self.app.db.list_findings(); self.assertEqual(len(fs), 1)
        self.assertIn("phishing email in your Gmail", fs[0].title)
        blob = json.dumps(fs[0].to_dict()); st = json.dumps(self.app.db.query("SELECT value FROM settings"))
        for secret in ("SECRETSUBJECT", "SECRETBODYTOKEN", "Dinner on Sunday", "AT1", "RT1"):
            self.assertNotIn(secret, blob + st)
        self.assertEqual(self.app.gmail.check()["new_findings"], 0)         # nothing re-screened or duplicated

    def test_only_reads_never_writes(self):
        self.connect(); self.app.gmail.check()
        gets = [l for l in self.g.log if l[0] == "GET"]
        self.assertTrue(gets)
        self.assertTrue(all("/modify" not in l[1] and "/send" not in l[1] and "/trash" not in l[1] and "/delete" not in l[1] for l in self.g.log))
        self.assertEqual([l for l in self.g.log if l[0] == "POST" and l[1] not in ("/token", "/revoke")], [])

    def test_disconnect_revokes_and_deletes_the_token(self):
        self.connect(); self.app.gmail.check()
        out = self.app.gmail_access("disconnect")
        self.assertTrue(out["google_revoked"]); self.assertFalse(out["connected"])
        self.assertEqual(next(l for l in self.g.log if l[1] == "/revoke")[2]["token"], "RT1")
        self.assertFalse((self.app.paths.home / "gmail.secret").exists())
        with self.assertRaises(ConsentRequired): self.app.gmail.check()
        ev = [e["event"] for e in self.app.audit.entries(60)]
        self.assertIn("gmail.connected", ev); self.assertIn("gmail.disconnected", ev); self.assertTrue(self.app.audit.verify()["ok"])

    def test_automatic_mode_checks_by_itself_and_stops_on_disconnect(self):
        self.connect(automatic=True)
        for _ in range(60):
            if self.app.gmail._state().get("last_check"): break
            time.sleep(0.1)
        self.assertTrue(self.app.gmail._state().get("last_check")); self.app.gmail_access("disconnect")

    def test_consent_persists_across_restart(self):
        self.connect()
        again = gmail.GmailGuard(self.app.db, self.app.audit, self.app.salt, self.app.paths.home, self.g.endpoints())
        self.assertTrue(again.connected()); self.assertEqual(again._access(), "AT2")      # refresh-token path works from the saved secret

    def test_html_only_mail_is_read_and_links_are_extracted(self):
        msg = {"payload": {"mimeType": "text/html", "headers": [{"name": "From", "value": "a@b.com"}], "body": {"data": b64('<p>Hi</p><a href="http://evil.example/x">click</a><script>bad()</script>')}}}
        text, hdr = gmail.message_text(msg)
        self.assertIn("http://evil.example/x", text); self.assertNotIn("bad()", text); self.assertEqual(gmail.sender_domain(hdr), "b.com")


if __name__ == "__main__":
    unittest.main()
