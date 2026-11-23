"""Gmail protection: read-only screening of your inbox for phishing, only after you connect your account.

How it connects: Google's standard "installed app" sign-in (OAuth 2.0 with PKCE on a loopback address). You create your own free Google
client ID, so the permission is between you and Google; Ultrimater has no server and never sees your Google password.

Scope requested: gmail.readonly ONLY. That scope cannot send, delete, move, label or change mail, and Ultrimater has no code that tries.
It reads headers, text and links of recent inbox messages, runs the same fixed Sentinel rules as the Threat page (look-alike senders,
Reply-To mismatch, failed SPF/DKIM/DMARC, urgent payment/credential requests, risky links) and keeps ONLY the findings. Message bodies and
subjects are never stored. The refresh token is encrypted with Windows DPAPI (tied to your Windows account) and deleted on disconnect,
when Ultrimater also asks Google to revoke it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from ..core.log import get_logger
from ..core.models import now_iso
from ..sentinel import analyzer as sentinel
from ..shield.quarantine import ConsentRequired

log = get_logger("gmail")
SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
DEFAULT_ENDPOINTS = {"auth": "https://accounts.google.com/o/oauth2/v2/auth", "token": "https://oauth2.googleapis.com/token",
                     "revoke": "https://oauth2.googleapis.com/revoke", "api": "https://gmail.googleapis.com"}
INTERVAL_SECONDS = 15 * 60
FIRST_WINDOW_DAYS = 7
MAX_MESSAGES_PER_CHECK = 100
MAX_BODY_CHARS = 20_000
FLOW_TIMEOUT = 180
KEEP = ("suspicious", "likely_scam")                   # weaker verdicts are not worth a finding in someone's inbox
SETUP_STEPS = ["Open console.cloud.google.com and create a project (free).",
               "Enable the Gmail API for it.",
               "Set up the OAuth consent screen (External, Testing) and add your own Gmail address as a test user.",
               "Create credentials → OAuth client ID → application type Desktop app.",
               "Paste the Client ID (and the client secret, if shown) below."]


class GmailError(ValueError):
    pass


# ---- protecting the token at rest ---------------------------------------------------------------------------
def protect(data: bytes) -> tuple[bytes, str]:
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class BLOB(ctypes.Structure):
                _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
            buf = ctypes.create_string_buffer(data, len(data))
            inp, out = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), BLOB()
            if ctypes.windll.crypt32.CryptProtectData(ctypes.byref(inp), "Ultrimater Gmail", None, None, None, 0, ctypes.byref(out)):
                try:
                    return ctypes.string_at(out.pbData, out.cbData), "Windows DPAPI (tied to your Windows account)"
                finally:
                    ctypes.windll.kernel32.LocalFree(out.pbData)
        except Exception as e:
            log.warning("DPAPI unavailable", extra={"ctx": {"error": str(e)[:100]}})
    return base64.b64encode(data), "file permissions only (this platform has no DPAPI)"


def unprotect(blob: bytes, how: str) -> bytes:
    if how.startswith("Windows DPAPI"):
        import ctypes
        from ctypes import wintypes

        class BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        buf = ctypes.create_string_buffer(blob, len(blob))
        inp, out = BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
            raise GmailError("The saved Gmail sign-in could not be unlocked on this Windows account. Disconnect and connect again.")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out.pbData)
    return base64.b64decode(blob)


# ---- reading message content ---------------------------------------------------------------------------------
class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []; self.links: list[str] = []; self._skip = 0

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            href = dict(attrs).get("href") or ""
            if re.match(r"(?i)https?://", href):
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def _b64(s: str) -> str:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", errors="replace")
    except Exception:
        return ""


def message_text(msg: dict[str, Any]) -> tuple[str, dict[str, str]]:
    """(analysis text, wanted headers). Header lines come first so the Sentinel header rules see them; links from HTML parts are appended."""
    payload = msg.get("payload") or {}
    hdr = {h["name"].lower(): h["value"] for h in payload.get("headers", []) if isinstance(h, dict) and "name" in h}
    plain: list[str] = []; html: list[str] = []

    def walk(p: dict[str, Any]) -> None:
        mt, data = p.get("mimeType", ""), (p.get("body") or {}).get("data")
        if data and mt == "text/plain":
            plain.append(_b64(data))
        elif data and mt == "text/html":
            html.append(_b64(data))
        for sub in p.get("parts") or []:
            walk(sub)
    walk(payload)
    links: list[str] = []
    body = "\n".join(plain)
    if html:
        t = _Text(); t.feed("\n".join(html)); links = t.links
        if not body.strip():
            body = " ".join(t.parts)
    head = "".join(f"{k.title()}: {hdr[k]}\n" for k in ("from", "reply-to", "return-path", "authentication-results") if k in hdr)
    text = head + "\n" + re.sub(r"[ \t]+", " ", body)[:MAX_BODY_CHARS]
    if links:
        text += "\n" + "\n".join(dict.fromkeys(links))[:4000]
    return text, hdr


def sender_domain(hdr: dict[str, str]) -> str:
    m = re.search(r"@([\w.-]+\.\w+)", hdr.get("from", ""))
    return m.group(1).lower() if m else "unknown sender"


# ---- the connector ---------------------------------------------------------------------------------------------
class GmailGuard:
    def __init__(self, db: Any, audit: Any, salt: bytes, home: Path, endpoints: dict[str, str] | None = None,
                 interval: float = INTERVAL_SECONDS, first_delay: float = 8.0):
        self.db, self.audit, self.salt, self.home = db, audit, salt, Path(home)
        self.ep = {**DEFAULT_ENDPOINTS, **(endpoints or {})}
        self.interval, self.first_delay = interval, first_delay
        self.open_url: Callable[[str], Any] = webbrowser.open      # replaceable (tests)
        self.run_first_check = True
        self.checking = False
        self.flow: dict[str, Any] | None = None
        self.error = ""
        self._token: tuple[str, float] | None = None
        self._run_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._secret_file = self.home / "gmail.secret"

    # -- state --
    def _state(self) -> dict[str, Any]:
        rows = self.db.query("SELECT value FROM settings WHERE key='gmail'")
        return json.loads(rows[0]["value"]) if rows else {}

    def _save(self, st: dict[str, Any]) -> None:
        self.db.set_setting("gmail", st)

    def connected(self) -> bool:
        st = self._state()
        return bool(st.get("enabled") and st.get("consented_at") and self._secret_file.exists())

    def _secrets(self) -> dict[str, str]:
        try:
            raw = json.loads(self._secret_file.read_text(encoding="utf-8"))
            return json.loads(unprotect(base64.b64decode(raw["blob"]), raw["how"]))
        except (OSError, ValueError, KeyError):
            return {}

    def _put_secrets(self, d: dict[str, str]) -> str:
        blob, how = protect(json.dumps(d).encode())
        self._secret_file.write_text(json.dumps({"how": how, "blob": base64.b64encode(blob).decode()}), encoding="utf-8")
        try:
            self._secret_file.chmod(0o600)
        except OSError:
            pass
        return how

    def status(self) -> dict[str, Any]:
        st = self._state(); on = self.connected()
        flow = self.flow if self.flow and time.time() - self.flow["started"] < FLOW_TIMEOUT else None
        return {"configured": bool(st.get("client_id")), "client_id_hint": (st.get("client_id") or "")[:12] + "…" if st.get("client_id") else "",
                "connected": on, "account": st.get("account") if on else None, "connecting": bool(flow and flow["status"] == "waiting"),
                "auth_url": flow["auth_url"] if flow and flow["status"] == "waiting" else None, "error": self.error,
                "automatic": bool(st.get("automatic")) if on else False, "consented_at": st.get("consented_at") if on else None,
                "last_check": st.get("last_check") if on else None, "last_summary": st.get("last_summary") if on else None, "checking": self.checking,
                "protected_by": st.get("protected_by"), "interval_minutes": round(self.interval / 60), "setup_steps": SETUP_STEPS, "scope": SCOPE,
                "note": "Read-only (gmail.readonly): Ultrimater cannot send, delete, move or change your mail. Message bodies and subjects are never stored, only findings."}

    # -- setup --
    def configure(self, client_id: str, client_secret: str = "") -> dict[str, Any]:
        client_id, client_secret = client_id.strip(), client_secret.strip()
        if not re.fullmatch(r"[\w.-]+\.apps\.googleusercontent\.com", client_id):
            raise ValueError("That does not look like a Google OAuth client ID (it should end in .apps.googleusercontent.com).")
        if len(client_secret) > 200:
            raise ValueError("The client secret looks too long.")
        st = self._state(); st["client_id"] = client_id; st.setdefault("enabled", False)
        sec = self._secrets() if self._secret_file.exists() else {}
        sec["client_secret"] = client_secret
        st["protected_by"] = self._put_secrets(sec) if (client_secret or sec.get("refresh_token")) else st.get("protected_by")
        self._save(st)
        self.audit.append("user", "gmail.configured", {})
        return self.status()

    def consent_details(self, automatic: bool) -> dict[str, Any]:
        return {"scope": "gmail", "label": "Gmail protection",
                "summary": "Ultrimater will sign in to your Google account (in your browser) and read your recent inbox messages to look for phishing and scams.",
                "roots": ["Your Gmail inbox: headers, text and links of messages from the last 7 days, then new ones (read-only)"], "estimate": "", "skipped": [],
                "promises": ["Read-only: the permission requested (gmail.readonly) cannot send, delete, move, label or change anything.",
                             "Message bodies and subjects are NOT stored. Only findings are kept, with short evidence excerpts and masked details.",
                             "Nothing is sent to Ultrimater, Anthropic or any server of ours: messages are analysed on this computer.",
                             "Your Google password is never seen by Ultrimater; you sign in on Google's own page.",
                             "The sign-in token is encrypted for your Windows account and deleted when you disconnect (Ultrimater also asks Google to revoke it).",
                             (f"Automatic mode: checks run at start-up and about every {round(self.interval / 60)} minutes while Ultrimater is open." if automatic else "Checks run only when you press Check now."),
                             "Google will warn that the app is unverified because you made the client ID yourself. That is expected."]}

    def connect(self, automatic: bool, consent: bool) -> dict[str, Any]:
        st = self._state()
        if not st.get("client_id"):
            raise ValueError("Add your Google client ID first.")
        if not consent:
            raise ConsentRequired("Ultrimater needs your permission to read your Gmail inbox.", self.consent_details(automatic))
        self.error = ""
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        state = secrets.token_urlsafe(24)
        guard = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def do_GET(self) -> None:
                u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
                if u.path != "/oauth/callback":
                    self.send_response(404); self.end_headers(); return
                ok = guard._finish(q, automatic, verifier, state, port)
                body = ("<h2>Ultrimater is connected to Gmail.</h2><p>You can close this tab and return to Ultrimater.</p>" if ok
                        else "<h2>Gmail was not connected.</h2><p>Return to Ultrimater to see why.</p>").encode()
                self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        redirect = f"http://127.0.0.1:{port}/oauth/callback"
        url = self.ep["auth"] + "?" + urllib.parse.urlencode({"client_id": st["client_id"], "redirect_uri": redirect, "response_type": "code", "scope": SCOPE, "state": state,
                                                              "code_challenge": challenge, "code_challenge_method": "S256", "access_type": "offline", "prompt": "consent"})
        self.flow = {"status": "waiting", "auth_url": url, "started": time.time(), "srv": srv}

        def serve() -> None:
            srv.timeout = 1
            t0 = time.time()
            while self.flow and self.flow.get("srv") is srv and self.flow["status"] == "waiting" and time.time() - t0 < FLOW_TIMEOUT:
                srv.handle_request()
            if self.flow and self.flow.get("srv") is srv and self.flow["status"] == "waiting":
                self.error = "Sign-in timed out. Press Connect to try again."
            srv.server_close()
            if self.flow and self.flow.get("srv") is srv:
                self.flow = None
        threading.Thread(target=serve, daemon=True, name="gmail-oauth").start()
        self.audit.append("user", "gmail.connect_started", {"automatic": bool(automatic)})
        try:
            self.open_url(url)
        except Exception:
            pass                                          # the UI also shows the link, so a failed auto-open is not fatal
        return self.status()

    def _post(self, url: str, data: dict[str, str]) -> dict[str, Any]:
        req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read().decode()).get("error_description") or "request refused"
            except Exception:
                msg = "request refused"
            raise GmailError(f"Google said: {msg}")
        except (urllib.error.URLError, OSError) as e:
            raise GmailError(f"Could not reach Google: {e}")

    def _finish(self, q: dict[str, list[str]], automatic: bool, verifier: str, state: str, port: int) -> bool:
        try:
            if (q.get("state") or [""])[0] != state:
                raise GmailError("The sign-in response did not match this request, so it was ignored.")
            if "error" in q:
                raise GmailError("Sign-in was cancelled or refused" + (f" ({q['error'][0][:40]})" if q["error"] else "") + ".")
            code = (q.get("code") or [""])[0]
            if not code:
                raise GmailError("No sign-in code was returned.")
            st, sec = self._state(), (self._secrets() if self._secret_file.exists() else {})
            tok = self._post(self.ep["token"], {"code": code, "client_id": st["client_id"], "client_secret": sec.get("client_secret", ""), "redirect_uri": f"http://127.0.0.1:{port}/oauth/callback",
                                                  "grant_type": "authorization_code", "code_verifier": verifier})
            if SCOPE not in str(tok.get("scope", "")):
                raise GmailError("Google did not grant read access to Gmail.")
            if not tok.get("refresh_token"):
                raise GmailError("Google did not return a long-lived sign-in. Remove Ultrimater at myaccount.google.com/permissions and connect again.")
            sec["refresh_token"] = tok["refresh_token"]
            how = self._put_secrets(sec)
            self._token = (tok["access_token"], time.time() + int(tok.get("expires_in", 3000)) - 60)
            prof = self._api("/gmail/v1/users/me/profile")
            st.update({"enabled": True, "consented_at": now_iso(), "automatic": bool(automatic), "account": str(prof.get("emailAddress", ""))[:120], "protected_by": how,
                       "last_check": None, "last_summary": None, "cursor": 0, "seen": [], "totals": {"screened": 0, "flagged": 0}})
            self._save(st)
            self.audit.append("user", "gmail.connected", {"automatic": bool(automatic), "scope": SCOPE})
            if self.flow:
                self.flow["status"] = "done"
            if automatic:
                self.start_auto()
            if self.run_first_check:
                threading.Thread(target=self._safe_check, daemon=True, name="gmail-first-check").start()
            return True
        except GmailError as e:
            self.error = str(e)
            if self.flow:
                self.flow["status"] = "failed"
            self.audit.append("system", "gmail.connect_failed", {})
            return False

    def disconnect(self) -> dict[str, Any]:
        sec = self._secrets() if self._secret_file.exists() else {}
        st = self._state()
        self._stop.set()
        self._save({"client_id": st.get("client_id"), "enabled": False})        # keep the client ID so reconnecting is one click; drop everything else
        revoked = False
        if sec.get("refresh_token"):
            try:
                self._post(self.ep["revoke"], {"token": sec["refresh_token"]}); revoked = True
            except GmailError:
                pass
        try:
            self._secret_file.unlink()
        except OSError:
            pass
        self._token = None; self.flow = None; self.error = ""
        self.audit.append("user", "gmail.disconnected", {"google_revoked": revoked})
        out = self.status(); out["google_revoked"] = revoked
        return out

    def reset(self) -> dict[str, Any]:
        """Disconnect and also forget the client ID (to switch to another Google project)."""
        self.disconnect()
        self._save({"enabled": False})
        self.audit.append("user", "gmail.client_forgotten", {})
        return self.status()

    # -- API access --
    def _access(self) -> str:
        if self._token and self._token[1] > time.time():
            return self._token[0]
        sec, st = self._secrets(), self._state()
        if not sec.get("refresh_token"):
            raise GmailError("Gmail is not connected.")
        tok = self._post(self.ep["token"], {"client_id": st.get("client_id", ""), "client_secret": sec.get("client_secret", ""), "refresh_token": sec["refresh_token"], "grant_type": "refresh_token"})
        self._token = (tok["access_token"], time.time() + int(tok.get("expires_in", 3000)) - 60)
        return self._token[0]

    def _api(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self.ep["api"] + path + ("?" + urllib.parse.urlencode(params, doseq=True) if params else "")
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self._access()}"})
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                return json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                self._token = None
                raise GmailError("Google refused access. Disconnect and connect Gmail again.")
            raise GmailError(f"Gmail returned an error ({e.code}).")
        except (urllib.error.URLError, OSError) as e:
            raise GmailError(f"Could not reach Gmail: {e}")

    # -- checking --
    def check(self) -> dict[str, Any]:
        if not self.connected():
            raise ConsentRequired("Gmail is not connected. Ultrimater needs your permission before it reads any mail.", self.consent_details(True))
        if not self._run_lock.acquire(blocking=False):
            return {"busy": True}
        self.checking = True
        try:
            st = self._state()
            after = int(st.get("cursor") or (time.time() - FIRST_WINDOW_DAYS * 86400))
            seen = set(st.get("seen", []))
            listing = self._api("/gmail/v1/users/me/messages", {"q": f"in:inbox after:{after}", "maxResults": MAX_MESSAGES_PER_CHECK})
            s = {"messages_screened": 0, "flagged": 0, "new_findings": 0, "notes": []}
            newest = after
            for ref in (listing.get("messages") or [])[:MAX_MESSAGES_PER_CHECK]:
                mid = str(ref.get("id", ""))
                if not mid or mid in seen:
                    continue
                msg = self._api(f"/gmail/v1/users/me/messages/{mid}", {"format": "full"})
                seen.add(mid); s["messages_screened"] += 1
                newest = max(newest, int(int(msg.get("internalDate", 0)) / 1000))
                text, hdr = message_text(msg)
                a = sentinel.analyze(text, self.salt, f"Gmail · from {sender_domain(hdr)}", None)
                if a.finding and a.verdict in KEEP:
                    f = a.finding
                    f.id = "fnd_g" + hashlib.sha256(f"gmail|{mid}".encode()).hexdigest()[:11]
                    f.title = ("Likely phishing email in your Gmail inbox" if a.verdict == "likely_scam" else "Suspicious email in your Gmail inbox")
                    f.recommended_actions = [a.recommended_action + " In Gmail, use ⋮ → Report phishing so Google can protect others."]
                    s["flagged"] += 1
                    if self.db.get_finding(f.id) is None:
                        s["new_findings"] += 1
                    self.db.save_finding(f)
            st = self._state()
            if st.get("enabled"):
                tot = st.get("totals") or {"screened": 0, "flagged": 0}
                tot["screened"] += s["messages_screened"]; tot["flagged"] += s["new_findings"]
                s["since_connecting"] = dict(tot)                  # a later quiet check must not hide what an earlier one found
                st.update({"last_check": now_iso(), "last_summary": s, "cursor": newest, "seen": sorted(seen)[-3000:], "totals": tot})
                self._save(st)
                self.audit.append("system", "gmail.checked", {k: v for k, v in s.items() if isinstance(v, int)})
            self.error = ""
            return s
        finally:
            self.checking = False
            self._run_lock.release()

    def _safe_check(self) -> None:
        try:
            self.check()
        except Exception as e:
            self.error = str(e)[:200]
            log.warning("gmail check failed", extra={"ctx": {"error": str(e)[:200]}})

    # -- automatic mode --
    def start_auto(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="gmail-guard")
        self._thread.start()

    def _loop(self) -> None:
        if self._stop.wait(self.first_delay):
            return
        while not self._stop.is_set():
            st = self._state()
            if st.get("enabled") and st.get("automatic") and self.connected():
                self._safe_check()
            if self._stop.wait(self.interval):
                break
