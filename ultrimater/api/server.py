"""Local HTTP API + static UI (standard library only: zero install friction).

Security model
  * Binds to 127.0.0.1 only.
  * Every /api request needs the per-launch session token (X-Session-Token). The token is injected into the page
    served from this same origin; there is no CORS header, so other websites cannot read responses or obtain it.
  * The Host header must be a loopback name (blocks DNS-rebinding).
  * Request bodies are size-limited. JSON is validated. Errors return JSON, details go to the structured log.
"""
from __future__ import annotations

import hmac
import json
import mimetypes
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .. import autostart, demo
from ..app import UltrimaterApp
from ..core.log import get_logger
from ..core.uiprefs import DEFAULTS as UI_DEFAULTS
from ..response.service import ActionError
from ..shield import defender
from ..shield.quarantine import ConfirmationRequired, QuarantineError

log = get_logger("api")
WEB_DIR = Path(__file__).resolve().parent.parent / "web"  # also correct inside a PyInstaller bundle (data added at ultrimater/web)
MAX_JSON = 2 * 1024 * 1024
MAX_UPLOAD = 25 * 1024 * 1024
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


class ApiError(Exception):
    def __init__(self, status: int, message: str, extra: dict[str, Any] | None = None):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra or {}


def make_handler(app: UltrimaterApp, token: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Ultrimater"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # route access logs to structured logging
            log.info(fmt % args)

        # ---- plumbing ---------------------------------------------------------------------------------
        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0] if not (self.headers.get("Host") or "").startswith("[") \
                else (self.headers.get("Host") or "").split("]")[0] + "]"
            return host in ALLOWED_HOSTS

        def _send(self, status: int, body: bytes, ctype: str, extra_headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, obj: Any) -> None:
            self._send(status, json.dumps(obj, default=str).encode("utf-8"), "application/json; charset=utf-8")

        def _read_all_body(self, path: str) -> None:
            """Always consume the request body (keep-alive safety) and enforce size limits before routing."""
            n = int(self.headers.get("Content-Length") or 0)
            limit = MAX_UPLOAD if path == "/api/vision/upload" else MAX_JSON
            if n > limit:
                self.close_connection = True
                raise ApiError(413, f"Request body exceeds {limit // (1024 * 1024)} MB limit")
            self._raw = self.rfile.read(n) if n else b""

        def _body(self, limit: int) -> bytes:
            return self._raw

        def _json_body(self) -> dict[str, Any]:
            raw = self._raw
            if not raw:
                return {}
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as e:
                raise ApiError(400, f"Invalid JSON: {e}")
            if not isinstance(obj, dict):
                raise ApiError(400, "JSON body must be an object")
            return obj

        def _dispatch(self, method: str) -> None:
            self._raw = b""
            try:
                if not self._host_ok():
                    raise ApiError(403, "Invalid Host header")
                u = urlparse(self.path)
                if not u.path.startswith("/api/"):
                    if method != "GET":
                        raise ApiError(405, "Method not allowed")
                    return self._static(u.path)
                supplied = self.headers.get("X-Session-Token", "")
                if not hmac.compare_digest(supplied, token):
                    raise ApiError(401, "Missing or invalid session token")
                if method in ("POST", "PUT", "DELETE") and self.headers.get("Sec-Fetch-Site") == "cross-site":
                    raise ApiError(403, "Cross-site requests are refused")
                self._read_all_body(u.path)
                result = self._route(method, u.path, parse_qs(u.query))
                self._json(200, result)
            except ApiError as e:
                self._json(e.status, {"error": e.message, **e.extra})
            except ConfirmationRequired as e:
                body = {"error": "confirmation_required", "message": str(e)}
                if getattr(e, "details", None):
                    body["details"] = e.details
                self._json(409, body)
            except (ActionError, QuarantineError, ValueError) as e:
                self._json(400, {"error": str(e)})
            except Exception:  # never leak internals; full detail goes to the log
                log.exception("unhandled error", extra={"ctx": {"path": self.path}})
                self._json(500, {"error": "Internal error. See the application log for details."})

        def do_GET(self) -> None: self._dispatch("GET")
        def do_POST(self) -> None: self._dispatch("POST")
        def do_PUT(self) -> None: self._dispatch("PUT")
        def do_DELETE(self) -> None: self._dispatch("DELETE")

        # ---- static -----------------------------------------------------------------------------------
        def _static(self, path: str) -> None:
            rel = "index.html" if path in ("/", "") else path.lstrip("/")
            target = (WEB_DIR / rel).resolve()
            if WEB_DIR.resolve() not in target.parents and target != WEB_DIR.resolve():
                raise ApiError(404, "Not found")
            if not target.is_file():
                raise ApiError(404, "Not found")
            data = target.read_bytes()
            if target.name == "index.html":
                data = data.replace(b"__SESSION_TOKEN__", token.encode())
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if target.suffix == ".js":
                ctype = "text/javascript"
            self._send(200, data, ctype + ("; charset=utf-8" if ctype.startswith("text/") else ""))

        # ---- routes -----------------------------------------------------------------------------------
        def _route(self, method: str, path: str, q: dict[str, list[str]]) -> Any:
            m = re.fullmatch
            if method == "GET":
                if path == "/api/status": return app.status()
                if path == "/api/findings":
                    fs = app.db.list_findings(status=(q.get("status") or [None])[0], module=(q.get("module") or [None])[0])
                    return {"findings": [f.to_dict() for f in fs]}
                if path == "/api/findings/search":
                    g = lambda k, d="": (q.get(k) or [d])[0]
                    lst = lambda k: [x for x in g(k).split(",") if x] or None
                    return app.search_findings(q=g("q"), severities=lst("severity"), modules=lst("module"), status=g("status", "open"), sort=g("sort", "severity"),
                                               offset=int(g("offset", "0") or 0), limit=int(g("limit", "50") or 50))
                if (mm := m(r"/api/findings/([\w-]+)", path)):
                    f = app.db.get_finding(mm.group(1))
                    if not f: raise ApiError(404, "Finding not found")
                    return {"finding": f.to_dict(), "actions": app.response.available_actions(f)}
                if path == "/api/graph": return app.graph()
                if path == "/api/scans": return {"scans": app.scan_history(100)}
                if (mm := m(r"/api/scan/([\w-]+)", path)):
                    s = app.scan_status(mm.group(1))
                    if s is None: raise ApiError(404, "Scan not found")
                    return s
                if path == "/api/actions": return {"actions": app.response.history()}
                if path == "/api/quarantine": return {"items": app.vault.list()}
                if path == "/api/exclusions": return {"exclusions": app.db.list_exclusions()}
                if path == "/api/audit": return {"entries": app.audit.entries(int((q.get("limit") or ["200"])[0])), "verification": app.audit.verify()}
                if path == "/api/settings": return {"settings": app.settings(), "unimplemented": app.status()["unimplemented"]}
                if path == "/api/defender": return app.defender_info(refresh=(q.get("refresh") or ["0"])[0] == "1")
                if path == "/api/summary": return app.summary()
                if path == "/api/scopes": return {"scopes": app.scope_plans()}
                if path == "/api/hashlist": return app.hashlists.summary()
                if path == "/api/rules": return app.rules_info()
                if path == "/api/integrity": return app.integrity()
                if path == "/api/diagnostics": return app.diagnostics_status()
                if path == "/api/watcher": return app.watcher_status()
                if path == "/api/browser": return app.browser_status()
                if path == "/api/gmail": return app.gmail_status()
                if path == "/api/ui-prefs": return {"prefs": app.get_ui_prefs(), "defaults": UI_DEFAULTS}
                if path == "/api/report": return app.export_report()
                if path == "/api/autostart": return autostart.status()
            elif method == "POST":
                if path == "/api/scan":
                    b = self._json_body()
                    scope = b.get("scope")
                    if scope is not None and scope not in ("quick", "user", "computer"):
                        raise ApiError(400, "scope must be quick, user or computer")
                    paths = b.get("paths") if isinstance(b.get("paths"), list) else [b.get("path", "")]
                    return app.start_scan([str(x) for x in paths[:20]] if not scope else None, scope, b.get("consent") is True, b.get("mode"))
                if path == "/api/pick":
                    b = self._json_body()
                    return app.pick(str(b.get("kind", "file")), str(b.get("title", "Choose"))[:80], str(b.get("filter", "all")))
                if path == "/api/diagnostics/run":
                    return app.start_diagnostics()
                if path == "/api/integrity/rebuild":
                    return app.integrity_rebuild(self._json_body().get("confirm") is True)
                if path == "/api/shield/system-check":
                    return app.system_check()
                if path == "/api/hashlist":
                    return app.import_hashlist(str(self._json_body().get("path", "")))
                if path == "/api/watcher":
                    b = self._json_body()
                    return app.set_watcher(b.get("enabled") is True, [str(x) for x in b.get("paths", [])][:10] if isinstance(b.get("paths"), list) else None, b.get("consent") is True)
                if path == "/api/gmail":
                    b = self._json_body()
                    return app.gmail_access(str(b.get("action", "")), str(b.get("client_id", ""))[:200], str(b.get("client_secret", ""))[:300], b.get("automatic") is not False, b.get("consent") is True)
                if path == "/api/browser":
                    b = self._json_body()
                    caps = [str(x) for x in b["caps"]][:8] if isinstance(b.get("caps"), list) else None
                    return app.browser_access(str(b.get("action", "")), str(b["browser"])[:20] if isinstance(b.get("browser"), str) else None, caps, b.get("automatic") is not False, b.get("consent") is True)
                if path == "/api/findings/bulk":
                    b = self._json_body()
                    return app.bulk_status(str(b.get("action", "")), [str(i) for i in b["ids"]][:5000] if isinstance(b.get("ids"), list) else None, b.get("filter") if isinstance(b.get("filter"), dict) else None)
                if path == "/api/quarantine/bulk":
                    b = self._json_body()
                    ids = b.get("finding_ids") if isinstance(b.get("finding_ids"), list) else []
                    return app.quarantine_findings([str(i) for i in ids], b.get("confirm") is True)
                if (mm := m(r"/api/scan/([\w-]+)/cancel", path)):
                    return {"cancelled": app.cancel_scan(mm.group(1))}
                if path == "/api/defender/scan":
                    b = self._json_body()
                    if b.get("confirm") is not True: raise ConfirmationRequired("Ask Windows Defender to scan this path. This may require administrator rights.")
                    app.audit.append("user", "defender.scan_requested", {"path": str(b.get("path", ""))})
                    return defender.start_scan(str(b.get("path", "")))
                if path == "/api/vision/upload":
                    name = self.headers.get("X-Filename", "upload.bin")
                    data = self._body(MAX_UPLOAD)
                    if not data: raise ApiError(400, "Empty upload")
                    return app.analyze_upload(name, data)
                if path == "/api/vision/path":
                    return app.analyze_path(str(self._json_body().get("path", "")))
                if path == "/api/vision/text":
                    b = self._json_body()
                    return app.analyze_pasted_text(str(b.get("text", "")), str(b.get("name", "pasted text")))
                if path == "/api/sentinel/analyze":
                    b = self._json_body()
                    return app.analyze_message(str(b.get("text", "")), b.get("label"), bool(b.get("use_ai", True)))
                if (mm := m(r"/api/findings/([\w-]+)/action", path)):
                    b = self._json_body()
                    return app.response.execute(str(b.get("type", "")), mm.group(1), b.get("confirm") is True)
                if (mm := m(r"/api/quarantine/([\w-]+)/restore", path)):
                    return app.response.restore_quarantined(mm.group(1), self._json_body().get("confirm") is True)
                if path == "/api/exclusions":
                    b = self._json_body()
                    kind, pat = str(b.get("kind", "path")), str(b.get("pattern", "")).strip()
                    if kind not in ("path", "hash") or not pat: raise ApiError(400, "kind must be 'path' or 'hash' and pattern is required")
                    app.db.add_exclusion(kind, pat, str(b.get("note", "")))
                    app.audit.append("user", "exclusion.added", {"kind": kind, "pattern": pat})
                    return {"exclusions": app.db.list_exclusions()}
                if path == "/api/demo/load":
                    return demo.load_demo(app)
                if path == "/api/privacy/clear":
                    if self._json_body().get("confirm") is not True: raise ConfirmationRequired("Delete all recorded findings from the local database? Files are not touched.")
                    app.wipe_findings()
                    return {"cleared": True}
            elif method == "PUT":
                if path == "/api/ui-prefs":
                    clean, rejected = app.set_ui_prefs(self._json_body())
                    return {"prefs": clean, "rejected": rejected}
                if path == "/api/settings":
                    return {"settings": app.update_settings(self._json_body())}
                if path == "/api/autostart":
                    want = self._json_body().get("enabled")
                    if not isinstance(want, bool): raise ApiError(400, "enabled must be true or false")
                    try: st = autostart.set_enabled(want)
                    except (RuntimeError, OSError) as e: raise ApiError(400, str(e))
                    app.audit.append("user", "autostart.enabled" if want else "autostart.disabled", {})
                    return st
            elif method == "DELETE":
                if path == "/api/demo":
                    return demo.clear_demo(app)
                if path == "/api/hashlist":
                    app.clear_hashlist()
                    return app.hashlists.summary()
                if path == "/api/ui-prefs":
                    app.reset_ui_prefs()
                    return {"prefs": None, "defaults": UI_DEFAULTS}
                if (mm := m(r"/api/exclusions/(\d+)", path)):
                    app.db.remove_exclusion(int(mm.group(1)))
                    app.audit.append("user", "exclusion.removed", {"id": int(mm.group(1))})
                    return {"exclusions": app.db.list_exclusions()}
            raise ApiError(404, "Unknown endpoint")

    return Handler


def create_server(app: UltrimaterApp, port: int = 8765) -> tuple[ThreadingHTTPServer, str]:
    token = secrets.token_urlsafe(32)
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, token))
    return srv, token


def serve(app: UltrimaterApp, port: int = 8765, open_browser: bool = True) -> None:
    srv, token = create_server(app, port)
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    log.info(f"Ultrimater listening on {url} (loopback only)")
    print(f"\n  Ultrimater is running at {url}\n  Data stays on this device. Press Ctrl+C to stop.\n")
    if open_browser:
        import webbrowser
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
