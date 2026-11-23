import json, threading, unittest, urllib.request, urllib.error
from ultrimater.api.server import create_server
from ultrimater.core.uiprefs import DEFAULTS, sanitize
from tests.helpers import new_app


class SanitizeTests(unittest.TestCase):
    def test_valid_values_pass_and_defaults_fill_the_rest(self):
        c, rej = sanitize({"accent": "#C9A45C", "blur": 12, "anim": False, "sheen": False})
        self.assertEqual((c["accent"], c["blur"], c["anim"], c["sheen"], c["bg"]), ("#c9a45c", 12, False, False, DEFAULTS["bg"])); self.assertEqual(rej, [])

    def test_css_injection_through_colour_is_rejected(self):
        for bad in ("red;background:url(//evil)", "#12345", "#gggggg", "rgb(1,2,3)", "#0a84ff;}body{display:none", 5, None, "javascript:alert(1)"):
            c, rej = sanitize({"accent": bad}); self.assertEqual(c["accent"], DEFAULTS["accent"], bad); self.assertIn("accent", rej)

    def test_numbers_are_clamped_and_non_numbers_rejected(self):
        self.assertEqual(sanitize({"blur": 9999})[0]["blur"], 40); self.assertEqual(sanitize({"blur": -5})[0]["blur"], 0)
        self.assertEqual(sanitize({"glass": 33.6})[0]["glass"], 34)
        for bad in ("12", True, [1], float("nan")): self.assertIn("blur", sanitize({"blur": bad})[1])

    def test_unknown_keys_and_bad_enums_are_dropped(self):
        c, rej = sanitize({"evil": 1, "bg": "../../x", "density": "huge", "font": "Comic Sans; x"})
        self.assertNotIn("evil", c); self.assertEqual((c["bg"], c["density"], c["font"]), (DEFAULTS["bg"], DEFAULTS["density"], DEFAULTS["font"])); self.assertEqual(sorted(rej), ["bg", "density", "evil", "font"])

    def test_light_mode_no_longer_exists(self):
        self.assertNotIn("mode", DEFAULTS)
        c, rej = sanitize({"mode": "light"}); self.assertNotIn("mode", c); self.assertEqual(rej, ["mode"])   # old saved/imported themes are ignored safely

    def test_removed_decorations_are_gone(self):
        for k in ("radius", "hud", "grid", "grain", "motion", "mode"):
            self.assertNotIn(k, DEFAULTS); self.assertIn(k, sanitize({k: True})[1])

    def test_non_object_input(self):
        for bad in (None, [], "x", 3): self.assertEqual(sanitize(bad)[0], DEFAULTS)


class PrefsApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = new_app(); cls.srv, cls.tok = create_server(cls.app, 0); cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()

    def call(self, m, body=None):
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/ui-prefs", method=m, headers={"X-Session-Token": self.tok}, data=json.dumps(body).encode() if body is not None else None)
        with urllib.request.urlopen(r) as x: return json.loads(x.read())

    def test_roundtrip_persist_and_reset(self):
        self.assertIsNone(self.call("GET")["prefs"])
        out = self.call("PUT", {"accent": "#2fb872", "density": "compact", "evil": "x"})
        self.assertEqual(out["rejected"], ["evil"]); self.assertEqual(self.call("GET")["prefs"]["accent"], "#2fb872")
        self.assertEqual(self.call("GET")["prefs"]["density"], "compact")
        self.assertEqual(self.call("GET")["defaults"], DEFAULTS)
        self.call("DELETE"); self.assertIsNone(self.call("GET")["prefs"])

    def test_survives_restart(self):
        self.app.set_ui_prefs({"bg": "crimson"}); from ultrimater.app import UltrimaterApp
        again = UltrimaterApp(self.app.paths.home); self.assertEqual(again.get_ui_prefs()["bg"], "crimson")
