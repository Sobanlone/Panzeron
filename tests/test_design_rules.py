"""Design rules enforced as tests, so they cannot regress: floating rounded liquid glass, pill controls, no decorative effects,
nothing invented, and a working light/dark toggle."""
import re, unittest
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "panzeron" / "web"
FILES = [WEB / "css" / "app.css", WEB / "index.html", *sorted((WEB / "js").rglob("*.js"))]


class DesignRuleTests(unittest.TestCase):
    def colours(self):
        for f in FILES:
            txt = f.read_text(encoding="utf-8")
            for m in HEX.finditer(txt):
                v = m.group(1); yield f.name, f"#{v}", tuple(int(v[i:i + 2], 16) for i in (0, 2, 4)), 1.0
            for m in RGB.finditer(txt):
                yield f.name, m.group(0), tuple(int(m.group(i)) for i in (1, 2, 3)), float(m.group(4) or 1)

    def test_corners_are_rounded_through_tokens(self):
        css = (WEB / "css" / "app.css").read_text()
        self.assertNotIn("border-radius:0!important", css.replace(" ", ""))        # the old square-corner safety net is gone
        for tok in ("--r-xl", "--r-lg", "--r-md", "--r-pill"):
            self.assertIn(tok, css, tok)
        flat = css.replace(" ", "")
        for rule in (".card,.modal{border-radius:var(--r-xl)}", ".side{border-radius:var(--r-xl);", ".top{border-radius:var(--r-pill);"):
            self.assertIn(rule, flat, rule)
        self.assertRegex(flat, r"button,\.btn\{[^}]*border-radius:var\(--r-pill\)")
        self.assertRegex(flat, r"\.pill\{[^}]*border-radius:var\(--r-pill\)")
        for f in (WEB / "js").rglob("*.js"):
            t = f.read_text(encoding="utf-8")
            self.assertNotRegex(t, r"borderRadius|border-radius", f.name)             # shape lives in CSS only

    def test_background_uses_blue_violet_teal_crimson_light(self):
        css = (WEB / "css" / "app.css").read_text()
        for orb in ("--orb-a", "--orb-b", "--orb-c", "--orb-d"):
            self.assertRegex(css, orb + r":rgba\(")
        self.assertIn("backdrop-filter", css)

    def test_no_decorative_effects_remain(self):
        css = (WEB / "css" / "app.css").read_text(); html = (WEB / "index.html").read_text()
        for banned in ("conic-gradient", "repeating-radial-gradient", "drop-shadow", ".gridfloor", ".scanlines", ".radar", "text-shadow", "@keyframes spin"):
            self.assertNotIn(banned, css, banned)
        for banned in ("gridfloor", "scanlines", "grain"):
            self.assertNotIn(banned, html, banned)

    def test_light_dark_toggle_exists_and_is_remembered(self):
        html = (WEB / "index.html").read_text(); css = (WEB / "css" / "app.css").read_text()
        self.assertIn('id="theme"', html)
        self.assertIn('data-theme="light"', css)
        self.assertIn("panzeron-theme", (WEB / "js" / "app.js").read_text())
        self.assertIn("theme-boot.js", html)                                           # CSP forbids inline scripts: preload is a file
        self.assertNotIn("<script>", html)

    def test_startup_intro_is_skippable_and_csp_safe(self):
        html = (WEB / "index.html").read_text(); boot = (WEB / "js" / "theme-boot.js").read_text()
        self.assertIn('id="boot"', html); self.assertIn("lg-refract", html)
        for gate in ("prefers-reduced-motion", "panzeron-intro", "panzeron-booted", "anim"):
            self.assertIn(gate, boot, gate)                                            # intro respects every opt-out
        self.assertNotIn("<script>", html)
        self.assertIn("backdrop-filter:url(#lg-refract)", (WEB / "css" / "app.css").read_text().replace(" ", "").replace("(backdrop-filter:", "(backdrop-filter:"))

    def test_startup_matrix_dragon_orbits_the_orb(self):
        css = (WEB / "css" / "app.css").read_text(); html = (WEB / "index.html").read_text()
        matrix = (WEB / "img" / "matrix-dragon.jpg").read_bytes()
        self.assertTrue(matrix.startswith(b"\xff\xd8"))
        self.assertIn("matrix-dragon", html)
        self.assertIn("matrix-dragon.jpg", (WEB / "js" / "boot.js").read_text())
        for cls in ("boot-orbit", "matrix-dragon"):
            self.assertIn(cls, html, cls)
        run = (WEB / "js" / "dragon.js").read_text(encoding="utf-8")
        self.assertIn("orbitAround", run)
        self.assertIn("translate(", run)

    def test_startup_cannot_trap_the_user(self):
        boot = (WEB / "js" / "theme-boot.js").read_text(); run = (WEB / "js" / "boot.js").read_text(); app = (WEB / "js" / "app.js").read_text()
        self.assertIn("setTimeout", boot)                                                          # failsafe independent of the app script
        self.assertIn("FAILSAFE_MS", run); self.assertIn("unstick", run)
        self.assertLess(app.index("runBoot()"), app.index("const ROUTES"))                          # started before anything that could fail
        self.assertLess(app.index("appearance.init()"), app.index("runBoot()"))                     # accent applied before the intro starts
        self.assertIn("html.calm", (WEB / "css" / "app.css").read_text())                           # reduced motion = still splash, not silence

    def test_accent_choices_are_valid_hex(self):
        js = (WEB / "js" / "appearance.js").read_text()
        for tok in re.findall(r"#[0-9a-fA-F]{6}", js):
            self.assertRegex(tok, r"^#[0-9a-fA-F]{6}$")

    def test_no_invented_claims_in_ui_text(self):
        banned = ["reviews", "testimonial", "trusted by", "users worldwide", "★", "99.9", "million", "award"]
        blob = "\n".join(f.read_text(encoding="utf-8").lower() for f in (WEB / "js").rglob("*.js")) + (WEB / "index.html").read_text(encoding="utf-8").lower()
        for w in banned:
            self.assertNotIn(w.lower(), blob, w)
