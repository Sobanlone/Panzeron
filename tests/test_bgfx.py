"""Static checks for the per-theme live backgrounds (js/bgfx.js): every theme has an effect (except Solid), and the effect code stays
self-contained, honours the animation switch, reduced motion and hidden tabs, and never touches the network or storage."""
import re
import unittest
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "panzeron" / "web" / "js"


class BackgroundEffectTests(unittest.TestCase):
    def setUp(self):
        self.fx = (WEB / "bgfx.js").read_text(encoding="utf-8")
        self.ap = (WEB / "appearance.js").read_text(encoding="utf-8")

    def test_every_theme_has_an_effect_and_a_name(self):
        themes = re.findall(r"^  (\w+): \{ label: '[^']+', fx: '([^']+)', opacities:", self.ap, re.M)
        ids = re.findall(r"^  (\w+): \{ label: '[^']+', fx: '", self.ap, re.M)
        self.assertEqual(set(ids), {"royal", "midnight", "ocean", "emerald", "crimson", "graphite", "solid"})
        table = re.search(r"const EFFECTS = \{([^}]*)\}", self.fx).group(1)
        for t in ids:
            if t != "solid":
                self.assertRegex(table, rf"\b{t}:", f"{t} has no effect")
        self.assertNotRegex(table, r"\bsolid:")               # Solid stays perfectly still

    def test_emerald_is_matrix_code(self):
        self.assertRegex(self.fx, r"emerald: matrix")
        self.assertIn("ｱｲｳ", self.fx)

    def test_effects_use_the_current_accent(self):
        self.assertIn("rgba(cfg.rgb", self.fx)
        self.assertIn("tint(cfg.rgb)", self.fx)
        for fixed in ("52,224,128", "220,255,232", "205,222,255", "150,215,255", "255,214,120", "190,200,220"):
            self.assertNotIn(fixed, self.fx)
        self.assertIn("gridRgb !== cfg.rgb.join(',')", self.fx)
        self.assertIn("opacities:", self.ap)
        self.assertIn("rgba(${rgb.join(',')},${a})", self.ap)

    def test_effects_are_self_contained(self):
        for banned in ("fetch(", "XMLHttpRequest", "sessionStorage", "WebSocket", "eval(", "new Function", "import("):
            self.assertNotIn(banned, self.fx)
        # the only thing it may store is the user's own "play despite Windows reduce-motion" choice
        for call in re.findall(r"localStorage\.\w+\(([^)]*)\)", self.fx):
            self.assertTrue(call.strip().startswith("FORCE"), call)

    def test_respects_user_and_system_settings(self):
        self.assertIn("prefers-reduced-motion", self.fx)
        self.assertIn("document.hidden", self.fx)
        self.assertIn("cfg.anim", self.fx)
        self.assertIn("setBackgroundEffect(", self.ap)


if __name__ == "__main__":
    unittest.main()
