"""Static checks for the 3D Matrix-code dragon in the startup intro (js/matrix-dragon.js)."""
import re
import unittest
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "panzeron" / "web"


class MatrixDragonTests(unittest.TestCase):
    def setUp(self):
        self.js = (WEB / "js" / "matrix-dragon.js").read_text(encoding="utf-8")
        self.boot = (WEB / "js" / "boot.js").read_text(encoding="utf-8")
        self.html = (WEB / "index.html").read_text(encoding="utf-8")
        self.css = (WEB / "css" / "app.css").read_text(encoding="utf-8")

    def test_wired_into_the_intro_with_a_fallback(self):
        self.assertIn("matrix-dragon.js", self.boot)
        self.assertIn("stopDragon()", self.boot)                       # it is stopped when the intro ends
        self.assertIn(".catch(", self.boot)                            # if it cannot start the plain CSS dragon stays
        self.assertIn("#boot.mx .boot-orbit{display:none}", self.css)  # only hidden once the code dragon is actually running
        self.assertIn('class="boot-orbit"', self.html)

    def test_dragon_passes_behind_and_in_front_of_the_ball(self):
        self.assertRegex(self.html, r'bo-cv back[^>]*></canvas>\s*<svg')                     # canvas under the ball
        self.assertRegex(self.html, r'<b class="ball"></b>\s*<canvas class="bo-cv front"')   # canvas over the ball
        self.assertIn("zc < 0 ? bx : fx", self.js)

    def test_true_3d_with_perspective(self):
        for needle in ("D / (D - zc)", "const bank", "const cam", "Math.sin(phi)", "Math.cos(phi)"):
            self.assertIn(needle, self.js)

    def test_it_swims_like_a_fish_with_a_straight_body(self):
        self.assertIn("function spine(", self.js)                       # a straight centre line plus a travelling wave...
        self.assertIn("Math.pow(u, 2.2)", self.js)                       # ...that grows toward the tail, so the tail flaps
        self.assertRegex(self.js, r"NOSE - L \* u")                      # the body itself is a straight line along x
        for part in ("'horn'", "'jaw'", "'spike'", "'wing'", "'fin'", "'leg'", "'eye'"):
            self.assertIn(part, self.js)                                 # a real dragon: horns, jaws, crest, wings, tail fin, legs, eyes
        self.assertIn("TAU * 0.62 * t - 1.7 * a", self.js)               # wingbeat with the tips lagging behind the roots

    def test_calm_mode_is_a_still_frame(self):
        self.assertIn("if (calm) frame(0, 0)", self.js)

    def test_dragon_and_code_rain_use_the_accent(self):
        self.assertIn("getPropertyValue('--accent')", self.js)
        self.assertIn("getPropertyValue('--accent-hi')", self.js)
        self.assertNotIn("rgb(46,232,124)", self.js)
        self.assertNotIn("rgba(34,200,108", self.js)

    def test_self_contained(self):
        for banned in ("fetch(", "XMLHttpRequest", "localStorage", "sessionStorage", "WebSocket", "eval(", "new Function"):
            self.assertNotIn(banned, self.js)
        self.assertNotIn("new Image", self.js)                            # nothing is loaded at all: the dragon is generated


if __name__ == "__main__":
    unittest.main()
