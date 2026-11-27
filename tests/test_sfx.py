import unittest
from pathlib import Path


WEB = Path(__file__).resolve().parent.parent / "panzeron" / "web" / "js"


class SoundEffectTests(unittest.TestCase):
    def test_hover_click_and_scan_sounds_are_wired(self):
        sfx = (WEB / "sfx.js").read_text(encoding="utf-8")
        app = (WEB / "app.js").read_text(encoding="utf-8")
        shield = (WEB / "pages" / "shield.js").read_text(encoding="utf-8")
        for sound in ("hover", "click", "scan", "boot"):
            self.assertIn(f"'{sound}'", sfx)
        self.assertIn("installSfx()", app)
        self.assertIn("playSfx('scan')", shield)

    def test_audio_is_local_synthesized_and_setting_gated(self):
        sfx = (WEB / "sfx.js").read_text(encoding="utf-8")
        self.assertIn("createOscillator()", sfx)
        self.assertIn("root.dataset.sound !== 'on'", sfx)
        for remote in ("fetch(", "XMLHttpRequest", "https://", "http://"):
            self.assertNotIn(remote, sfx)


if __name__ == "__main__":
    unittest.main()
