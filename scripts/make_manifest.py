"""Writes MANIFEST.sha256 for an Panzeron folder (run when packaging; the Windows build scripts do this automatically).
Usage: python scripts/make_manifest.py [folder]    (default: the project folder)"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from panzeron.shield.trust import TrustStore

root = Path(sys.argv[1]) if len(sys.argv) > 1 else None
ts = TrustStore(root)
print(f"Wrote {ts.manifest_path} ({ts.rebuild()} files)")
