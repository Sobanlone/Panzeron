import tempfile
from pathlib import Path
from panzeron.app import PanzeronApp

SALT = b"t" * 32

def new_app() -> PanzeronApp:
    return PanzeronApp(Path(tempfile.mkdtemp()))
