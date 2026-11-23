import tempfile
from pathlib import Path
from ultrimater.app import UltrimaterApp

SALT = b"t" * 32

def new_app() -> UltrimaterApp:
    return UltrimaterApp(Path(tempfile.mkdtemp()))
