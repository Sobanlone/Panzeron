"""PyInstaller entry point (windowed build): launches the desktop application."""
import sys
from panzeron.desktop import run

if __name__ == "__main__":
    sys.exit(run())
