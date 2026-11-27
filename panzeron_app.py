"""PyInstaller entry point (windowed build): launches the desktop application."""
import sys
from panzeron.desktop import main

if __name__ == "__main__":
    sys.exit(main())
