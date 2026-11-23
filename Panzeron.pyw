"""Double-click to start Panzeron (the .pyw extension runs without a console window)."""
import sys
from panzeron.desktop import run

if __name__ == "__main__":
    sys.exit(run())
