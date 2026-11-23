"""Double-click to start Ultrimater (the .pyw extension runs without a console window)."""
import sys
from ultrimater.desktop import run

if __name__ == "__main__":
    sys.exit(run())
