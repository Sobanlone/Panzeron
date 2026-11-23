"""Panzeron entry point.
  python -m panzeron                 desktop window (default)
  python -m panzeron --server-only   engine + default browser tab (developer mode)
"""
import argparse
import sys


def main() -> None:
    ap = argparse.ArgumentParser(prog="panzeron")
    ap.add_argument("--server-only", action="store_true", help="developer mode: serve on localhost and open the default browser")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true", help="with --server-only: do not open a browser")
    args = ap.parse_args()
    if args.server_only:
        from .api.server import serve
        from .app import PanzeronApp
        from .core.config import Paths
        from .core.log import setup_logging
        paths = Paths.create()
        setup_logging(paths.logs)
        serve(PanzeronApp(paths.home), args.port, not args.no_browser)
    else:
        from .desktop import run
        sys.exit(run(port=args.port))


if __name__ == "__main__":
    main()
