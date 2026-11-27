"""Panzeron entry point.
  python -m panzeron                 desktop window (default)
  python -m panzeron --background    start in the system tray
  python -m panzeron --quit          quit a running instance
  python -m panzeron --server-only   engine + default browser tab (developer mode)
"""
import argparse
import sys


def main() -> None:
    ap = argparse.ArgumentParser(prog="panzeron")
    ap.add_argument("--server-only", action="store_true", help="developer mode: serve on localhost and open the default browser")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true", help="with --server-only: do not open a browser")
    ap.add_argument("--background", action="store_true", help="start in the system tray without opening a window")
    ap.add_argument("--quit", action="store_true", help="quit a running Panzeron from another process")
    args = ap.parse_args()
    if args.quit:
        from .tray import request_quit
        request_quit()
    elif args.server_only:
        from .api.server import serve
        from .app import PanzeronApp
        from .core.config import Paths
        from .core.log import setup_logging
        paths = Paths.create()
        setup_logging(paths.logs)
        serve(PanzeronApp(paths.home), args.port, not args.no_browser)
    else:
        from .desktop import run
        sys.exit(run(port=args.port, background=args.background))


if __name__ == "__main__":
    main()
