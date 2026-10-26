"""Start CyberAudit Monitor on http://127.0.0.1:5000

Usage:
    python run.py              start the server (creates and seeds the database on first run)
    python run.py --reset-db   delete the local database and re-create the demo data, then start
"""
import argparse
import os
import sys

from app.config import Config


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberAudit Monitor")
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind (default 127.0.0.1, local only)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--reset-db", action="store_true", help="delete the database and re-seed demo data")
    args = parser.parse_args()

    if args.reset_db:
        for suffix in ("", "-wal", "-shm"):
            path = Config.DATABASE + suffix
            if os.path.exists(path):
                os.remove(path)
        print("Database removed; demo data will be re-created.")

    from app import create_app
    print("Preparing CyberAudit Monitor (the first start seeds about 2,000 demo records)...")
    app = create_app()
    print(f"\n  CyberAudit Monitor is running:  http://{args.host}:{args.port}\n  Press Ctrl+C to stop.\n")
    app.run(host=args.host, port=args.port, debug=False, threaded=True, use_reloader=False)


if __name__ == "__main__":
    sys.exit(main())
