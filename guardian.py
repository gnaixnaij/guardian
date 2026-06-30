#!/usr/bin/env python3
"""
Guardian — Lightweight free EDR for small teams.
Monitor processes, files, and network. Detect threats. View in dashboard.
"""
import os
import sys
import threading
import argparse

sys.path.insert(0, os.path.dirname(__file__))

from agent.monitor import Guardian, run_agent
from dashboard.app import run as run_dashboard


def main():
    parser = argparse.ArgumentParser(description="Guardian — Free EDR")
    parser.add_argument("--headless", action="store_true", help="Run without dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Dashboard port")
    parser.add_argument("--duration", type=int, help="Run for N seconds then exit")
    args = parser.parse_args()

    print("""
    ╔══════════════════════════════╗
    ║     Guardian — Free EDR      ║
    ║  Lightweight threat detection ║
    ╚══════════════════════════════╝
    """)

    g = run_agent(duration=args.duration)

    if not args.headless and args.duration is None:
        print(f"\nStarting dashboard at http://127.0.0.1:{args.port}")
        dashboard_thread = threading.Thread(
            target=run_dashboard, args=(g,), kwargs={"port": args.port},
            daemon=True
        )
        dashboard_thread.start()

        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down")

    print(f"\nCollected {len(g.alerts)} alerts total")
    high = [a for a in g.alerts if a["severity"] == "high"]
    if high:
        print(f"⚠️  {len(high)} high-severity alerts found")


if __name__ == "__main__":
    main()
