#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_all.py — launch the scoreboard + every implemented challenge together.
Each challenge runs in its own process on its own port. Ctrl+C stops all.
"""
import os, sys, subprocess, glob, time

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def main():
    procs = []
    # scoreboard first
    procs.append(subprocess.Popen([PY, os.path.join(ROOT, "index.py")]))
    # every challenge that has an app.py
    for app in sorted(glob.glob(os.path.join(ROOT, "challenges", "*", "app.py"))):
        procs.append(subprocess.Popen([PY, app]))
        time.sleep(0.15)

    print("\n" + "=" * 54)
    print("  Web App Pentesting CTF is running")
    print("  Scoreboard:  http://127.0.0.1:8000")
    print("  Stop all:    Ctrl+C")
    print("=" * 54 + "\n")
    try:
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        print("\nStopping all challenges...")
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
