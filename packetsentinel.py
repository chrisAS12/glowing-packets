#!/usr/bin/env python3
"""
Root-level convenience launcher for PacketSentinel in prod-app.
Allows executing directly from the prod-app directory:
    python packetsentinel.py --ui
"""

from __future__ import annotations

import sys
from pathlib import Path

COMPANION_DIR = Path(__file__).resolve().parent / "companion"
if str(COMPANION_DIR) not in sys.path:
    sys.path.insert(0, str(COMPANION_DIR))

from packetsentinel.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
