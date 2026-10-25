#!/usr/bin/env python3
"""
Standalone launcher for PacketSentinel (used both directly from Python and as PyInstaller entrypoint).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure companion/ directory is always on sys.path regardless of CWD
COMPANION_DIR = Path(__file__).resolve().parent
if str(COMPANION_DIR) not in sys.path:
    sys.path.insert(0, str(COMPANION_DIR))

from packetsentinel.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
