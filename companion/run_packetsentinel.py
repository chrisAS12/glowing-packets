#!/usr/bin/env python3
"""
Standalone launcher for PacketSentinel (used both directly from Python and as PyInstaller entrypoint).
"""

from __future__ import annotations

import sys
from packetsentinel.cli import main

if __name__ == "__main__":
    sys.exit(main())
