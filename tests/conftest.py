"""
Pytest bootstrap for standalone (no-Hermes) test runs.

Just puts the repo root on sys.path so `import hermes_bridge...` resolves.
The Hermes-core (`gateway.platforms.base`) and websockets stubs live in
test_rpc.py itself (it needs a REAL BasePlatformAdapter base class, not a
MagicMock), so they work both under pytest and when the file is run directly.
test_crypto.py imports crypto.py directly and needs no stubs at all.
"""

import os
import sys

# Make the `hermes_bridge` package importable from the repo root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
