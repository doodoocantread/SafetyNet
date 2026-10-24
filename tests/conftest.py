"""Shared test setup.

The hackingBuddy translator ships inside the agent image (it runs in the
container, not in the host app), so make that package importable for the unit
tests that exercise it — without installing the whole hackingBuddy stack.
"""

import sys
from pathlib import Path

_HB_IMAGE = Path(__file__).resolve().parents[1] / "agent_image_hackingbuddy"
if str(_HB_IMAGE) not in sys.path:
    sys.path.insert(0, str(_HB_IMAGE))
