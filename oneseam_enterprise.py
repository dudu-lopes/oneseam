"""
Compatibility launcher.

Use `python oneseam.py` as the primary entrypoint.
This file remains for backward compatibility with older scripts.
"""

from pathlib import Path
import runpy
import sys

if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).with_name("oneseam.py")), run_name="__main__")
else:
    import oneseam as _oneseam
    sys.modules[__name__] = _oneseam
