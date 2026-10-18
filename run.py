"""Launch with /usr/bin/python3 -I run.py from the reviewed source tree."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from skidplate.ui import main

if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        raise SystemExit(f"Skidplate: {error}") from None
