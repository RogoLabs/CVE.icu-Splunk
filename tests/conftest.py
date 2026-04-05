"""Pytest configuration for TA-cveicu tests."""

import sys
from pathlib import Path

# Add TA-cveicu/bin and TA-cveicu/bin/lib to sys.path
repo_root = Path(__file__).parent.parent
bin_path = repo_root / "TA-cveicu" / "bin"
lib_path = bin_path / "lib"

sys.path.insert(0, str(bin_path))
sys.path.insert(0, str(lib_path))
