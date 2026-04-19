#!/bin/bash
# Install vendored Python dependencies for TA-cveicu
#
# v1.1.x uses urllib3 1.26.x for Splunk 9 compatibility (OpenSSL 1.0.2)
# v2.0.x uses urllib3 2.x which requires OpenSSL 1.1.1+

set -e

LIB_DIR="$(cd "$(dirname "$0")/../TA-cveicu/bin/lib" && pwd)"

echo "Installing vendored dependencies to: $LIB_DIR"

rm -rf "$LIB_DIR"
mkdir -p "$LIB_DIR"

pip install --target="$LIB_DIR" --no-deps \
    "splunk-sdk>=2.1,<3" \
    "requests>=2.31,<3" \
    "urllib3>=1.26,<1.27" \
    "charset-normalizer>=3,<4" \
    "certifi>=2024" \
    "idna>=3,<4" \
    "deprecation>=2,<3" \
    "packaging>=24"

# Clean up unnecessary files
find "$LIB_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$LIB_DIR" -name "*.pyc" -delete 2>/dev/null || true
rm -rf "$LIB_DIR"/bin 2>/dev/null || true

echo ""
echo "Installed:"
python3 -c "
import sys; sys.path.insert(0, '$LIB_DIR')
from urllib3 import __version__ as u; print(f'  urllib3 {u}')
import requests; print(f'  requests {requests.__version__}')
import splunklib; print(f'  splunklib (splunk-sdk)')
"
echo ""
echo "Done. urllib3 1.26.x is compatible with Splunk 9's OpenSSL 1.0.2."
