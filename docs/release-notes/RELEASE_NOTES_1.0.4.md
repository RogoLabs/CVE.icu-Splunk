## 1.0.4 — April 14, 2026

### Data Input Renamed to "cve.icu"

The modular input now appears as **cve.icu** in Settings > Data Inputs, matching the app's branding and documentation.

Previously, the data input was registered as "CVE List V5", which caused confusion for users who couldn't find it after installation. This was reported by users following the setup documentation that referenced "cve.icu" by name.

### What Changed

- Renamed modular input scheme title from "CVE List V5" to "cve.icu"
- Updated README documentation to match

### Upgrade Notes

- No configuration changes required — existing inputs will continue to work
- After upgrading, the input type will appear as "cve.icu" instead of "CVE List V5" in Settings > Data Inputs

### Testing

- Added integration test suite for add-on installation validation (`tests/integration/test_addon_install.py`)
- Added `test.sh` convenience script for running unit, integration, and package tests
- Passes Splunk AppInspect precert with 0 errors, 0 failures
