# TA-cveicu v1.0.6 Release Notes

**Release Date:** April 14, 2026

## Bug Fixes

### Fixed: Modular input still fails to register on some systems (exit code 1)

Version 1.0.5 added a fallback for `--scheme` introspection when `splunklib` could not be imported. However, the fallback was placed at the bottom of the script in `__main__`, which was never reached because the script crashed during module-level imports before getting there. Specifically, `github_client.py` imports `requests`, which imports `urllib3`, which requires SSL shared libraries (e.g., `libssl.so.3`). On systems where those libraries are missing from the Python environment Splunk uses for introspection, the entire script would fail at import time.

The `--scheme` handler is now the very first thing that runs after `sys.path` setup, before any imports that could fail. This guarantees the modular input registers correctly regardless of the Python environment's SSL library availability.

## Upgrade Instructions

1. Download [TA-cveicu 1.0.6 from Splunkbase](https://splunkbase.splunk.com/app/8395)
2. Go to **Apps > Manage Apps > Install app from file**
3. Upload the package and check **Upgrade app**
4. Restart Splunk

## Verification

After upgrading, confirm the data input appears:

**Settings > Data Inputs > cve.icu**

To verify in the logs:

```spl
index=_internal sourcetype=splunkd component=ModularInputs "cveicu"
```

You should see successful scheme registration instead of the exit code 1 error.
