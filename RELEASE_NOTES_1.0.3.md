## Release Notes — TA-cveicu v1.0.3

### Fix: Temp ZIP File Cleanup Preventing /tmp Disk Exhaustion

Temporary ZIP files downloaded during CVE processing were not being cleaned up, causing `/tmp` to fill up on Splunk Cloud Search Heads over time.

**What was broken:** The `download_release_asset()` method creates temp files via `tempfile.mkstemp(suffix='.zip')` for both baseline and delta ZIP downloads. Neither `_process_baseline` nor `_process_deltas` deleted these files after processing. On Splunk Cloud with hourly delta runs, thousands of ZIPs accumulated in `/tmp`, eventually causing critical disk utilization.

**What changed:**

- Added `try/finally` cleanup blocks in `_process_baseline` to delete the temp ZIP after baseline processing
- Added `try/finally` cleanup blocks in `_process_deltas` to delete each temp ZIP after delta processing
- Cleanup occurs on both success and error paths, matching the existing pattern used for nested ZIP cleanup in `github_client.py`

**Reported via:** Splunk Support Case #4012420

**Upgrade notes:** No manual steps required. After installing 1.0.3, temp files will be automatically cleaned up after each processing run. Any existing accumulated ZIP files in `/tmp` from prior versions should be manually removed or will be cleared on the next system restart.
