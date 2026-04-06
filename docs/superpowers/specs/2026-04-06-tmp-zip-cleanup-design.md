# Temp ZIP File Cleanup Fix

**Date:** 2026-04-06
**Status:** Approved
**Severity:** Critical (causes disk exhaustion on Splunk Cloud Search Heads)

## Problem

`download_release_asset()` in `github_client.py:302` creates temp files in `/tmp` via `tempfile.mkstemp(suffix='.zip')`. Neither `_process_baseline` nor `_process_deltas` in `cveicu.py` deletes these files after processing. On Splunk Cloud, hourly delta runs accumulate thousands of ZIPs, eventually filling the Search Head disk.

**Reported via:** Splunk Support Case #4012420 — Search Head in the 'porter' stack reached critical disk utilization due to accumulated `.zip` files in `/tmp`.

## Root Cause

- `download_release_asset()` returns a file path to a temp `.zip` file
- Callers in `cveicu.py` (`_process_baseline` line ~348, `_process_deltas` line ~453) use the file but never delete it
- Nested ZIP cleanup in `stream_zip_contents()` (line 364-370) works correctly — the top-level downloads are the gap

## Solution: Caller-side `try/finally` cleanup

Wrap the download-process-cleanup cycle in `try/finally` blocks in both caller methods. This mirrors the existing cleanup pattern for nested ZIPs in `github_client.py`.

### Changes

**`cveicu.py` — `_process_baseline` (~line 345-398):**

- Store the returned path from `download_release_asset()` in `zip_path`
- Wrap `stream_zip_contents` iteration and batch processing in `try/finally`
- In `finally`: delete file with `os.unlink(zip_path)`, wrapped in try/except to avoid masking errors
- Log cleanup at debug level

**`cveicu.py` — `_process_deltas` (~line 453-485):**

- Same pattern: store `zip_path`, wrap processing in `try/finally`, delete in `finally`
- Inside the `for delta in deltas` loop, so each delta ZIP is cleaned up before the next download

### What doesn't change

- `github_client.py` — no API changes
- Nested ZIP cleanup in `stream_zip_contents` — already correct
- No new dependencies, no config changes

## Alternatives Considered

**Context manager on `download_release_asset`:** More Pythonic but invasive — changes the API contract for a simple fix.

**Tracked cleanup in `GitHubClient.close()`:** Keeps files alive too long and depends on `close()` being called, which is the same class of problem.
