# Temp ZIP File Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix temp ZIP file accumulation in `/tmp` that causes disk exhaustion on Splunk Cloud Search Heads.

**Architecture:** Add `try/finally` cleanup blocks around ZIP processing in both `_process_baseline` and `_process_deltas` methods in `cveicu.py`. Tests verify cleanup happens on both success and error paths.

**Tech Stack:** Python 3, pytest, unittest.mock

---

### Task 1: Write tests for baseline ZIP cleanup

**Files:**

- Create: `tests/unit/test_zip_cleanup.py`

- [ ] **Step 1: Create test file with baseline cleanup tests**

```python
"""Unit tests for temp ZIP file cleanup in cveicu.py."""

import os
import tempfile
import json
import zipfile
from unittest.mock import MagicMock, patch, PropertyMock

import pytest


def _make_temp_zip():
    """Create a real temp ZIP file with a minimal CVE JSON inside."""
    fd, path = tempfile.mkstemp(suffix=".zip")
    with os.fdopen(fd, "wb") as f:
        with zipfile.ZipFile(f, "w") as zf:
            cve = {
                "cveMetadata": {
                    "cveId": "CVE-2024-0001",
                    "dateUpdated": "2024-01-01T00:00:00Z",
                },
            }
            zf.writestr("CVE-2024-0001.json", json.dumps(cve))
    return path


def _make_input_instance():
    """Create a CVEListV5Input with mocked dependencies."""
    # Patch splunklib imports before importing cveicu
    import sys
    from unittest.mock import MagicMock

    # Ensure splunklib.modularinput is mockable
    if "splunklib" not in sys.modules:
        sys.modules["splunklib"] = MagicMock()
        sys.modules["splunklib.modularinput"] = MagicMock()

    from cveicu import CVEListV5Input

    instance = CVEListV5Input.__new__(CVEListV5Input)
    instance.logger = MagicMock()
    instance.resource_manager = MagicMock()
    instance.resource_manager.check_memory_usage.return_value = True
    instance.timeout_manager = MagicMock()
    instance.timeout_manager.check_timeout.return_value = True
    return instance


class TestBaselineZipCleanup:
    def test_zip_deleted_after_successful_processing(self):
        """Temp ZIP must be deleted after baseline processes successfully."""
        zip_path = _make_temp_zip()
        assert os.path.exists(zip_path)

        instance = _make_input_instance()
        github_client = MagicMock()
        checkpoint_manager = MagicMock()
        cve_processor = MagicMock()
        ew = MagicMock()

        # find_baseline_release returns a release with the right asset
        github_client.find_baseline_release.return_value = {
            "tag_name": "cve_2024-01-01_0000Z",
            "assets": [
                {
                    "name": "all_CVEs_at_midnight.zip",
                    "browser_download_url": "https://example.com/all.zip",
                }
            ],
        }
        checkpoint_manager.is_initial_load_needed.return_value = True
        checkpoint_manager.get_checkpoint.return_value = {}
        github_client.download_release_asset.return_value = zip_path
        github_client.stream_zip_contents.return_value = iter([])
        cve_processor.get_stats.return_value = {"processed": 0, "skipped": 0, "errors": 0}
        cve_processor.max_date_updated = None

        instance._process_baseline(
            github_client=github_client,
            checkpoint_manager=checkpoint_manager,
            cve_processor=cve_processor,
            batch_size=500,
            ew=ew,
        )

        assert not os.path.exists(zip_path), "Temp ZIP was not deleted after successful baseline processing"

    def test_zip_deleted_when_processing_raises(self):
        """Temp ZIP must be deleted even when processing throws an exception."""
        zip_path = _make_temp_zip()
        assert os.path.exists(zip_path)

        instance = _make_input_instance()
        github_client = MagicMock()
        checkpoint_manager = MagicMock()
        cve_processor = MagicMock()
        ew = MagicMock()

        github_client.find_baseline_release.return_value = {
            "tag_name": "cve_2024-01-01_0000Z",
            "assets": [
                {
                    "name": "all_CVEs_at_midnight.zip",
                    "browser_download_url": "https://example.com/all.zip",
                }
            ],
        }
        checkpoint_manager.is_initial_load_needed.return_value = True
        checkpoint_manager.get_checkpoint.return_value = {}
        github_client.download_release_asset.return_value = zip_path
        github_client.stream_zip_contents.side_effect = RuntimeError("corrupt zip")

        with pytest.raises(RuntimeError, match="corrupt zip"):
            instance._process_baseline(
                github_client=github_client,
                checkpoint_manager=checkpoint_manager,
                cve_processor=cve_processor,
                batch_size=500,
                ew=ew,
            )

        assert not os.path.exists(zip_path), "Temp ZIP was not deleted after baseline processing error"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/gamblin/Documents/Github/SplunkCVEList && python -m pytest tests/unit/test_zip_cleanup.py::TestBaselineZipCleanup -v`

Expected: Both tests FAIL — the first because the file still exists after processing, the second because the exception propagates but cleanup doesn't happen.

- [ ] **Step 3: Commit test file**

```bash
git add tests/unit/test_zip_cleanup.py
git commit -m "test: add failing tests for baseline ZIP cleanup"
```

---

### Task 2: Implement baseline ZIP cleanup

**Files:**

- Modify: `TA-cveicu/bin/cveicu.py:347-398`

- [ ] **Step 1: Add try/finally around baseline ZIP processing**

In `_process_baseline`, wrap lines 355-398 (everything after the download and null-check) in a `try/finally` block that deletes the temp file:

Replace this block (lines 355-398):

```python
        # Process CVEs in batches
        batch = []
        total_events = 0

        for filename, cve_data in github_client.stream_zip_contents(zip_content):
            # Check resource limits
            if not self.resource_manager.check_memory_usage():
                self.logger.warning("Memory pressure detected, forcing GC")
                # Memory cleanup is automatic in check_memory_usage

            if not self.timeout_manager.check_timeout():
                self.logger.warning("Timeout approaching, saving checkpoint and exiting")
                break

            batch.append(cve_data)

            if len(batch) >= batch_size:
                events_written = self._write_batch(batch, cve_processor, ew)
                total_events += events_written
                batch = []

                # Save checkpoint periodically
                if total_events % 10000 == 0:
                    self.logger.info(f"Progress: {total_events} events written")
                    checkpoint_manager.save_checkpoint(
                        last_release_tag=release_tag,
                        last_cve_date_updated=cve_processor.max_date_updated,
                        records_processed=total_events
                    )

        # Process remaining batch
        if batch:
            events_written = self._write_batch(batch, cve_processor, ew)
            total_events += events_written

        # Save final checkpoint
        checkpoint_manager.save_checkpoint(
            last_release_tag=release_tag,
            last_cve_date_updated=cve_processor.max_date_updated,
            records_processed=total_events,
            initial_load_completed=True
        )

        self.logger.info(f"Baseline processing complete: {total_events} events")
```

With:

```python
        # Process CVEs in batches, ensuring temp ZIP is cleaned up
        try:
            batch = []
            total_events = 0

            for filename, cve_data in github_client.stream_zip_contents(zip_content):
                # Check resource limits
                if not self.resource_manager.check_memory_usage():
                    self.logger.warning("Memory pressure detected, forcing GC")
                    # Memory cleanup is automatic in check_memory_usage

                if not self.timeout_manager.check_timeout():
                    self.logger.warning("Timeout approaching, saving checkpoint and exiting")
                    break

                batch.append(cve_data)

                if len(batch) >= batch_size:
                    events_written = self._write_batch(batch, cve_processor, ew)
                    total_events += events_written
                    batch = []

                    # Save checkpoint periodically
                    if total_events % 10000 == 0:
                        self.logger.info(f"Progress: {total_events} events written")
                        checkpoint_manager.save_checkpoint(
                            last_release_tag=release_tag,
                            last_cve_date_updated=cve_processor.max_date_updated,
                            records_processed=total_events
                        )

            # Process remaining batch
            if batch:
                events_written = self._write_batch(batch, cve_processor, ew)
                total_events += events_written

            # Save final checkpoint
            checkpoint_manager.save_checkpoint(
                last_release_tag=release_tag,
                last_cve_date_updated=cve_processor.max_date_updated,
                records_processed=total_events,
                initial_load_completed=True
            )

            self.logger.info(f"Baseline processing complete: {total_events} events")
        finally:
            try:
                os.unlink(zip_content)
                self.logger.debug(f"Cleaned up temp file: {zip_content}")
            except OSError:
                pass
```

- [ ] **Step 2: Run baseline tests to verify they pass**

Run: `cd /Users/gamblin/Documents/Github/SplunkCVEList && python -m pytest tests/unit/test_zip_cleanup.py::TestBaselineZipCleanup -v`

Expected: Both tests PASS

- [ ] **Step 3: Commit**

```bash
git add TA-cveicu/bin/cveicu.py
git commit -m "fix: clean up temp ZIP after baseline processing"
```

---

### Task 3: Write tests for delta ZIP cleanup

**Files:**

- Modify: `tests/unit/test_zip_cleanup.py`

- [ ] **Step 1: Add delta cleanup tests to the test file**

Append to `tests/unit/test_zip_cleanup.py`:

```python
class TestDeltaZipCleanup:
    def test_zip_deleted_after_successful_delta(self):
        """Temp ZIP must be deleted after each delta processes successfully."""
        zip_path = _make_temp_zip()
        assert os.path.exists(zip_path)

        instance = _make_input_instance()
        github_client = MagicMock()
        checkpoint_manager = MagicMock()
        cve_processor = MagicMock()
        ew = MagicMock()

        checkpoint_manager.get_checkpoint.return_value = {"last_release": "cve_2024-01-01_0100Z"}
        github_client.find_delta_releases_since.return_value = [
            {
                "tag_name": "cve_2024-01-01_0200Z",
                "assets": [{"name": "delta_CVEs_at_0200Z.zip", "browser_download_url": "https://example.com/delta.zip"}],
            }
        ]
        github_client.download_release_asset.return_value = zip_path
        github_client.stream_zip_contents.return_value = iter([])
        cve_processor.max_date_updated = None

        instance._process_deltas(
            github_client=github_client,
            checkpoint_manager=checkpoint_manager,
            cve_processor=cve_processor,
            batch_size=500,
            ew=ew,
        )

        assert not os.path.exists(zip_path), "Temp ZIP was not deleted after successful delta processing"

    def test_zip_deleted_when_delta_raises(self):
        """Temp ZIP must be deleted even when delta processing throws."""
        zip_path = _make_temp_zip()
        assert os.path.exists(zip_path)

        instance = _make_input_instance()
        github_client = MagicMock()
        checkpoint_manager = MagicMock()
        cve_processor = MagicMock()
        ew = MagicMock()

        checkpoint_manager.get_checkpoint.return_value = {"last_release": "cve_2024-01-01_0100Z"}
        github_client.find_delta_releases_since.return_value = [
            {
                "tag_name": "cve_2024-01-01_0200Z",
                "assets": [{"name": "delta_CVEs_at_0200Z.zip", "browser_download_url": "https://example.com/delta.zip"}],
            }
        ]
        github_client.download_release_asset.return_value = zip_path
        github_client.stream_zip_contents.side_effect = RuntimeError("corrupt zip")

        with pytest.raises(RuntimeError, match="corrupt zip"):
            instance._process_deltas(
                github_client=github_client,
                checkpoint_manager=checkpoint_manager,
                cve_processor=cve_processor,
                batch_size=500,
                ew=ew,
            )

        assert not os.path.exists(zip_path), "Temp ZIP was not deleted after delta processing error"

    def test_all_zips_cleaned_in_multi_delta_run(self):
        """All temp ZIPs must be cleaned up when processing multiple deltas."""
        zip_paths = [_make_temp_zip() for _ in range(3)]
        for p in zip_paths:
            assert os.path.exists(p)

        instance = _make_input_instance()
        github_client = MagicMock()
        checkpoint_manager = MagicMock()
        cve_processor = MagicMock()
        ew = MagicMock()

        checkpoint_manager.get_checkpoint.return_value = {"last_release": "cve_2024-01-01_0100Z"}
        github_client.find_delta_releases_since.return_value = [
            {
                "tag_name": f"cve_2024-01-01_0{i}00Z",
                "assets": [{"name": f"delta_CVEs_at_0{i}00Z.zip", "browser_download_url": f"https://example.com/delta{i}.zip"}],
            }
            for i in range(2, 5)
        ]
        github_client.download_release_asset.side_effect = zip_paths
        github_client.stream_zip_contents.return_value = iter([])
        cve_processor.max_date_updated = None

        instance._process_deltas(
            github_client=github_client,
            checkpoint_manager=checkpoint_manager,
            cve_processor=cve_processor,
            batch_size=500,
            ew=ew,
        )

        for p in zip_paths:
            assert not os.path.exists(p), f"Temp ZIP {p} was not deleted after multi-delta processing"
```

- [ ] **Step 2: Run delta tests to verify they fail**

Run: `cd /Users/gamblin/Documents/Github/SplunkCVEList && python -m pytest tests/unit/test_zip_cleanup.py::TestDeltaZipCleanup -v`

Expected: All three tests FAIL — files still exist after processing.

- [ ] **Step 3: Commit test additions**

```bash
git add tests/unit/test_zip_cleanup.py
git commit -m "test: add failing tests for delta ZIP cleanup"
```

---

### Task 4: Implement delta ZIP cleanup

**Files:**

- Modify: `TA-cveicu/bin/cveicu.py:453-485`

- [ ] **Step 1: Add try/finally around delta ZIP processing**

In `_process_deltas`, wrap the per-delta processing block. Replace this code inside the `for delta in deltas:` loop (lines 453-485):

```python
            download_url = delta_asset.get("browser_download_url")
            zip_content = github_client.download_release_asset(download_url)

            if not zip_content:
                self.logger.warning(f"Failed to download delta: {release_tag}")
                continue

            # Process CVEs
            batch = []

            for filename, cve_data in github_client.stream_zip_contents(zip_content):
                # Only process if newer than checkpoint
                cve_id = cve_data.get("cveMetadata", {}).get("cveId", "")
                date_updated = cve_data.get("cveMetadata", {}).get("dateUpdated")

                if checkpoint_manager.should_process_cve(date_updated):
                    batch.append(cve_data)

                if len(batch) >= batch_size:
                    events_written = self._write_batch(batch, cve_processor, ew)
                    total_events += events_written
                    batch = []

            # Process remaining batch
            if batch:
                events_written = self._write_batch(batch, cve_processor, ew)
                total_events += events_written

            # Update checkpoint for each processed delta
            checkpoint_manager.save_checkpoint(
                last_release_tag=release_tag,
                last_cve_date_updated=cve_processor.max_date_updated,
                records_processed=total_events
            )
```

With:

```python
            download_url = delta_asset.get("browser_download_url")
            zip_content = github_client.download_release_asset(download_url)

            if not zip_content:
                self.logger.warning(f"Failed to download delta: {release_tag}")
                continue

            # Process CVEs, ensuring temp ZIP is cleaned up
            try:
                batch = []

                for filename, cve_data in github_client.stream_zip_contents(zip_content):
                    # Only process if newer than checkpoint
                    cve_id = cve_data.get("cveMetadata", {}).get("cveId", "")
                    date_updated = cve_data.get("cveMetadata", {}).get("dateUpdated")

                    if checkpoint_manager.should_process_cve(date_updated):
                        batch.append(cve_data)

                    if len(batch) >= batch_size:
                        events_written = self._write_batch(batch, cve_processor, ew)
                        total_events += events_written
                        batch = []

                # Process remaining batch
                if batch:
                    events_written = self._write_batch(batch, cve_processor, ew)
                    total_events += events_written

                # Update checkpoint for each processed delta
                checkpoint_manager.save_checkpoint(
                    last_release_tag=release_tag,
                    last_cve_date_updated=cve_processor.max_date_updated,
                    records_processed=total_events
                )
            finally:
                try:
                    os.unlink(zip_content)
                    self.logger.debug(f"Cleaned up temp file: {zip_content}")
                except OSError:
                    pass
```

- [ ] **Step 2: Run all cleanup tests to verify they pass**

Run: `cd /Users/gamblin/Documents/Github/SplunkCVEList && python -m pytest tests/unit/test_zip_cleanup.py -v`

Expected: All 5 tests PASS

- [ ] **Step 3: Run the full test suite to check for regressions**

Run: `cd /Users/gamblin/Documents/Github/SplunkCVEList && python -m pytest tests/ -v`

Expected: All existing tests still pass

- [ ] **Step 4: Commit**

```bash
git add TA-cveicu/bin/cveicu.py
git commit -m "fix: clean up temp ZIP after delta processing

Closes #4"
```
