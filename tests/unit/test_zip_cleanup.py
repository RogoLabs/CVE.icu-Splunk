"""Unit tests for temp ZIP file cleanup in cveicu.py."""

import os
import sys
import json
import zipfile
from unittest.mock import MagicMock

import pytest

# Mock splunklib before importing cveicu
if "splunklib" not in sys.modules:
    mock_splunklib = MagicMock()
    mock_modularinput = MagicMock()

    # Create a proper base class for Script
    class MockScript:
        def __init__(self):
            pass

        def run(self, argv):
            return 0

    mock_modularinput.Script = MockScript
    mock_modularinput.Scheme = None
    mock_modularinput.Argument = None
    mock_modularinput.Event = None
    mock_modularinput.EventWriter = None

    sys.modules["splunklib"] = mock_splunklib
    sys.modules["splunklib.modularinput"] = mock_modularinput

from cveicu import CVEListV5Input


def _make_temp_zip(tmp_path):
    """Create a real temp ZIP file with a minimal CVE JSON inside."""
    path = str(tmp_path / "test.zip")
    with zipfile.ZipFile(path, "w") as zf:
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
    instance = CVEListV5Input.__new__(CVEListV5Input)
    instance.logger = MagicMock()
    instance.resource_manager = MagicMock()
    instance.resource_manager.check_memory_usage.return_value = True
    instance.timeout_manager = MagicMock()
    instance.timeout_manager.check_timeout.return_value = True
    return instance


class TestBaselineZipCleanup:
    def test_zip_deleted_after_successful_processing(self, tmp_path):
        """Temp ZIP must be deleted after baseline processes successfully."""
        zip_path = _make_temp_zip(tmp_path)
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
        github_client.stream_zip_contents.return_value = iter([])
        cve_processor.get_stats.return_value = {
            "processed": 0,
            "skipped": 0,
            "errors": 0,
        }
        cve_processor.max_date_updated = None

        instance._process_baseline(
            github_client=github_client,
            checkpoint_manager=checkpoint_manager,
            cve_processor=cve_processor,
            batch_size=500,
            ew=ew,
        )

        assert not os.path.exists(zip_path), (
            "Temp ZIP was not deleted after successful baseline processing"
        )

    def test_zip_deleted_when_processing_raises(self, tmp_path):
        """Temp ZIP must be deleted even when processing throws an exception."""
        zip_path = _make_temp_zip(tmp_path)
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

        assert not os.path.exists(zip_path), (
            "Temp ZIP was not deleted after baseline processing error"
        )
