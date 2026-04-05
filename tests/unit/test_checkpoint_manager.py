"""Unit tests for checkpoint manager."""

import pytest
from unittest.mock import MagicMock
from cveicu_lib.checkpoint_manager import CheckpointManager


@pytest.fixture
def manager():
    """Create a CheckpointManager that won't try to connect to Splunk."""
    mgr = CheckpointManager.__new__(CheckpointManager)
    mgr.input_name = "test_input"
    mgr.session_key = "fake_key"
    mgr.splunk_uri = "https://localhost:8089"
    mgr.app = "TA-cveicu"
    mgr.logger = MagicMock()

    # Set instance attributes directly to avoid property access
    mock_service = MagicMock()
    mock_collection = MagicMock()
    mock_collection.data.query.return_value = []  # Return empty list for KV Store queries

    mgr._service = mock_service
    mgr._collection = mock_collection
    mgr._checkpoint_cache = None
    return mgr


class TestDefaultCheckpoint:
    def test_returns_default_when_no_kvstore(self, manager):
        checkpoint = manager.get_checkpoint()

        assert checkpoint["input_name"] == "test_input"
        assert checkpoint["last_release_tag"] is None
        assert checkpoint["initial_load_completed"] is False
        assert checkpoint["total_records_processed"] == 0

    def test_is_initial_load_needed_true_by_default(self, manager):
        assert manager.is_initial_load_needed() is True

    def test_get_last_release_tag_none_by_default(self, manager):
        assert manager.get_last_release_tag() is None


class TestCheckpointCache:
    def test_checkpoint_cached_after_first_load(self, manager):
        checkpoint1 = manager.get_checkpoint()
        checkpoint2 = manager.get_checkpoint()

        assert checkpoint1 is checkpoint2

    def test_save_updates_cache(self, manager):
        manager.save_checkpoint(
            last_release_tag="cve_2024_03_01_0000Z",
            records_processed=500,
        )

        checkpoint = manager.get_checkpoint()
        assert checkpoint["last_release_tag"] == "cve_2024_03_01_0000Z"
        assert checkpoint["total_records_processed"] == 500

    def test_save_accumulates_records(self, manager):
        manager.save_checkpoint(records_processed=100)
        manager.save_checkpoint(records_processed=200)

        checkpoint = manager.get_checkpoint()
        assert checkpoint["total_records_processed"] == 300


class TestShouldProcessCVE:
    def test_no_date_updated_returns_true(self, manager):
        assert manager.should_process_cve(None) is True

    def test_no_checkpoint_returns_true(self, manager):
        assert manager.should_process_cve("2024-01-01T00:00:00.000Z") is True

    def test_newer_cve_returns_true(self, manager):
        manager.save_checkpoint(last_cve_date_updated="2024-01-01T00:00:00Z")
        assert manager.should_process_cve("2024-02-01T00:00:00Z") is True

    def test_older_cve_returns_false(self, manager):
        manager.save_checkpoint(last_cve_date_updated="2024-06-01T00:00:00Z")
        assert manager.should_process_cve("2024-01-01T00:00:00Z") is False


class TestErrorTracking:
    def test_error_increments_consecutive(self, manager):
        manager.save_checkpoint(error="Connection failed")
        manager.save_checkpoint(error="Timeout")

        checkpoint = manager.get_checkpoint()
        assert checkpoint["consecutive_errors"] == 2
        assert checkpoint["last_error"] == "Timeout"

    def test_success_resets_consecutive_errors(self, manager):
        manager.save_checkpoint(error="Connection failed")
        manager.save_checkpoint(records_processed=10)

        checkpoint = manager.get_checkpoint()
        assert checkpoint["consecutive_errors"] == 0
        assert checkpoint["last_error"] is None
