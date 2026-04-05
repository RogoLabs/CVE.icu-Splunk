"""Unit tests for resource manager."""

import time
import pytest
from cveicu_lib.resource_manager import ResourceManager, TimeoutManager


class TestResourceManager:
    def test_default_thresholds(self):
        rm = ResourceManager()
        assert rm.max_memory_mb == 512
        assert rm.MEMORY_WARNING_THRESHOLD == 0.8
        assert rm.MEMORY_CRITICAL_THRESHOLD == 0.9

    def test_custom_memory_limit(self):
        rm = ResourceManager(max_memory_mb=1024)
        assert rm.max_memory_mb == 1024
        assert rm.max_memory_bytes == 1024 * 1024 * 1024

    def test_check_memory_returns_true_when_usage_unknown(self):
        rm = ResourceManager()
        result = rm.check_memory_usage()
        assert result is True


class TestTimeoutManager:
    def test_not_started_returns_safe(self):
        tm = TimeoutManager(timeout_seconds=60)
        assert tm.check_timeout() is True

    def test_within_timeout_returns_safe(self):
        tm = TimeoutManager(timeout_seconds=120)
        tm.start()
        assert tm.check_timeout() is True

    def test_exceeded_timeout_returns_false(self):
        tm = TimeoutManager(timeout_seconds=1, checkpoint_interval=1)
        tm.start()
        tm.start_time = time.time() - 2
        assert tm.check_timeout() is False

    def test_approaching_timeout_returns_false(self):
        tm = TimeoutManager(timeout_seconds=100)
        tm.start()
        tm.start_time = time.time() - 30
        assert tm.check_timeout() is True

        tm.start_time = time.time() - 95
        assert tm.check_timeout() is False

    def test_should_checkpoint_first_call(self):
        tm = TimeoutManager(checkpoint_interval=300)
        assert tm.should_checkpoint() is True

    def test_should_checkpoint_respects_interval(self):
        tm = TimeoutManager(checkpoint_interval=300)
        tm.should_checkpoint()
        assert tm.should_checkpoint() is False

    def test_should_checkpoint_after_interval(self):
        tm = TimeoutManager(checkpoint_interval=1)
        tm.should_checkpoint()
        tm.last_checkpoint_time = time.time() - 2
        assert tm.should_checkpoint() is True

    def test_get_elapsed_time_not_started(self):
        tm = TimeoutManager()
        assert tm.get_elapsed_time() == 0.0

    def test_get_remaining_time_not_started(self):
        tm = TimeoutManager(timeout_seconds=3600)
        assert tm.get_remaining_time() == 3600.0

    def test_get_remaining_time_running(self):
        tm = TimeoutManager(timeout_seconds=100)
        tm.start()
        tm.start_time = time.time() - 40
        remaining = tm.get_remaining_time()
        assert 59 <= remaining <= 61

    def test_reset(self):
        tm = TimeoutManager()
        tm.start()
        tm.reset()
        assert tm.start_time is None
        assert tm.last_checkpoint_time is None
