"""Integration tests for EPSS/KEV command execution in Splunk."""

import pytest


class TestCommandExecution:
    """Tests that run without --live (command structure only)."""

    def test_command_is_registered(self, splunk_api):
        """Verify the cveicuepsskev command is recognized by Splunk."""
        result = splunk_api.get(
            "/servicesNS/-/TA-cveicu/configs/conf-commands/cveicuepsskev",
            params={"output_mode": "json"},
        )
        assert result.status_code == 200

    def test_command_executes_without_error(self, splunk_api):
        """Verify the command runs without syntax errors.

        Without --live, external APIs may be unreachable — we only check
        that the command itself doesn't error. It may return 0 rows.
        """
        result = splunk_api.run_search(
            "| cveicuepsskev mode=kev | head 1 | stats count"
        )
        assert "results" in result


@pytest.mark.live
class TestCommandWithLiveData:
    def test_kev_command_returns_data(self, splunk_api):
        result = splunk_api.run_search_async("| cveicuepsskev mode=kev | head 5")
        results = result.get("results", [])
        assert len(results) == 5
        assert results[0]["cve_id"].startswith("CVE-")
        assert results[0]["in_kev"] == "true"

    def test_epss_command_returns_data(self, splunk_api):
        result = splunk_api.run_search_async("| cveicuepsskev mode=epss | head 5")
        results = result.get("results", [])
        assert len(results) == 5
        assert results[0]["cve_id"].startswith("CVE-")
        assert "epss_score" in results[0]
