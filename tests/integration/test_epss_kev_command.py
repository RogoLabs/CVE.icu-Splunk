"""Integration tests for EPSS/KEV command execution in Splunk."""

import pytest
import requests


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
        """Verify the command is recognized by Splunk and doesn't have syntax errors.

        The command fetches from external APIs which may be unreachable in CI.
        We accept either successful results OR a known network/runtime error
        (exit code 1) — the key assertion is that Splunk recognizes the command
        (no "Unknown search command" error). Connection errors from long-running
        external API fetches are also acceptable.
        """
        try:
            result = splunk_api.run_search(
                "| cveicuepsskev mode=kev | head 1 | stats count"
            )
        except (
            requests.exceptions.ChunkedEncodingError,
            requests.exceptions.ConnectionError,
        ):
            return
        if "results" in result:
            return
        messages = result.get("messages", [])
        for msg in messages:
            text = msg.get("text", "")
            assert "Unknown search command" not in text, (
                f"Command not registered: {text}"
            )


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
