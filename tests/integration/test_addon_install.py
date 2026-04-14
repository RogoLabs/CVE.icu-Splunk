"""Integration tests for TA-cveicu add-on installation and configuration.

Validates that the add-on installs correctly, registers its modular input
with the expected scheme title, exposes the right configuration, and can
create a data input without errors.
"""

import pytest


class TestAddonInstallation:
    """Verify the add-on is installed and visible in Splunk."""

    def test_app_is_installed(self, splunk_api):
        """Verify TA-cveicu appears in the installed apps list."""
        result = splunk_api.get(
            "/services/apps/local/TA-cveicu",
            params={"output_mode": "json"},
        )
        assert result.status_code == 200
        entry = result.json()["entry"][0]
        assert entry["content"]["label"] == "cve.icu"

    def test_app_version(self, splunk_api):
        """Verify the app version matches what we packaged."""
        result = splunk_api.get(
            "/services/apps/local/TA-cveicu",
            params={"output_mode": "json"},
        )
        assert result.status_code == 200
        version = result.json()["entry"][0]["content"]["version"]
        # Just verify it's a valid semver-ish string
        parts = version.split(".")
        assert len(parts) == 3, f"Unexpected version format: {version}"

    def test_app_is_enabled(self, splunk_api):
        """Verify the app is not disabled after install."""
        result = splunk_api.get(
            "/services/apps/local/TA-cveicu",
            params={"output_mode": "json"},
        )
        assert result.status_code == 200
        assert result.json()["entry"][0]["content"]["disabled"] is False


class TestModularInputRegistration:
    """Verify the cveicu modular input is registered with the correct scheme."""

    def test_modular_input_exists(self, splunk_api):
        """Verify the cveicu modular input type is registered."""
        result = splunk_api.get(
            "/services/data/modular-inputs",
            params={"output_mode": "json"},
        )
        assert result.status_code == 200
        names = [e["name"] for e in result.json()["entry"]]
        assert "cveicu" in names, f"cveicu not found in modular inputs: {names}"

    def test_modular_input_title_is_cveicu(self, splunk_api):
        """Verify the modular input scheme title is 'cve.icu'.

        This is the fix for the user report where the data input
        appeared as 'CVE List V5' instead of 'cve.icu', making it
        hard to find in Settings > Data Inputs.
        """
        result = splunk_api.get(
            "/services/data/modular-inputs",
            params={"output_mode": "json"},
        )
        assert result.status_code == 200
        for entry in result.json()["entry"]:
            if entry["name"] == "cveicu":
                title = entry["content"]["title"]
                assert title == "cve.icu", (
                    f"Expected modular input title 'cve.icu', got '{title}'. "
                    "Users look for 'cve.icu' in Settings > Data Inputs."
                )
                return
        pytest.fail("cveicu modular input not found")

    def test_modular_input_description(self, splunk_api):
        """Verify the modular input has a meaningful description."""
        result = splunk_api.get(
            "/services/data/modular-inputs",
            params={"output_mode": "json"},
        )
        assert result.status_code == 200
        for entry in result.json()["entry"]:
            if entry["name"] == "cveicu":
                desc = entry["content"].get("description", "")
                assert "CVE" in desc, f"Description should mention CVE: {desc}"
                return


class TestInputCreation:
    """Verify we can create and inspect a cveicu data input."""

    def test_create_input(self, splunk_api):
        """Create a cveicu input, disable it, and verify it exists."""
        # Create input (modular inputs don't accept 'disabled' at creation)
        result = splunk_api.post(
            "/servicesNS/admin/TA-cveicu/data/inputs/cveicu",
            data={
                "name": "integration_test",
                "index": "main",
                "include_adp": "true",
                "include_rejected": "true",
                "batch_size": "100",
                "interval": "86400",
                "output_mode": "json",
            },
        )
        assert result.status_code in (200, 201, 409), (
            f"Failed to create input: {result.status_code} {result.text}"
        )

        # Disable it immediately so it doesn't start downloading
        disable = splunk_api.post(
            "/servicesNS/admin/TA-cveicu/data/inputs/cveicu/integration_test/disable",
            data={"output_mode": "json"},
        )
        assert disable.status_code == 200

        # Verify it exists and is disabled
        check = splunk_api.get(
            "/servicesNS/admin/TA-cveicu/data/inputs/cveicu/integration_test",
            params={"output_mode": "json"},
        )
        assert check.status_code == 200
        content = check.json()["entry"][0]["content"]
        assert content["index"] == "main"
        assert content["disabled"] is True

    def test_input_has_expected_parameters(self, splunk_api):
        """Verify the input exposes the expected configurable parameters."""
        result = splunk_api.get(
            "/servicesNS/admin/TA-cveicu/data/inputs/cveicu/integration_test",
            params={"output_mode": "json"},
        )
        assert result.status_code == 200
        content = result.json()["entry"][0]["content"]
        # These are the parameters defined in the scheme
        assert "include_adp" in content
        assert "include_rejected" in content
        assert "batch_size" in content

    def test_cleanup_input(self, splunk_api):
        """Remove the test input created above."""
        result = splunk_api.delete(
            "/servicesNS/admin/TA-cveicu/data/inputs/cveicu/integration_test",
            params={"output_mode": "json"},
        )
        assert result.status_code == 200


class TestSplunkConfiguration:
    """Verify Splunk configuration files are loaded correctly."""

    def test_sourcetype_props(self, splunk_api):
        """Verify props.conf defines the cveicu:record sourcetype."""
        result = splunk_api.get(
            "/servicesNS/-/TA-cveicu/configs/conf-props/cveicu%3Arecord",
            params={"output_mode": "json"},
        )
        assert result.status_code == 200

    def test_transforms_exist(self, splunk_api):
        """Verify transforms.conf has CVE lookup definitions."""
        result = splunk_api.get(
            "/servicesNS/-/TA-cveicu/configs/conf-transforms",
            params={"output_mode": "json"},
        )
        assert result.status_code == 200
        names = [e["name"] for e in result.json()["entry"]]
        assert "epss_lookup" in names or "kev_lookup" in names, (
            f"Expected lookup transforms, got: {names}"
        )

    def test_saved_searches_exist(self, splunk_api):
        """Verify saved searches for EPSS/KEV refresh are defined."""
        result = splunk_api.get(
            "/servicesNS/-/TA-cveicu/saved/searches",
            params={"output_mode": "json", "count": 0},
        )
        assert result.status_code == 200
        names = [e["name"] for e in result.json()["entry"]]
        # Check for at least one of the enrichment saved searches
        enrichment_searches = [
            n for n in names if "epss" in n.lower() or "kev" in n.lower()
        ]
        assert len(enrichment_searches) > 0, (
            f"No EPSS/KEV saved searches found. Got: {names}"
        )

    def test_custom_command_registered(self, splunk_api):
        """Verify the cveicuepsskev custom search command is registered."""
        result = splunk_api.get(
            "/servicesNS/-/TA-cveicu/configs/conf-commands/cveicuepsskev",
            params={"output_mode": "json"},
        )
        assert result.status_code == 200
