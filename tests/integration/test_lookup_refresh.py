"""Integration tests for EPSS/KEV lookup refresh via saved searches."""

import pytest


@pytest.mark.live
class TestKEVLookupRefresh:
    def test_kev_saved_search_populates_lookup(self, splunk_api):
        """Trigger KEV Lookup Refresh and verify kev_lookup.csv is populated.

        This is the exact scenario that was broken on Splunk Cloud (issue #2).
        The saved search runs: | cveicu_epss_kev mode=kev | outputlookup kev_lookup.csv
        """
        result = splunk_api.run_search_async(
            "| cveicu_epss_kev mode=kev | outputlookup kev_lookup.csv"
        )

        lookup_result = splunk_api.run_search(
            "| inputlookup kev_lookup.csv | stats count"
        )
        results = lookup_result.get("results", [])
        assert len(results) > 0
        count = int(results[0]["count"])
        assert count > 100, f"Expected 100+ KEV entries, got {count}"

    def test_kev_lookup_has_expected_fields(self, splunk_api):
        """Verify the KEV lookup contains all expected fields."""
        result = splunk_api.run_search(
            "| inputlookup kev_lookup.csv | head 1 | fields cve_id kev_vendor kev_product "
            "kev_vulnerability_name kev_date_added kev_due_date kev_required_action "
            "kev_ransomware in_kev"
        )
        results = result.get("results", [])
        assert len(results) == 1
        row = results[0]
        assert row["cve_id"].startswith("CVE-")
        assert row["in_kev"] == "true"
        assert row["kev_vendor"] != ""


@pytest.mark.live
class TestEPSSLookupRefresh:
    def test_epss_saved_search_populates_lookup(self, splunk_api):
        """Trigger EPSS Lookup Refresh and verify epss_lookup.csv is populated."""
        result = splunk_api.run_search_async(
            "| cveicu_epss_kev mode=epss | outputlookup epss_lookup.csv"
        )

        lookup_result = splunk_api.run_search(
            "| inputlookup epss_lookup.csv | stats count"
        )
        results = lookup_result.get("results", [])
        assert len(results) > 0
        count = int(results[0]["count"])
        assert count > 1000, f"Expected 1000+ EPSS entries, got {count}"

    def test_epss_lookup_has_expected_fields(self, splunk_api):
        """Verify the EPSS lookup contains all expected fields."""
        result = splunk_api.run_search(
            "| inputlookup epss_lookup.csv | head 1 | fields cve_id epss_score epss_percentile"
        )
        results = result.get("results", [])
        assert len(results) == 1
        row = results[0]
        assert row["cve_id"].startswith("CVE-")
        assert float(row["epss_score"]) >= 0
        assert float(row["epss_percentile"]) >= 0
