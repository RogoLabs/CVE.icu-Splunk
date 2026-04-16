"""Integration tests for dashboard loading on a live Splunk instance."""

import os

import pytest
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SPLUNK_URL = os.environ.get("SPLUNK_URL", "https://localhost:8089")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "TestPassword123!")

pytestmark = pytest.mark.integration


@pytest.fixture
def splunk_session():
    """Create an authenticated requests session to Splunk."""
    session = requests.Session()
    session.auth = (SPLUNK_USER, SPLUNK_PASSWORD)
    session.verify = False
    resp = session.get(
        f"{SPLUNK_URL}/services/server/info",
        params={"output_mode": "json"},
    )
    if resp.status_code != 200:
        pytest.skip("Splunk instance not available")
    return session


class TestModularInputRegistration:
    def test_cveicu_input_is_registered(self, splunk_session):
        resp = splunk_session.get(
            f"{SPLUNK_URL}/services/data/modular-input/cveicu",
            params={"output_mode": "json"},
        )
        assert resp.status_code == 200, f"Modular input not registered: {resp.text}"

    def test_cveicu_input_creation(self, splunk_session):
        resp = splunk_session.post(
            f"{SPLUNK_URL}/servicesNS/admin/TA-cveicu/data/inputs/cveicu/ci_test_input",
            params={"output_mode": "json"},
            data={
                "include_adp": "true",
                "include_rejected": "true",
                "batch_size": "100",
                "index": "main",
            },
        )
        assert resp.status_code in (201, 409), f"Input creation failed: {resp.text}"
        splunk_session.delete(
            f"{SPLUNK_URL}/servicesNS/admin/TA-cveicu/data/inputs/cveicu/ci_test_input",
            params={"output_mode": "json"},
        )


class TestDashboardLoading:
    DASHBOARDS = [
        "cve_explorer",
        "risk_priority",
        "vulnerability_landscape",
        "operational_health",
        "setup_page_dashboard",
    ]

    @pytest.mark.parametrize("dashboard", DASHBOARDS)
    def test_dashboard_loads(self, splunk_session, dashboard):
        resp = splunk_session.get(
            f"{SPLUNK_URL}/servicesNS/admin/TA-cveicu/data/ui/views/{dashboard}",
            params={"output_mode": "json"},
        )
        assert resp.status_code == 200, (
            f"Dashboard {dashboard} failed to load: {resp.text}"
        )


class TestLookupDefinitions:
    LOOKUPS = [
        "cvss_severity_lookup",
        "cwe_lookup",
        "epss_lookup",
        "kev_lookup",
        "risk_priority_lookup",
    ]

    @pytest.mark.parametrize("lookup", LOOKUPS)
    def test_lookup_exists(self, splunk_session, lookup):
        resp = splunk_session.get(
            f"{SPLUNK_URL}/servicesNS/admin/TA-cveicu/data/transforms/lookups/{lookup}",
            params={"output_mode": "json"},
        )
        assert resp.status_code == 200, f"Lookup {lookup} not found: {resp.text}"


class TestMacroDefinition:
    def test_macro_exists(self, splunk_session):
        resp = splunk_session.get(
            f"{SPLUNK_URL}/servicesNS/admin/TA-cveicu/configs/conf-macros/cveicu_index",
            params={"output_mode": "json"},
        )
        assert resp.status_code == 200, f"Macro cveicu_index not found: {resp.text}"

    def test_macro_default_value(self, splunk_session):
        resp = splunk_session.get(
            f"{SPLUNK_URL}/servicesNS/admin/TA-cveicu/configs/conf-macros/cveicu_index",
            params={"output_mode": "json"},
        )
        assert resp.status_code == 200
        entry = resp.json()["entry"][0]["content"]
        assert entry["definition"] == "index=main"
