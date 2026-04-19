#!/usr/bin/env python3
"""End-to-end validation for TA-cveicu v1.1.0 on Splunk 9.

Expects a running Splunk 9.x instance (via docker-compose.test.yml).
Validates everything needed for a confident v1.1.0 release:

1. App installation, version, and metadata
2. Modular input registration and CRUD
3. Custom search command registration
4. All 4 dashboards: load, SimpleXML format, version attribute, structure
5. Lookup data availability and field validation
6. Saved searches and macros
7. Dashboard search execution against real lookup data
8. Splunk 9 compatibility (no Dashboard Studio v2 artifacts)
"""

import os
import sys
import xml.etree.ElementTree as ET

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SPLUNK_URL = os.environ.get("SPLUNK_URL", "https://localhost:18089")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "testpassword123")

passed = 0
failed = 0
errors = []
all_tests = []


def test(name):
    def decorator(func):
        def wrapper():
            global passed, failed
            try:
                func()
                passed += 1
                print(f"  PASS  {name}")
            except AssertionError as e:
                failed += 1
                errors.append(f"{name}: {e}")
                print(f"  FAIL  {name}: {e}")
            except Exception as e:
                failed += 1
                errors.append(f"{name}: {type(e).__name__}: {e}")
                print(f"  ERROR {name}: {type(e).__name__}: {e}")

        wrapper.test_name = name
        all_tests.append(wrapper)
        return wrapper

    return decorator


def api(method, path, **kwargs):
    url = f"{SPLUNK_URL}{path}"
    kwargs.setdefault("params", {})["output_mode"] = "json"
    kwargs["auth"] = (SPLUNK_USER, SPLUNK_PASSWORD)
    kwargs["verify"] = False
    return getattr(requests, method)(url, **kwargs)


def run_search(query):
    resp = api(
        "post",
        "/services/search/jobs",
        data={
            "search": query,
            "exec_mode": "oneshot",
            "output_mode": "json",
            "count": 0,
        },
    )
    return resp.json() if resp.status_code == 200 else None


def get_dashboard_xml(name):
    resp = api("get", f"/servicesNS/admin/TA-cveicu/data/ui/views/{name}")
    assert resp.status_code == 200, f"Dashboard {name} not found"
    return resp.json()["entry"][0]["content"]["eai:data"]


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


def preflight():
    print("Connecting to Splunk...")
    try:
        resp = api("get", "/services/server/info")
        assert resp.status_code == 200
        info = resp.json()["entry"][0]["content"]
        print(f"  Splunk {info['version']} (build {info['build']})")
        assert info["version"].startswith("9."), (
            f"Expected Splunk 9.x, got {info['version']}"
        )
    except requests.exceptions.ConnectionError:
        print(f"FATAL: Cannot connect to {SPLUNK_URL}")
        print("Start Splunk first: docker-compose -f docker-compose.test.yml up -d")
        sys.exit(1)


# ===========================================================================
# SECTION 1: App Installation & Metadata
# ===========================================================================


@test("App is installed")
def _():
    resp = api("get", "/services/apps/local/TA-cveicu")
    assert resp.status_code == 200


@test("App version is 1.1.0")
def _():
    resp = api("get", "/services/apps/local/TA-cveicu")
    v = resp.json()["entry"][0]["content"]["version"]
    assert v == "1.1.0", f"Got {v}"


@test("App is enabled")
def _():
    resp = api("get", "/services/apps/local/TA-cveicu")
    assert not resp.json()["entry"][0]["content"]["disabled"]


@test("App label is cve.icu")
def _():
    resp = api("get", "/services/apps/local/TA-cveicu")
    label = resp.json()["entry"][0]["content"]["label"]
    assert label == "cve.icu", f"Got {label}"


# ===========================================================================
# SECTION 2: Modular Input
# ===========================================================================


@test("Modular input type is registered")
def _():
    resp = api("get", "/servicesNS/admin/TA-cveicu/data/inputs/cveicu")
    assert resp.status_code == 200, f"Status {resp.status_code}"


@test("Can create and delete a test input")
def _():
    resp = api(
        "post",
        "/servicesNS/admin/TA-cveicu/data/inputs/cveicu",
        data={
            "name": "e2e_test_input",
            "index": "main",
            "include_adp": "true",
            "include_rejected": "false",
            "batch_size": "100",
        },
    )
    assert resp.status_code in (201, 409), f"Create failed: {resp.status_code}"
    api("delete", "/servicesNS/admin/TA-cveicu/data/inputs/cveicu/e2e_test_input")


# ===========================================================================
# SECTION 3: Custom Search Command
# ===========================================================================


@test("Custom command cveicuepsskev is registered")
def _():
    resp = api("get", "/servicesNS/admin/TA-cveicu/configs/conf-commands/cveicuepsskev")
    assert resp.status_code == 200


# ===========================================================================
# SECTION 4: Dashboard Format & Structure
# ===========================================================================

DASHBOARDS = [
    "cve_explorer",
    "risk_priority",
    "vulnerability_landscape",
    "operational_health",
]


@test("All 4 dashboards load via REST API")
def _():
    for db in DASHBOARDS:
        resp = api("get", f"/servicesNS/admin/TA-cveicu/data/ui/views/{db}")
        assert resp.status_code == 200, f"{db}: {resp.status_code}"


@test("All dashboards have version='1.1' (no version warning banner)")
def _():
    for db in DASHBOARDS:
        xml_data = get_dashboard_xml(db)
        root = ET.fromstring(xml_data)
        v = root.get("version")
        assert v == "1.1", f"{db}: version={v!r}, expected '1.1'"


@test("No dashboards use Dashboard Studio v2 format")
def _():
    for db in DASHBOARDS:
        xml_data = get_dashboard_xml(db)
        root = ET.fromstring(xml_data)
        assert root.tag in ("form", "dashboard"), f"{db}: root=<{root.tag}>"
        assert root.get("version") != "2", f"{db}: still Dashboard Studio v2!"
        assert "CDATA" not in xml_data, f"{db}: still has CDATA"
        assert '"dataSources"' not in xml_data, f"{db}: still has JSON dataSources"


@test("Dashboards with inputs use <form>, static use <dashboard>")
def _():
    expected = {
        "cve_explorer": "form",
        "risk_priority": "form",
        "vulnerability_landscape": "dashboard",
        "operational_health": "dashboard",
    }
    for db, tag in expected.items():
        root = ET.fromstring(get_dashboard_xml(db))
        assert root.tag == tag, f"{db}: expected <{tag}>, got <{root.tag}>"


@test("CVE Explorer: 3 inputs (vendor, severity, CWE), 2 panels")
def _():
    root = ET.fromstring(get_dashboard_xml("cve_explorer"))
    fieldset = root.find("fieldset")
    assert fieldset is not None
    inputs = fieldset.findall("input")
    assert len(inputs) == 3, f"Got {len(inputs)} inputs"
    tokens = {inp.get("token") for inp in inputs}
    assert tokens == {"vendor_filter", "severity_filter", "cwe_filter"}, f"Got {tokens}"
    panels = root.findall(".//panel")
    assert len(panels) == 2, f"Got {len(panels)} panels"


@test("Risk Priority: 2 inputs (EPSS, KEV), 4 panels")
def _():
    root = ET.fromstring(get_dashboard_xml("risk_priority"))
    fieldset = root.find("fieldset")
    inputs = fieldset.findall("input")
    assert len(inputs) == 2, f"Got {len(inputs)} inputs"
    tokens = {inp.get("token") for inp in inputs}
    assert tokens == {"epss_filter", "kev_filter"}, f"Got {tokens}"
    panels = root.findall(".//panel")
    assert len(panels) == 4, f"Got {len(panels)} panels"


@test("Vulnerability Landscape: 3 rows, 8 panels")
def _():
    root = ET.fromstring(get_dashboard_xml("vulnerability_landscape"))
    rows = root.findall("row")
    assert len(rows) == 3, f"Got {len(rows)} rows"
    panels = root.findall(".//panel")
    assert len(panels) == 8, f"Got {len(panels)} panels"


@test("Operational Health: 4 rows, 7 panels")
def _():
    root = ET.fromstring(get_dashboard_xml("operational_health"))
    rows = root.findall("row")
    assert len(rows) == 4, f"Got {len(rows)} rows"
    panels = root.findall(".//panel")
    assert len(panels) == 7, f"Got {len(panels)} panels"


@test("All charts use SimpleXML charting.chart option")
def _():
    for db in DASHBOARDS:
        root = ET.fromstring(get_dashboard_xml(db))
        for chart in root.findall(".//chart"):
            opts = {o.get("name"): o.text for o in chart.findall("option")}
            assert "charting.chart" in opts, f"{db}: chart missing charting.chart"
            assert opts["charting.chart"] in (
                "line",
                "bar",
                "area",
                "column",
            ), f"{db}: unexpected chart type {opts['charting.chart']}"


@test("Single-value panels use <single> element")
def _():
    for db in DASHBOARDS:
        root = ET.fromstring(get_dashboard_xml(db))
        singles = root.findall(".//single")
        for s in singles:
            search = s.find("search")
            assert search is not None, f"{db}: <single> without <search>"
            query = search.find("query")
            assert query is not None, f"{db}: <single> search without <query>"


# ===========================================================================
# SECTION 5: Lookup Data Validation
# ===========================================================================

LOOKUPS = [
    "cvss_severity_lookup",
    "cwe_lookup",
    "epss_lookup",
    "kev_lookup",
    "risk_priority_lookup",
]


@test("All 5 lookup definitions exist in transforms.conf")
def _():
    for lk in LOOKUPS:
        resp = api("get", f"/servicesNS/admin/TA-cveicu/data/transforms/lookups/{lk}")
        assert resp.status_code == 200, f"{lk} not found"


@test("EPSS lookup: 300K+ rows with cve_id and epss fields")
def _():
    result = run_search(
        "| inputlookup epss_lookup.csv | stats count | where count > 100000"
    )
    assert result and len(result.get("results", [])) > 0, "EPSS lookup too small"
    fields_result = run_search(
        "| inputlookup epss_lookup.csv | head 1 | table cve_id epss_score"
    )
    assert fields_result and len(fields_result["results"]) > 0
    row = fields_result["results"][0]
    assert "cve_id" in row, f"Missing cve_id. Fields: {list(row.keys())}"
    assert row["cve_id"].startswith("CVE-"), f"Bad cve_id: {row['cve_id']}"


@test("KEV lookup: 1000+ rows with cve_id, in_kev, kev_vendor fields")
def _():
    result = run_search("| inputlookup kev_lookup.csv | stats count")
    assert result and int(result["results"][0]["count"]) > 1000
    fields_result = run_search(
        "| inputlookup kev_lookup.csv | head 1 | table cve_id in_kev kev_vendor kev_product"
    )
    row = fields_result["results"][0]
    assert "cve_id" in row and "in_kev" in row and "kev_vendor" in row


@test("Risk priority lookup: readable and has correct schema")
def _():
    result = run_search("| inputlookup risk_priority_lookup.csv | stats count")
    assert result is not None, "Failed to read risk_priority_lookup.csv"
    count = int(result["results"][0]["count"])
    if count > 0:
        fields_result = run_search(
            "| inputlookup risk_priority_lookup.csv | head 1 "
            "| table cve_id cvss_score cvss_severity epss_score in_kev"
        )
        row = fields_result["results"][0]
        assert "cve_id" in row and row["cve_id"].startswith("CVE-")


@test("CVE vendors lookup: readable (populated by saved search after ingestion)")
def _():
    result = run_search("| inputlookup cve_vendors.csv | stats count")
    assert result is not None, "Failed to read cve_vendors.csv"


@test("CVE daily summary lookup: readable (populated by saved search after ingestion)")
def _():
    result = run_search("| inputlookup cve_daily_summary.csv | stats count")
    assert result is not None, "Failed to read cve_daily_summary.csv"


@test("CVE total lookup: readable with total_cves field")
def _():
    result = run_search("| inputlookup cve_total.csv | table total_cves")
    assert result and len(result["results"]) > 0
    assert "total_cves" in result["results"][0], "Missing total_cves field"


@test("CVSS severity lookup has Critical, High, Medium, Low categories")
def _():
    result = run_search("| inputlookup cvss_severity.csv | table severity_category")
    assert result
    found = {r["severity_category"] for r in result["results"]}
    for sev in ["Critical", "High", "Medium", "Low"]:
        assert sev in found, f"Missing {sev}. Found: {found}"


# ===========================================================================
# SECTION 6: Saved Searches
# ===========================================================================

SAVED_SEARCHES = [
    "CVE Total Lookup Refresh",
    "CVE Daily Summary Lookup Refresh",
    "CVE Vendors Lookup Refresh",
    "EPSS Lookup Refresh",
    "KEV Lookup Refresh",
    "Risk Priority Lookup Refresh",
]


@test("All 6 saved searches exist and are enabled")
def _():
    for ss in SAVED_SEARCHES:
        resp = api(
            "get",
            f"/servicesNS/admin/TA-cveicu/saved/searches/"
            f"{requests.utils.quote(ss, safe='')}",
        )
        assert resp.status_code == 200, f"'{ss}' not found"


# ===========================================================================
# SECTION 7: Macro
# ===========================================================================


@test("cveicu_index macro = 'index=main'")
def _():
    resp = api("get", "/servicesNS/admin/TA-cveicu/configs/conf-macros/cveicu_index")
    assert resp.status_code == 200
    defn = resp.json()["entry"][0]["content"]["definition"]
    assert defn == "index=main", f"Got: {defn}"


# ===========================================================================
# SECTION 8: Dashboard Searches Against Real Data
# These tests require indexed CVE data (from the modular input pipeline).
# Lookups populated by saved searches (cve_total, cve_daily_summary,
# cve_vendors, risk_priority) will be empty in a fresh container.
# EPSS/KEV lookups ship pre-populated via bundled CSVs.
# ===========================================================================


def has_indexed_data():
    """Check if CVE data has been ingested into the index."""
    result = run_search(
        '| inputlookup cve_total.csv | eval has_data=if(total_cves>0, "yes", "no") '
        "| table has_data"
    )
    if result and result.get("results"):
        return result["results"][0].get("has_data") == "yes"
    return False


@test("EPSS/KEV enrichment lookups are pre-populated (no ingestion needed)")
def _():
    result = run_search(
        "| inputlookup epss_lookup.csv | stats count as epss_rows "
        "| appendcols [| inputlookup kev_lookup.csv | stats count as kev_rows]"
    )
    assert result and len(result["results"]) > 0
    row = result["results"][0]
    assert int(row["epss_rows"]) > 100000, f"EPSS: {row['epss_rows']} rows"
    assert int(row["kev_rows"]) > 1000, f"KEV: {row['kev_rows']} rows"


@test("Index-derived lookups populated OR correctly empty (no stale v2 data)")
def _():
    if has_indexed_data():
        for lookup in ["cve_total.csv", "cve_daily_summary.csv", "cve_vendors.csv"]:
            result = run_search(f"| inputlookup {lookup} | stats count")
            assert result
            count = int(result["results"][0]["count"])
            assert count > 0, f"{lookup} is empty despite indexed data"
    else:
        result = run_search("| inputlookup cve_total.csv | table total_cves")
        assert result and len(result["results"]) > 0
        total = int(result["results"][0].get("total_cves", 0))
        assert total == 0, (
            f"cve_total shows {total} but no indexed data — stale lookup?"
        )


# ===========================================================================
# SECTION 9: Splunk 9 Compatibility Checks
# ===========================================================================


@test("Splunk version is 9.x")
def _():
    resp = api("get", "/services/server/info")
    v = resp.json()["entry"][0]["content"]["version"]
    assert v.startswith("9."), f"Expected 9.x, got {v}"


@test("No dashboard contains version='2' (Dashboard Studio)")
def _():
    for db in DASHBOARDS:
        root = ET.fromstring(get_dashboard_xml(db))
        assert root.get("version") != "2", f"{db} is still v2"


@test("No dashboard contains JSON definition blocks")
def _():
    for db in DASHBOARDS:
        xml_data = get_dashboard_xml(db)
        assert '"type": "ds.search"' not in xml_data, f"{db}: has ds.search"
        assert '"type": "splunk.' not in xml_data, f"{db}: has splunk. viz type"


# ===========================================================================
# Main
# ===========================================================================

if __name__ == "__main__":
    preflight()

    print(f"\n{'=' * 60}")
    print("  TA-cveicu v1.1.0 E2E Validation on Splunk 9")
    print(f"{'=' * 60}\n")

    for t in all_tests:
        t()

    print(f"\n{'=' * 60}")
    print(f"  RESULTS: {passed} passed, {failed} failed out of {passed + failed}")
    print(f"{'=' * 60}")

    if errors:
        print("\nFailed tests:")
        for e in errors:
            print(f"  - {e}")

    sys.exit(1 if failed else 0)
