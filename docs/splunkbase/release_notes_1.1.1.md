## v1.1.1 — Fix: Splunk Cloud Compatibility

**Fix:** Added `python.required = python3` to the modular input and custom search command configurations. Splunk's updated Cloud vetting process now requires this setting in addition to `python.version = python3`. Without it, the app loses Splunk Cloud Platform compatibility. No functional changes — data pipeline, enrichment, and dashboards are identical to v1.1.0.

---

## What's New in v1.1 (included in v1.1.1)

**Compatible with Splunk 9.3+ and Splunk Cloud (9.x).** Backport of all v2.0 features using SimpleXML dashboards.

### Features

- Four SimpleXML dashboards: CVE Explorer, Risk Priority, Vulnerability Landscape, and Operational Health
- EPSS enrichment: Daily FIRST EPSS scores via custom search command
- CISA KEV integration: Known Exploited Vulnerabilities catalog refreshed every 6 hours
- Risk Priority lookup: Pre-computed table combining CVSS, EPSS, KEV, and SSVC data for fast triage
- Zero-configuration start: Input enabled by default, data starts flowing immediately after install
- Configurable index macro: All dashboards and saved searches use the cveicu_index macro

### Key Differences from v2.0.x

- SimpleXML dashboards instead of Dashboard Studio v2
- Splunk 9.3+ instead of Splunk 10+
- Python 3.9+ instead of 3.11+
- urllib3 1.26.x for OpenSSL 1.0.2 compatibility
- Same data pipeline and enrichment as v2.0.x
