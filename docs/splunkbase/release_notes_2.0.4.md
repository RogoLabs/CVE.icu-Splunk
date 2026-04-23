## v2.0.4 — Fix: Splunk Cloud Compatibility

**Fix:** Added `python.required = 3.13` to the modular input and custom search command configurations. Splunk's updated Cloud vetting process now requires this setting in addition to `python.version = python3`. Without it, the app loses Splunk Cloud Platform compatibility. No functional changes — data pipeline, enrichment, and dashboards are identical to v2.0.3.

---

## What's New in v2.0 (included in v2.0.4)

**Requires Splunk 10.0+ or Splunk Cloud.** Users on Splunk 9 should remain on v1.1.1.

### New Features

- Four Dashboard Studio v2 dashboards: CVE Explorer, Risk Priority, Vulnerability Landscape, and Operational Health
- EPSS enrichment: Daily FIRST EPSS scores joined at search time for exploit probability ranking
- CISA KEV integration: Known Exploited Vulnerabilities catalog refreshed every 6 hours
- SSVC decision data: CISA Stakeholder-Specific Vulnerability Categorization from ADP containers
- Risk Priority lookup: Pre-computed table combining CVSS, EPSS, KEV, and SSVC data for fast triage
- Zero-configuration start: Input enabled by default, data starts flowing immediately after install
- Configurable index macro: All dashboards and saved searches use the cveicu_index macro
- CIM Vulnerabilities data model mapping
- CI/CD pipeline: GitHub Actions with unit tests, AppInspect validation, and Docker integration tests

### Improvements

- CVSS v4.0 support in addition to v3.1, v3.0, and v2.0
- Multi-value field extractions for CWE IDs, vendors, products, and references
- Pre-computed dashboard lookups for instant panel loading
- Expanded CWE lookup: 298 unique entries covering CWE Top 25, OWASP Top 10, and more
- Cooperative timeout management and memory monitoring (512MB limit)

### Breaking Changes from v1.x

- Splunk 10+ required for dashboards (Dashboard Studio v2)
- Setup page removed: GitHub token configured via REST API
- Python 3.11+ required (3.9 dropped)

### Migration from v1.x

1. Upgrade Splunk to 10.0+ first
2. Install v2.0.4 via Manage Apps
3. No data migration needed -- same sourcetypes and field extractions
4. If using a custom index, create local/macros.conf with your cveicu_index definition
