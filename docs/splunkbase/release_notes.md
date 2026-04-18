## v2.0.0 — Major Release

**Requires Splunk 10.0+ or Splunk Cloud.** Users on Splunk 9 should remain on v1.0.6.

### New Features

- **Four Dashboard Studio v2 dashboards:** CVE Explorer, Risk Priority, Vulnerability Landscape, and Operational Health — all built with Dashboard Studio's JSON format for Splunk 10+
- **EPSS enrichment:** Daily bulk download of FIRST EPSS scores via custom search command, joined at search time
- **CISA KEV enrichment:** Known Exploited Vulnerabilities catalog refreshed every 6 hours
- **SSVC decision data:** CISA Stakeholder-Specific Vulnerability Categorization extracted from ADP containers
- **Risk Priority lookup:** Pre-computed table combining CVSS, EPSS, KEV, and SSVC data for fast triage
- **Zero-configuration start:** Input is enabled by default — data starts flowing immediately after installation with no API keys or setup pages required
- **Configurable index macro:** All dashboards and saved searches use the `cveicu_index` macro, overridable in `local/macros.conf`
- **CIM Vulnerabilities data model mapping:** Fields mapped to the Splunk CIM Vulnerabilities data model
- **CI/CD pipeline:** GitHub Actions with unit tests (Python 3.11/3.12), AppInspect validation, and Docker integration tests

### Improvements

- **CVSS v4.0 support:** Extracts CVSS v4.0 scores in addition to v3.1, v3.0, and v2.0
- **Multi-value field extractions:** CWE IDs, vendors, products, and references extracted via regex transforms for proper multi-value handling
- **Pre-computed dashboard lookups:** Saved searches refresh KPI lookups on a schedule so dashboards load instantly without running expensive searches
- **Expanded CWE lookup:** 298 unique CWE entries covering CWE Top 25, OWASP Top 10, memory safety, injection, auth, and crypto categories
- **Cooperative timeout management:** Modular input checks elapsed time between batches to avoid Splunk Watchdog kills
- **Memory monitoring:** Warns at 80% and pauses at 90% of the 512MB limit

### Breaking Changes

- **Splunk 10+ required:** Dashboard Studio v2 dashboards do not render on Splunk 9
- **Setup page removed:** GitHub token is now configured via REST API (`storage/passwords`) instead of a setup page UI
- **Python 3.11+ required:** Python 3.9 support dropped (EOL October 2025, not shipped with any Splunk 10 release)

### Migration from v1.x

1. Upgrade Splunk to 10.0+ first
2. Install v2.0.0 — standard upgrade via Manage Apps
3. No data migration needed — same sourcetypes and field extractions
4. If using a custom index, create `local/macros.conf` with your `cveicu_index` definition
