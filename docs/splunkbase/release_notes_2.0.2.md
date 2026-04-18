## v2.0.2 — Fix: Reliable Lookup Population on Fresh Install

**Fix:** Removed `run_on_startup` from index-dependent saved searches and switched to tighter cron schedules (every 5-10 minutes). In v2.0.1, the `run_on_startup` flag caused saved searches to fire before the modular input finished ingesting baseline data (~2 minutes), producing empty lookup tables. Dashboards now fully populate within 10 minutes of install.

- CVE Total: refreshes every 5 minutes
- Daily Summary, Vendors, Risk Priority: refresh every 10 minutes
- EPSS and KEV: unchanged (external API fetches, not index-dependent)

---

## What's New in v2.0 (included in v2.0.2)

**Requires Splunk 10.0+ or Splunk Cloud.** Users on Splunk 9 should remain on v1.0.6.

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
2. Install v2.0.2 via Manage Apps
3. No data migration needed -- same sourcetypes and field extractions
4. If using a custom index, create local/macros.conf with your cveicu_index definition
