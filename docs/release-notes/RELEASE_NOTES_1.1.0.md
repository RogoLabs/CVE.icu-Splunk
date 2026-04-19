# TA-cveicu v1.1.0 Release Notes

**Release Date:** April 19, 2026

## Overview

v1.1.0 is a Splunk 9 backport of v2.0.x. It delivers the same data pipeline, enrichment, and dashboard functionality using SimpleXML instead of Dashboard Studio v2. This release exists for users who cannot upgrade to Splunk 10.

## Requirements

- Splunk Enterprise 9.3+ or Splunk Cloud (9.x)
- Python 3.9+ (bundled with Splunk 9)
- No external dependencies or API keys required

## What's New (vs v1.0.6)

### All v2.0 Features, Splunk 9 Compatible

- **CVE Explorer** — Search/filter CVEs by vendor, severity, CWE. Publication trend chart + detailed records table.
- **Risk Priority** — EPSS/KEV triage dashboard with score distribution, KEV filtering, and enriched risk table.
- **Vulnerability Landscape** — Executive overview with 8 panels: total CVEs, weekly new, severity distribution, top vendors, publication trends, CISA KEV growth.
- **Operational Health** — Diagnostics: last run time, error count, enrichment lookup sizes, audit events, daily volume chart.

### EPSS/KEV Enrichment Pipeline

- EPSS bulk data from FIRST (327K+ CVE scores) via custom search command
- CISA KEV catalog (1,500+ known exploited vulnerabilities)
- Risk Priority lookup joins CVSS + EPSS + KEV at search time
- All lookups refresh automatically via saved searches

### Default Input Enabled on Install

The `cveicu://default` data input is enabled out of the box. Data starts ingesting immediately — no setup page or manual configuration required.

### Configurable Index Macro

All dashboards and saved searches use the `cveicu_index` macro (defaults to `index=main`). Override once in `local/macros.conf`:

```ini
[cveicu_index]
definition = index=cve_data
```

## Key Differences from v2.0.x

| Feature          | v1.1.x                            | v2.0.x              |
| ---------------- | --------------------------------- | ------------------- |
| Dashboard format | SimpleXML (`version="1.1"`)       | Dashboard Studio v2 |
| Minimum Splunk   | 9.3+                              | 10.0+               |
| Python tested    | 3.9, 3.11, 3.12                   | 3.11, 3.12          |
| urllib3          | 1.26.x (OpenSSL 1.0.2 compatible) | 2.x                 |
| Data pipeline    | Identical                         | Identical           |
| Enrichment       | Identical                         | Identical           |

## Bug Fixes (vs v1.0.6)

- **Modular input registration** — `--scheme` handler runs before any library imports, preventing silent registration failures on Splunk 9
- **urllib3 compatibility** — Vendored urllib3 downgraded to 1.26.x for Splunk 9's OpenSSL 1.0.2
- **`replicate=true` removed from outputlookup** — Was causing saved search failures on Splunk Enterprise
- **Time-based charts use CVE publication date** — No more misleading spikes from bulk ingest timing
- **Dashboard version attribute** — All dashboards include `version="1.1"` to prevent the "dashboard version is missing" warning banner

## Install

1. Download the v1.1.0 release from the [v1.x branch](https://github.com/RogoLabs/CVE.icu-Splunk/tree/v1.x)
2. Go to **Apps > Manage Apps > Install app from file**
3. Upload the package and restart Splunk if prompted
4. Data ingestion starts automatically within minutes
5. EPSS/KEV lookups populate on first startup via saved searches

## Verified On

- Splunk Enterprise 9.4.10 (build 3673ab0c12ee)
- 32/32 E2E validation tests passing
- Full pipeline: 327,684 CVE records ingested and all dashboards populated
