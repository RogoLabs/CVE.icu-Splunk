# TA-cveicu v2.0.0 Release Notes

**Release Date:** April 21, 2026

## Breaking Changes

### Requires Splunk 10.0+

All four dashboards are now built with Dashboard Studio v2 (`<dashboard version="2">`), which requires Splunk Enterprise 10.0+ or Splunk Cloud. Users on Splunk 9 should remain on v1.0.6.

### Setup Page Removed

The setup page UI has been removed. GitHub tokens are now stored via Splunk's REST API:

```
curl -k -u admin:<password> \
  https://localhost:8089/servicesNS/nobody/TA-cveicu/storage/passwords \
  -d name=github_api_token -d realm=TA-cveicu -d password=<your_token>
```

### Python 3.9 No Longer Tested

Python 3.9 reached EOL in October 2025. Splunk 10 ships Python 3.11.8. CI tests now run against Python 3.11 and 3.12 only.

## New Features

### Default Input Enabled on Install

The `cveicu://default` data input is now enabled out of the box. Data starts ingesting immediately after installation without needing to copy configs to `local/` or run a setup flow.

### Configurable Index Macro

All dashboards and saved searches reference the `cveicu_index` macro (defaults to `index=main`). Override it once in `local/macros.conf` and it updates everywhere:

```ini
[cveicu_index]
definition = index=cve_data
```

### Dashboard Studio Dashboards

Four new dashboards built with Dashboard Studio v2:

- **CVE Explorer** — Search and filter the full CVE database with vendor, severity, and CWE filters
- **Risk Priority** — Risk-ranked CVEs combining CVSS, EPSS, KEV, and SSVC signals
- **Vulnerability Landscape** — Executive-level overview with eight panels
- **Operational Health** — Technical diagnostics and enrichment status

### EPSS/KEV Risk Priority Scoring

Pre-computed risk priority scores combine CVSS base scores, EPSS exploit probability, CISA KEV status, and SSVC exploitation state into a single weighted score. Updated hourly via saved search.

### CI/CD Pipeline

GitHub Actions workflow with unit tests (Python 3.11, 3.12), Splunk AppInspect validation, and Docker-based integration tests (28 tests against a live Splunk instance).

## Bug Fixes

- **`replicate=true` removed from outputlookup** — This option is Splunk Cloud-only and caused all saved search dispatches to fail on Splunk Enterprise
- **Time-based charts use CVE publication date** — All dashboard charts now use `datePublished` instead of Splunk ingest time, eliminating misleading spikes when bulk data arrives at once
- **Saved search time ranges fixed** — Vendors and Risk Priority saved searches no longer use `dispatch.earliest_time` windows that break after the initial bulk ingest ages out
- **CVE Explorer time range picker removed** — The picker filtered on ingest `_time`, not publication date, producing incorrect results

## Removed

- `ta_cveicu_setup_handler.py` — Setup page REST handler (402 lines)
- `fetch_epss_kev.py` — Dead duplicate of `cveicu_epss_kev_command.py`
- `restmap.conf` — Setup handler endpoint
- `web.conf` — Setup page web exposure
- `appserver/` — Empty setup UI asset directory

## Upgrade Instructions

1. Ensure you are running **Splunk Enterprise 10.0+** or Splunk Cloud
2. Download TA-cveicu 2.0.0 from Splunkbase
3. Go to **Apps > Manage Apps > Install app from file**
4. Upload the package and check **Upgrade app**
5. Restart Splunk if prompted
6. (Optional) Store a GitHub token via the REST API for higher rate limits
7. (Optional) Set `cveicu_index` macro if using a non-default index
