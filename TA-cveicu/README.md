# TA-cveicu - CVE Intelligence for Splunk

<p align="center">
  <img src="https://cve.icu/static/images/logo.png" alt="cve.icu Logo" width="120"/>
</p>

Splunk Technology Add-on for ingesting the complete CVE database from the official CVE Program repository.

Powered by [cve.icu](https://cve.icu) - Fast, searchable CVE lookup service.

## Overview

This add-on ingests CVE (Common Vulnerabilities and Exposures) V5 records from the
[CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) GitHub repository into Splunk.

### Key Features

- **Efficient Bulk Download**: Uses GitHub Release ZIP files instead of per-file API calls
- **Incremental Updates**: Baseline load followed by hourly delta processing
- **Full CVE V5 Schema Support**: Extracts cveMetadata, CNA containers, and ADP enrichment
- **CVSS Score Extraction**: Parses CVSS v2.0, v3.0, v3.1, and v4.0 scores
- **CISA-ADP Integration**: Includes CISA Authorized Data Publisher enrichment
- **EPSS Enrichment**: Daily FIRST EPSS scores via bulk CSV download
- **CISA KEV Enrichment**: Known Exploited Vulnerabilities catalog updated every 6 hours
- **Risk Priority Scoring**: Pre-computed risk scores combining CVSS, EPSS, KEV, and SSVC data
- **Secure Credential Storage**: GitHub token stored via Splunk's encrypted storage
- **Cloud Compatible**: Meets Splunk Cloud and AppInspect vetting requirements

## Requirements

- **Splunk Enterprise 10.0+** or **Splunk Cloud**
- Python 3.11+ (bundled with Splunk 10)
- Network access to GitHub API (api.github.com)

> **Splunk 9 users:** v2.0.x requires Splunk 10+. If you're on Splunk 9, use [v1.1.2](https://splunkbase.splunk.com/app/8395). See [Splunk 9 End of Support](#splunk-9-end-of-support) below.

## Installation

### From Splunkbase

1. Download [TA-cveicu from Splunkbase](https://splunkbase.splunk.com/app/8395)
2. Go to **Apps > Manage Apps > Install app from file**
3. Upload the `.spl` or `.tar.gz` package
4. Restart Splunk if prompted

### Manual Installation

1. Extract the add-on to `$SPLUNK_HOME/etc/apps/`
2. Restart Splunk

## Configuration

The add-on starts ingesting CVE data immediately after installation using a default input. No setup is required for basic operation.

### GitHub Token (Optional but Recommended)

The add-on works without authentication, but GitHub's unauthenticated API rate limit is **60 requests/hour** — shared across all unauthenticated traffic from your IP. If you run other tools that call the GitHub API (CLI, CI/CD, IDE plugins, etc.), you may exhaust this limit and see "rate limit exceeded" errors.

A GitHub Personal Access Token increases this to **5,000 requests/hour**:

1. Create a token at **Settings > Developer settings > Personal access tokens > Tokens (classic)**
2. Select scope: `public_repo` (read-only access to public repositories)
3. In Splunk, store the token via the REST API:
   ```
   curl -k -u admin:<password> \
     https://localhost:8089/servicesNS/nobody/TA-cveicu/storage/passwords \
     -d name=github_api_token -d realm=TA-cveicu -d password=<your_token>
   ```

> **Note:** Most users with light GitHub API usage will not hit the rate limit. The initial baseline download requires only a few API calls. If you see "GitHub API rate limit exceeded" errors in the add-on logs, configuring a token will resolve the issue.

### Customizing the Data Input

The default input writes to `index=main` with hourly polling. To customize:

```ini
# local/inputs.conf
[cveicu://default]
index = cve_data
include_adp = true
include_rejected = false
batch_size = 500
interval = 3600
```

You can also create additional inputs via **Settings > Data Inputs > cve.icu**.

### Changing the Index

All dashboards and saved searches use the `cveicu_index` macro (defaults to `index=main`). To use a different index:

```ini
# local/macros.conf
[cveicu_index]
definition = index=cve_data
```

## Sourcetypes

| Sourcetype      | Description                              |
| --------------- | ---------------------------------------- |
| `cveicu:record` | CVE vulnerability records (primary data) |
| `cveicu:error`  | Error events during processing           |
| `cveicu:audit`  | Audit and operational events             |

## Extracted Fields

### Core CVE Fields

- `cve_id` - CVE identifier (e.g., CVE-2024-1234)
- `state` - Record state (PUBLISHED, REJECTED)
- `date_published` - Initial publication date
- `date_updated` - Last modification date
- `assigner` - Assigning CNA short name
- `title` - Vulnerability title
- `description` - Vulnerability description

### Affected Products

- `affected_vendor` - Primary affected vendor name
- `affected_product` - Primary affected product name
- `cwe_id` - Primary CWE identifier

### CVSS Scores

- `cvss_v40_score`, `cvss_v40_severity`, `cvss_v40_vector` - CVSS v4.0
- `cvss_v31_score`, `cvss_v31_severity`, `cvss_v31_vector` - CVSS v3.1
- `cvss_v30_score`, `cvss_v30_severity`, `cvss_v30_vector` - CVSS v3.0
- `cvss_v20_score`, `cvss_v20_vector` - CVSS v2.0
- `cvss_score` - Best available CVSS score (v4.0 > v3.1 > v3.0 > v2.0)
- `cvss_severity` - Best available severity rating

### ADP Enrichment

- `has_cisa_adp` - Boolean: CISA-ADP data present
- `has_cve_program_container` - Boolean: CVE Program Container present
- `cisa_ssvc` - CISA SSVC decision tree data (JSON)

### CIM Vulnerabilities Data Model

The following fields map to the [Splunk CIM Vulnerabilities](https://docs.splunk.com/Documentation/CIM/latest/User/Vulnerabilities) data model:

- `vulnerability_id` - CVE identifier
- `cvss` - Best available CVSS score
- `severity_id` - CVSS score (numeric severity)
- `vendor_product` - Affected vendor
- `dest` - CVE identifier (destination)
- `signature` - CVE identifier
- `signature_id` - CVE identifier
- `category` - CWE classification

## Example Searches

### High Severity CVEs (Last 7 Days)

```spl
index=<your_cve_index> sourcetype="cveicu:record"
| where cvss_v31_score >= 9.0 OR cvss_v40_score >= 9.0
| eval severity=coalesce(cvss_v40_severity, cvss_v31_severity, "Unknown")
| table cve_id, title, severity, affected_vendor, affected_product
```

### CVEs by Vendor

```spl
index=<your_cve_index> sourcetype="cveicu:record"
| mvexpand affected_vendor
| stats count by affected_vendor
| sort -count
| head 20
```

### CVEs with CISA-ADP Enrichment

```spl
index=<your_cve_index> sourcetype="cveicu:record" has_cisa_adp=true
| spath input=cisa_ssvc
| table cve_id, title, cisa_ssvc
```

### New CVEs by Day

```spl
index=<your_cve_index> sourcetype="cveicu:record"
| timechart span=1d count
```

## Troubleshooting

### Check Input Status

```spl
index=_internal sourcetype=splunkd component=ModularInputs "cveicu"
```

### Check Add-on Logs

```spl
index=_internal source="*TA-cveicu.log*"
```

### Verify Checkpoint

```spl
| inputlookup ta_cveicu_checkpoints
```

### Common Issues

| Issue                   | Solution                                            |
| ----------------------- | --------------------------------------------------- |
| Rate limit errors       | Configure GitHub Personal Access Token              |
| No events ingested      | Check network connectivity to api.github.com        |
| Incomplete initial load | Allow sufficient time; baseline contains 300K+ CVEs |
| Memory errors           | Reduce batch_size parameter                         |

## Data Volume Estimates

- **Initial Load**: ~300,000+ CVE records (~2-3 GB indexed)
- **Daily Updates**: ~50-200 new/updated CVEs (~10-50 MB/day)
- **Hourly Deltas**: ~5-20 CVEs per delta release

## EPSS/KEV Enrichment

Scheduled saved searches automatically refresh enrichment lookups:

| Saved Search          | Schedule      | Source                | Lookup                   |
| --------------------- | ------------- | --------------------- | ------------------------ |
| EPSS Lookup Refresh   | Daily at 6 AM | FIRST EPSS bulk CSV   | epss_lookup.csv          |
| KEV Lookup Refresh    | Every 6 hours | CISA KEV catalog      | kev_lookup.csv           |
| Risk Priority Refresh | Every 30 min  | Computed from lookups | risk_priority_lookup.csv |

These lookups are joined at search time via `transforms.conf` to enrich CVE data with exploit probability scores, known exploitation status, and computed risk priority.

## Architecture

```
GitHub CVEProject/cvelistV5
    │
    ├── Releases
    │   ├── cve_X.X.X (baseline) → all_CVEs.zip
    │   └── cve_X.X.X_YYYYMMDD_HHMM (delta) → deltaCves.zip
    │
    ▼
TA-cveicu Modular Input
    │
    ├── Download ZIP (streaming)
    ├── Parse CVE JSON records
    ├── Extract fields (CVSS, CWE, affected products)
    └── Write events to Splunk
    │
    ▼
Splunk Index                          Enrichment Lookups
    └── sourcetype=cveicu:record          ├── FIRST EPSS bulk CSV → epss_lookup.csv
                                          ├── CISA KEV  → kev_lookup.csv
                                          └── Combined  → risk_priority_lookup.csv
```

## Dashboards

v2.0.0 includes four Dashboard Studio dashboards (requires Splunk 10+):

### CVE Explorer

Search and filter the full CVE database. Includes a publication sparkline (last 30 days), filterable table with vendor/severity/CWE dropdowns, and date-sorted results.

### Risk Priority

Risk-ranked CVE table combining CVSS, EPSS, KEV, and SSVC signals. Filter by EPSS threshold or KEV-only to focus on the highest-risk vulnerabilities. Includes an EPSS score distribution chart and single-value panels for KEV count and high-EPSS CVEs.

### Vulnerability Landscape

Executive-level overview with eight panels: total CVEs, new this week, critical+high count, EPSS >0.5% percentage, severity distribution, top 10 vendors, weekly publication trend, and CISA KEV growth over time.

### Operational Health

Technical diagnostics: last successful run, error count (24h), total events ingested, enrichment lookup sizes, recent audit events, daily volume by publication date, and recent errors/warnings from splunkd.

## Splunk 9 End of Support

**v2.0.0 requires Splunk Enterprise 10.0+ or Splunk Cloud.** Users on Splunk 9 should remain on v1.0.6.

### Why Splunk 10+?

All four dashboards are built with **Dashboard Studio v2** (`<dashboard version="2">`), which uses a JSON definition format introduced in Splunk 10. SimpleXML dashboards from Splunk 9 and earlier are not compatible with Dashboard Studio, and vice versa. Rewriting the dashboards in the modern framework was necessary to support the enrichment panels, risk scoring visualizations, and filter interactions that v2.0.0 provides.

### What Changed from v1.x

| Area          | v1.x (Splunk 9)                 | v2.0.0 (Splunk 10+)                                         |
| ------------- | ------------------------------- | ----------------------------------------------------------- |
| Dashboards    | SimpleXML                       | Dashboard Studio v2 (JSON)                                  |
| Setup         | Setup page UI                   | REST API credential storage                                 |
| Default input | Disabled, requires manual setup | Enabled on install                                          |
| Index config  | Hardcoded `index=main`          | Configurable via `cveicu_index` macro                       |
| Python        | 3.7+ (tested 3.9)               | 3.11+ (tested 3.11, 3.12)                                   |
| CI/CD         | None                            | GitHub Actions (unit tests, AppInspect, Docker integration) |

### Migrating from v1.x

1. **Upgrade Splunk first** — v2.0.0 will not render dashboards on Splunk 9
2. **Install v2.0.0** — standard upgrade process via Manage Apps
3. **No data migration required** — same sourcetypes (`cveicu:record`, `cveicu:error`, `cveicu:audit`) and field extractions
4. **Custom local/ overrides carry forward** — if you customized `inputs.conf` or other configs in `local/`, they still work
5. **Set your index** — if you use a non-default index, create `local/macros.conf` with your `cveicu_index` definition (see [Changing the Index](#changing-the-index))

### Python 3.9 EOL

Python 3.9 reached end-of-life in October 2025. Splunk 10.0 ships Python 3.11.8 — there is no supported Splunk 10 environment that runs Python 3.9. The CI test matrix for v2.0.0 tests against Python 3.11 and 3.12 only. All vendored dependencies in `bin/lib/` are compatible with Python 3.11+.

## Support

- **Issues**: [GitHub Issue Tracker](https://github.com/RogoLabs/CVE.icu-Splunk/issues)
- **Website**: [cve.icu](https://cve.icu)

## Version History

| Version | Date       | Changes                                                                                                                |
| ------- | ---------- | ---------------------------------------------------------------------------------------------------------------------- |
| 2.0.0   | 2026-04-21 | Splunk 10+ required, Dashboard Studio v2, `cveicu_index` macro, CI pipeline, default input enabled, setup page removed |
| 1.0.6   | 2026-04-14 | Fix modular input registration on systems with missing SSL libs                                                        |
| 1.0.5   | 2026-04-14 | Fix field extractions and modular input registration                                                                   |
| 1.0.4   | 2026-04-14 | Rename data input to "cve.icu" for discoverability                                                                     |
| 1.0.3   | 2026-04-06 | Fix temp ZIP file cleanup preventing /tmp disk exhaustion                                                              |
| 1.0.2   | 2026-04-05 | Fix EPSS/KEV lookup refresh on Splunk Cloud                                                                            |
| 1.0.1   | 2026-02-16 | Remove upper bound from Splunk version requirement                                                                     |
| 1.0.0   | 2026-01-22 | Initial release                                                                                                        |

## License

Apache License 2.0 - See [LICENSE](LICENSE)
