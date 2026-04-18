# CVE Intelligence Powered by cve.icu

This Splunk Technology Add-on ingests the complete CVE V5 database (327,000+ vulnerabilities) from the official [CVE Program repository](https://github.com/CVEProject/cvelistV5) into Splunk. Data starts flowing immediately after installation -- no API keys, setup pages, or manual configuration required.

## How It Works

1. **Install the add-on** -- the modular input is enabled by default
2. **Initial baseline load** downloads a ZIP of all published CVEs (~490MB) and ingests 327,000+ records in minutes
3. **Hourly delta updates** pull only new and modified CVEs, typically 5-20 records per cycle
4. **Enrichment lookups** refresh automatically: EPSS scores daily, KEV catalog every 6 hours

## Data Enrichment

The add-on combines four threat intelligence sources at search time:

| Source                            | Description                                                                          | Refresh              |
| --------------------------------- | ------------------------------------------------------------------------------------ | -------------------- |
| **CVSS** (v2.0, v3.0, v3.1, v4.0) | Vulnerability severity scores extracted from CVE records                             | With each CVE update |
| **FIRST EPSS**                    | Exploit Prediction Scoring System -- probability a CVE will be exploited in the wild | Daily                |
| **CISA KEV**                      | Known Exploited Vulnerabilities catalog -- confirmed active exploitation             | Every 6 hours        |
| **CISA SSVC**                     | Stakeholder-Specific Vulnerability Categorization from ADP containers                | With each CVE update |

## Dashboards (Splunk 10+ required)

Four Dashboard Studio v2 dashboards are included:

- **CVE Explorer** -- Search and filter the full CVE database by vendor, severity, CWE, or keyword. Includes a 30-day publication sparkline and paginated results table.
- **Risk Priority** -- Triage view combining CVSS, EPSS, KEV, and SSVC signals. Filter by EPSS threshold or KEV-only to focus on the most exploitable vulnerabilities.
- **Vulnerability Landscape** -- Executive overview with total CVE count, new this week, severity distribution, top vendors, weekly publication trends, and KEV growth over time.
- **Operational Health** -- Technical diagnostics showing last successful run, error count, ingestion volume, enrichment lookup status, and recent audit events.

## Extracted Fields

### Core CVE Fields

- `cve_id` -- CVE identifier (e.g., CVE-2024-1234)
- `state` -- PUBLISHED or REJECTED
- `date_published`, `date_updated` -- Publication and modification dates
- `title`, `description` -- Vulnerability details
- `affected_vendor`, `affected_product` -- Impacted software
- `cwe_id` -- Weakness classification

### CVSS Scores

- `cvss_score` -- Best available score (v4.0 > v3.1 > v3.0 > v2.0)
- `cvss_severity` -- Best available severity (CRITICAL, HIGH, MEDIUM, LOW)
- Version-specific fields: `cvss_v40_score`, `cvss_v31_score`, `cvss_v30_score`, `cvss_v20_score`

### Enrichment Fields (via lookups)

- `epss_score` -- Exploit probability (0-1)
- `in_kev` -- Whether the CVE is in the CISA KEV catalog
- `ssvc_exploitation` -- SSVC exploitation status (active, poc, none)

## Sourcetypes

| Sourcetype      | Description                              |
| --------------- | ---------------------------------------- |
| `cveicu:record` | CVE vulnerability records (primary data) |
| `cveicu:error`  | Error events during processing           |
| `cveicu:audit`  | Audit and operational events             |

## Configuration

### Changing the Index

All dashboards and saved searches use the `cveicu_index` macro, which defaults to `index=main`. To use a different index, create `local/macros.conf`:

```
[cveicu_index]
definition = index=your_cve_index
```

### GitHub Token (Optional)

The add-on works without authentication using GitHub's public API (60 requests/hour). This is sufficient for normal operation since each hourly run requires only 1-2 API calls. If you share an IP with heavy GitHub API usage and see rate limit errors, you can add a token for 5,000 requests/hour:

```
curl -k -u admin:yourpassword \
  https://localhost:8089/servicesNS/nobody/TA-cveicu/storage/passwords \
  -d name=github_api_token -d realm=TA-cveicu -d password=your_token
```

### Input Parameters

| Parameter          | Default | Description                      |
| ------------------ | ------- | -------------------------------- |
| `interval`         | 3600    | Polling interval in seconds      |
| `include_adp`      | true    | Include CISA-ADP enrichment data |
| `include_rejected` | false   | Include rejected/withdrawn CVEs  |
| `batch_size`       | 500     | Records per processing batch     |

## CIM Compatibility

Fields are mapped to the [Splunk CIM Vulnerabilities](https://docs.splunk.com/Documentation/CIM/latest/User/Vulnerabilities) data model: `vulnerability_id`, `cvss`, `severity_id`, `vendor_product`, `dest`, `signature`, `category`.

## Requirements

- Splunk Enterprise 10.0+ or Splunk Cloud (dashboards require Dashboard Studio v2)
- Network access to github.com and api.github.com
- Approximately 2-3 GB of index storage for the full CVE database

## Support

- Issues: [GitHub Issue Tracker](https://github.com/RogoLabs/CVE.icu-Splunk/issues)
- Website: [cve.icu](https://cve.icu)
