# TA-cvelist-v5

Splunk Technology Add-on for CVE List V5 data ingestion from the CVEProject/cvelistV5 GitHub repository.

## Overview

This add-on ingests CVE (Common Vulnerabilities and Exposures) V5 records from the 
[CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) GitHub repository into Splunk.

### Key Features

- **Efficient Bulk Download**: Uses GitHub Release ZIP files instead of per-file API calls
- **Incremental Updates**: Baseline load followed by hourly delta processing
- **Full CVE V5 Schema Support**: Extracts cveMetadata, CNA containers, and ADP enrichment
- **CVSS Score Extraction**: Parses CVSS v2.0, v3.0, v3.1, and v4.0 scores
- **CISA-ADP Integration**: Includes CISA Authorized Data Publisher enrichment
- **Secure Credential Storage**: GitHub token stored via Splunk's encrypted storage
- **Cloud Compatible**: Meets Splunk Cloud and AppInspect vetting requirements

## Requirements

- Splunk Enterprise 8.2+ or Splunk Cloud
- Python 3.7+ (bundled with Splunk 8.x+)
- Network access to GitHub API (api.github.com)

## Installation

### From Splunkbase

1. Download TA-cvelist-v5 from Splunkbase
2. Go to **Apps > Manage Apps > Install app from file**
3. Upload the `.spl` or `.tar.gz` package
4. Restart Splunk if prompted

### Manual Installation

1. Extract the add-on to `$SPLUNK_HOME/etc/apps/`
2. Restart Splunk

## Configuration

### Step 1: Configure GitHub Token (Recommended)

A GitHub Personal Access Token increases API rate limits from 60 to 5,000 requests/hour.

1. Create a GitHub token at **Settings > Developer settings > Personal access tokens > Tokens (classic)**
2. Select scope: `public_repo` (read access to public repositories)
3. In Splunk, go to **Apps > TA-cvelist-v5 > Setup**
4. Enter your GitHub Personal Access Token
5. Click **Save**

### Step 2: Create Data Input

1. Go to **Settings > Data Inputs > CVE List V5**
2. Click **New**
3. Configure:
   - **Name**: Unique input name (e.g., `cve_feed`)
   - **Index**: Destination index for CVE events
   - **Include ADP Data**: Include CISA-ADP and CVE Program Container data (default: true)
   - **Include Rejected**: Include CVEs with REJECTED state (default: true)
   - **Batch Size**: Records per batch (default: 500)
4. Click **Save**

### Input Configuration (inputs.conf)

```ini
[cvelist_v5://cve_production]
index = cve_data
include_adp = true
include_rejected = true
batch_size = 500
interval = 3600
```

## Sourcetypes

| Sourcetype | Description |
|------------|-------------|
| `ta:cvelist:v5:record` | CVE vulnerability records (primary data) |
| `ta:cvelist:v5:error` | Error events during processing |
| `ta:cvelist:v5:audit` | Audit and operational events |

## Extracted Fields

### Core CVE Fields
- `cve_id` - CVE identifier (e.g., CVE-2024-1234)
- `state` - Record state (PUBLISHED, REJECTED)
- `date_published` - Initial publication date
- `date_updated` - Last modification date
- `assigner` - Assigning CNA short name
- `title` - Vulnerability title
- `description` - Vulnerability description

### Affected Products (Multi-value)
- `affected_vendor` - Affected vendor names
- `affected_product` - Affected product names
- `cwe_id` - Associated CWE identifiers

### CVSS Scores
- `cvss_v40_score`, `cvss_v40_severity`, `cvss_v40_vector`
- `cvss_v31_score`, `cvss_v31_severity`, `cvss_v31_vector`
- `cvss_v30_score`, `cvss_v30_severity`, `cvss_v30_vector`
- `cvss_v20_score`, `cvss_v20_vector`

### ADP Enrichment
- `has_cisa_adp` - Boolean: CISA-ADP data present
- `has_cve_program_container` - Boolean: CVE Program Container present
- `cisa_ssvc` - CISA SSVC decision tree data (JSON)

## Example Searches

### High Severity CVEs (Last 7 Days)
```spl
index=cve_data sourcetype="ta:cvelist:v5:record" 
| where cvss_v31_score >= 9.0 OR cvss_v40_score >= 9.0
| eval severity=coalesce(cvss_v40_severity, cvss_v31_severity, "Unknown")
| table cve_id, title, severity, affected_vendor, affected_product
```

### CVEs by Vendor
```spl
index=cve_data sourcetype="ta:cvelist:v5:record"
| mvexpand affected_vendor
| stats count by affected_vendor
| sort -count
| head 20
```

### CVEs with CISA-ADP Enrichment
```spl
index=cve_data sourcetype="ta:cvelist:v5:record" has_cisa_adp=true
| spath input=cisa_ssvc
| table cve_id, title, cisa_ssvc
```

### New CVEs by Day
```spl
index=cve_data sourcetype="ta:cvelist:v5:record"
| timechart span=1d count
```

## Troubleshooting

### Check Input Status
```spl
index=_internal sourcetype=splunkd component=ModularInputs "cvelist_v5"
```

### Check Add-on Logs
```spl
index=_internal source="*TA-cvelist-v5.log*"
```

### Verify Checkpoint
```spl
| inputlookup ta_cvelist_v5_checkpoints
```

### Common Issues

| Issue | Solution |
|-------|----------|
| Rate limit errors | Configure GitHub Personal Access Token |
| No events ingested | Check network connectivity to api.github.com |
| Incomplete initial load | Allow sufficient time; baseline contains 200K+ CVEs |
| Memory errors | Reduce batch_size parameter |

## Data Volume Estimates

- **Initial Load**: ~200,000+ CVE records (~2-3 GB indexed)
- **Daily Updates**: ~50-200 new/updated CVEs (~10-50 MB/day)
- **Hourly Deltas**: ~5-20 CVEs per delta release

## Architecture

```
GitHub CVEProject/cvelistV5
    │
    ├── Releases
    │   ├── cve_X.X.X (baseline) → all_CVEs.zip
    │   └── cve_X.X.X_YYYYMMDD_HHMM (delta) → deltaCves.zip
    │
    ▼
TA-cvelist-v5 Modular Input
    │
    ├── Download ZIP (streaming)
    ├── Parse CVE JSON records
    ├── Extract fields (CVSS, CWE, affected products)
    └── Write events to Splunk
    │
    ▼
Splunk Index
    └── sourcetype=ta:cvelist:v5:record
```

## Support

- **Issues**: [GitHub Issue Tracker](https://github.com/your-repo/TA-cvelist-v5/issues)
- **Documentation**: See `plan.md` for detailed technical design

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024 | Initial release |

## License

Apache License 2.0 - See [LICENSE](LICENSE) file
