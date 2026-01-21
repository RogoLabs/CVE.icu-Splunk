# cve.icu - Splunk Add-on for CVE List V5

<p align="center">
  <img src="https://cve.icu/static/images/logo.png" alt="cve.icu Logo" width="120"/>
</p>

A Splunk Technology Add-on (TA) that ingests the complete CVE (Common Vulnerabilities and Exposures) database from the official [CVE List V5 GitHub repository](https://github.com/CVEProject/cvelistV5). This add-on provides real-time vulnerability intelligence directly in your Splunk environment.

## Features

- **Complete CVE Database**: Ingests 300,000+ published CVEs from the official CVE List V5 repository
- **Incremental Updates**: Smart checkpointing ensures only new/updated CVEs are fetched after initial load
- **Rich Data Extraction**: Parses all CVE metadata including:
  - CVSS scores (v2, v3.0, v3.1, v4.0)
  - CWE classifications
  - Affected vendors and products
  - References and advisories
  - Problem types and descriptions
- **Pre-built Dashboard**: Beautiful "CVE Sentinel" dashboard with:
  - Real-time KPI panels (Total CVEs, Critical, High, Medium, Low counts)
  - CVE severity distribution over time
  - Top affected vendors and products
  - CWE category breakdown
  - Searchable CVE table with drill-down
- **Lookup-based Performance**: KPI data stored in lookups for instant dashboard loading
- **GitHub API Integration**: Efficient tree-based fetching with configurable rate limiting

## Requirements

- Splunk Enterprise 8.x or later
- Python 3.7+ (included with Splunk)
- Network access to GitHub API (api.github.com)
- Optional: GitHub Personal Access Token for higher API rate limits

## Installation

1. Download or clone this repository
2. Copy the `TA-cvelist-v5` folder to `$SPLUNK_HOME/etc/apps/`
3. Restart Splunk: `$SPLUNK_HOME/bin/splunk restart`
4. Configure the modular input (see Configuration section)

## Configuration

### Setting Up the Modular Input

1. Navigate to **Settings > Data Inputs**
2. Click on **CVE List V5**
3. Click **New** to create a new input
4. Configure the following:

| Parameter | Description | Default |
|-----------|-------------|---------|
| Name | Unique input name | `cvelist` |
| Interval | Polling interval in seconds | `3600` (1 hour) |
| Index | Target Splunk index | `main` |
| GitHub Token | Optional Personal Access Token | (empty) |
| Batch Size | CVEs per processing batch | `1000` |
| Max Workers | Parallel download threads | `10` |

### GitHub Token (Recommended)

For production use, create a GitHub Personal Access Token to avoid rate limiting:

1. Go to GitHub → Settings → Developer Settings → Personal Access Tokens
2. Generate a new token (no special scopes needed for public repos)
3. Add the token to the modular input configuration

## Dashboard

The add-on includes the **CVE Sentinel** dashboard with:

### KPI Panels
- **Total CVEs**: Complete count of all published vulnerabilities
- **Critical/High/Medium/Low**: Severity breakdown based on highest CVSS score

### Visualizations
- **CVE Trend**: Timeline showing vulnerability publication trends
- **Top Vendors**: Most affected software vendors
- **Top Products**: Most vulnerable products
- **CWE Categories**: Common weakness enumeration breakdown
- **Severity Distribution**: Pie chart of CVSS severity ratings

### CVE Search Table
Interactive table with:
- CVE ID (clickable links to cve.icu)
- Description
- CVSS Score and Severity
- Affected Vendors/Products
- CWE Classifications
- Publication Date

## Data Model

### Index: `main` (configurable)
### Sourcetype: `cve:json:v5`

### Key Fields

| Field | Description |
|-------|-------------|
| `cve_id` | CVE identifier (e.g., CVE-2024-1234) |
| `state` | CVE state (PUBLISHED, REJECTED, etc.) |
| `description` | Vulnerability description |
| `cvss_score` | Highest CVSS score across all versions |
| `cvss_severity` | Severity rating (CRITICAL, HIGH, MEDIUM, LOW) |
| `cvss_version` | CVSS version used for scoring |
| `affected_vendors` | Multi-value list of affected vendors |
| `affected_products` | Multi-value list of affected products |
| `cwe_ids` | Multi-value list of CWE identifiers |
| `references` | URLs to advisories and references |
| `date_published` | Original publication date |
| `date_updated` | Last modification date |

## Sample Searches

### Find Critical CVEs from the Last 7 Days
```spl
index=main sourcetype="cve:json:v5" cvss_severity=CRITICAL
| where date_published > relative_time(now(), "-7d")
| table cve_id description cvss_score affected_vendors
```

### Top 10 Most Vulnerable Vendors
```spl
index=main sourcetype="cve:json:v5"
| mvexpand affected_vendors
| stats count by affected_vendors
| sort - count
| head 10
```

### CVEs Affecting a Specific Product
```spl
index=main sourcetype="cve:json:v5" affected_products="*apache*"
| table cve_id cvss_score cvss_severity description date_published
| sort - cvss_score
```

### Severity Distribution
```spl
index=main sourcetype="cve:json:v5"
| stats count by cvss_severity
| sort - count
```

## Architecture

```
TA-cvelist-v5/
├── default/
│   ├── app.conf              # App configuration
│   ├── inputs.conf           # Default input settings
│   └── data/ui/views/        # Dashboard XML
├── bin/
│   ├── cvelist_v5.py         # Main modular input
│   ├── cve_processor.py      # CVE data extraction
│   ├── github_client.py      # GitHub API client
│   └── checkpoint_manager.py # State management
├── static/
│   └── appIcon*.png          # App icons
└── lookups/
    └── cve_kpis.csv          # Cached KPI data
```

## Performance

- **Initial Load**: ~45 minutes for 300K+ CVEs (depends on network/GitHub rate limits)
- **Incremental Updates**: Seconds to minutes depending on new CVE count
- **Dashboard Load**: Instant (<1 second) using lookup-cached KPIs

## Troubleshooting

### No Data Appearing
1. Check the modular input is enabled: Settings > Data Inputs > CVE List V5
2. Verify network connectivity to api.github.com
3. Check `index=_internal sourcetype=splunkd component=ExecProcessor cvelist` for errors

### Rate Limiting
- Add a GitHub Personal Access Token to increase limits from 60 to 5,000 requests/hour
- Reduce `max_workers` if hitting secondary rate limits

### Slow Dashboard
- Run the "Update KPI Lookup" saved search to refresh cached KPIs
- Ensure the lookup file exists at `$SPLUNK_HOME/etc/apps/TA-cvelist-v5/lookups/cve_kpis.csv`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [CVE Program](https://www.cve.org/) - The official CVE database
- [cve.icu](https://cve.icu) - Fast, searchable CVE lookup service
- [CVE List V5](https://github.com/CVEProject/cvelistV5) - Official CVE data repository

## Author

Built with ❤️ for the security community