# cve.icu — CVE Intelligence for Splunk

<p align="center">
  <img src="https://cve.icu/static/images/logo.png" alt="cve.icu Logo" width="120"/>
</p>

Splunk Technology Add-on for ingesting the complete CVE V5 database (327,000+ vulnerabilities) with EPSS, KEV, SSVC, and CVSS enrichment. Data starts flowing immediately after installation — no API keys or setup required.

## Install

**[Download from Splunkbase](https://splunkbase.splunk.com/app/8395)** or install via **Apps > Manage Apps > Install app from file** in Splunk.

## Requirements

- Splunk Enterprise 10.0+ or Splunk Cloud
- Python 3.11+ (bundled with Splunk 10)

> Splunk 9 users: Use [v1.1.2](https://github.com/RogoLabs/CVE.icu-Splunk/tree/v1.x).

## Documentation

- **[Add-on documentation](TA-cveicu/README.md)** — Configuration, fields, searches, troubleshooting
- **[Splunkbase listing](https://splunkbase.splunk.com/app/8395)** — Install, details, release notes
- **[Screenshots](docs/screenshots/)** — Dashboard previews
- **[Release notes](docs/release-notes/)** — Version history

## Dashboards

| Dashboard               | Description                                                                  |
| ----------------------- | ---------------------------------------------------------------------------- |
| CVE Explorer            | Search and filter the full CVE database by vendor, severity, CWE, or keyword |
| Risk Priority           | Triage view combining CVSS, EPSS, KEV, and SSVC signals                      |
| Vulnerability Landscape | Executive overview with trends, severity distribution, and top vendors       |
| Operational Health      | Ingestion diagnostics, error monitoring, and enrichment status               |

## Links

- **Website**: [cve.icu](https://cve.icu)
- **Issues**: [GitHub Issues](https://github.com/RogoLabs/CVE.icu-Splunk/issues)
- **Support**: support@rogolabs.net

## License

Apache License 2.0
