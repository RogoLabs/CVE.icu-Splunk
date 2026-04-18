The cve.icu add-on ingests the complete CVE V5 database directly into Splunk. Unlike traditional collectors that rely on slow per-CVE API crawling, this add-on streams data from official GitHub release ZIP files, enabling initial ingestion of over 327,000 CVE records in minutes. Hourly delta updates keep the data current with only a few API calls per run -- no GitHub token required.

Key Features:

Full CVE V5 Schema Support: Parses the modern CVE JSON 5.x schema including cveMetadata, CNA containers, and CISA-ADP enrichment. Extracts CVSS scores across all versions (v2.0, v3.0, v3.1, v4.0), CWE classifications, and affected product/vendor data.

Risk Prioritization Beyond CVSS: Integrates three enrichment sources to help security teams identify "patch now" threats: FIRST Exploit Prediction Scoring System (EPSS) scores updated daily, CISA Known Exploited Vulnerabilities (KEV) catalog refreshed every 6 hours, and CISA SSVC (Stakeholder-Specific Vulnerability Categorization) decision data from ADP containers.

Four Dashboard Studio Dashboards: CVE Explorer for searching and filtering the full database, Risk Priority for EPSS/KEV/SSVC-ranked threat triage, Vulnerability Landscape for executive-level trend analysis, and Operational Health for monitoring ingestion status and errors.

Production-Ready Architecture: Resource-aware modular input with memory monitoring (512MB limit), cooperative timeout management, and KV Store checkpointing with file fallback. Pre-computed lookup CSVs power dashboard KPIs so panels load instantly without running expensive searches. Splunk Cloud compatible and AppInspect validated.

Zero-Configuration Start: Works out of the box -- install and data starts flowing. No API keys, no setup pages, no index creation required. Customize the target index via the cveicu_index macro when ready.
