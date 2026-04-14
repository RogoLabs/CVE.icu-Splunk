# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**TA-cveicu** is a Splunk Technology Add-on that ingests the CVE List V5 database (~300K+ CVEs) from the official CVEProject/cvelistV5 GitHub repository. It provides CVSS scoring, CWE classification, EPSS/KEV enrichment, and vulnerability dashboards. Current version: 1.0.6.

## Repository Structure

All add-on code lives under `TA-cveicu/`. Key areas:

- `bin/cveicu.py` — Main modular input (download, extract, process CVEs)
- `bin/cveicu_epss_kev.py` — EPSS/KEV enrichment modular input
- `bin/cveicu_epss_kev_command.py` — Custom search command for EPSS/KEV
- `bin/ta_cveicu_setup_handler.py` — REST handler for setup UI
- `bin/cveicu_lib/` — Core library:
  - `github_client.py` — GitHub API interaction, ZIP downloads, rate limiting
  - `cve_processor.py` — CVE V5 JSON parsing and field extraction
  - `checkpoint_manager.py` — KV Store state management (with file fallback)
  - `credential_manager.py` — Secure GitHub token storage
  - `resource_manager.py` — Memory monitoring (512MB limit) and timeout management
  - `rate_limiter.py` — API rate limiting
  - `logging_config.py` — Centralized logging
- `bin/lib/` — Vendored dependencies (splunklib, requests, urllib3, certifi, etc.)
- `default/` — Splunk configuration (inputs.conf, props.conf, transforms.conf, savedsearches.conf, etc.)
- `default/data/ui/views/` — Dashboard XMLs (multiple variants: fast, instant, tstats)
- `lookups/` — CSV lookup tables (cvss_severity, cwe, epss, kev, risk_priority)

## Build & Packaging

Package for Splunk deployment:

```bash
COPYFILE_DISABLE=1 tar -czf TA-cveicu-1.0.6.tar.gz --exclude='__pycache__' --exclude='*.pyc' TA-cveicu/
```

The `COPYFILE_DISABLE=1` prevents macOS resource fork (`._`) files from being included, which cause AppInspect failures. The `.spl` format is just a renamed `.tar.gz`. Splunkbase submission requires passing AppInspect validation:

```bash
splunk-appinspect inspect TA-cveicu-1.0.6.tar.gz --mode precert
```

There is no test suite, linter, or CI/CD pipeline in this repository.

## Architecture

**Data pipeline**: GitHub Releases ZIP download → Extract → Parse CVE V5 JSON → Emit Splunk events → Checkpoint progress in KV Store

**Incremental updates**: First run downloads the full baseline ZIP. Subsequent runs fetch only delta ZIPs based on the last checkpointed release tag.

**Enrichment pipeline** (separate input): FIRST EPSS API + CISA KEV catalog → CSV lookups → Joined at search time via transforms.conf

**Dashboard performance**: Scheduled saved searches pre-compute KPIs into lookup CSVs (`savedsearches.conf`), so dashboards load from lookups rather than running expensive searches.

**Primary sourcetype**: `cveicu:record` (JSON). Also `cveicu:error` and `cveicu:audit`.

## Key Conventions

- **Vendored dependencies**: All Python libraries are bundled in `bin/lib/` for AppInspect compliance. No pip install needed.
- **Python 3 only**: Explicitly set in inputs.conf (`python.version = python3`).
- **Splunk Cloud safe**: Uses Entity API for config, monitors memory to stay under Watchdog limits, cooperative timeout checking (no signals).
- **KV Store primary, file fallback**: Checkpoint manager tries KV Store first, falls back to file-based checkpoints.
- **Credential storage**: GitHub tokens stored via Splunk's `storage/passwords` endpoint with realm-based separation.
- **Resource limits**: Memory warning at 80% of 512MB, critical at 90%. Default timeout 1 hour with 5-minute checkpoint intervals.
