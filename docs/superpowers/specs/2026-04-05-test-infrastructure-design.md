# Test Infrastructure Design for TA-cveicu

**Date:** 2026-04-05
**Status:** Approved

## Goal

Add unit and integration test infrastructure to the TA-cveicu repository. Unit tests run without dependencies. Integration tests use a minimal Docker-based Splunk instance (free license, no ES/NFR required). A `--live` flag optionally enables tests that hit real external APIs (FIRST EPSS, CISA KEV).

## Test Structure

```
tests/
├── conftest.py                      # Shared fixtures, --live flag registration
├── fixtures/
│   ├── epss_sample.csv.gz           # Small gzipped EPSS CSV (~20 rows)
│   ├── kev_sample.json              # Small KEV catalog (~10 entries)
│   └── cve_v5_sample.json           # Sample CVE V5 record
├── unit/
│   ├── test_cve_processor.py
│   ├── test_epss_kev_command.py
│   ├── test_checkpoint_manager.py
│   └── test_resource_manager.py
├── integration/
│   ├── conftest.py                  # Docker fixtures (start/stop Splunk, wait for ready)
│   ├── test_lookup_refresh.py       # Trigger saved searches, verify lookups populated
│   └── test_epss_kev_command.py     # Run command via REST API, check output
docker-compose.test.yml              # Minimal Splunk container definition
requirements-dev.txt                 # pytest, requests
```

## How to Run

```bash
# Unit tests only (no Docker needed)
pytest tests/unit/

# Integration tests (requires Docker running)
pytest tests/integration/

# All tests
pytest tests/

# Include tests that hit live FIRST/CISA APIs
pytest tests/ --live
```

## Unit Tests

### test_cve_processor.py

- Feed sample CVE V5 JSON through the processor
- Verify extracted fields: cve_id, cvss scores, CWE, vendors, products
- Test PUBLISHED vs REJECTED handling
- Test missing fields and malformed records

### test_epss_kev_command.py

- Mock `urllib.request.urlopen` to return fixture data (gzipped EPSS CSV, KEV JSON)
- Verify `generate()` yields correct row dicts with expected field names and values
- Test `mode=epss`, `mode=kev`, and `mode=all`
- Directly covers the Splunk Cloud fix (PR #3)

### test_checkpoint_manager.py

- Test file-based fallback path (no Splunk service required)
- Verify checkpoint save/load/update cycle

### test_resource_manager.py

- Test memory threshold calculations
- Test timeout manager logic (cooperative timeout checking)

### Mocking Strategy

Use `unittest.mock.patch` to intercept `urllib.request.urlopen` in command tests, returning fixture data. No mock HTTP server needed.

## Integration Tests

### Docker Setup (docker-compose.test.yml)

- Image: `splunk/splunk:latest`
- License: Free (no NFR required)
- Ports: 8089 (REST API) mapped to host
- Environment: `SPLUNK_START_ARGS=--accept-license`, `SPLUNK_PASSWORD=testpassword123`
- Volume: mounts `TA-cveicu/` into `/opt/splunk/etc/apps/TA-cveicu/` (read-only)

### Fixtures (tests/integration/conftest.py)

- Session-scoped fixture starts container via `docker compose up -d`
- Polls `https://localhost:8089/services/server/health` until ready (timeout: 3 minutes)
- Tears down with `docker compose down -v` after all integration tests

### test_lookup_refresh.py

- Triggers `KEV Lookup Refresh` and `EPSS Lookup Refresh` saved searches via Splunk REST API
- Waits for search completion
- Verifies lookup CSVs are populated via `/servicesNS/-/-/data/lookup-table-files/` endpoint
- This is the exact scenario that was broken on Splunk Cloud (issue #2)

### test_epss_kev_command.py

- Runs `| cveicu_epss_kev mode=kev | head 5` via REST search API
- Verifies results return with expected fields
- With `--live`: asserts actual data content from real APIs
- Without `--live`: confirms command executes without error (empty results acceptable if external APIs unreachable)

## --live Flag Behavior

| Test type                     | Default (no flag)                | --live     |
| ----------------------------- | -------------------------------- | ---------- |
| Unit tests with fixtures      | Always run                       | Always run |
| Integration tests             | Always run (if Docker available) | Always run |
| Tests asserting real API data | Skipped                          | Run        |

## Dependencies (requirements-dev.txt)

```
pytest>=7.0
requests>=2.28
```

`requests` is used in integration tests for Splunk REST API calls. The vendored copy in `bin/lib/` is not used for tests — we use the system/venv copy to keep test code independent of the app bundle.

## Splunk Cloud Testing

Splunk Cloud instances cannot be provisioned programmatically. Cloud-specific validation (deploy app, trigger saved search, check lookup) remains a manual pre-release step. The integration tests against local Docker exercise the same code paths (`| outputlookup`) and catch the class of issues seen in issue #2.
