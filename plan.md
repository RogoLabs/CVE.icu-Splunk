# Technical Design Document (TDD)
## Splunk Add-on: TA-cvelist-v5
### CVE V5 List Ingestion from GitHub

---

**Document Version:** 1.1  
**Date:** January 20, 2026  
**Author:** Senior Splunk Developer / Software Architect  
**Status:** DRAFT - Awaiting Approval  
**AppInspect Target:** Cloud Vetting (Splunkbase Ready)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Data Acquisition Strategy](#2-data-acquisition-strategy)
3. [Splunk Modular Input Architecture](#3-splunk-modular-input-architecture)
4. [Data Mapping & Schema Analysis](#4-data-mapping--schema-analysis)
5. [Scalability & Error Handling](#5-scalability--error-handling)
6. [Compliance & Security (AppInspect/Splunkbase)](#6-compliance--security-appinspectsplunkbase)
7. [Directory Map](#7-directory-map)
8. [Configuration Files Specification](#8-configuration-files-specification)
9. [Implementation Phases](#9-implementation-phases)

---

## 1. Executive Summary

### 1.1 Objective
Build a Splunk Technology Add-on (TA-cvelist-v5) that ingests CVE Records in JSON 5.x format from the official CVEProject GitHub repository into Splunk for security analytics, vulnerability management, and threat intelligence correlation.

### 1.2 Key Challenges
- **Volume:** 200,000+ CVE Record files (and growing)
- **Rate Limits:** GitHub API limits of 5,000 requests/hour (authenticated)
- **Data Complexity:** Deeply nested JSON with multiple containers (CNA, ADP, CVE Program)
- **Incremental Updates:** Efficient delta synchronization without full re-ingestion

### 1.3 Proposed Solution
A Python 3-based Splunk Modular Input that leverages GitHub Releases (ZIP files) for bulk operations and implements intelligent checkpointing using the `dateUpdated` field from CVE metadata.

---

## 2. Data Acquisition Strategy

### 2.1 Why GitHub Releases (ZIP) vs. GitHub API

| Aspect | GitHub Releases (ZIP) | GitHub API (Contents/Trees) |
|--------|----------------------|----------------------------|
| **Initial Load (200K+ files)** | ✅ Single ZIP download (~500MB) | ❌ 200K+ API calls = 40+ hours at rate limit |
| **Rate Limit Impact** | ✅ Minimal (1-2 requests) | ❌ Exhausts 5,000/hr limit in ~40 min |
| **Network Efficiency** | ✅ Compressed bulk transfer | ❌ Individual HTTP overhead per file |
| **Incremental Updates** | ✅ Hourly delta ZIPs available | ⚠️ Requires tree diffing logic |
| **Data Freshness** | ⚠️ Hourly granularity | ✅ Near real-time |
| **Complexity** | ✅ Simple extraction | ❌ Pagination, recursion handling |

### 2.2 Recommended Hybrid Approach

```
┌─────────────────────────────────────────────────────────────────┐
│                    DATA ACQUISITION FLOW                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   INITIAL    │    │ INCREMENTAL  │    │   FALLBACK   │      │
│  │    LOAD      │    │   UPDATES    │    │    MODE      │      │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘      │
│         │                   │                   │               │
│         ▼                   ▼                   ▼               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  Baseline    │    │  Delta ZIP   │    │  GitHub API  │      │
│  │  ZIP File    │    │  (Hourly)    │    │  (Git Trees) │      │
│  │  "all_CVEs"  │    │              │    │              │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 2.2.1 Initial Load Strategy
1. **Fetch Latest Baseline:** Download `YYYY-MM-DD_all_CVEs_at_midnight.zip` from GitHub Releases
2. **Stream Extraction:** Use Python `zipfile` with streaming to avoid memory exhaustion
3. **Batch Processing:** Process CVE records in batches of 1,000 for Splunk ingestion
4. **Checkpoint Creation:** Store baseline date and last processed CVE timestamp

#### 2.2.2 Incremental Update Strategy
1. **Hourly Delta Check:** Poll for `YYYY-MM-DD_delta_CVEs_at_HH00Z.zip`
2. **Sequential Processing:** Apply deltas in chronological order since last checkpoint
3. **Deduplication:** Use `cveMetadata.dateUpdated` to avoid re-processing unchanged records
4. **Fallback:** If delta chain is broken (>24 hours gap), fall back to baseline + delta reconstruction

#### 2.2.3 Release Asset URL Pattern
```
Baseline: https://github.com/CVEProject/cvelistV5/releases/download/cve_YYYY-MM-DD_0000Z/YYYY-MM-DD_all_CVEs_at_midnight.zip
Delta:    https://github.com/CVEProject/cvelistV5/releases/download/cve_YYYY-MM-DD_HH00Z/YYYY-MM-DD_delta_CVEs_at_HH00Z.zip
```

---

## 3. Splunk Modular Input Architecture

### 3.1 Input Configuration Schema

```xml
<!-- inputs.conf.spec -->
[cvelist_v5://<name>]
# NOTE: github_token is NOT stored here - retrieved from Splunk credential storage
initial_load_mode = <string>      # "baseline_zip" | "api" | "skip"
update_interval = <integer>       # Polling interval in seconds (default: 3600)
batch_size = <integer>            # Records per batch (default: 1000)
include_adp_containers = <bool>   # Include ADP data (default: true)
include_rejected = <bool>         # Include REJECTED CVEs (default: true)
proxy_url = <string>              # Optional: HTTP proxy URL
max_memory_mb = <integer>         # Memory limit in MB (default: 512, for Cloud Watchdog)
execution_timeout = <integer>     # Max execution time per run in seconds (default: 3600)
```

> **🔒 SECURITY NOTE:** The GitHub API token is stored securely using Splunk's Storage/Passwords REST API endpoint, NOT in `inputs.conf`. See [Section 6: Compliance & Security](#6-compliance--security-appinspectsplunkbase) for details.

### 3.2 Modular Input Class Structure

```python
class CVEListV5Input(Script):
    """
    Splunk Modular Input for CVE List V5 ingestion.
    Inherits from splunklib.modularinput.Script
    """
    
    def get_scheme(self) -> Scheme
    def validate_input(self, validation_definition: ValidationDefinition) -> None
    def stream_events(self, inputs: InputDefinition, ew: EventWriter) -> None
```

### 3.3 The `stream_events` Method - Core Logic

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      stream_events() FLOW                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. INITIALIZATION                                                      │
│     ├── Load checkpoint from KV Store / file                            │
│     ├── Validate GitHub connectivity                                    │
│     └── Determine operation mode (initial vs. incremental)              │
│                                                                         │
│  2. DATA ACQUISITION                                                    │
│     ├── [Initial] Download baseline ZIP                                 │
│     │   └── Stream extract → process in batches                         │
│     └── [Incremental] Fetch delta ZIPs since last checkpoint            │
│         └── Apply in chronological order                                │
│                                                                         │
│  3. RECORD PROCESSING (per CVE JSON file)                               │
│     ├── Parse JSON with error handling                                  │
│     ├── Extract dateUpdated for checkpoint comparison                   │
│     ├── Skip if dateUpdated <= last_checkpoint (deduplication)          │
│     ├── Flatten/transform nested structures                             │
│     └── Create Splunk Event with proper timestamp                       │
│                                                                         │
│  4. EVENT WRITING                                                       │
│     ├── Set _time = cveMetadata.datePublished (or dateUpdated)          │
│     ├── Set sourcetype = "ta:cvelist:v5:record" (AppInspect compliant)  │
│     ├── Set source = "ta-cvelist-v5://<input_name>"                     │
│     └── ew.write_event(event)                                           │
│                                                                         │
│  5. CHECKPOINT UPDATE                                                   │
│     └── Persist max(dateUpdated) and release tag processed              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.4 Checkpointing Strategy

#### 3.4.1 Why `dateUpdated` Over Hash-Based Tracking

| Criteria | `cveMetadata.dateUpdated` | File Hash (SHA-256) |
|----------|---------------------------|---------------------|
| **Schema Support** | ✅ Native V5 field | ❌ External computation |
| **Semantic Meaning** | ✅ "Last modification time" | ⚠️ "Content changed" only |
| **Query Efficiency** | ✅ Simple timestamp comparison | ❌ Requires hash storage/lookup |
| **Splunk Integration** | ✅ Maps directly to `_time` | ❌ No temporal context |
| **Delta ZIP Alignment** | ✅ ZIPs organized by time | ❌ N/A |

#### 3.4.2 Checkpoint Data Structure

```json
{
    "checkpoint_version": "1.0",
    "last_successful_run": "2026-01-20T15:30:00Z",
    "last_release_tag": "cve_2026-01-20_1500Z",
    "last_cve_date_updated": "2026-01-20T14:45:22.123Z",
    "total_records_processed": 287453,
    "initial_load_completed": true,
    "failed_cves": []
}
```

#### 3.4.3 Checkpoint Storage Options

1. **Primary: Splunk KV Store** (Recommended)
   - Collection: `cvelist_v5_checkpoints`
   - Persists across restarts
   - Supports clustering

2. **Fallback: File-based**
   - Location: `$SPLUNK_HOME/var/lib/splunk/modinputs/cvelist_v5/<input_name>/checkpoint.json`

#### 3.4.4 Deduplication Logic

```python
def should_process_cve(cve_record: dict, checkpoint: dict) -> bool:
    """
    Determine if a CVE record should be ingested based on dateUpdated.
    """
    cve_date_updated = cve_record.get("cveMetadata", {}).get("dateUpdated")
    
    if not cve_date_updated:
        # No dateUpdated means new record or legacy format - always process
        return True
    
    last_checkpoint_time = checkpoint.get("last_cve_date_updated")
    
    if not last_checkpoint_time:
        # No checkpoint exists - process everything
        return True
    
    # Parse and compare timestamps
    return parse_timestamp(cve_date_updated) > parse_timestamp(last_checkpoint_time)
```

---

## 4. Data Mapping & Schema Analysis

### 4.1 CVE V5 Record Top-Level Structure

```json
{
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1" | "5.2.0",
    "cveMetadata": { ... },      // CVE ID, state, timestamps, assigner info
    "containers": {
        "cna": { ... },          // CNA-provided vulnerability details (REQUIRED)
        "adp": [ ... ]           // ADP containers (optional, array)
    }
}
```

### 4.2 Key Schema Objects Analysis

#### 4.2.1 `cveMetadata` (Indexed Fields)

| Field | Type | Splunk Field | Indexed | Description |
|-------|------|--------------|---------|-------------|
| `cveId` | string | `cve_id` | ✅ | CVE-YYYY-NNNNN format |
| `state` | enum | `state` | ✅ | PUBLISHED / REJECTED |
| `assignerOrgId` | UUID | `assigner_org_id` | ✅ | CNA organization UUID |
| `assignerShortName` | string | `assigner` | ✅ | CNA short name |
| `dateReserved` | timestamp | `date_reserved` | ✅ | Reservation date |
| `datePublished` | timestamp | `date_published` | ✅ | Publication date |
| `dateUpdated` | timestamp | `date_updated` | ✅ | Last update timestamp |

#### 4.2.2 `containers.cna` (CNA Container)

| Field | Type | Nested Complexity | Handling Strategy |
|-------|------|-------------------|-------------------|
| `providerMetadata` | object | Low | Flatten to `cna_provider_*` |
| `title` | string | None | Direct mapping |
| `descriptions` | array[object] | Medium | Extract English description |
| `affected` | array[product] | **HIGH** | MV field + JSON preservation |
| `problemTypes` | array[object] | Medium | Extract CWE IDs as MV field |
| `references` | array[reference] | Medium | MV field for URLs |
| `metrics` | array[cvss] | **HIGH** | Extract CVSS scores + JSON |
| `credits` | array[object] | Low | MV field for credited parties |

#### 4.2.3 `containers.adp[]` (ADP Containers)

Includes:
- **CVE Program Container:** `title = "CVE Program Container"`, `shortName = "CVE"`
- **CISA-ADP Container:** SSVC scores, KEV data, Vulnrichment (CPE, CWE, CVSS)

### 4.3 Splunk Event Structure

```json
{
    "_time": "<datePublished or dateUpdated>",
    "_raw": "<full JSON record>",
    "sourcetype": "ta:cvelist:v5:record",
    "source": "ta-cvelist-v5://<input_name>",
    "host": "<splunk_hostname>",
    
    // Extracted fields (indexed)
    "cve_id": "CVE-2026-12345",
    "state": "PUBLISHED",
    "assigner": "cisco",
    "date_published": "2026-01-15T10:30:00Z",
    "date_updated": "2026-01-20T08:15:00Z",
    
    // Multi-value fields
    "affected_vendor": ["Cisco", "Meraki"],
    "affected_product": ["IOS XE", "MX Security Appliance"],
    "cwe_id": ["CWE-78", "CWE-120"],
    "reference_url": ["https://...", "https://..."],
    
    // CVSS Scores (highest severity)
    "cvss_v31_score": 9.8,
    "cvss_v31_severity": "CRITICAL",
    "cvss_v31_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    
    // Nested JSON preserved for spath
    "affected_json": "[{...}]",
    "metrics_json": "[{...}]"
}
```

### 4.4 Props.conf Configuration

```ini
# default/props.conf
# NOTE: See Section 8.2 for complete AppInspect-compliant configuration

[ta:cvelist:v5:record]
# Timestamp extraction
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%Z
TIME_PREFIX = "datePublished"\s*:\s*"
MAX_TIMESTAMP_LOOKAHEAD = 64

# Line breaking - each CVE is a single JSON event
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TRUNCATE = 0

# Character encoding
CHARSET = UTF-8

# JSON parsing
KV_MODE = json

# Indexed field extractions (search-time)
FIELDALIAS-cve_id = cveMetadata.cveId AS cve_id
FIELDALIAS-state = cveMetadata.state AS state
FIELDALIAS-assigner = cveMetadata.assignerShortName AS assigner
FIELDALIAS-date_published = cveMetadata.datePublished AS date_published
FIELDALIAS-date_updated = cveMetadata.dateUpdated AS date_updated

# Calculated fields for nested JSON arrays
EVAL-affected_vendors = mvdedup(spath(_raw, "containers.cna.affected{}.vendor"))
EVAL-affected_products = mvdedup(spath(_raw, "containers.cna.affected{}.product"))
EVAL-cwe_ids = mvdedup(spath(_raw, "containers.cna.problemTypes{}.descriptions{}.cweId"))
EVAL-reference_urls = spath(_raw, "containers.cna.references{}.url")

# CVSS extraction (prioritize v3.1, then v3.0, then v2.0)
EVAL-cvss_v31_score = spath(_raw, "containers.cna.metrics{}.cvssV3_1.baseScore")
EVAL-cvss_v31_severity = spath(_raw, "containers.cna.metrics{}.cvssV3_1.baseSeverity")
EVAL-cvss_v31_vector = spath(_raw, "containers.cna.metrics{}.cvssV3_1.vectorString")

# ADP container detection
EVAL-has_cisa_adp = if(match(_raw, "\"shortName\"\s*:\s*\"CISA-ADP\""), "true", "false")
EVAL-has_cvss_from_adp = if(isnotnull(spath(_raw, "containers.adp{}.metrics{}.cvssV3_1")), "true", "false")
```

### 4.5 Transforms.conf for Complex Extractions

```ini
# transforms.conf

[cve_cpe_extraction]
REGEX = "criteria"\s*:\s*"(cpe:[^"]+)"
FORMAT = cpe_criteria::$1
MV_ADD = true

[cve_affected_versions]
REGEX = "versions"\s*:\s*\[\s*\{[^}]*"version"\s*:\s*"([^"]+)"
FORMAT = affected_version::$1
MV_ADD = true
```

---

## 5. Scalability & Error Handling

### 5.1 GitHub API Rate Limit Management

#### 5.1.1 Rate Limit Headers Monitoring

```python
class GitHubRateLimiter:
    """
    Manages GitHub API rate limits with automatic backoff.
    """
    
    def check_rate_limit(self, response: requests.Response) -> None:
        remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
        reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
        
        if remaining < 100:  # Buffer threshold
            sleep_seconds = reset_time - time.time() + 10
            self.logger.warning(
                f"GitHub rate limit low ({remaining} remaining). "
                f"Sleeping for {sleep_seconds} seconds."
            )
            time.sleep(max(0, sleep_seconds))
```

#### 5.1.2 Rate Limit Strategy Matrix

| Scenario | Unauthenticated | Authenticated (PAT) |
|----------|-----------------|---------------------|
| **Limit** | 60 requests/hr | 5,000 requests/hr |
| **ZIP Download** | ✅ Uses releases (no limit) | ✅ Uses releases (no limit) |
| **API Fallback** | ⚠️ Very limited | ✅ Sufficient for delta checks |
| **Recommended** | Only for ZIP downloads | Full functionality |

#### 5.1.3 Automatic Retry with Exponential Backoff

```python
@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=4, max=60),
    retry=retry_if_exception_type((requests.exceptions.RequestException, RateLimitExceeded)),
    before_sleep=before_sleep_log(logger, logging.WARNING)
)
def fetch_with_retry(url: str, headers: dict) -> requests.Response:
    response = requests.get(url, headers=headers, timeout=300)
    
    if response.status_code == 403 and 'rate limit' in response.text.lower():
        raise RateLimitExceeded("GitHub rate limit exceeded")
    
    response.raise_for_status()
    return response
```

### 5.2 Error Handling & Logging Strategy

#### 5.2.1 Error Categories and Handling

| Error Type | Severity | Action | Log Level |
|------------|----------|--------|-----------|
| Network timeout | WARNING | Retry with backoff | `WARNING` |
| Rate limit (403) | WARNING | Sleep until reset | `WARNING` |
| ZIP download partial | ERROR | Retry or fallback to baseline | `ERROR` |
| Malformed JSON | ERROR | Skip record, log CVE ID | `ERROR` |
| Schema validation fail | WARNING | Ingest with warning flag | `WARNING` |
| Checkpoint corruption | ERROR | Reset to initial load | `ERROR` |
| Splunk write failure | CRITICAL | Halt and alert | `CRITICAL` |

#### 5.2.2 Logging to splunkd.log

```python
import logging
import splunk.clilib.cli_common as comm

def setup_logging(input_name: str) -> logging.Logger:
    """
    Configure logger to write to splunkd.log via Splunk's logging infrastructure.
    """
    logger = logging.getLogger(f"cvelist_v5.{input_name}")
    logger.setLevel(logging.INFO)
    
    # Splunk modular input framework automatically routes to splunkd.log
    # Format: timestamp log_level component message
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s [CVEListV5:%(name)s] %(message)s'
    ))
    logger.addHandler(handler)
    
    return logger
```

#### 5.2.3 Error Event Generation

For critical errors, also write an error event to a dedicated index:

```python
def log_error_event(ew: EventWriter, error_type: str, message: str, cve_id: str = None):
    """
    Write error event to Splunk for monitoring/alerting.
    """
    error_event = Event()
    error_event.stanza = "cvelist_v5_errors"
    error_event.sourcetype = "cve:v5:error"
    error_event.data = json.dumps({
        "error_type": error_type,
        "message": message,
        "cve_id": cve_id,
        "timestamp": datetime.utcnow().isoformat()
    })
    ew.write_event(error_event)
```

#### 5.2.4 Partial ZIP Download Recovery

```python
def download_zip_with_resume(url: str, local_path: str, expected_size: int = None) -> bool:
    """
    Download ZIP with resume capability for partial downloads.
    """
    headers = {}
    mode = 'wb'
    
    if os.path.exists(local_path):
        existing_size = os.path.getsize(local_path)
        headers['Range'] = f'bytes={existing_size}-'
        mode = 'ab'
        logger.info(f"Resuming download from byte {existing_size}")
    
    response = requests.get(url, headers=headers, stream=True, timeout=600)
    
    if response.status_code == 206:  # Partial Content
        with open(local_path, mode) as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    elif response.status_code == 200:
        # Server doesn't support resume, start fresh
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    else:
        raise DownloadError(f"Failed to download: HTTP {response.status_code}")
```

### 5.3 Memory Management for Large ZIP Processing

```python
def stream_process_zip(zip_path: str, batch_size: int = 1000) -> Iterator[List[dict]]:
    """
    Memory-efficient ZIP processing using streaming extraction.
    Yields batches of CVE records without loading entire ZIP into memory.
    """
    batch = []
    
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for file_info in zf.infolist():
            if not file_info.filename.endswith('.json'):
                continue
            
            if file_info.filename.startswith('delta') or 'cves/' not in file_info.filename:
                continue
            
            try:
                with zf.open(file_info) as json_file:
                    cve_record = json.load(json_file)
                    batch.append(cve_record)
                    
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
                        
            except json.JSONDecodeError as e:
                logger.error(f"Malformed JSON in {file_info.filename}: {e}")
                continue
    
    # Yield remaining records
    if batch:
        yield batch
```

---

## 6. Compliance & Security (AppInspect/Splunkbase)

This section details how TA-cvelist-v5 meets all Splunkbase Publishing Criteria and passes Splunk AppInspect (Cloud-vetting version).

### 6.1 Secure Credential Storage (GitHub API Token)

#### 6.1.1 Problem Statement
Storing API tokens in plain text within `inputs.conf` is a **critical security violation** that will fail AppInspect cloud vetting. Credentials in configuration files can be:
- Exposed in version control
- Visible to users with file system access
- Included in diagnostic bundles (diag)

#### 6.1.2 Solution: Splunk Storage/Passwords REST API

The GitHub API token will be stored and retrieved using Splunk's secure credential storage mechanism.

**Storage Flow (Setup UI → Credential Store):**
```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│   Setup UI /    │────▶│ POST to REST API     │────▶│ Splunk Credential   │
│   REST Handler  │     │ /storage/passwords   │     │ Store (encrypted)   │
└─────────────────┘     └──────────────────────┘     └─────────────────────┘
```

**Retrieval Flow (Modular Input → Credential Store):**
```python
# bin/cvelist_v5_lib/credential_manager.py

import splunklib.client as client

class CredentialManager:
    """
    Securely retrieves credentials from Splunk's storage/passwords endpoint.
    AppInspect Compliant: No plain-text credentials in config files.
    """
    
    REALM = "TA-cvelist-v5"
    CREDENTIAL_NAME = "github_api_token"
    
    def __init__(self, session_key: str, splunk_uri: str = "https://localhost:8089"):
        self.service = client.connect(
            token=session_key,
            host="localhost",
            port=8089,
            app="TA-cvelist-v5"
        )
    
    def get_github_token(self) -> str | None:
        """
        Retrieve GitHub token from Splunk's encrypted credential storage.
        Returns None if no token is configured (allows anonymous access).
        """
        try:
            # Access storage/passwords endpoint
            storage_passwords = self.service.storage_passwords
            
            # Look for our credential by realm and username
            for credential in storage_passwords:
                if (credential.realm == self.REALM and 
                    credential.username == self.CREDENTIAL_NAME):
                    return credential.clear_password
            
            return None  # No token configured - will use unauthenticated access
            
        except Exception as e:
            # Log but don't fail - token is optional
            logging.warning(f"Could not retrieve GitHub token: {e}")
            return None
    
    def store_github_token(self, token: str) -> bool:
        """
        Store GitHub token securely. Called by setup REST handler.
        """
        try:
            storage_passwords = self.service.storage_passwords
            
            # Delete existing credential if present
            for credential in storage_passwords:
                if (credential.realm == self.REALM and 
                    credential.username == self.CREDENTIAL_NAME):
                    credential.delete()
                    break
            
            # Create new credential
            storage_passwords.create(
                password=token,
                username=self.CREDENTIAL_NAME,
                realm=self.REALM
            )
            return True
            
        except Exception as e:
            logging.error(f"Failed to store GitHub token: {e}")
            return False
```

#### 6.1.3 REST Handler for Setup UI

```python
# bin/cvelist_v5_setup_handler.py

import splunk.admin as admin
import splunk.rest as rest

class CVEListSetupHandler(admin.MConfigHandler):
    """
    Custom REST handler for secure credential configuration.
    Endpoint: /servicesNS/nobody/TA-cvelist-v5/cvelist_v5_setup
    """
    
    def setup(self):
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in ['github_token']:
                self.supportedArgs.addOptArg(arg)
    
    def handleEdit(self, confInfo):
        github_token = self.callerArgs.data.get('github_token', [None])[0]
        
        if github_token:
            # Store in credential storage, NOT in conf file
            cred_mgr = CredentialManager(self.getSessionKey())
            if cred_mgr.store_github_token(github_token):
                self.writeConf('inputs', 'cvelist_v5', {'token_configured': 'true'})
            else:
                raise admin.AdminManagerException("Failed to store credential")
```

#### 6.1.4 restmap.conf Configuration

```ini
# default/restmap.conf

[admin:cvelist_v5_setup]
match = /cvelist_v5_setup
members = cvelist_v5_setup

[admin_external:cvelist_v5_setup]
handlertype = python
handlerfile = cvelist_v5_setup_handler.py
handleraction = edit
```

---

### 6.2 Cloud Compatibility Requirements

#### 6.2.1 Restricted Operations (MUST NOT USE)

The following are **prohibited** in Splunk Cloud and will fail AppInspect:

| Prohibited | Reason | Compliant Alternative |
|------------|--------|----------------------|
| `os.system()` | Shell injection risk | `requests` library |
| `subprocess.*` | Arbitrary code execution | `splunklib` APIs |
| `eval()` / `exec()` | Code injection | Static logic |
| `ctypes` / `cffi` | Native code loading | Pure Python |
| `socket.socket()` | Direct network access | `requests` with proxy support |
| File writes outside `$SPLUNK_HOME/var` | Sandbox violation | Use designated paths |

#### 6.2.2 Approved Libraries

```python
# All imports must be from this approved list:

# Standard Library (Python 3.7+)
import json
import logging
import time
import zipfile
import io
import os.path          # Path operations only, NOT os.system
import tempfile         # Within $SPLUNK_HOME/var/run/splunk
from datetime import datetime, timezone
from typing import Iterator, List, Dict, Optional

# Splunk SDK (bundled with Splunk)
import splunklib.client as client
import splunklib.modularinput as smi
from splunklib.modularinput import Script, Scheme, Argument, Event, EventWriter

# HTTP Requests (vendored in app)
import requests         # Vendored in bin/ta_cvelist_v5/aob_py3/

# Retry Logic (vendored)
from tenacity import retry, stop_after_attempt, wait_exponential
```

#### 6.2.3 Linux Compatibility Checklist

- [x] No Windows-specific paths (e.g., `C:\`)
- [x] No case-insensitive file operations
- [x] UTF-8 encoding explicitly specified
- [x] Line endings: LF only (no CRLF)
- [x] Shebang line: `#!/usr/bin/env python3`
- [x] File permissions: 644 for files, 755 for executables

---

### 6.3 Naming Conventions Compliance

#### 6.3.1 App & Package Naming

| Element | Convention | Our Implementation |
|---------|------------|--------------------|
| App folder | `TA-<name>` or `<provider>_addon_<name>` | ✅ `TA-cvelist-v5` |
| Package ID | Lowercase, alphanumeric + hyphens | ✅ `TA-cvelist-v5` |
| App label | Human readable | ✅ `CVE List V5 Add-on` |

#### 6.3.2 Sourcetype Naming

| Sourcetype | Format | Description |
|------------|--------|-------------|
| `ta:cvelist:v5:record` | ✅ `<app>:<category>:<type>` | Main CVE record events |
| `ta:cvelist:v5:error` | ✅ `<app>:<category>:<type>` | Error/diagnostic events |
| `ta:cvelist:v5:audit` | ✅ `<app>:<category>:<type>` | Checkpoint/audit events |

#### 6.3.3 Input Stanza Naming

```ini
# Correct naming pattern
[cvelist_v5://production]
[cvelist_v5://test_environment]

# Internal references use app prefix
index = main
sourcetype = ta:cvelist:v5:record
source = ta-cvelist-v5://production
```

#### 6.3.4 KV Store Collection Naming

```ini
# default/collections.conf
[ta_cvelist_v5_checkpoints]     # Prefixed with app name
[ta_cvelist_v5_error_tracking]  # Prefixed with app name
```

---

### 6.4 Resource Management (Cloud Watchdog Compliance)

Splunk Cloud enforces strict resource limits via the "Watchdog" process. Exceeding these limits results in process termination.

#### 6.4.1 Memory Management

**Default Limits:**
- Modular inputs: ~512 MB per process
- Search commands: ~1 GB

**Implementation Strategy:**

```python
# bin/cvelist_v5_lib/resource_manager.py

import resource
import gc
from typing import Iterator, List

class ResourceManager:
    """
    Monitors and enforces resource limits to prevent Watchdog termination.
    """
    
    DEFAULT_MEMORY_LIMIT_MB = 512
    MEMORY_WARNING_THRESHOLD = 0.8  # 80% of limit
    
    def __init__(self, max_memory_mb: int = DEFAULT_MEMORY_LIMIT_MB):
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.logger = logging.getLogger("ta_cvelist_v5.resource_manager")
    
    def check_memory_usage(self) -> bool:
        """
        Check current memory usage against limit.
        Returns True if within safe limits, False if approaching limit.
        """
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)
            current_mb = usage.ru_maxrss / 1024  # Convert KB to MB (Linux)
            
            usage_ratio = (current_mb * 1024 * 1024) / self.max_memory_bytes
            
            if usage_ratio > self.MEMORY_WARNING_THRESHOLD:
                self.logger.warning(
                    f"Memory usage at {usage_ratio:.1%} of limit "
                    f"({current_mb:.0f}MB / {self.max_memory_bytes / (1024*1024):.0f}MB)"
                )
                # Force garbage collection
                gc.collect()
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Could not check memory usage: {e}")
            return True  # Assume OK if we can't check
    
    def stream_process_with_memory_check(
        self, 
        items: Iterator, 
        batch_size: int = 1000
    ) -> Iterator[List]:
        """
        Process items in batches with memory checks between batches.
        Triggers GC if memory is high.
        """
        batch = []
        
        for item in items:
            batch.append(item)
            
            if len(batch) >= batch_size:
                yield batch
                batch = []
                
                # Check memory between batches
                if not self.check_memory_usage():
                    gc.collect()
        
        if batch:
            yield batch
```

#### 6.4.2 Execution Timeout Management

```python
# bin/cvelist_v5_lib/timeout_manager.py

import signal
import time
from contextlib import contextmanager
from typing import Optional

class TimeoutManager:
    """
    Manages execution timeouts to prevent Watchdog termination.
    Uses cooperative timeout checking (no signals in threaded context).
    """
    
    DEFAULT_TIMEOUT_SECONDS = 3600  # 1 hour max execution
    CHECKPOINT_INTERVAL = 300       # Save progress every 5 minutes
    
    def __init__(self, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS):
        self.timeout_seconds = timeout_seconds
        self.start_time: Optional[float] = None
        self.last_checkpoint_time: Optional[float] = None
        self.logger = logging.getLogger("ta_cvelist_v5.timeout_manager")
    
    def start(self) -> None:
        """Start the timeout timer."""
        self.start_time = time.time()
        self.last_checkpoint_time = self.start_time
    
    def check_timeout(self) -> bool:
        """
        Check if execution is approaching timeout.
        Returns True if safe to continue, False if should stop.
        """
        if self.start_time is None:
            return True
        
        elapsed = time.time() - self.start_time
        remaining = self.timeout_seconds - elapsed
        
        if remaining < 60:  # Less than 1 minute remaining
            self.logger.warning(
                f"Approaching timeout: {remaining:.0f}s remaining. "
                "Stopping gracefully to save checkpoint."
            )
            return False
        
        return True
    
    def should_checkpoint(self) -> bool:
        """
        Check if it's time to save a checkpoint.
        Returns True if checkpoint should be saved.
        """
        if self.last_checkpoint_time is None:
            return True
        
        elapsed = time.time() - self.last_checkpoint_time
        
        if elapsed >= self.CHECKPOINT_INTERVAL:
            self.last_checkpoint_time = time.time()
            return True
        
        return False
    
    def get_elapsed_time(self) -> float:
        """Get elapsed execution time in seconds."""
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time
```

#### 6.4.3 Graceful Shutdown Pattern

```python
# In stream_events() method

def stream_events(self, inputs: InputDefinition, ew: EventWriter) -> None:
    timeout_mgr = TimeoutManager(timeout_seconds=config.get('execution_timeout', 3600))
    resource_mgr = ResourceManager(max_memory_mb=config.get('max_memory_mb', 512))
    
    timeout_mgr.start()
    
    for batch in self.process_cve_records():
        # Check resource limits before processing batch
        if not timeout_mgr.check_timeout():
            self.logger.info("Timeout approaching - saving checkpoint and exiting")
            self.save_checkpoint()
            break
        
        if not resource_mgr.check_memory_usage():
            self.logger.info("Memory limit approaching - reducing batch size")
            # Adaptive batch sizing
            self.current_batch_size = max(100, self.current_batch_size // 2)
        
        # Process batch
        for cve_record in batch:
            event = self.create_event(cve_record)
            ew.write_event(event)
        
        # Periodic checkpoint
        if timeout_mgr.should_checkpoint():
            self.save_checkpoint()
```

---

### 6.5 Logging Compliance

#### 6.5.1 Log File Requirements

| Requirement | Implementation |
|-------------|----------------|
| Log file name | `TA-cvelist-v5.log` |
| Log location | `$SPLUNK_HOME/var/log/splunk/` |
| Log rotation | Handled by Splunk (props.conf for internal logs) |
| Log format | Standard Python logging format |

#### 6.5.2 Logging Configuration

```python
# bin/cvelist_v5_lib/logging_config.py

import logging
import logging.handlers
import os

def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """
    Configure logging to TA-cvelist-v5.log in Splunk's log directory.
    AppInspect Compliant: Uses standard Python logging library.
    """
    
    # Determine Splunk log directory
    splunk_home = os.environ.get('SPLUNK_HOME', '/opt/splunk')
    log_dir = os.path.join(splunk_home, 'var', 'log', 'splunk')
    log_file = os.path.join(log_dir, 'TA-cvelist-v5.log')
    
    # Create logger
    logger = logging.getLogger('ta_cvelist_v5')
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # File handler with rotation (10MB max, 5 backups)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding='utf-8'
    )
    
    # Format: timestamp level [component] message
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S %z'
    )
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    
    # Also log to stderr for splunkd.log capture
    stderr_handler = logging.StreamHandler()
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)
    
    return logger
```

#### 6.5.3 Log Level Configuration in inputs.conf.spec

```ini
# README/inputs.conf.spec (addition)

log_level = DEBUG | INFO | WARNING | ERROR | CRITICAL
* Logging verbosity level
* DEBUG: Verbose debugging information
* INFO: General operational messages (default)
* WARNING: Warning conditions
* ERROR: Error conditions
* CRITICAL: Critical failures
* Default: INFO
```

#### 6.5.4 Sample Log Output

```
2026-01-20 15:30:00 +0000 INFO [ta_cvelist_v5.input] Starting CVE List V5 input: production
2026-01-20 15:30:01 +0000 INFO [ta_cvelist_v5.github] Checking for new releases since cve_2026-01-20_1400Z
2026-01-20 15:30:02 +0000 INFO [ta_cvelist_v5.github] Found 2 new delta releases
2026-01-20 15:30:15 +0000 INFO [ta_cvelist_v5.processor] Processing batch 1/5 (1000 records)
2026-01-20 15:30:45 +0000 WARNING [ta_cvelist_v5.processor] Malformed JSON in CVE-2026-9999: Expecting ',' delimiter
2026-01-20 15:31:00 +0000 INFO [ta_cvelist_v5.checkpoint] Checkpoint saved: 4500 records processed
2026-01-20 15:32:00 +0000 INFO [ta_cvelist_v5.input] Run completed: 4500 events written in 120.5s
```

---

### 6.6 Packaging for Splunkbase

#### 6.6.1 Pre-Packaging Checklist

```bash
# Ensure no prohibited files exist
find TA-cvelist-v5 -name ".DS_Store" -delete
find TA-cvelist-v5 -name "__pycache__" -type d -exec rm -rf {} +
find TA-cvelist-v5 -name "*.pyc" -delete
find TA-cvelist-v5 -name ".git*" -delete
find TA-cvelist-v5 -name "*.bak" -delete
find TA-cvelist-v5 -name "Thumbs.db" -delete

# Verify file permissions
find TA-cvelist-v5 -type f -exec chmod 644 {} \;
find TA-cvelist-v5 -type d -exec chmod 755 {} \;
chmod 755 TA-cvelist-v5/bin/*.py
```

#### 6.6.2 app.manifest for Cloud Vetting

```json
// app.manifest
{
  "schemaVersion": "2.0.0",
  "info": {
    "title": "CVE List V5 Add-on",
    "id": {
      "group": null,
      "name": "TA-cvelist-v5",
      "version": "1.0.0"
    },
    "author": [
      {
        "name": "Your Organization",
        "email": "support@yourorg.com",
        "company": "Your Organization"
      }
    ],
    "releaseDate": null,
    "description": "Splunk Add-on for ingesting CVE V5 records from GitHub CVEProject repository",
    "classification": {
      "intendedAudience": "Security",
      "categories": ["Security, Fraud & Compliance", "IT Operations"],
      "developmentStatus": "Production/Stable"
    },
    "commonInformationModels": null,
    "license": {
      "name": "Apache License 2.0",
      "text": "LICENSE",
      "uri": "https://www.apache.org/licenses/LICENSE-2.0"
    },
    "privacyPolicy": {
      "name": null,
      "text": null,
      "uri": null
    },
    "releaseNotes": {
      "name": "Release Notes",
      "text": "README.md",
      "uri": null
    }
  },
  "dependencies": null,
  "tasks": null,
  "inputGroups": null,
  "incompatibleApps": null,
  "platformRequirements": {
    "splunk": {
      "Enterprise": ">=8.2"
    }
  },
  "supportedDeployments": ["_standalone", "_distributed", "_search_head_clustering"],
  "targetWorkloads": ["_search_heads", "_indexers", "_forwarders"]
}
```

#### 6.6.3 Packaging Commands

```bash
# Method 1: Using Splunk Packaging Toolkit (SLIM)
pip install splunk-packaging-toolkit
slim package TA-cvelist-v5 -o ./output/

# Method 2: Manual tar.gz (with exclusions)
SPLUNK_VERSION="1.0.0"
tar --exclude='.DS_Store' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.git*' \
    --exclude='local' \
    --exclude='local.meta' \
    -czvf "TA-cvelist-v5-${SPLUNK_VERSION}.tar.gz" \
    TA-cvelist-v5/

# Rename to .spl for Splunkbase
mv "TA-cvelist-v5-${SPLUNK_VERSION}.tar.gz" "TA-cvelist-v5-${SPLUNK_VERSION}.spl"
```

#### 6.6.4 AppInspect Validation

```bash
# Install AppInspect CLI
pip install splunk-appinspect

# Run standard checks
splunk-appinspect inspect TA-cvelist-v5-1.0.0.spl --mode precert

# Run cloud vetting checks (required for Splunk Cloud)
splunk-appinspect inspect TA-cvelist-v5-1.0.0.spl \
    --mode precert \
    --included-tags cloud \
    --included-tags splunk_appinspect

# Generate HTML report
splunk-appinspect inspect TA-cvelist-v5-1.0.0.spl \
    --mode precert \
    --included-tags cloud \
    --output-file appinspect-report.html \
    --output-format html
```

#### 6.6.5 Common AppInspect Failures to Avoid

| Check ID | Description | Our Mitigation |
|----------|-------------|----------------|
| `check_for_subprocess` | No subprocess usage | ✅ Using `requests` only |
| `check_for_os_system` | No os.system calls | ✅ No shell execution |
| `check_for_credentials_in_config` | No plain-text secrets | ✅ Using storage/passwords |
| `check_for_dangerous_functions` | No eval/exec | ✅ Static code only |
| `check_python_version` | Python 3 compatible | ✅ Python 3.7+ |
| `check_for_binary_files` | No unexpected binaries | ✅ Pure Python |
| `check_for_pycache` | No __pycache__ | ✅ Excluded in packaging |

---

### 6.7 Complete README/inputs.conf.spec

```ini
# README/inputs.conf.spec
# Documentation for TA-cvelist-v5 modular input parameters

[cvelist_v5://<name>]
* Modular input for ingesting CVE V5 records from the GitHub CVEProject repository.
* This input downloads CVE records in JSON 5.x format and indexes them into Splunk.
* GitHub API token (if configured) is stored securely via Splunk's credential storage.

initial_load_mode = baseline_zip | api | skip
* Method for initial CVE list population on first run.
* baseline_zip: Download complete ZIP from GitHub Releases (recommended for 200K+ records)
* api: Use GitHub API to fetch individual records (slow, may hit rate limits)
* skip: Skip initial load, only process incremental updates going forward
* Default: baseline_zip

update_interval = <positive integer>
* Interval in seconds between checking for CVE updates.
* Minimum: 900 (15 minutes) to respect GitHub rate limits
* Maximum: 86400 (24 hours)
* Default: 3600 (1 hour)

batch_size = <positive integer>
* Number of CVE records to process per batch before writing to Splunk.
* Larger batches are more efficient but use more memory.
* Range: 100-5000
* Default: 1000

include_adp_containers = true | false
* Include ADP (Authorized Data Publisher) container data in events.
* ADP containers include CISA-ADP enrichments (SSVC, KEV, Vulnrichment) and CVE Program Container.
* Setting to false reduces event size but loses enrichment data.
* Default: true

include_rejected = true | false
* Include CVE records with state=REJECTED.
* Rejected CVEs are kept for historical reference but are no longer valid.
* Default: true

proxy_url = <string>
* HTTP/HTTPS proxy URL for GitHub API requests.
* Format: http://[username:password@]host:port or https://[username:password@]host:port
* Leave empty for direct connection.
* Default: (empty)

ssl_verify = true | false
* Verify SSL/TLS certificates when connecting to GitHub.
* Set to false only for debugging with corporate SSL inspection proxies.
* Default: true

max_memory_mb = <positive integer>
* Maximum memory usage in megabytes before triggering garbage collection.
* Prevents Splunk Cloud Watchdog from terminating the input.
* Range: 256-2048
* Default: 512

execution_timeout = <positive integer>
* Maximum execution time in seconds per input run.
* Input will checkpoint and exit gracefully before this timeout.
* Prevents Splunk Cloud Watchdog termination.
* Range: 300-7200
* Default: 3600

log_level = DEBUG | INFO | WARNING | ERROR | CRITICAL
* Logging verbosity level for TA-cvelist-v5.log.
* DEBUG: Verbose debugging including API responses
* INFO: General operational messages (recommended)
* WARNING: Warning conditions only
* ERROR: Error conditions only
* CRITICAL: Critical failures only
* Default: INFO

index = <string>
* Destination index for CVE record events.
* Default: main

sourcetype = <string>
* Sourcetype for CVE record events.
* Default: ta:cvelist:v5:record
```

---

### 6.8 Compliance Checklist Summary

| Requirement | Section | Status | Implementation |
|-------------|---------|--------|----------------|
| **Secure Credential Storage** | 6.1 | ✅ | Splunk Storage/Passwords REST API |
| **No Plain-Text Secrets** | 6.1 | ✅ | Token retrieved at runtime, not in config |
| **Cloud Compatible Code** | 6.2 | ✅ | No subprocess, os.system, eval, exec |
| **Approved Libraries Only** | 6.2 | ✅ | requests, splunklib, standard library |
| **Linux Compatible** | 6.2 | ✅ | LF line endings, UTF-8, proper permissions |
| **Naming Conventions** | 6.3 | ✅ | TA-cvelist-v5, ta:cvelist:v5:* sourcetypes |
| **Resource Management** | 6.4 | ✅ | Memory limits, timeout handling |
| **Watchdog Compliance** | 6.4 | ✅ | Graceful shutdown, checkpointing |
| **Logging Compliance** | 6.5 | ✅ | TA-cvelist-v5.log, standard Python logging |
| **Complete Documentation** | 6.7 | ✅ | Full README/inputs.conf.spec |
| **Clean Packaging** | 6.6 | ✅ | No .DS_Store, __pycache__, .git |
| **app.manifest Present** | 6.6 | ✅ | Cloud vetting manifest included |

---

## 7. Directory Map

```
TA-cvelist-v5/
├── README.md                           # Add-on documentation
├── LICENSE                             # Apache 2.0 license
├── app.manifest                        # Splunk Cloud vetting manifest (JSON)
│
├── default/
│   ├── app.conf                        # App metadata and configuration
│   ├── inputs.conf                     # Default input configurations (NO SECRETS)
│   ├── props.conf                      # Field extractions and parsing
│   ├── transforms.conf                 # Complex field transformations
│   ├── collections.conf                # KV Store collection definitions
│   ├── restmap.conf                    # REST API endpoint mappings (credential handler)
│   ├── web.conf                        # Setup page configuration
│   └── data/
│       └── ui/
│           └── views/
│               └── ta_cvelist_v5_setup.xml  # Setup dashboard
│
├── local/                              # (Created at runtime, excluded from package)
│   └── inputs.conf                     # User-configured inputs
│
├── metadata/
│   ├── default.meta                    # Default permissions
│   └── local.meta                      # (Created at runtime)
│
├── bin/
│   ├── cvelist_v5_input.py             # Main modular input script (755 permissions)
│   ├── cvelist_v5_setup_handler.py     # REST handler for secure credential setup
│   ├── cvelist_v5_lib/
│   │   ├── __init__.py
│   │   ├── credential_manager.py       # Secure credential retrieval (storage/passwords)
│   │   ├── github_client.py            # GitHub API/Release client (requests only)
│   │   ├── cve_processor.py            # CVE record parsing/transformation
│   │   ├── checkpoint_manager.py       # Checkpoint persistence logic
│   │   ├── resource_manager.py         # Memory/timeout management (Cloud Watchdog)
│   │   ├── logging_config.py           # Logging setup (TA-cvelist-v5.log)
│   │   ├── rate_limiter.py             # Rate limit handling
│   │   └── validators.py               # Schema validation utilities
│   └── ta_cvelist_v5/
│       └── aob_py3/                    # Vendored dependencies (requests, tenacity)
│           ├── requests/
│           ├── urllib3/
│           ├── certifi/
│           ├── chardet/
│           ├── idna/
│           └── tenacity/
│
├── lib/
│   └── requirements.txt                # Python dependencies (for development)
│
├── lookups/
│   └── ta_cvelist_v5_severity.csv      # CVSS score to severity mapping
│
├── static/
│   ├── appIcon.png                     # App icon (36x36 PNG)
│   ├── appIcon_2x.png                  # App icon retina (72x72 PNG)
│   └── appIconAlt.png                  # App icon alternate
│
└── README/
    ├── inputs.conf.spec                # COMPLETE input parameter documentation
    └── ta_cvelist_v5.conf.spec         # Additional configuration documentation
```

---

## 8. Configuration Files Specification

### 8.1 app.conf

```ini
# default/app.conf

[install]
is_configured = false
state = enabled
build = 1

[package]
id = TA-cvelist-v5
check_for_updates = true

[launcher]
author = Your Organization
description = Splunk Add-on for CVE List V5 ingestion from GitHub
version = 1.0.0

[ui]
is_visible = true
label = CVE List V5 Add-on
```

### 8.2 props.conf (Updated Sourcetype Naming)

```ini
# default/props.conf

[ta:cvelist:v5:record]
# Compliant sourcetype naming: <app>:<category>:<type>
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%Z
TIME_PREFIX = "datePublished"\s*:\s*"
MAX_TIMESTAMP_LOOKAHEAD = 64
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TRUNCATE = 0
CHARSET = UTF-8
KV_MODE = json

# Field aliases for CVE metadata
FIELDALIAS-cve_id = cveMetadata.cveId AS cve_id
FIELDALIAS-state = cveMetadata.state AS state
FIELDALIAS-assigner = cveMetadata.assignerShortName AS assigner
FIELDALIAS-date_published = cveMetadata.datePublished AS date_published
FIELDALIAS-date_updated = cveMetadata.dateUpdated AS date_updated

# EVAL extractions for nested arrays
EVAL-affected_vendors = mvdedup(spath(_raw, "containers.cna.affected{}.vendor"))
EVAL-affected_products = mvdedup(spath(_raw, "containers.cna.affected{}.product"))
EVAL-cwe_ids = mvdedup(spath(_raw, "containers.cna.problemTypes{}.descriptions{}.cweId"))
EVAL-reference_urls = spath(_raw, "containers.cna.references{}.url")
EVAL-cvss_v31_score = spath(_raw, "containers.cna.metrics{}.cvssV3_1.baseScore")
EVAL-cvss_v31_severity = spath(_raw, "containers.cna.metrics{}.cvssV3_1.baseSeverity")

[ta:cvelist:v5:error]
# Error events sourcetype
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6NZ
SHOULD_LINEMERGE = false
KV_MODE = json

[ta:cvelist:v5:audit]
# Audit/checkpoint events sourcetype
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6NZ
SHOULD_LINEMERGE = false
KV_MODE = json
```

### 8.3 collections.conf (Compliant Naming)

```ini
# default/collections.conf

[ta_cvelist_v5_checkpoints]
# Compliant naming: prefixed with app identifier
field.input_name = string
field.checkpoint_version = string
field.last_successful_run = string
field.last_release_tag = string
field.last_cve_date_updated = string
field.total_records_processed = number
field.initial_load_completed = bool
accelerated_fields.input_name = {"input_name": 1}

[ta_cvelist_v5_errors]
# Error tracking for failed CVE records
field.cve_id = string
field.error_type = string
field.error_message = string
field.timestamp = string
field.retry_count = number
```

### 8.4 restmap.conf (Credential Handler)

```ini
# default/restmap.conf

[admin:ta_cvelist_v5]
match = /ta_cvelist_v5
members = ta_cvelist_v5_settings

[admin_external:ta_cvelist_v5_settings]
handlertype = python
handlerfile = cvelist_v5_setup_handler.py
handleraction = edit, list
capability = admin_all_objects
```

### 8.5 web.conf (Setup Page)

```ini
# default/web.conf

[settings]
enable_insecure_login = false

[endpoint:ta_cvelist_v5_settings]
allowMethod = GET,POST
```

---

## 9. Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)
- [ ] Project scaffolding and directory structure (Section 7 compliant)
- [ ] Secure credential manager using storage/passwords API
- [ ] GitHub client with rate limiting (requests library only)
- [ ] ZIP download and streaming extraction
- [ ] Basic checkpoint management with KV Store

### Phase 2: Modular Input & Compliance (Week 2-3)
- [ ] `stream_events()` implementation
- [ ] Initial load workflow (baseline ZIP)
- [ ] Incremental update workflow (delta ZIPs)
- [ ] Splunk event writing with compliant sourcetypes (`ta:cvelist:v5:*`)
- [ ] Resource manager (memory/timeout limits for Cloud Watchdog)
- [ ] Logging to `TA-cvelist-v5.log` with rotation

### Phase 3: Data Transformation (Week 3-4)
- [ ] CVE record parsing and field extraction
- [ ] props.conf and transforms.conf tuning
- [ ] Multi-value field handling (affected, CWE, references)
- [ ] CVSS score extraction across versions

### Phase 4: Error Handling & Resilience (Week 4)
- [ ] Comprehensive error handling
- [ ] Graceful shutdown on timeout/memory limits
- [ ] Retry mechanisms with exponential backoff
- [ ] Partial download recovery

### Phase 5: Security & Compliance Validation (Week 5)
- [ ] Verify no plain-text credentials in any config
- [ ] Verify no subprocess/os.system calls
- [ ] Verify Linux compatibility (LF line endings, permissions)
- [ ] Complete README/inputs.conf.spec documentation
- [ ] Unit tests for all modules
- [ ] Integration tests with sample data

### Phase 6: Packaging & Splunkbase Submission (Week 6)
- [ ] Pre-packaging cleanup (remove .DS_Store, __pycache__, etc.)
- [ ] Generate app.manifest for Cloud vetting
- [ ] Run AppInspect with `--included-tags cloud`
- [ ] Fix any AppInspect failures
- [ ] Generate .spl package using SLIM toolkit
- [ ] Splunkbase submission and certification

---

## Appendix A: Sample CVE V5 Record (Annotated)

```json
{
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {
        "cveId": "CVE-2026-12345",           // → cve_id (indexed)
        "assignerOrgId": "uuid-here",
        "assignerShortName": "cisco",        // → assigner (indexed)
        "state": "PUBLISHED",                // → state (indexed)
        "dateReserved": "2026-01-10T00:00:00.000Z",
        "datePublished": "2026-01-15T10:30:00.000Z",  // → _time
        "dateUpdated": "2026-01-20T08:15:00.000Z"     // → Checkpoint key
    },
    "containers": {
        "cna": {
            "providerMetadata": { "orgId": "...", "shortName": "cisco" },
            "title": "Buffer Overflow in Cisco IOS XE",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "A vulnerability in the web UI..."  // → description
                }
            ],
            "affected": [                    // → affected_json (preserved)
                {
                    "vendor": "Cisco",       // → affected_vendor (MV)
                    "product": "IOS XE",     // → affected_product (MV)
                    "versions": [
                        { "version": "17.3", "status": "affected", "lessThan": "17.6" }
                    ]
                }
            ],
            "problemTypes": [
                {
                    "descriptions": [
                        { "lang": "en", "description": "CWE-120", "cweId": "CWE-120" }
                    ]
                }
            ],
            "references": [
                { "url": "https://sec.cisco.com/...", "tags": ["vendor-advisory"] }
            ],
            "metrics": [
                {
                    "cvssV3_1": {
                        "version": "3.1",
                        "baseScore": 9.8,        // → cvss_v31_score
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
                }
            ]
        },
        "adp": [
            {
                "title": "CISA-ADP Vulnrichment",
                "providerMetadata": { "shortName": "CISA-ADP" },
                "metrics": [
                    { "other": { "type": "ssvc", "content": { "timestamp": "...", "options": {...} } } }
                ]
            }
        ]
    }
}
```

---

## Appendix B: Useful Splunk Searches

```spl
# Count CVEs by state
index=main sourcetype="ta:cvelist:v5:record" 
| stats count by state

# Top 10 vendors by CVE count
index=main sourcetype="ta:cvelist:v5:record" state=PUBLISHED
| mvexpand affected_vendors
| stats count by affected_vendors
| sort -count | head 10

# Critical CVSS vulnerabilities this month
index=main sourcetype="ta:cvelist:v5:record" cvss_v31_severity="CRITICAL"
| where _time > relative_time(now(), "-30d")
| table cve_id, affected_vendors, affected_products, cvss_v31_score, date_published

# CVEs with CISA KEV data
index=main sourcetype="ta:cvelist:v5:record" has_cisa_adp="true"
| spath path="containers.adp{}.metrics{}.other.content.kev" output=kev_data
| where isnotnull(kev_data)
```

---

**END OF TECHNICAL DESIGN DOCUMENT**

---

*Awaiting approval to proceed with implementation. Reply "Go" to begin Phase 1.*
