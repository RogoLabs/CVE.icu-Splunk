# TA-cveicu v1.0.5 Release Notes

**Release Date:** April 15, 2026

## Bug Fixes

### Fixed: All field extractions silently failing (props.conf)

The `EVAL` field definitions in `props.conf` used `json_extract()`, which does not exist in Splunk. This caused every extracted field — `cve_id`, `state`, `title`, `cvss_score`, `cvss_severity`, `affected_vendor`, `affected_product`, `cwe_id`, `description`, and all CIM mappings — to silently return null.

All field extractions now use the correct `spath()` eval function.

Additionally:

- `FIELDALIAS` directives replaced with `EVAL` statements for CIM Vulnerabilities Data Model mappings, since `FIELDALIAS` cannot reference `EVAL`-computed fields
- Coalesced CVSS fields (`cvss_score`, `cvss_severity`) now inline their `spath()` calls, since `EVAL` fields cannot reference other `EVAL` fields in the same stanza

### Fixed: Modular input fails to register (exit code 1)

On some Splunk installations, the bundled `splunklib` library fails to import during startup introspection — typically due to a missing shared library like `libssl.so.3` in the Python environment Splunk uses internally. This caused the modular input script to crash with exit code 1, preventing the "cve.icu" data input from appearing under Settings > Data Inputs.

The script now includes a built-in fallback that returns valid scheme XML without requiring `splunklib`, ensuring the data input always registers correctly.

## Upgrade Instructions

1. Download TA-cveicu 1.0.5 from Splunkbase
2. Go to **Apps > Manage Apps > Install app from file**
3. Upload the package and check **Upgrade app**
4. Restart Splunk

## Verification

After upgrading, confirm the fix with:

```spl
index=_internal sourcetype=splunkd component=ModularInputs "cveicu"
```

You should see successful scheme registration. To verify field extractions:

```spl
index=<your_cve_index> sourcetype="cveicu:record" | head 5
| table cve_id, state, title, cvss_score, cvss_severity, affected_vendor, cwe_id
```

All fields should now be populated.
