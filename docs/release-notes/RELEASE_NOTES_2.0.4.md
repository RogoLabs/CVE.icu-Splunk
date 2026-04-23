# TA-cveicu v2.0.4 Release Notes

**Release Date:** April 23, 2026

## Overview

v2.0.4 is a compliance fix to maintain Splunk Cloud Platform compatibility. Splunk's updated Cloud vetting process now requires `python.required = python3` in addition to the existing `python.version = python3` for all Python modular inputs and custom search commands.

## Requirements

- Splunk Enterprise 10.0+ or Splunk Cloud
- Python 3.11+ (bundled with Splunk 10)
- No external dependencies or API keys required

## Changes

### Splunk Cloud Compliance

- Added `python.required = python3` to the `[cveicu]` modular input stanza in `inputs.conf`
- Added `python.required = python3` to the `[cveicuepsskev]` custom search command stanza in `commands.conf`
- Resolves AppInspect checks `check_modular_inputs_python_required` and `check_commands_conf_python_required`

No functional changes. Data pipeline, enrichment, dashboards, and all other behavior are identical to v2.0.3.

## Install

1. Download v2.0.4 from Splunkbase
2. Go to **Apps > Manage Apps > Install app from file**
3. Upload the package and check **Upgrade app** if upgrading from v2.0.3
4. Restart Splunk if prompted
