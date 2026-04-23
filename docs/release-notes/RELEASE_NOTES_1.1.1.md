# TA-cveicu v1.1.1 Release Notes

**Release Date:** April 23, 2026

## Overview

v1.1.1 is a compliance fix to maintain Splunk Cloud Platform compatibility. Splunk's updated Cloud vetting process now requires `python.required = 3.13` in addition to the existing `python.version = python3` for all Python modular inputs and custom search commands.

## Requirements

- Splunk Enterprise 9.3+ or Splunk Cloud (9.x)
- Python 3.9+ (bundled with Splunk 9)
- No external dependencies or API keys required

## Changes

### Splunk Cloud Compliance

- Added `python.required = 3.13` to the `[cveicu]` modular input stanza in `inputs.conf`
- Added `python.required = 3.13` to the `[cveicuepsskev]` custom search command stanza in `commands.conf`
- Resolves AppInspect checks `check_modular_inputs_python_required` and `check_commands_conf_python_required`

No functional changes. Data pipeline, enrichment, dashboards, and all other behavior are identical to v1.1.0.

## Install

1. Download the v1.1.1 release from Splunkbase or the [v1.x branch](https://github.com/RogoLabs/CVE.icu-Splunk/tree/v1.x)
2. Go to **Apps > Manage Apps > Install app from file**
3. Upload the package and check **Upgrade app** if upgrading from v1.1.0
4. Restart Splunk if prompted
