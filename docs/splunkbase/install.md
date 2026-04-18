# Installation

1. Install the add-on from Splunkbase via **Apps > Manage Apps > Install app from file**, or extract it to `$SPLUNK_HOME/etc/apps/`
2. Restart Splunk if prompted
3. Data ingestion begins automatically -- the add-on downloads the full CVE baseline (327,000+ records) on first run and pulls hourly delta updates thereafter

No setup page, no API keys, and no manual input creation required. Open the cve.icu app from your Splunk home screen to access the dashboards.

## Optional Configuration

**Change the target index:** Create `local/macros.conf` with your preferred index:

```
[cveicu_index]
definition = index=your_cve_index
```

**Adjust input settings:** Create `local/inputs.conf` to customize polling interval, batch size, or other parameters:

```
[cveicu://default]
index = your_cve_index
interval = 3600
batch_size = 500
```

**Add a GitHub token:** Only needed if you see rate limit errors. See the Details tab for instructions.
