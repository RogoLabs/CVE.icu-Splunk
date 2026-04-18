# Troubleshooting

## No Data Appearing

1. Verify the modular input is enabled: **Settings > Data Inputs > cve.icu**. The default input ships enabled, but check that it hasn't been disabled.
2. Check network connectivity from your Splunk instance to `api.github.com` and `github.com` (the baseline ZIP downloads from github.com directly).
3. Search for add-on logs:
   ```
   index=_internal sourcetype=splunkd "cveicu"
   ```
4. Check audit events from the add-on itself:
   ```
   index=main sourcetype="cveicu:audit"
   ```
5. The initial baseline download is approximately 490MB and ingests 327,000+ records. Allow a few minutes for the first run to complete.

## Rate Limit Errors

If you see "GitHub API rate limit exceeded" in the logs, your IP's unauthenticated GitHub API quota (60 requests/hour) is exhausted. This is rare since each hourly run uses only 1-2 API calls, but can happen if other tools on the same IP also use the GitHub API.

To resolve, add a GitHub Personal Access Token (increases limit to 5,000 requests/hour):

```
curl -k -u admin:yourpassword \
  https://localhost:8089/servicesNS/nobody/TA-cveicu/storage/passwords \
  -d name=github_api_token -d realm=TA-cveicu -d password=your_token
```

Create the token at GitHub **Settings > Developer settings > Personal access tokens** with `public_repo` scope.

## Dashboards Not Rendering

The four included dashboards use Dashboard Studio v2 format, which requires **Splunk 10.0 or later**. On Splunk 9.x, the dashboards will not render. The modular input and field extractions still work on Splunk 9 -- only the dashboards require Splunk 10.

## Slow Dashboard Loading

Dashboards are powered by pre-computed lookup CSVs that refresh on a schedule via saved searches. If dashboards show no data or stale data:

1. Verify saved searches are enabled: **Settings > Searches, reports, and alerts**, filter by "TA-cveicu"
2. Manually run a saved search to refresh lookups:
   ```
   | savedsearch "CVE Total Lookup Refresh"
   ```
3. Check that lookup files exist:
   ```
   | inputlookup cve_total.csv
   | inputlookup cve_daily_summary.csv
   | inputlookup cve_vendors.csv
   ```

## Memory Issues

The modular input monitors memory usage and will pause processing if it approaches the 512MB limit. If you see memory warnings in the logs, reduce the batch size in `local/inputs.conf`:

```
[cveicu://default]
batch_size = 250
```

## Changing the Index

If you store CVE data in a custom index, update the `cveicu_index` macro so dashboards and saved searches query the correct location:

```
# local/macros.conf
[cveicu_index]
definition = index=your_cve_index
```

## Checking Checkpoint Status

To see the current ingestion state:

```
| inputlookup ta_cveicu_checkpoints
```

This shows the last successful run, total records processed, and whether the initial baseline load has completed.

## Getting Help

- File an issue: [GitHub Issue Tracker](https://github.com/RogoLabs/CVE.icu-Splunk/issues)
- Website: [cve.icu](https://cve.icu)
