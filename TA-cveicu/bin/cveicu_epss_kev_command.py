#!/usr/bin/env python3
"""
CVE.ICU EPSS/KEV Custom Search Command Wrapper

This command is called by Splunk saved searches to refresh EPSS and KEV lookups.
Usage in SPL:
  | cveicuepsskev mode=epss | outputlookup epss_lookup.csv
  | cveicuepsskev mode=kev | outputlookup kev_lookup.csv

Author: CVE.ICU Team
"""

import os
import sys

# Add lib directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "cveicu_lib"))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option


@Configuration()
class CveicuepsskevCommand(GeneratingCommand):
    """Fetches EPSS scores or KEV catalog and yields rows for | outputlookup"""

    mode = Option(require=False, default="all")

    def generate(self):
        """Yield EPSS/KEV rows for Splunk to process via | outputlookup"""
        mode = self.mode if self.mode else "all"

        if mode in ("epss", "all"):
            for row in self._fetch_epss():
                yield row

        if mode in ("kev", "all"):
            for row in self._fetch_kev():
                yield row

    def _fetch_epss(self):
        """Fetch EPSS scores from FIRST.org bulk download and yield rows"""
        import urllib.request
        import gzip
        import csv

        epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"

        try:
            request = urllib.request.Request(
                epss_url, headers={"User-Agent": "TA-cveicu/2.0.0"}
            )

            with urllib.request.urlopen(request, timeout=120) as response:
                compressed_data = response.read()

            decompressed_data = gzip.decompress(compressed_data).decode("utf-8")

            lines = decompressed_data.strip().split("\n")
            data_lines = [l for l in lines if not l.startswith("#")]
            reader = csv.DictReader(data_lines)

            for row in reader:
                cve = row.get("cve", "")
                if cve.startswith("CVE-"):
                    yield {
                        "cve_id": cve,
                        "epss_score": row.get("epss", "0"),
                        "epss_percentile": row.get("percentile", "0"),
                    }
        except Exception as e:
            self.logger.error("Failed to fetch EPSS scores: %s", str(e))
            yield {"_raw": f"ERROR: Failed to fetch EPSS data: {e}"}

    def _fetch_kev(self):
        """Fetch CISA KEV catalog and yield rows"""
        import urllib.request
        import json

        kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

        try:
            request = urllib.request.Request(
                kev_url, headers={"User-Agent": "TA-cveicu/2.0.0"}
            )

            with urllib.request.urlopen(request, timeout=60) as response:
                kev_data = json.loads(response.read().decode("utf-8"))

            for vuln in kev_data.get("vulnerabilities", []):
                yield {
                    "cve_id": vuln.get("cveID", ""),
                    "kev_vendor": vuln.get("vendorProject", ""),
                    "kev_product": vuln.get("product", ""),
                    "kev_vulnerability_name": vuln.get("vulnerabilityName", ""),
                    "kev_date_added": vuln.get("dateAdded", ""),
                    "kev_due_date": vuln.get("dueDate", ""),
                    "kev_required_action": vuln.get("requiredAction", ""),
                    "kev_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                    "in_kev": "true",
                }
        except Exception as e:
            self.logger.error("Failed to fetch KEV catalog: %s", str(e))
            yield {"_raw": f"ERROR: Failed to fetch KEV data: {e}"}


if __name__ == "__main__":
    # For command-line testing
    if len(sys.argv) > 1 and sys.argv[1] in ("epss", "kev", "all"):
        cmd = CveicuepsskevCommand()
        cmd.mode = sys.argv[1]
        for result in cmd.generate():
            print(result)
    else:
        # Normal Splunk dispatch
        dispatch(CveicuepsskevCommand, sys.argv, sys.stdin, sys.stdout, __name__)
