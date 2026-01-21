#!/usr/bin/env python3
"""
CVE.ICU EPSS/KEV Custom Search Command Wrapper

This command is called by Splunk saved searches to refresh EPSS and KEV lookups.
Usage in SPL:
  | script cveicu_epss_kev epss
  | script cveicu_epss_kev kev

Author: CVE.ICU Team
"""

import os
import sys
import csv

# Add lib directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'cveicu_lib'))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option


@Configuration()
class EPSSKEVCommand(GeneratingCommand):
    """Fetches EPSS scores or KEV catalog and outputs to lookup files"""
    
    mode = Option(require=False, default='all')
    
    def __init__(self):
        super(EPSSKEVCommand, self).__init__()
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.lookup_dir = os.path.join(self.app_dir, 'lookups')
    
    def generate(self):
        """Generate results and update lookup files"""
        import urllib.request
        import json
        import gzip
        from io import StringIO
        
        mode = self.mode if self.mode else 'all'
        
        results = []
        
        if mode in ('epss', 'all'):
            try:
                epss_result = self._fetch_epss()
                results.append({'type': 'epss', 'status': 'success', 'count': epss_result})
            except Exception as e:
                results.append({'type': 'epss', 'status': 'error', 'error': str(e)})
        
        if mode in ('kev', 'all'):
            try:
                kev_result = self._fetch_kev()
                results.append({'type': 'kev', 'status': 'success', 'count': kev_result})
            except Exception as e:
                results.append({'type': 'kev', 'status': 'error', 'error': str(e)})
        
        for r in results:
            yield r
    
    def _fetch_epss(self):
        """Fetch EPSS scores from FIRST.org bulk download"""
        import urllib.request
        import gzip
        import csv
        from io import StringIO
        
        # EPSS bulk download URL (gzipped CSV)
        epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
        
        # Create request with headers
        request = urllib.request.Request(
            epss_url,
            headers={'User-Agent': 'CVE-ICU-Splunk/1.0'}
        )
        
        # Download and decompress
        with urllib.request.urlopen(request, timeout=120) as response:
            compressed_data = response.read()
        
        decompressed_data = gzip.decompress(compressed_data).decode('utf-8')
        
        # Parse CSV
        lines = decompressed_data.strip().split('\n')
        
        # Skip comment lines (start with #)
        data_lines = [l for l in lines if not l.startswith('#')]
        
        reader = csv.DictReader(data_lines)
        
        # Write to lookup file
        epss_lookup_path = os.path.join(self.lookup_dir, 'epss_lookup.csv')
        
        count = 0
        with open(epss_lookup_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['cve_id', 'epss_score', 'epss_percentile'])
            
            for row in reader:
                cve = row.get('cve', '')
                epss = row.get('epss', '0')
                percentile = row.get('percentile', '0')
                
                if cve.startswith('CVE-'):
                    writer.writerow([cve, epss, percentile])
                    count += 1
        
        return count
    
    def _fetch_kev(self):
        """Fetch CISA Known Exploited Vulnerabilities catalog"""
        import urllib.request
        import json
        import csv
        
        kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        request = urllib.request.Request(
            kev_url,
            headers={'User-Agent': 'CVE-ICU-Splunk/1.0'}
        )
        
        with urllib.request.urlopen(request, timeout=60) as response:
            kev_data = json.loads(response.read().decode('utf-8'))
        
        vulnerabilities = kev_data.get('vulnerabilities', [])
        
        # Write to lookup file
        kev_lookup_path = os.path.join(self.lookup_dir, 'kev_lookup.csv')
        
        with open(kev_lookup_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'cve_id', 'kev_vendor', 'kev_product', 'kev_vulnerability_name',
                'kev_date_added', 'kev_due_date', 'kev_required_action',
                'kev_ransomware', 'in_kev'
            ])
            
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.get('cveID', ''),
                    vuln.get('vendorProject', ''),
                    vuln.get('product', ''),
                    vuln.get('vulnerabilityName', ''),
                    vuln.get('dateAdded', ''),
                    vuln.get('dueDate', ''),
                    vuln.get('requiredAction', ''),
                    vuln.get('knownRansomwareCampaignUse', 'Unknown'),
                    'true'
                ])
        
        return len(vulnerabilities)


if __name__ == '__main__':
    # For command-line testing
    if len(sys.argv) > 1 and sys.argv[1] in ('epss', 'kev', 'all'):
        cmd = EPSSKEVCommand()
        cmd.mode = sys.argv[1]
        for result in cmd.generate():
            print(result)
    else:
        # Normal Splunk dispatch
        dispatch(EPSSKEVCommand, sys.argv, sys.stdin, sys.stdout, __name__)
