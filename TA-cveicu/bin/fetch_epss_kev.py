#!/usr/bin/env python3
"""
Standalone EPSS/KEV Fetcher for CVE.ICU

This script fetches EPSS scores and CISA KEV catalog data
and writes them to lookup files. Run independently of Splunk.

Usage:
    python3 fetch_epss_kev.py [epss|kev|all]

Author: CVE.ICU Team
"""

import os
import sys
import csv
import json
import gzip
import urllib.request
from io import StringIO

# Determine lookup directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOOKUP_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), 'lookups')


def fetch_epss():
    """Fetch EPSS scores from FIRST.org bulk download"""
    print("[+] Fetching EPSS scores from epss.cyentia.com...")
    
    # EPSS bulk download URL (gzipped CSV)
    epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    
    # Create request with headers
    request = urllib.request.Request(
        epss_url,
        headers={'User-Agent': 'CVE-ICU-Splunk/1.0'}
    )
    
    # Download and decompress
    print("[+] Downloading compressed EPSS data...")
    with urllib.request.urlopen(request, timeout=120) as response:
        compressed_data = response.read()
    
    print(f"[+] Downloaded {len(compressed_data)} bytes, decompressing...")
    decompressed_data = gzip.decompress(compressed_data).decode('utf-8')
    
    # Parse CSV
    lines = decompressed_data.strip().split('\n')
    
    # Skip comment lines (start with #)
    data_lines = [l for l in lines if not l.startswith('#')]
    
    reader = csv.DictReader(data_lines)
    
    # Write to lookup file
    epss_lookup_path = os.path.join(LOOKUP_DIR, 'epss_lookup.csv')
    
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
    
    print(f"[+] Wrote {count} EPSS records to {epss_lookup_path}")
    return count


def fetch_kev():
    """Fetch CISA Known Exploited Vulnerabilities catalog"""
    print("[+] Fetching CISA KEV catalog...")
    
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    request = urllib.request.Request(
        kev_url,
        headers={'User-Agent': 'CVE-ICU-Splunk/1.0'}
    )
    
    with urllib.request.urlopen(request, timeout=60) as response:
        kev_data = json.loads(response.read().decode('utf-8'))
    
    vulnerabilities = kev_data.get('vulnerabilities', [])
    print(f"[+] Found {len(vulnerabilities)} vulnerabilities in KEV catalog")
    
    # Write to lookup file
    kev_lookup_path = os.path.join(LOOKUP_DIR, 'kev_lookup.csv')
    
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
    
    print(f"[+] Wrote {len(vulnerabilities)} KEV records to {kev_lookup_path}")
    return len(vulnerabilities)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'all'
    
    print(f"[*] EPSS/KEV Fetcher - Mode: {mode}")
    print(f"[*] Lookup directory: {LOOKUP_DIR}")
    
    # Ensure lookup directory exists
    os.makedirs(LOOKUP_DIR, exist_ok=True)
    
    if mode in ('epss', 'all'):
        try:
            epss_count = fetch_epss()
            print(f"[✓] EPSS: {epss_count} records")
        except Exception as e:
            print(f"[✗] EPSS fetch failed: {e}")
    
    if mode in ('kev', 'all'):
        try:
            kev_count = fetch_kev()
            print(f"[✓] KEV: {kev_count} records")
        except Exception as e:
            print(f"[✗] KEV fetch failed: {e}")
    
    print("[*] Done!")


if __name__ == '__main__':
    main()
