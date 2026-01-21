#!/usr/bin/env python3
"""
EPSS and KEV Enrichment Script for TA-cveicu

Fetches FIRST EPSS (Exploit Prediction Scoring System) scores and
CISA KEV (Known Exploited Vulnerabilities) catalog to enrich CVE data.

This script can run as:
1. A modular input (scheduled)
2. A scripted lookup (on-demand)

Data Sources:
- EPSS: https://api.first.org/data/v1/epss
- KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import os
import sys
import json
import csv
import logging
import gzip
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

try:
    import requests
except ImportError:
    requests = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ta_cveicu.epss_kev")


class EPSSFetcher:
    """
    Fetches EPSS (Exploit Prediction Scoring System) scores from FIRST.
    
    EPSS provides probability scores (0-1) indicating the likelihood
    that a vulnerability will be exploited in the next 30 days.
    """
    
    # EPSS API endpoints
    EPSS_API_BASE = "https://api.first.org/data/v1/epss"
    EPSS_BULK_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    
    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = cache_dir or "/tmp/ta_cveicu"
        self.cache_file = os.path.join(self.cache_dir, "epss_scores.csv")
        self.cache_age_hours = 24  # Refresh daily
        
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, exist_ok=True)
    
    def fetch_bulk_scores(self) -> Dict[str, Dict[str, float]]:
        """
        Fetch all EPSS scores in bulk (recommended for large datasets).
        
        Returns:
            Dict mapping CVE ID to {epss: score, percentile: percentile}
        """
        if requests is None:
            logger.error("requests library not available")
            return {}
        
        # Check cache freshness
        if self._is_cache_fresh():
            return self._load_from_cache()
        
        logger.info("Fetching bulk EPSS scores from FIRST...")
        
        try:
            response = requests.get(self.EPSS_BULK_URL, timeout=120, stream=True)
            response.raise_for_status()
            
            scores = {}
            
            # Decompress and parse CSV
            with gzip.open(response.raw, 'rt') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cve_id = row.get('cve', '').upper()
                    if cve_id.startswith('CVE-'):
                        try:
                            scores[cve_id] = {
                                'epss': float(row.get('epss', 0)),
                                'percentile': float(row.get('percentile', 0))
                            }
                        except (ValueError, TypeError):
                            continue
            
            # Cache results
            self._save_to_cache(scores)
            
            logger.info(f"Fetched {len(scores)} EPSS scores")
            return scores
            
        except Exception as e:
            logger.error(f"Failed to fetch EPSS scores: {e}")
            # Return cached data if available
            if os.path.exists(self.cache_file):
                return self._load_from_cache()
            return {}
    
    def fetch_scores_for_cves(self, cve_ids: List[str]) -> Dict[str, Dict[str, float]]:
        """
        Fetch EPSS scores for specific CVE IDs using the API.
        
        Args:
            cve_ids: List of CVE IDs
            
        Returns:
            Dict mapping CVE ID to {epss: score, percentile: percentile}
        """
        if requests is None or not cve_ids:
            return {}
        
        scores = {}
        
        # API supports batches of up to 100
        batch_size = 100
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            
            try:
                params = {'cve': ','.join(batch)}
                response = requests.get(self.EPSS_API_BASE, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                for item in data.get('data', []):
                    cve_id = item.get('cve', '').upper()
                    scores[cve_id] = {
                        'epss': float(item.get('epss', 0)),
                        'percentile': float(item.get('percentile', 0))
                    }
                    
            except Exception as e:
                logger.error(f"Failed to fetch EPSS batch: {e}")
        
        return scores
    
    def _is_cache_fresh(self) -> bool:
        """Check if cache file exists and is fresh enough."""
        if not os.path.exists(self.cache_file):
            return False
        
        mtime = datetime.fromtimestamp(os.path.getmtime(self.cache_file))
        age = datetime.now() - mtime
        return age < timedelta(hours=self.cache_age_hours)
    
    def _load_from_cache(self) -> Dict[str, Dict[str, float]]:
        """Load EPSS scores from cache."""
        scores = {}
        try:
            with open(self.cache_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    scores[row['cve_id']] = {
                        'epss': float(row['epss']),
                        'percentile': float(row['percentile'])
                    }
        except Exception as e:
            logger.error(f"Failed to load EPSS cache: {e}")
        return scores
    
    def _save_to_cache(self, scores: Dict[str, Dict[str, float]]) -> None:
        """Save EPSS scores to cache."""
        try:
            with open(self.cache_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['cve_id', 'epss', 'percentile'])
                for cve_id, data in scores.items():
                    writer.writerow([cve_id, data['epss'], data['percentile']])
        except Exception as e:
            logger.error(f"Failed to save EPSS cache: {e}")


class KEVFetcher:
    """
    Fetches CISA Known Exploited Vulnerabilities (KEV) catalog.
    
    The KEV catalog contains vulnerabilities that have been actively
    exploited in the wild and have known remediation actions.
    """
    
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = cache_dir or "/tmp/ta_cveicu"
        self.cache_file = os.path.join(self.cache_dir, "kev_catalog.json")
        self.cache_age_hours = 24
        
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, exist_ok=True)
    
    def fetch_catalog(self) -> Dict[str, Dict[str, Any]]:
        """
        Fetch the full KEV catalog.
        
        Returns:
            Dict mapping CVE ID to KEV details
        """
        if requests is None:
            logger.error("requests library not available")
            return {}
        
        # Check cache
        if self._is_cache_fresh():
            return self._load_from_cache()
        
        logger.info("Fetching CISA KEV catalog...")
        
        try:
            response = requests.get(self.KEV_URL, timeout=60)
            response.raise_for_status()
            
            data = response.json()
            catalog = {}
            
            for vuln in data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID', '').upper()
                if cve_id.startswith('CVE-'):
                    catalog[cve_id] = {
                        'vendor': vuln.get('vendorProject'),
                        'product': vuln.get('product'),
                        'vulnerability_name': vuln.get('vulnerabilityName'),
                        'date_added': vuln.get('dateAdded'),
                        'short_description': vuln.get('shortDescription'),
                        'required_action': vuln.get('requiredAction'),
                        'due_date': vuln.get('dueDate'),
                        'known_ransomware_campaign': vuln.get('knownRansomwareCampaignUse', 'Unknown'),
                        'notes': vuln.get('notes', '')
                    }
            
            # Cache results
            self._save_to_cache(catalog)
            
            logger.info(f"Fetched {len(catalog)} KEV entries")
            return catalog
            
        except Exception as e:
            logger.error(f"Failed to fetch KEV catalog: {e}")
            if os.path.exists(self.cache_file):
                return self._load_from_cache()
            return {}
    
    def _is_cache_fresh(self) -> bool:
        if not os.path.exists(self.cache_file):
            return False
        mtime = datetime.fromtimestamp(os.path.getmtime(self.cache_file))
        return datetime.now() - mtime < timedelta(hours=self.cache_age_hours)
    
    def _load_from_cache(self) -> Dict[str, Dict[str, Any]]:
        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load KEV cache: {e}")
            return {}
    
    def _save_to_cache(self, catalog: Dict[str, Dict[str, Any]]) -> None:
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(catalog, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save KEV cache: {e}")


class RiskPriorityCalculator:
    """
    Calculates Risk Priority scores for CVEs based on multiple factors.
    
    Risk Priority = (CVSS * EPSS * KEV_Multiplier * SSVC_Multiplier)
    
    Factors:
    - CVSS Base Score (0-10)
    - EPSS Score (0-1, converted to multiplier)
    - KEV Status (2x if in KEV)
    - SSVC Exploitation Status (Active=2x, PoC=1.5x)
    """
    
    # SSVC Exploitation multipliers
    SSVC_MULTIPLIERS = {
        'active': 2.0,
        'poc': 1.5,
        'none': 1.0,
    }
    
    # KEV multiplier
    KEV_MULTIPLIER = 2.0
    
    @classmethod
    def calculate(
        cls,
        cvss_score: float,
        epss_score: float = 0.0,
        in_kev: bool = False,
        ssvc_exploitation: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Calculate Risk Priority score.
        
        Args:
            cvss_score: CVSS base score (0-10)
            epss_score: EPSS probability (0-1)
            in_kev: Whether CVE is in CISA KEV
            ssvc_exploitation: SSVC exploitation status
            
        Returns:
            Dict with risk_priority score and contributing factors
        """
        # Normalize CVSS to 0-1
        cvss_normalized = cvss_score / 10.0 if cvss_score else 0.0
        
        # EPSS as-is (already 0-1)
        epss_normalized = epss_score if epss_score else 0.01  # Min 1%
        
        # KEV multiplier
        kev_mult = cls.KEV_MULTIPLIER if in_kev else 1.0
        
        # SSVC multiplier
        ssvc_mult = 1.0
        if ssvc_exploitation:
            ssvc_lower = ssvc_exploitation.lower()
            ssvc_mult = cls.SSVC_MULTIPLIERS.get(ssvc_lower, 1.0)
        
        # Calculate combined score (0-100 scale)
        # Formula: CVSS * (1 + EPSS) * KEV * SSVC
        risk_priority = cvss_score * (1 + epss_normalized * 10) * kev_mult * ssvc_mult
        
        # Cap at 100
        risk_priority = min(100, risk_priority)
        
        # Categorize
        if risk_priority >= 80:
            risk_category = "CRITICAL"
        elif risk_priority >= 60:
            risk_category = "HIGH"
        elif risk_priority >= 40:
            risk_category = "MEDIUM"
        elif risk_priority >= 20:
            risk_category = "LOW"
        else:
            risk_category = "MINIMAL"
        
        return {
            'risk_priority': round(risk_priority, 2),
            'risk_category': risk_category,
            'cvss_contribution': round(cvss_normalized * 10, 2),
            'epss_contribution': round(epss_normalized * 10, 2),
            'kev_multiplier': kev_mult,
            'ssvc_multiplier': ssvc_mult
        }


def generate_splunk_lookups(output_dir: str) -> None:
    """
    Generate lookup files for Splunk.
    
    Creates:
    - epss_lookup.csv: CVE ID to EPSS score mapping
    - kev_lookup.csv: CVE ID to KEV details mapping
    """
    logger.info(f"Generating Splunk lookups in {output_dir}")
    
    # Fetch data
    epss = EPSSFetcher(output_dir)
    kev = KEVFetcher(output_dir)
    
    epss_scores = epss.fetch_bulk_scores()
    kev_catalog = kev.fetch_catalog()
    
    # Generate EPSS lookup
    epss_file = os.path.join(output_dir, "epss_lookup.csv")
    with open(epss_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['cve_id', 'epss_score', 'epss_percentile'])
        for cve_id, data in epss_scores.items():
            writer.writerow([
                cve_id,
                round(data['epss'], 6),
                round(data['percentile'], 4)
            ])
    logger.info(f"Generated {epss_file} with {len(epss_scores)} entries")
    
    # Generate KEV lookup
    kev_file = os.path.join(output_dir, "kev_lookup.csv")
    with open(kev_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'cve_id', 'kev_vendor', 'kev_product', 'kev_vulnerability_name',
            'kev_date_added', 'kev_due_date', 'kev_required_action',
            'kev_ransomware', 'in_kev'
        ])
        for cve_id, data in kev_catalog.items():
            writer.writerow([
                cve_id,
                data.get('vendor', ''),
                data.get('product', ''),
                data.get('vulnerability_name', ''),
                data.get('date_added', ''),
                data.get('due_date', ''),
                data.get('required_action', ''),
                data.get('known_ransomware_campaign', ''),
                'true'
            ])
    logger.info(f"Generated {kev_file} with {len(kev_catalog)} entries")


def main():
    """
    Main entry point for command-line usage.
    
    Usage: python cveicu_epss_kev.py [output_directory]
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Fetch EPSS and KEV data')
    parser.add_argument('output_dir', nargs='?', default='.',
                        help='Output directory for lookup files')
    parser.add_argument('--epss-only', action='store_true',
                        help='Only fetch EPSS scores')
    parser.add_argument('--kev-only', action='store_true',
                        help='Only fetch KEV catalog')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    generate_splunk_lookups(args.output_dir)


if __name__ == "__main__":
    main()
