#!/usr/bin/env python3
"""
EPSS and KEV Enrichment Script for TA-cveicu

Data sources are fetched by the cveicuepsskev custom search command
(cveicu_epss_kev_command.py), which is invoked by saved searches.

This module is retained for command-line lookup generation only.

Data Sources:
- EPSS: https://epss.cyentia.com/epss_scores-current.csv.gz
- KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
