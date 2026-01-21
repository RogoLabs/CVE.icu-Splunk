"""
CVE Processor for TA-cveicu

Parses and transforms CVE V5 JSON records into Splunk events.
"""

import json
import logging
from datetime import datetime
from typing import Optional, Dict, List, Any, Iterator

try:
    from splunklib.modularinput import Event
except ImportError:
    Event = None


class CVEProcessor:
    """
    Processes CVE V5 JSON records and transforms them into Splunk events.
    
    Handles the complex nested structure of CVE records including:
    - cveMetadata: CVE ID, state, timestamps, assigner info
    - containers.cna: CNA-provided vulnerability details
    - containers.adp: ADP enrichment data (CISA-ADP, CVE Program Container)
    """
    
    SOURCETYPE = "cveicu:record"
    ERROR_SOURCETYPE = "cveicu:error"
    AUDIT_SOURCETYPE = "cveicu:audit"
    
    def __init__(
        self,
        input_name: str,
        index: str = "main",
        include_adp: bool = True,
        include_rejected: bool = True,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the CVE Processor.
        
        Args:
            input_name: Name of the modular input
            index: Destination Splunk index
            include_adp: Whether to include ADP container data
            include_rejected: Whether to include REJECTED CVEs
            logger: Optional logger instance
        """
        self.input_name = input_name
        self.index = index
        self.include_adp = include_adp
        self.include_rejected = include_rejected
        self.logger = logger or logging.getLogger("ta_cveicu.cve_processor")
        
        # Statistics
        self.processed_count = 0
        self.skipped_count = 0
        self.error_count = 0
        self.max_date_updated: Optional[str] = None
    
    def process_cve_record(self, cve_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a single CVE record.
        
        Args:
            cve_data: Raw CVE JSON data
            
        Returns:
            Processed event data dictionary or None if should be skipped
        """
        try:
            # Skip non-dict data (e.g., deltaLog.json contains a list)
            if not isinstance(cve_data, dict):
                self.skipped_count += 1
                return None
            
            # Extract metadata
            metadata = cve_data.get("cveMetadata", {})
            if not metadata:
                # Not a CVE record (might be a manifest or log file)
                self.skipped_count += 1
                return None
            
            cve_id = metadata.get("cveId", "UNKNOWN")
            state = metadata.get("state", "UNKNOWN")
            
            # Skip rejected if configured
            if not self.include_rejected and state == "REJECTED":
                self.skipped_count += 1
                self.logger.debug(f"Skipping rejected CVE: {cve_id}")
                return None
            
            # Extract timestamps
            date_published = metadata.get("datePublished")
            date_updated = metadata.get("dateUpdated")
            
            # Track max dateUpdated for checkpoint
            if date_updated:
                if self.max_date_updated is None or date_updated > self.max_date_updated:
                    self.max_date_updated = date_updated
            
            # Build event data
            event_data = {
                # Full raw JSON preserved
                "_raw": cve_data,
                
                # Top-level extracted fields
                "cve_id": cve_id,
                "state": state,
                "data_type": cve_data.get("dataType"),
                "data_version": cve_data.get("dataVersion"),
                
                # Metadata fields
                "assigner_org_id": metadata.get("assignerOrgId"),
                "assigner": metadata.get("assignerShortName"),
                "date_reserved": metadata.get("dateReserved"),
                "date_published": date_published,
                "date_updated": date_updated,
            }
            
            # Extract CNA container data
            containers = cve_data.get("containers", {})
            cna = containers.get("cna", {})
            
            if cna:
                event_data.update(self._extract_cna_data(cna))
            
            # Extract ADP container data if enabled
            if self.include_adp:
                adp_list = containers.get("adp", [])
                if adp_list:
                    event_data.update(self._extract_adp_data(adp_list))
            
            self.processed_count += 1
            return event_data
            
        except Exception as e:
            self.error_count += 1
            cve_id = "UNKNOWN"
            if isinstance(cve_data, dict):
                cve_id = cve_data.get("cveMetadata", {}).get("cveId", "UNKNOWN")
            self.logger.error(f"Error processing {cve_id}: {e}")
            return None
    
    def _extract_cna_data(self, cna: Dict[str, Any]) -> Dict[str, Any]:
        """Extract fields from CNA container."""
        result = {
            "title": cna.get("title"),
            "cna_provider": cna.get("providerMetadata", {}).get("shortName"),
        }
        
        # Extract descriptions (English preferred)
        descriptions = cna.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang", "").startswith("en"):
                result["description"] = desc.get("value")
                break
        if "description" not in result and descriptions:
            result["description"] = descriptions[0].get("value")
        
        # Extract affected products (multi-value)
        affected = cna.get("affected", [])
        vendors = []
        products = []
        for item in affected:
            vendor = item.get("vendor")
            product = item.get("product")
            if vendor and vendor not in vendors:
                vendors.append(vendor)
            if product and product not in products:
                products.append(product)
        
        if vendors:
            result["affected_vendor"] = vendors
        if products:
            result["affected_product"] = products
        
        # Preserve full affected JSON for spath queries
        if affected:
            result["affected_json"] = json.dumps(affected)
        
        # Extract problem types / CWE IDs
        problem_types = cna.get("problemTypes", [])
        cwe_ids = []
        for pt in problem_types:
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId")
                if cwe_id and cwe_id not in cwe_ids:
                    cwe_ids.append(cwe_id)
        
        if cwe_ids:
            result["cwe_id"] = cwe_ids
        
        # Extract references
        references = cna.get("references", [])
        urls = [ref.get("url") for ref in references if ref.get("url")]
        if urls:
            result["reference_url"] = urls
        
        # Extract CVSS scores
        metrics = cna.get("metrics", [])
        result.update(self._extract_cvss(metrics))
        
        # Preserve full metrics JSON
        if metrics:
            result["metrics_json"] = json.dumps(metrics)
        
        return result
    
    def _extract_cvss(self, metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract CVSS scores from metrics, prioritizing newer versions."""
        result = {}
        
        for metric in metrics:
            # CVSS v4.0
            if "cvssV4_0" in metric:
                cvss = metric["cvssV4_0"]
                result["cvss_v40_score"] = cvss.get("baseScore")
                result["cvss_v40_severity"] = cvss.get("baseSeverity")
                result["cvss_v40_vector"] = cvss.get("vectorString")
            
            # CVSS v3.1
            if "cvssV3_1" in metric:
                cvss = metric["cvssV3_1"]
                result["cvss_v31_score"] = cvss.get("baseScore")
                result["cvss_v31_severity"] = cvss.get("baseSeverity")
                result["cvss_v31_vector"] = cvss.get("vectorString")
            
            # CVSS v3.0
            elif "cvssV3_0" in metric and "cvss_v31_score" not in result:
                cvss = metric["cvssV3_0"]
                result["cvss_v30_score"] = cvss.get("baseScore")
                result["cvss_v30_severity"] = cvss.get("baseSeverity")
                result["cvss_v30_vector"] = cvss.get("vectorString")
            
            # CVSS v2.0
            if "cvssV2_0" in metric:
                cvss = metric["cvssV2_0"]
                result["cvss_v20_score"] = cvss.get("baseScore")
                result["cvss_v20_vector"] = cvss.get("vectorString")
        
        return result
    
    def _extract_adp_data(self, adp_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract fields from ADP containers.
        
        Specifically extracts CISA Vulnrichment data including:
        - SSVC Decision Points (Exploitation, Automatable, Technical Impact)
        - KEV Status
        - Recovery information
        """
        result = {
            "adp_providers": [],
            "has_cisa_adp": False,
            "has_cve_program_container": False,
            # SSVC Decision Points (Stakeholder-Specific Vulnerability Categorization)
            "ssvc_exploitation": None,
            "ssvc_automatable": None,
            "ssvc_technical_impact": None,
            "ssvc_decision": None,
            # CISA KEV Integration
            "cisa_kev": False,
            "cisa_date_added": None,
            "cisa_required_action": None,
            "cisa_due_date": None,
            # Recovery Information
            "cisa_recovery": None,
            "cisa_value_density": None,
        }
        
        for adp in adp_list:
            provider = adp.get("providerMetadata", {}).get("shortName", "")
            if provider:
                result["adp_providers"].append(provider)
            
            title = adp.get("title", "")
            
            # Check for CISA-ADP (Vulnrichment)
            if "CISA" in provider or "CISA" in title:
                result["has_cisa_adp"] = True
                
                # Extract CISA SSVC data from metrics
                for metric in adp.get("metrics", []):
                    other = metric.get("other", {})
                    
                    # SSVC Decision Points
                    if other.get("type") == "ssvc":
                        ssvc_content = other.get("content", {})
                        result["cisa_ssvc"] = json.dumps(ssvc_content)
                        
                        # Extract individual SSVC decision points
                        options = ssvc_content.get("options", [])
                        for option in options:
                            option_type = option.get("type", "").lower()
                            option_value = option.get("Exploitation") or option.get("exploitation")
                            
                            if option_type == "exploitation" or "Exploitation" in option:
                                result["ssvc_exploitation"] = option.get("Exploitation", option.get("exploitation"))
                            
                            if option_type == "automatable" or "Automatable" in option:
                                result["ssvc_automatable"] = option.get("Automatable", option.get("automatable"))
                            
                            if option_type == "technical impact" or "Technical Impact" in option:
                                result["ssvc_technical_impact"] = option.get("Technical Impact", option.get("technical_impact"))
                        
                        # Check for SSVC decision directly at root
                        if "Exploitation" in ssvc_content:
                            result["ssvc_exploitation"] = ssvc_content.get("Exploitation")
                        if "Automatable" in ssvc_content:
                            result["ssvc_automatable"] = ssvc_content.get("Automatable")
                        if "Technical Impact" in ssvc_content:
                            result["ssvc_technical_impact"] = ssvc_content.get("Technical Impact")
                        
                        # Extract overall decision if present
                        if "Decision" in ssvc_content:
                            result["ssvc_decision"] = ssvc_content.get("Decision")
                        elif "decision" in ssvc_content:
                            result["ssvc_decision"] = ssvc_content.get("decision")
                    
                    # KEV (Known Exploited Vulnerabilities) indicator
                    if other.get("type") == "kev":
                        kev_content = other.get("content", {})
                        result["cisa_kev"] = True
                        result["cisa_date_added"] = kev_content.get("dateAdded")
                        result["cisa_required_action"] = kev_content.get("requiredAction")
                        result["cisa_due_date"] = kev_content.get("dueDate")
                        result["cisa_reference"] = kev_content.get("reference")
                
                # Extract CISA tags for recovery, value density
                tags = adp.get("tags", [])
                for tag in tags:
                    tag_lower = tag.lower() if isinstance(tag, str) else ""
                    if "kev" in tag_lower:
                        result["cisa_kev"] = True
                    elif tag in ["Attended", "Unattended", "Marginal", "Concentrated"]:
                        # Value Density
                        result["cisa_value_density"] = tag
                    elif tag in ["Automatic", "Supported", "Manual", "Not Defined"]:
                        # Recovery
                        result["cisa_recovery"] = tag
            
            # Check for CVE Program Container
            if "CVE Program" in title:
                result["has_cve_program_container"] = True
            
            # Extract additional CVSS from ADP
            adp_metrics = adp.get("metrics", [])
            adp_cvss = self._extract_cvss(adp_metrics)
            
            # Only add ADP CVSS if CNA didn't provide it
            for key, value in adp_cvss.items():
                if key not in result and value is not None:
                    result[f"adp_{key}"] = value
        
        return result
    
    def create_splunk_event(
        self,
        event_data: Dict[str, Any],
        host: str = "cveicu"
    ) -> Optional[Any]:
        """
        Create a Splunk Event object from processed data.
        
        Args:
            event_data: Processed event data dictionary
            host: Splunk host value
            
        Returns:
            Splunk Event object or None
        """
        if Event is None:
            # Return dict for testing without splunklib
            return event_data
        
        try:
            # Determine event time from datePublished or dateUpdated
            event_time = None
            date_published = event_data.get("date_published")
            date_updated = event_data.get("date_updated")
            
            time_str = date_published or date_updated
            if time_str:
                try:
                    # Parse ISO timestamp
                    dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                    event_time = dt.timestamp()
                except (ValueError, TypeError):
                    pass
            
            # Create event
            event = Event()
            event.stanza = self.input_name
            event.sourceType = self.SOURCETYPE
            event.index = self.index
            event.host = host
            event.source = f"ta-cveicu://{self.input_name}"
            
            if event_time:
                event.time = event_time
            
            # Serialize the full raw JSON as event data
            raw_data = event_data.get("_raw", event_data)
            event.data = json.dumps(raw_data, separators=(',', ':'))
            
            return event
            
        except Exception as e:
            self.logger.error(f"Error creating Splunk event: {e}")
            return None
    
    def process_batch(
        self,
        cve_records: List[Dict[str, Any]],
        host: str = "cveicu"
    ) -> Iterator[Any]:
        """
        Process a batch of CVE records and yield Splunk events.
        
        Args:
            cve_records: List of raw CVE JSON data
            host: Splunk host value
            
        Yields:
            Splunk Event objects
        """
        for cve_data in cve_records:
            event_data = self.process_cve_record(cve_data)
            
            if event_data is not None:
                event = self.create_splunk_event(event_data, host)
                if event is not None:
                    yield event
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return {
            "processed": self.processed_count,
            "skipped": self.skipped_count,
            "errors": self.error_count,
            "max_date_updated": self.max_date_updated
        }
    
    def reset_stats(self) -> None:
        """Reset processing statistics."""
        self.processed_count = 0
        self.skipped_count = 0
        self.error_count = 0
        self.max_date_updated = None
