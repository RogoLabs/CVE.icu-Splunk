#!/usr/bin/env python3
"""
CVE List V5 Modular Input for Splunk

Ingests CVE V5 records from the GitHub CVEProject/cvelistV5 repository
using release ZIP files for efficient bulk and delta downloads.
"""

import os
import sys
import json
import time
import traceback
from datetime import datetime
from typing import Optional

# Add lib path for bundled packages
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
sys.path.insert(0, os.path.dirname(__file__))

try:
    from splunklib.modularinput import (
        Script,
        Scheme,
        Argument,
        Event,
        EventWriter
    )
except ImportError:
    # Fallback for testing
    Script = object
    Scheme = None
    Argument = None
    Event = None
    EventWriter = None

from cvelist_v5_lib.logging_config import setup_logging, get_logger
from cvelist_v5_lib.credential_manager import CredentialManager
from cvelist_v5_lib.github_client import GitHubClient
from cvelist_v5_lib.checkpoint_manager import CheckpointManager
from cvelist_v5_lib.cve_processor import CVEProcessor
from cvelist_v5_lib.resource_manager import ResourceManager, TimeoutManager


class CVEListV5Input(Script):
    """
    Splunk Modular Input for CVE List V5 data ingestion.
    
    This modular input downloads CVE V5 records from GitHub releases:
    - Initial load uses the baseline ZIP (full export)
    - Subsequent runs use hourly delta ZIPs for incremental updates
    """
    
    MASK = "********"
    APP_NAME = "TA-cvelist-v5"
    
    def __init__(self):
        super().__init__()
        self.logger = None
        self.resource_manager = None
        self.timeout_manager = None
    
    def get_scheme(self) -> Optional[Scheme]:
        """
        Define the modular input scheme.
        
        Returns:
            Scheme object describing input configuration
        """
        if Scheme is None:
            return None
        
        scheme = Scheme("CVE List V5")
        scheme.title = "CVE List V5"
        scheme.description = (
            "Ingests CVE V5 records from the CVEProject/cvelistV5 GitHub repository. "
            "Downloads baseline and delta ZIP files for efficient bulk processing."
        )
        scheme.use_external_validation = False
        scheme.streaming_mode = Scheme.streaming_mode_xml
        scheme.use_single_instance = False
        
        # Note: 'index' is handled internally by Splunk, not defined in scheme
        
        # Include ADP data
        include_adp_arg = Argument("include_adp")
        include_adp_arg.title = "Include ADP Data"
        include_adp_arg.description = (
            "Include ADP (Authorized Data Publisher) container data "
            "(CISA-ADP, CVE Program Container)"
        )
        include_adp_arg.data_type = Argument.data_type_boolean
        include_adp_arg.required_on_create = False
        include_adp_arg.required_on_edit = False
        scheme.add_argument(include_adp_arg)
        
        # Include rejected CVEs
        include_rejected_arg = Argument("include_rejected")
        include_rejected_arg.title = "Include Rejected CVEs"
        include_rejected_arg.description = "Include CVEs with REJECTED state"
        include_rejected_arg.data_type = Argument.data_type_boolean
        include_rejected_arg.required_on_create = False
        include_rejected_arg.required_on_edit = False
        scheme.add_argument(include_rejected_arg)
        
        # Batch size for event writing
        batch_size_arg = Argument("batch_size")
        batch_size_arg.title = "Batch Size"
        batch_size_arg.description = "Number of CVE records to process per batch (default: 500)"
        batch_size_arg.data_type = Argument.data_type_number
        batch_size_arg.required_on_create = False
        batch_size_arg.required_on_edit = False
        scheme.add_argument(batch_size_arg)
        
        return scheme
    
    def validate_input(self, validation_definition):
        """
        Validate input configuration.
        
        Args:
            validation_definition: ValidationDefinition with stanza params
        """
        # Basic validation - check index exists (Splunk handles this)
        pass
    
    def stream_events(self, inputs, ew: EventWriter) -> None:
        """
        Stream CVE events to Splunk.
        
        This is the main entry point for the modular input.
        
        Args:
            inputs: InputDefinition with configuration
            ew: EventWriter for writing events to Splunk
        """
        # Initialize logging
        self.logger = setup_logging("stream_events")
        self.logger.info("CVE List V5 modular input starting")
        
        # Get Splunk metadata
        server_host = inputs.metadata.get("server_host", "localhost")
        server_uri = inputs.metadata.get("server_uri", "https://localhost:8089")
        session_key = inputs.metadata.get("session_key")
        
        if not session_key:
            self.logger.error("No session key available")
            self._write_error_event(ew, "No session key available", "startup")
            return
        
        # Process each input stanza
        for input_name, input_config in inputs.inputs.items():
            try:
                self._process_input(
                    input_name=input_name,
                    input_config=input_config,
                    server_uri=server_uri,
                    session_key=session_key,
                    server_host=server_host,
                    ew=ew
                )
            except Exception as e:
                self.logger.error(f"Fatal error processing {input_name}: {e}")
                self.logger.error(traceback.format_exc())
                self._write_error_event(ew, str(e), input_name)
    
    def _process_input(
        self,
        input_name: str,
        input_config: dict,
        server_uri: str,
        session_key: str,
        server_host: str,
        ew: EventWriter
    ) -> None:
        """
        Process a single input stanza.
        
        Args:
            input_name: Name of the input stanza
            input_config: Configuration dictionary
            server_uri: Splunk management URI
            session_key: Splunk session key
            server_host: Splunk server hostname
            ew: EventWriter for writing events
        """
        # Extract configuration
        index = input_config.get("index", "main")
        include_adp = self._str_to_bool(input_config.get("include_adp", "true"))
        include_rejected = self._str_to_bool(input_config.get("include_rejected", "true"))
        batch_size = int(input_config.get("batch_size", "500"))
        
        self.logger.info(
            f"Processing input: {input_name}, index={index}, "
            f"include_adp={include_adp}, include_rejected={include_rejected}"
        )
        
        # Initialize resource management
        self.resource_manager = ResourceManager(max_memory_mb=512, logger=self.logger)
        self.timeout_manager = TimeoutManager(timeout_seconds=3600, logger=self.logger)
        
        # Write audit event for start
        self._write_audit_event(ew, "Input started", input_name, index)
        
        # Get GitHub token from credential manager
        cred_manager = CredentialManager(
            session_key=session_key,
            splunk_uri=server_uri,
            logger=self.logger
        )
        github_token = cred_manager.get_github_token()
        
        if not github_token:
            self.logger.warning(
                "No GitHub token configured - using unauthenticated API (60 req/hr limit)"
            )
        
        # Initialize components
        github_client = GitHubClient(
            github_token=github_token,
            logger=self.logger
        )
        
        checkpoint_manager = CheckpointManager(
            input_name=input_name,
            session_key=session_key,
            splunk_uri=server_uri,
            logger=self.logger
        )
        
        cve_processor = CVEProcessor(
            input_name=input_name,
            index=index,
            include_adp=include_adp,
            include_rejected=include_rejected,
            logger=self.logger
        )
        
        # Get current checkpoint
        checkpoint = checkpoint_manager.get_checkpoint()
        self.logger.info(f"Current checkpoint: {checkpoint}")
        
        # Determine processing mode
        if checkpoint_manager.is_initial_load_needed():
            self.logger.info("Initial load needed - downloading baseline release")
            self._process_baseline(
                github_client=github_client,
                checkpoint_manager=checkpoint_manager,
                cve_processor=cve_processor,
                batch_size=batch_size,
                ew=ew
            )
        else:
            self.logger.info("Incremental update - downloading delta releases")
            self._process_deltas(
                github_client=github_client,
                checkpoint_manager=checkpoint_manager,
                cve_processor=cve_processor,
                batch_size=batch_size,
                ew=ew
            )
        
        # Write completion audit event
        stats = cve_processor.get_stats()
        self._write_audit_event(
            ew,
            f"Input completed - processed: {stats['processed']}, skipped: {stats['skipped']}, errors: {stats['errors']}",
            input_name,
            index
        )
        
        self.logger.info(f"Input {input_name} completed: {stats}")
    
    def _process_baseline(
        self,
        github_client: GitHubClient,
        checkpoint_manager: CheckpointManager,
        cve_processor: CVEProcessor,
        batch_size: int,
        ew: EventWriter
    ) -> None:
        """
        Process the baseline (full) release.
        
        Args:
            github_client: GitHub API client
            checkpoint_manager: Checkpoint persistence manager
            cve_processor: CVE record processor
            batch_size: Event batch size
            ew: EventWriter for writing events
        """
        # Find baseline release
        baseline = github_client.find_baseline_release()
        
        if not baseline:
            self.logger.error("No baseline release found")
            self._write_error_event(ew, "No baseline release found", "baseline")
            return
        
        release_tag = baseline.get("tag_name", "unknown")
        self.logger.info(f"Processing baseline release: {release_tag}")
        
        # Check if baseline was already substantially processed (resumable checkpoint)
        # This handles the case where baseline processing timed out after processing most records
        existing_checkpoint = checkpoint_manager.get_checkpoint()
        existing_records = existing_checkpoint.get("total_records_processed", 0)
        existing_tag = existing_checkpoint.get("last_release_tag", "")
        
        # If we've already processed >300K records for this same release tag,
        # consider baseline complete and skip to delta processing
        BASELINE_COMPLETION_THRESHOLD = 300000
        if existing_tag == release_tag and existing_records >= BASELINE_COMPLETION_THRESHOLD:
            self.logger.info(
                f"Baseline already substantially processed ({existing_records} records for {release_tag}). "
                f"Marking initial load complete and switching to delta mode."
            )
            checkpoint_manager.save_checkpoint(
                last_release_tag=release_tag,
                last_cve_date_updated=existing_checkpoint.get("last_cve_date_updated"),
                records_processed=existing_records,
                initial_load_completed=True
            )
            self._write_audit_event(
                ew,
                f"Baseline marked complete after resume detection: {existing_records} records",
                "cvelist_v5_input",
                "main"
            )
            return
        
        # Find all_CVEs_at_midnight.zip asset
        all_cves_asset = None
        for asset in baseline.get("assets", []):
            asset_name = asset.get("name", "")
            if "all_CVEs_at_midnight" in asset_name and asset_name.endswith(".zip"):
                all_cves_asset = asset
                break
        
        if not all_cves_asset:
            self.logger.error("No all_CVEs_at_midnight.zip found in baseline release")
            self._write_error_event(ew, "No all_CVEs_at_midnight.zip found", "baseline")
            return
        
        download_url = all_cves_asset.get("browser_download_url")
        self.logger.info(f"Downloading baseline: {download_url}")
        
        # Download and stream ZIP contents
        zip_content = github_client.download_release_asset(download_url)
        
        if not zip_content:
            self.logger.error("Failed to download baseline ZIP")
            self._write_error_event(ew, "Failed to download baseline ZIP", "baseline")
            return
        
        # Process CVEs in batches
        batch = []
        total_events = 0
        
        for filename, cve_data in github_client.stream_zip_contents(zip_content):
            # Check resource limits
            if not self.resource_manager.check_memory_usage():
                self.logger.warning("Memory pressure detected, forcing GC")
                # Memory cleanup is automatic in check_memory_usage
            
            if not self.timeout_manager.check_timeout():
                self.logger.warning("Timeout approaching, saving checkpoint and exiting")
                break
            
            batch.append(cve_data)
            
            if len(batch) >= batch_size:
                events_written = self._write_batch(batch, cve_processor, ew)
                total_events += events_written
                batch = []
                
                # Save checkpoint periodically
                if total_events % 10000 == 0:
                    self.logger.info(f"Progress: {total_events} events written")
                    checkpoint_manager.save_checkpoint(
                        last_release_tag=release_tag,
                        last_cve_date_updated=cve_processor.max_date_updated,
                        records_processed=total_events
                    )
        
        # Process remaining batch
        if batch:
            events_written = self._write_batch(batch, cve_processor, ew)
            total_events += events_written
        
        # Save final checkpoint
        checkpoint_manager.save_checkpoint(
            last_release_tag=release_tag,
            last_cve_date_updated=cve_processor.max_date_updated,
            records_processed=total_events,
            initial_load_completed=True
        )
        
        self.logger.info(f"Baseline processing complete: {total_events} events")
    
    def _process_deltas(
        self,
        github_client: GitHubClient,
        checkpoint_manager: CheckpointManager,
        cve_processor: CVEProcessor,
        batch_size: int,
        ew: EventWriter
    ) -> None:
        """
        Process delta (incremental) releases.
        
        Args:
            github_client: GitHub API client
            checkpoint_manager: Checkpoint persistence manager
            cve_processor: CVE record processor
            batch_size: Event batch size
            ew: EventWriter for writing events
        """
        checkpoint = checkpoint_manager.get_checkpoint()
        last_release = checkpoint.get("last_release")
        
        # Find delta releases since last checkpoint
        deltas = github_client.find_delta_releases_since(last_release)
        
        if not deltas:
            self.logger.info("No new delta releases found")
            return
        
        self.logger.info(f"Found {len(deltas)} delta releases to process")
        
        total_events = 0
        
        for delta in deltas:
            if not self.timeout_manager.check_timeout():
                self.logger.warning("Timeout approaching, stopping delta processing")
                break
            
            release_tag = delta.get("tag_name", "unknown")
            self.logger.info(f"Processing delta: {release_tag}")
            
            # Find deltaCves.zip asset
            delta_asset = None
            for asset in delta.get("assets", []):
                name = asset.get("name", "")
                if "deltaCves" in name or "delta" in name.lower():
                    delta_asset = asset
                    break
            
            if not delta_asset:
                self.logger.warning(f"No delta ZIP found in {release_tag}")
                continue
            
            download_url = delta_asset.get("browser_download_url")
            zip_content = github_client.download_release_asset(download_url)
            
            if not zip_content:
                self.logger.warning(f"Failed to download delta: {release_tag}")
                continue
            
            # Process CVEs
            batch = []
            
            for filename, cve_data in github_client.stream_zip_contents(zip_content):
                # Only process if newer than checkpoint
                cve_id = cve_data.get("cveMetadata", {}).get("cveId", "")
                date_updated = cve_data.get("cveMetadata", {}).get("dateUpdated")
                
                if checkpoint_manager.should_process_cve(date_updated):
                    batch.append(cve_data)
                
                if len(batch) >= batch_size:
                    events_written = self._write_batch(batch, cve_processor, ew)
                    total_events += events_written
                    batch = []
            
            # Process remaining batch
            if batch:
                events_written = self._write_batch(batch, cve_processor, ew)
                total_events += events_written
            
            # Update checkpoint for each processed delta
            checkpoint_manager.save_checkpoint(
                last_release_tag=release_tag,
                last_cve_date_updated=cve_processor.max_date_updated,
                records_processed=total_events
            )
        
        self.logger.info(f"Delta processing complete: {total_events} events")
    
    def _write_batch(
        self,
        batch: list,
        cve_processor: CVEProcessor,
        ew: EventWriter
    ) -> int:
        """
        Write a batch of events to Splunk.
        
        Args:
            batch: List of raw CVE data
            cve_processor: CVE processor instance
            ew: EventWriter
            
        Returns:
            Number of events written
        """
        count = 0
        for event in cve_processor.process_batch(batch):
            if event is not None:
                try:
                    ew.write_event(event)
                    count += 1
                except Exception as e:
                    self.logger.error(f"Error writing event: {e}")
        return count
    
    def _write_error_event(
        self,
        ew: EventWriter,
        message: str,
        context: str
    ) -> None:
        """Write an error event."""
        try:
            event = Event()
            event.stanza = context
            event.sourceType = "ta:cvelist:v5:error"
            event.data = json.dumps({
                "level": "ERROR",
                "message": message,
                "context": context,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            ew.write_event(event)
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to write error event: {e}")
    
    def _write_audit_event(
        self,
        ew: EventWriter,
        message: str,
        input_name: str,
        index: str
    ) -> None:
        """Write an audit event."""
        try:
            event = Event()
            event.stanza = input_name
            event.sourceType = "ta:cvelist:v5:audit"
            event.index = index
            event.data = json.dumps({
                "level": "INFO",
                "message": message,
                "input_name": input_name,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            ew.write_event(event)
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to write audit event: {e}")
    
    @staticmethod
    def _str_to_bool(value: str) -> bool:
        """Convert string to boolean."""
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes", "on")


if __name__ == "__main__":
    sys.exit(CVEListV5Input().run(sys.argv))
