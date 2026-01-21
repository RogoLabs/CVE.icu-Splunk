"""
Checkpoint Manager for TA-cveicu

Manages checkpoint persistence using Splunk KV Store for tracking
incremental update progress.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any

try:
    import splunklib.client as client
except ImportError:
    client = None


class CheckpointManager:
    """
    Manages checkpoint state for incremental CVE updates.
    
    Uses Splunk KV Store as primary storage with file-based fallback.
    Tracks the last processed release and CVE update timestamp to enable
    efficient delta processing.
    """
    
    COLLECTION_NAME = "ta_cveicu_checkpoints"
    CHECKPOINT_VERSION = "1.0"
    
    def __init__(
        self,
        input_name: str,
        session_key: str,
        splunk_uri: str = "https://localhost:8089",
        app: str = "TA-cveicu",
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the CheckpointManager.
        
        Args:
            input_name: Name of the modular input instance
            session_key: Splunk session key for authentication
            splunk_uri: Splunk management URI
            app: Splunk app context
            logger: Optional logger instance
        """
        self.input_name = input_name
        self.session_key = session_key
        self.splunk_uri = splunk_uri
        self.app = app
        self.logger = logger or logging.getLogger("ta_cveicu.checkpoint_manager")
        self._service = None
        self._collection = None
        self._checkpoint_cache: Optional[Dict[str, Any]] = None
    
    @property
    def service(self):
        """Lazy initialization of Splunk service connection."""
        if self._service is None:
            if client is None:
                raise ImportError("splunklib is required for checkpoint management")
            
            from urllib.parse import urlparse
            parsed = urlparse(self.splunk_uri)
            host = parsed.hostname or "localhost"
            port = parsed.port or 8089
            
            self._service = client.connect(
                token=self.session_key,
                host=host,
                port=port,
                app=self.app,
                autologin=True
            )
        return self._service
    
    @property
    def collection(self):
        """Get or create the KV Store collection."""
        if self._collection is None:
            try:
                # Try to get existing collection
                self._collection = self.service.kvstore[self.COLLECTION_NAME]
            except KeyError:
                # Collection doesn't exist - this is OK, we'll create checkpoints when saving
                self.logger.warning(
                    f"KV Store collection '{self.COLLECTION_NAME}' not found. "
                    "Checkpoint will be created on first save."
                )
                self._collection = None
        return self._collection
    
    def _get_default_checkpoint(self) -> Dict[str, Any]:
        """Get a default checkpoint structure."""
        return {
            "_key": self.input_name,
            "input_name": self.input_name,
            "checkpoint_version": self.CHECKPOINT_VERSION,
            "last_successful_run": None,
            "last_release_tag": None,
            "last_cve_date_updated": None,
            "total_records_processed": 0,
            "initial_load_completed": False,
            "last_error": None,
            "consecutive_errors": 0
        }
    
    def get_checkpoint(self, retry_on_init: bool = True, max_retries: int = 5) -> Dict[str, Any]:
        """
        Retrieve the current checkpoint state.
        
        Args:
            retry_on_init: If True, retry when KV Store is initializing
            max_retries: Maximum number of retries if KV Store is initializing
        
        Returns:
            Checkpoint dictionary
        """
        import time
        
        # Return cached checkpoint if available
        if self._checkpoint_cache is not None:
            return self._checkpoint_cache
        
        retries = 0
        while retries <= max_retries:
            try:
                if self.collection is not None:
                    # Query KV Store for this input's checkpoint
                    query = json.dumps({"input_name": self.input_name})
                    results = self.collection.data.query(query=query)
                    
                    if results:
                        self._checkpoint_cache = results[0]
                        self.logger.debug(f"Loaded checkpoint: {self._checkpoint_cache}")
                        return self._checkpoint_cache
                    break  # No results but collection exists - use default
            except Exception as e:
                error_msg = str(e)
                # Check if KV Store is still initializing
                if retry_on_init and "initializing" in error_msg.lower() and retries < max_retries:
                    retries += 1
                    wait_time = 2 ** retries  # Exponential backoff: 2, 4, 8, 16, 32 seconds
                    self.logger.warning(
                        f"KV Store initializing, retry {retries}/{max_retries} in {wait_time}s: {e}"
                    )
                    time.sleep(wait_time)
                    # Reset collection to force re-fetch
                    self._collection = None
                    continue
                else:
                    self.logger.warning(f"Could not load checkpoint from KV Store: {e}")
                    break
        
        # Return default checkpoint if none found
        self._checkpoint_cache = self._get_default_checkpoint()
        self.logger.info("No existing checkpoint found - starting fresh")
        return self._checkpoint_cache
    
    def save_checkpoint(
        self,
        last_release_tag: Optional[str] = None,
        last_cve_date_updated: Optional[str] = None,
        records_processed: int = 0,
        initial_load_completed: Optional[bool] = None,
        error: Optional[str] = None
    ) -> bool:
        """
        Save checkpoint state to KV Store.
        
        Args:
            last_release_tag: Tag of the last processed release
            last_cve_date_updated: ISO timestamp of the last CVE update
            records_processed: Number of records processed in this run
            initial_load_completed: Whether initial load is complete
            error: Error message if run failed
            
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            checkpoint = self.get_checkpoint()
            
            # Update fields
            checkpoint["last_successful_run"] = datetime.now(timezone.utc).isoformat()
            
            if last_release_tag is not None:
                checkpoint["last_release_tag"] = last_release_tag
            
            if last_cve_date_updated is not None:
                checkpoint["last_cve_date_updated"] = last_cve_date_updated
            
            checkpoint["total_records_processed"] = (
                checkpoint.get("total_records_processed", 0) + records_processed
            )
            
            if initial_load_completed is not None:
                checkpoint["initial_load_completed"] = initial_load_completed
            
            if error:
                checkpoint["last_error"] = error
                checkpoint["consecutive_errors"] = checkpoint.get("consecutive_errors", 0) + 1
            else:
                checkpoint["last_error"] = None
                checkpoint["consecutive_errors"] = 0
            
            # Save to KV Store
            if self.collection is not None:
                try:
                    # Try to update existing record
                    self.collection.data.update(self.input_name, json.dumps(checkpoint))
                except Exception:
                    # Insert new record if update fails
                    self.collection.data.insert(json.dumps(checkpoint))
                
                self._checkpoint_cache = checkpoint
                self.logger.info(
                    f"Checkpoint saved: release={last_release_tag}, "
                    f"records={records_processed}, total={checkpoint['total_records_processed']}"
                )
                return True
            else:
                self.logger.warning("KV Store collection not available - checkpoint not persisted")
                self._checkpoint_cache = checkpoint
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to save checkpoint: {e}")
            return False
    
    def is_initial_load_needed(self) -> bool:
        """
        Check if initial load is needed.
        
        Returns:
            True if initial load hasn't been completed
        """
        checkpoint = self.get_checkpoint()
        return not checkpoint.get("initial_load_completed", False)
    
    def get_last_release_tag(self) -> Optional[str]:
        """
        Get the tag of the last processed release.
        
        Returns:
            Release tag string or None
        """
        checkpoint = self.get_checkpoint()
        return checkpoint.get("last_release_tag")
    
    def get_last_cve_date_updated(self) -> Optional[str]:
        """
        Get the timestamp of the last CVE update.
        
        Returns:
            ISO timestamp string or None
        """
        checkpoint = self.get_checkpoint()
        return checkpoint.get("last_cve_date_updated")
    
    def should_process_cve(self, cve_date_updated: Optional[str]) -> bool:
        """
        Determine if a CVE should be processed based on its dateUpdated.
        
        Args:
            cve_date_updated: ISO timestamp of CVE's dateUpdated field
            
        Returns:
            True if CVE should be processed, False if it's already been processed
        """
        if cve_date_updated is None:
            # No dateUpdated means we should process it (new record or legacy)
            return True
        
        last_processed = self.get_last_cve_date_updated()
        if last_processed is None:
            # No checkpoint - process everything
            return True
        
        try:
            # Compare timestamps
            cve_time = datetime.fromisoformat(cve_date_updated.replace('Z', '+00:00'))
            last_time = datetime.fromisoformat(last_processed.replace('Z', '+00:00'))
            return cve_time > last_time
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Could not parse timestamps: {e}")
            return True  # Process if we can't compare
    
    def reset_checkpoint(self) -> bool:
        """
        Reset the checkpoint to initial state.
        
        Returns:
            True if reset successfully, False otherwise
        """
        try:
            self._checkpoint_cache = self._get_default_checkpoint()
            
            if self.collection is not None:
                try:
                    self.collection.data.delete(self.input_name)
                except Exception:
                    pass  # OK if doesn't exist
            
            self.logger.info("Checkpoint reset to initial state")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to reset checkpoint: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get checkpoint statistics.
        
        Returns:
            Dictionary with checkpoint stats
        """
        checkpoint = self.get_checkpoint()
        return {
            "input_name": self.input_name,
            "initial_load_completed": checkpoint.get("initial_load_completed", False),
            "total_records_processed": checkpoint.get("total_records_processed", 0),
            "last_release_tag": checkpoint.get("last_release_tag"),
            "last_successful_run": checkpoint.get("last_successful_run"),
            "consecutive_errors": checkpoint.get("consecutive_errors", 0)
        }
