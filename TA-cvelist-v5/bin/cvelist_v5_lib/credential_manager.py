"""
Credential Manager for TA-cvelist-v5

Securely retrieves credentials from Splunk's storage/passwords endpoint.
AppInspect Compliant: No plain-text credentials in config files.
"""

import logging
from typing import Optional

try:
    import splunklib.client as client
except ImportError:
    # For standalone testing
    client = None


class CredentialManager:
    """
    Securely retrieves and stores credentials using Splunk's storage/passwords API.
    
    This class provides a secure mechanism for handling GitHub API tokens without
    storing them in plain text configuration files, meeting Splunk AppInspect
    and Cloud vetting requirements.
    """
    
    REALM = "TA-cvelist-v5"
    CREDENTIAL_NAME = "github_api_token"
    
    def __init__(
        self,
        session_key: str,
        splunk_uri: str = "https://localhost:8089",
        app: str = "TA-cvelist-v5",
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the CredentialManager.
        
        Args:
            session_key: Splunk session key for authentication
            splunk_uri: Splunk management URI (default: https://localhost:8089)
            app: Splunk app context (default: TA-cvelist-v5)
            logger: Optional logger instance
        """
        self.session_key = session_key
        self.splunk_uri = splunk_uri
        self.app = app
        self.logger = logger or logging.getLogger("ta_cvelist_v5.credential_manager")
        self._service = None
    
    @property
    def service(self):
        """Lazy initialization of Splunk service connection."""
        if self._service is None:
            if client is None:
                raise ImportError("splunklib is required for credential management")
            
            # Parse URI components
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
    
    def get_github_token(self) -> Optional[str]:
        """
        Retrieve GitHub token from Splunk's encrypted credential storage.
        
        Returns:
            The GitHub API token if configured, None otherwise.
            Returns None if no token is configured (allows anonymous access).
        """
        try:
            storage_passwords = self.service.storage_passwords
            
            # Look for our credential by realm and username
            for credential in storage_passwords:
                if (credential.realm == self.REALM and 
                    credential.username == self.CREDENTIAL_NAME):
                    self.logger.debug("GitHub token retrieved from secure storage")
                    return credential.clear_password
            
            self.logger.info("No GitHub token configured - using unauthenticated access")
            return None
            
        except Exception as e:
            # Log but don't fail - token is optional
            self.logger.warning(f"Could not retrieve GitHub token: {e}")
            return None
    
    def store_github_token(self, token: str) -> bool:
        """
        Store GitHub token securely in Splunk's credential storage.
        
        This method is called by the setup REST handler when a user
        configures their GitHub API token.
        
        Args:
            token: The GitHub Personal Access Token to store
            
        Returns:
            True if successfully stored, False otherwise
        """
        try:
            storage_passwords = self.service.storage_passwords
            
            # Delete existing credential if present
            for credential in storage_passwords:
                if (credential.realm == self.REALM and 
                    credential.username == self.CREDENTIAL_NAME):
                    credential.delete()
                    self.logger.info("Deleted existing GitHub token")
                    break
            
            # Create new credential
            storage_passwords.create(
                password=token,
                username=self.CREDENTIAL_NAME,
                realm=self.REALM
            )
            
            self.logger.info("GitHub token stored securely")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store GitHub token: {e}")
            return False
    
    def delete_github_token(self) -> bool:
        """
        Delete the stored GitHub token.
        
        Returns:
            True if successfully deleted or not found, False on error
        """
        try:
            storage_passwords = self.service.storage_passwords
            
            for credential in storage_passwords:
                if (credential.realm == self.REALM and 
                    credential.username == self.CREDENTIAL_NAME):
                    credential.delete()
                    self.logger.info("GitHub token deleted")
                    return True
            
            self.logger.info("No GitHub token found to delete")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete GitHub token: {e}")
            return False
    
    def has_github_token(self) -> bool:
        """
        Check if a GitHub token is configured.
        
        Returns:
            True if a token exists, False otherwise
        """
        try:
            storage_passwords = self.service.storage_passwords
            
            for credential in storage_passwords:
                if (credential.realm == self.REALM and 
                    credential.username == self.CREDENTIAL_NAME):
                    return True
            
            return False
            
        except Exception as e:
            self.logger.warning(f"Could not check for GitHub token: {e}")
            return False
