#!/usr/bin/env python3
"""
TA-cveicu Setup REST Handler

Handles secure storage and retrieval of GitHub Personal Access Token
using Splunk's storage/passwords endpoint.
"""

import os
import sys
import logging
import configparser

# Add lib path for bundled packages
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
sys.path.insert(0, os.path.dirname(__file__))

try:
    import splunk.admin as admin
    import splunk.rest as rest
    import splunk.entity as entity
except ImportError:
    admin = None
    rest = None
    entity = None


class TAcveicuSetupHandler(admin.MConfigHandler):
    """
    REST handler for TA-cveicu configuration.
    
    Manages secure storage of GitHub token using Splunk credentials.
    """
    
    APP_NAME = "TA-cveicu"
    REALM = "TA-cveicu"
    CREDENTIAL_NAME = "github_token"
    MASK = "********"
    
    def setup(self):
        """Define supported arguments."""
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in ["github_token"]:
                self.supportedArgs.addOptArg(arg)
    
    def handleList(self, confInfo):
        """
        Handle GET request - return masked credential status.
        
        Args:
            confInfo: Configuration info object
        """
        confInfo["github_settings"]["github_token"] = ""
        
        # Check if credential exists
        try:
            credential = self._get_credential()
            if credential:
                confInfo["github_settings"]["github_token"] = self.MASK
        except Exception as e:
            logging.error(f"Error checking credential: {e}")
    
    def handleEdit(self, confInfo):
        """
        Handle POST request - store credential securely.
        
        Args:
            confInfo: Configuration info object
        """
        github_token = self.callerArgs.data.get("github_token", [""])[0] or ""
        
        # Always ensure we have an entry in confInfo
        confInfo["github_settings"]["github_token"] = ""
        
        # Skip if masked value sent back (no change needed)
        if github_token == self.MASK:
            confInfo["github_settings"]["github_token"] = self.MASK
            self._mark_configured()
            return
        
        try:
            if github_token and github_token.strip():
                # Store new token
                self._store_credential(github_token.strip())
                confInfo["github_settings"]["github_token"] = self.MASK
                logging.info("GitHub token stored successfully")
            else:
                # No token provided - just mark as configured
                # Try to delete any existing token (ignore errors)
                try:
                    self._delete_credential()
                except Exception:
                    pass
                confInfo["github_settings"]["github_token"] = ""
                logging.info("No token provided, app configured without token")
            
            # Mark app as configured
            self._mark_configured()
            
        except Exception as e:
            logging.error(f"Error storing credential: {e}")
            # Still mark as configured even if credential storage fails
            self._mark_configured()
            raise admin.AdminManagerException(
                admin.ADMIN_ERROR_INTERNAL,
                f"Failed to store credential: {e}"
            )
    
    def _mark_configured(self):
        """Mark the app as configured by writing to local/app.conf."""
        try:
            app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            local_dir = os.path.join(app_dir, "local")
            local_app_conf = os.path.join(local_dir, "app.conf")
            
            # Create local directory if it doesn't exist
            if not os.path.exists(local_dir):
                os.makedirs(local_dir)
            
            # Read existing or create new config
            config = configparser.ConfigParser()
            if os.path.exists(local_app_conf):
                config.read(local_app_conf)
            
            # Set is_configured = true
            if "install" not in config:
                config["install"] = {}
            config["install"]["is_configured"] = "true"
            
            # Write config
            with open(local_app_conf, "w") as f:
                config.write(f)
            
            logging.info("App marked as configured")
        except Exception as e:
            logging.error(f"Failed to mark app as configured: {e}")
    
    def _get_credential(self):
        """
        Retrieve stored credential.
        
        Returns:
            Credential clear password or None
        """
        if entity is None:
            return None
        
        try:
            entities = entity.getEntities(
                ["storage", "passwords"],
                namespace=self.APP_NAME,
                owner="nobody",
                sessionKey=self.getSessionKey(),
                search=f"realm={self.REALM}"
            )
            
            for stanza_name, stanza in list(entities.items()):
                if stanza.get("username") == self.CREDENTIAL_NAME:
                    return stanza.get("clear_password")
            
            return None
        except Exception as e:
            logging.debug(f"No credential found: {e}")
            return None
    
    def _store_credential(self, clear_password):
        """
        Store credential securely.
        
        Args:
            clear_password: The password to store
        """
        if rest is None:
            raise RuntimeError("Splunk REST module not available")
        
        # First try to delete any existing credential
        try:
            self._delete_credential()
        except Exception:
            pass  # OK if it doesn't exist
        
        # Create new credential
        endpoint = f"/servicesNS/nobody/{self.APP_NAME}/storage/passwords"
        
        postargs = {
            "name": self.CREDENTIAL_NAME,
            "password": clear_password,
            "realm": self.REALM
        }
        
        response, content = rest.simpleRequest(
            endpoint,
            sessionKey=self.getSessionKey(),
            postargs=postargs,
            method="POST",
            raiseAllErrors=True
        )
        
        return response
    
    def _delete_credential(self):
        """Delete stored credential."""
        if rest is None:
            return
        
        endpoint = f"/servicesNS/nobody/{self.APP_NAME}/storage/passwords/{self.REALM}%3A{self.CREDENTIAL_NAME}%3A"
        
        try:
            response, content = rest.simpleRequest(
                endpoint,
                sessionKey=self.getSessionKey(),
                method="DELETE"
            )
            return response
        except Exception:
            pass  # OK if it doesn't exist


if admin is not None:
    admin.init(TAcveicuSetupHandler, admin.CONTEXT_APP_ONLY)
