#!/usr/bin/env python3
"""
TA-cvelist-v5 Setup REST Handler

Handles secure storage and retrieval of GitHub Personal Access Token
using Splunk's storage/passwords endpoint.
"""

import os
import sys
import json
import logging

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


class TAcvelistV5SetupHandler(admin.MConfigHandler):
    """
    REST handler for TA-cvelist-v5 configuration.
    
    Manages secure storage of GitHub token using Splunk credentials.
    """
    
    APP_NAME = "TA-cvelist-v5"
    REALM = "TA-cvelist-v5"
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
        github_token = self.callerArgs.data.get("github_token", [None])[0]
        
        if github_token is None:
            return
        
        # Skip if masked value sent back
        if github_token == self.MASK:
            return
        
        try:
            if github_token:
                # Store new token
                self._store_credential(github_token)
                confInfo["github_settings"]["github_token"] = self.MASK
                logging.info("GitHub token stored successfully")
            else:
                # Delete existing token
                self._delete_credential()
                confInfo["github_settings"]["github_token"] = ""
                logging.info("GitHub token deleted")
        except Exception as e:
            logging.error(f"Error storing credential: {e}")
            raise admin.AdminManagerException(
                admin.ADMIN_ERROR_INTERNAL,
                f"Failed to store credential: {e}"
            )
    
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
    admin.init(TAcvelistV5SetupHandler, admin.CONTEXT_APP_ONLY)
