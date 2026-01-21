#!/usr/bin/env python3
"""
TA-cveicu Setup REST Handler

Handles secure storage and retrieval of GitHub Personal Access Token
using Splunk's storage/passwords endpoint.

Splunk Cloud Compatible - Uses Entity API for configuration state.
"""

import os
import sys
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

# Configure logging to splunkd.log
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [TA-cveicu] %(message)s'
)
logger = logging.getLogger('ta_cveicu_setup')


class TAcveicuSetupHandler(admin.MConfigHandler):
    """
    REST handler for TA-cveicu configuration.
    
    Manages secure storage of GitHub token using Splunk credentials.
    Uses Entity API for Splunk Cloud compatibility.
    """
    
    APP_NAME = "TA-cveicu"
    REALM = "TA-cveicu"
    CREDENTIAL_NAME = "github_token"
    MASK = "********"
    
    def setup(self):
        """Define supported arguments."""
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in ["github_token", "theme"]:
                self.supportedArgs.addOptArg(arg)
    
    def handleList(self, confInfo):
        """
        Handle GET request - return masked credential status and theme.
        
        Args:
            confInfo: Configuration info object
        """
        confInfo["github_settings"]["github_token"] = ""
        confInfo["github_settings"]["theme"] = self._get_theme()
        
        # Check if credential exists
        try:
            credential = self._get_credential()
            if credential:
                confInfo["github_settings"]["github_token"] = self.MASK
        except Exception as e:
            logger.error(f"Error checking credential: {e}")
    
    def handleEdit(self, confInfo):
        """
        Handle POST request - store credential and theme securely.
        
        Uses Entity API for Splunk Cloud compatibility.
        
        Args:
            confInfo: Configuration info object
        """
        github_token = self.callerArgs.data.get("github_token", [""])[0] or ""
        theme = self.callerArgs.data.get("theme", ["light"])[0] or "light"
        
        # Always ensure we have an entry in confInfo
        confInfo["github_settings"]["github_token"] = ""
        confInfo["github_settings"]["theme"] = theme
        
        # Save theme preference using Entity API
        self._save_theme(theme)
        
        # Skip credential update if masked value sent back (no change)
        if github_token == self.MASK:
            confInfo["github_settings"]["github_token"] = self.MASK
            self._mark_configured()
            return
        
        try:
            if github_token and github_token.strip():
                # Store new token securely
                self._store_credential(github_token.strip())
                confInfo["github_settings"]["github_token"] = self.MASK
                logger.info("GitHub token stored successfully")
            else:
                # No token provided - just mark as configured
                try:
                    self._delete_credential()
                except Exception:
                    pass  # OK if no credential exists
                confInfo["github_settings"]["github_token"] = ""
                logger.info("App configured without GitHub token")
            
            # Mark app as configured using Entity API
            self._mark_configured()
            
        except Exception as e:
            logger.error(f"Error in handleEdit: {e}")
            # Still mark as configured to prevent redirect loop
            try:
                self._mark_configured()
            except Exception:
                pass
            raise admin.AdminManagerException(
                admin.ADMIN_ERROR_INTERNAL,
                f"Failed to store credential: {e}"
            )
    
    def _mark_configured(self):
        """
        Ensure the app is configured and refresh Splunk's configuration cache.
        
        The is_configured=1 setting is already in default/app.conf, which is the
        recommended approach as it:
        - Works on Splunk Cloud (no filesystem writes needed)
        - Replicates correctly on Search Head Clusters
        - Survives app upgrades
        
        This method performs the critical "Cache Killer" reload by POSTing to
        /servicesNS/nobody/TA-cveicu/apps/local/TA-cveicu/_reload which forces
        Splunk Web to immediately recognize the configured state and prevents
        the redirect loop.
        """
        session_key = self.getSessionKey()
        
        # Log that we're marking as configured
        logger.info("[TA-cveicu] Marking app as configured (default/app.conf has is_configured=1)")
        
        # Cache Killer - Force Splunk Web to reload app configuration cache
        # This is the critical step that destroys the redirect loop
        self._reload_app(session_key)
    
    def _reload_app(self, session_key):
        """
        Force Splunk to reload the app configuration (Cache Killer).
        
        This is the critical step that destroys Splunk Web's internal
        configuration cache and prevents the redirect loop. The POST to
        apps/local/TA-cveicu/_reload refreshes Splunk's in-memory cache
        so the UI immediately recognizes is_configured=true.
        
        Args:
            session_key: Splunk session key from self.getSessionKey()
        """
        try:
            # POST to apps/local/TA-cveicu/_reload to invalidate cache
            endpoint = f"/servicesNS/nobody/{self.APP_NAME}/apps/local/{self.APP_NAME}/_reload"
            response, content = rest.simpleRequest(
                endpoint,
                sessionKey=session_key,
                method="POST"
            )
            
            if response.status in (200, 201):
                logger.info(f"[TA-cveicu] Cache reload successful (POST {endpoint})")
            else:
                logger.warning(f"[TA-cveicu] Cache reload returned status {response.status}")
            
        except Exception as e:
            logger.warning(f"[TA-cveicu] App-specific reload failed: {e}")
            
            # Fallback: Reload all apps
            try:
                endpoint = "/services/apps/local/_reload"
                response, content = rest.simpleRequest(
                    endpoint,
                    sessionKey=session_key,
                    method="POST"
                )
                logger.info("[TA-cveicu] All apps cache reloaded successfully (fallback)")
            except Exception as e2:
                logger.warning(f"[TA-cveicu] Full app reload also failed (non-critical): {e2}")
        
        # Additional: Bump the app to invalidate browser cache
        try:
            endpoint = f"/servicesNS/nobody/{self.APP_NAME}/apps/local/{self.APP_NAME}/_bump"
            response, content = rest.simpleRequest(
                endpoint,
                sessionKey=session_key,
                method="POST"
            )
            logger.debug(f"[TA-cveicu] App bump successful")
        except Exception as e:
            logger.debug(f"[TA-cveicu] App bump failed (non-critical): {e}")
    
    def _save_theme(self, theme):
        """
        Save theme preference using Entity API.
        
        Args:
            theme: Theme name ('light' or 'dark')
        """
        try:
            session_key = self.getSessionKey()
            
            # Try to get existing entity, create if not exists
            try:
                theme_entity = entity.getEntity(
                    ["configs", "conf-cveicu", "ui"],
                    None,
                    namespace=self.APP_NAME,
                    owner="nobody",
                    sessionKey=session_key
                )
                theme_entity["theme"] = theme
                entity.setEntity(theme_entity, sessionKey=session_key)
                
            except Exception:
                # Entity doesn't exist, create via REST
                endpoint = f"/servicesNS/nobody/{self.APP_NAME}/configs/conf-cveicu"
                postargs = {
                    "name": "ui",
                    "theme": theme
                }
                rest.simpleRequest(
                    endpoint,
                    sessionKey=session_key,
                    postargs=postargs,
                    method="POST"
                )
            
            logger.info(f"Theme preference saved: {theme}")
            
        except Exception as e:
            logger.warning(f"Failed to save theme via Entity API: {e}")
            # Fallback to file-based storage for non-cloud environments
            self._save_theme_file(theme)
    
    def _save_theme_file(self, theme):
        """Fallback: Save theme to local/cveicu.conf file."""
        try:
            import configparser
            app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            local_dir = os.path.join(app_dir, "local")
            conf_file = os.path.join(local_dir, "cveicu.conf")
            
            if not os.path.exists(local_dir):
                os.makedirs(local_dir)
            
            config = configparser.ConfigParser()
            if os.path.exists(conf_file):
                config.read(conf_file)
            
            if "ui" not in config:
                config["ui"] = {}
            config["ui"]["theme"] = theme
            
            with open(conf_file, "w") as f:
                config.write(f)
            
            logger.info(f"Theme saved to file: {theme}")
        except Exception as e:
            logger.error(f"Failed to save theme to file: {e}")
    
    def _get_theme(self):
        """
        Get theme preference.
        
        Returns:
            Theme name ('light' or 'dark'), defaults to 'light'
        """
        try:
            session_key = self.getSessionKey()
            
            # Try Entity API first
            try:
                theme_entity = entity.getEntity(
                    ["configs", "conf-cveicu", "ui"],
                    None,
                    namespace=self.APP_NAME,
                    owner="nobody",
                    sessionKey=session_key
                )
                return theme_entity.get("theme", "light")
            except Exception:
                pass
            
            # Fallback to file
            return self._get_theme_file()
            
        except Exception as e:
            logger.debug(f"Failed to get theme: {e}")
            return "light"
    
    def _get_theme_file(self):
        """Fallback: Get theme from local/cveicu.conf file."""
        try:
            import configparser
            app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            conf_file = os.path.join(app_dir, "local", "cveicu.conf")
            
            if os.path.exists(conf_file):
                config = configparser.ConfigParser()
                config.read(conf_file)
                return config.get("ui", "theme", fallback="light")
            return "light"
        except Exception:
            return "light"
    
    def _get_credential(self):
        """
        Retrieve stored credential from storage/passwords.
        
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
            logger.debug(f"No credential found: {e}")
            return None
    
    def _store_credential(self, clear_password):
        """
        Store credential securely in storage/passwords.
        
        Args:
            clear_password: The password to store
        """
        if rest is None:
            raise RuntimeError("Splunk REST module not available")
        
        # Delete any existing credential first
        try:
            self._delete_credential()
        except Exception:
            pass
        
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
        """Delete stored credential from storage/passwords."""
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
            pass


if admin is not None:
    admin.init(TAcveicuSetupHandler, admin.CONTEXT_APP_ONLY)
