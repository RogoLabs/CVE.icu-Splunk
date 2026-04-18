"""
TA-cveicu Library Package

Core modules for CVE List V5 ingestion from GitHub.
"""

__version__ = "2.0.0"
__author__ = "cve.icu"

from .logging_config import setup_logging
from .credential_manager import CredentialManager
from .resource_manager import ResourceManager, TimeoutManager
from .rate_limiter import RateLimiter
from .github_client import GitHubClient
from .checkpoint_manager import CheckpointManager
from .cve_processor import CVEProcessor

__all__ = [
    "setup_logging",
    "CredentialManager",
    "ResourceManager",
    "TimeoutManager",
    "RateLimiter",
    "GitHubClient",
    "CheckpointManager",
    "CVEProcessor",
]
