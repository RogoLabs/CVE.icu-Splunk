"""
GitHub Client for TA-cveicu

Handles communication with GitHub for downloading CVE releases and delta updates.
Uses only the requests library for AppInspect compliance.
"""

import io
import json
import logging
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import Optional, Dict, List, Iterator, Any, Tuple
from urllib.parse import urljoin

# Import requests - will be vendored in production
try:
    import requests
except ImportError:
    requests = None

from .rate_limiter import RateLimiter, RateLimitExceeded


class GitHubClientError(Exception):
    """Base exception for GitHub client errors."""
    pass


class GitHubClient:
    """
    Client for interacting with the CVEProject/cvelistV5 GitHub repository.
    
    Supports downloading baseline ZIP files and delta updates from GitHub Releases.
    Uses the requests library for all HTTP operations (AppInspect compliant).
    """
    
    # Repository configuration
    REPO_OWNER = "CVEProject"
    REPO_NAME = "cvelistV5"
    API_BASE = "https://api.github.com"
    RELEASES_URL = f"{API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/releases"
    
    # Download configuration
    DOWNLOAD_TIMEOUT = 600  # 10 minutes for large files
    CHUNK_SIZE = 8192  # 8KB chunks for streaming
    
    def __init__(
        self,
        github_token: Optional[str] = None,
        proxy_url: Optional[str] = None,
        ssl_verify: bool = True,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the GitHub client.
        
        Args:
            github_token: Optional GitHub Personal Access Token
            proxy_url: Optional HTTP proxy URL
            ssl_verify: Whether to verify SSL certificates
            logger: Optional logger instance
        """
        if requests is None:
            raise ImportError("requests library is required")
        
        self.github_token = github_token
        self.proxy_url = proxy_url
        self.ssl_verify = ssl_verify
        self.logger = logger or logging.getLogger("ta_cveicu.github_client")
        self.rate_limiter = RateLimiter(logger=self.logger)
        
        # Configure session
        self._session = requests.Session()
        self._configure_session()
    
    def _configure_session(self) -> None:
        """Configure the requests session with auth and proxies."""
        # Set headers
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'TA-cveicu/1.0.0 Splunk-Addon'
        }
        
        if self.github_token:
            headers['Authorization'] = f'token {self.github_token}'
            self.logger.debug("GitHub token configured")
        else:
            self.logger.info("No GitHub token - using unauthenticated access (60 req/hr)")
        
        self._session.headers.update(headers)
        
        # Set proxy
        if self.proxy_url:
            self._session.proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
            self.logger.debug(f"Proxy configured: {self.proxy_url}")
        
        # Set SSL verification
        self._session.verify = self.ssl_verify
    
    def _make_request(
        self,
        method: str,
        url: str,
        stream: bool = False,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """
        Make an HTTP request with rate limit handling.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            stream: Whether to stream the response
            timeout: Request timeout in seconds
            **kwargs: Additional arguments for requests
            
        Returns:
            Response object
            
        Raises:
            GitHubClientError: On request failure
        """
        self.rate_limiter.wait_if_needed()
        
        try:
            response = self._session.request(
                method=method,
                url=url,
                stream=stream,
                timeout=timeout or 30,
                **kwargs
            )
            
            # Update rate limit info
            self.rate_limiter.update_from_headers(dict(response.headers))
            
            # Check for rate limit response
            if response.status_code == 403:
                if 'rate limit' in response.text.lower():
                    raise RateLimitExceeded(
                        "GitHub API rate limit exceeded",
                        reset_time=self.rate_limiter.reset_time
                    )
            
            response.raise_for_status()
            return response
            
        except requests.exceptions.Timeout:
            raise GitHubClientError(f"Request timeout: {url}")
        except requests.exceptions.ConnectionError as e:
            raise GitHubClientError(f"Connection error: {e}")
        except requests.exceptions.HTTPError as e:
            raise GitHubClientError(f"HTTP error: {e}")
    
    def get_releases(
        self,
        per_page: int = 100,
        max_releases: Optional[int] = None
    ) -> Iterator[Dict[str, Any]]:
        """
        Fetch releases from the repository.
        
        Args:
            per_page: Number of releases per page (max 100)
            max_releases: Maximum total releases to fetch
            
        Yields:
            Release dictionaries
        """
        page = 1
        total_fetched = 0
        
        while True:
            url = f"{self.RELEASES_URL}?per_page={per_page}&page={page}"
            response = self._make_request('GET', url)
            releases = response.json()
            
            if not releases:
                break
            
            for release in releases:
                yield release
                total_fetched += 1
                
                if max_releases and total_fetched >= max_releases:
                    return
            
            if len(releases) < per_page:
                break
            
            page += 1
    
    def find_baseline_release(self, target_date: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
        """
        Find the baseline (all_CVEs_at_midnight) release for a given date.
        
        Args:
            target_date: Target date (default: most recent)
            
        Returns:
            Release dictionary or None if not found
        """
        for release in self.get_releases(max_releases=50):
            tag = release.get('tag_name', '')
            
            # Look for baseline releases (end with _0000Z)
            if '_0000Z' in tag:
                # Check for baseline ZIP asset
                for asset in release.get('assets', []):
                    if 'all_CVEs_at_midnight.zip' in asset.get('name', ''):
                        if target_date:
                            # Parse release date from tag
                            # Format: cve_YYYY-MM-DD_0000Z
                            try:
                                date_str = tag.split('_')[1]
                                release_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                                if release_date == target_date.date():
                                    return release
                            except (IndexError, ValueError):
                                continue
                        else:
                            return release  # Return most recent
        
        return None
    
    def find_delta_releases_since(
        self,
        since_tag: str,
        max_releases: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Find all delta releases since a given release tag.
        
        Args:
            since_tag: Release tag to start from (exclusive)
            max_releases: Maximum releases to check
            
        Returns:
            List of delta release dictionaries (chronological order)
        """
        deltas = []
        found_start = False
        
        for release in self.get_releases(max_releases=max_releases):
            tag = release.get('tag_name', '')
            
            if tag == since_tag:
                found_start = True
                break
            
            # Check if this is a delta release
            for asset in release.get('assets', []):
                if 'delta_CVEs_at_' in asset.get('name', ''):
                    deltas.append(release)
                    break
        
        # Return in chronological order (oldest first)
        deltas.reverse()
        
        if not found_start:
            self.logger.warning(f"Start tag '{since_tag}' not found in recent releases")
        
        return deltas
    
    def download_release_asset(
        self,
        asset_url: str,
        destination: Optional[str] = None
    ) -> str:
        """
        Download a release asset to a file.
        
        Args:
            asset_url: Browser download URL for the asset
            destination: Destination file path (default: temp file)
            
        Returns:
            Path to the downloaded file
        """
        self.logger.info(f"Downloading asset: {asset_url}")
        
        # Use headers for direct download
        headers = {'Accept': 'application/octet-stream'}
        
        response = self._make_request(
            'GET',
            asset_url,
            stream=True,
            timeout=self.DOWNLOAD_TIMEOUT,
            headers=headers
        )
        
        # Determine destination
        if destination is None:
            fd, destination = tempfile.mkstemp(suffix='.zip')
            os.close(fd)
        
        # Stream download
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0
        
        with open(destination, 'wb') as f:
            for chunk in response.iter_content(chunk_size=self.CHUNK_SIZE):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    
                    # Log progress for large files
                    if total_size > 0 and downloaded % (10 * 1024 * 1024) < self.CHUNK_SIZE:
                        progress = (downloaded / total_size) * 100
                        self.logger.debug(f"Download progress: {progress:.1f}%")
        
        self.logger.info(f"Downloaded {downloaded / (1024*1024):.1f}MB to {destination}")
        return destination
    
    def stream_zip_contents(
        self,
        zip_path: str,
        file_pattern: str = ".json"
    ) -> Iterator[Tuple[str, Dict[str, Any]]]:
        """
        Stream contents of a ZIP file without loading entirely into memory.
        Handles nested ZIPs (e.g., all_CVEs_at_midnight.zip.zip contains cves.zip).
        
        Args:
            zip_path: Path to the ZIP file
            file_pattern: File extension to filter
            
        Yields:
            Tuples of (filename, parsed JSON content)
        """
        self.logger.debug(f"Streaming ZIP contents from {zip_path}")
        
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for file_info in zf.infolist():
                # Skip directories
                if file_info.is_dir():
                    continue
                
                # Handle nested ZIP files (e.g., cves.zip inside the outer zip)
                if file_info.filename.endswith('.zip'):
                    self.logger.info(f"Found nested ZIP: {file_info.filename}")
                    # Extract nested ZIP to temp file and process it
                    with zf.open(file_info) as nested_zip_data:
                        # Create temp file for nested ZIP
                        fd, nested_path = tempfile.mkstemp(suffix='.zip')
                        try:
                            with os.fdopen(fd, 'wb') as tmp_file:
                                # Stream copy the nested ZIP
                                while True:
                                    chunk = nested_zip_data.read(8192)
                                    if not chunk:
                                        break
                                    tmp_file.write(chunk)
                            
                            # Recursively process the nested ZIP
                            yield from self.stream_zip_contents(nested_path, file_pattern)
                        finally:
                            # Clean up temp file
                            try:
                                os.unlink(nested_path)
                            except Exception:
                                pass
                    continue
                
                # Skip non-JSON files
                if not file_info.filename.endswith(file_pattern):
                    continue
                # Skip delta manifest files
                if 'delta' in file_info.filename and 'manifest' in file_info.filename.lower():
                    continue
                
                try:
                    with zf.open(file_info) as json_file:
                        content = json.load(json_file)
                        yield (file_info.filename, content)
                        
                except json.JSONDecodeError as e:
                    self.logger.warning(
                        f"Malformed JSON in {file_info.filename}: {e}"
                    )
                except Exception as e:
                    self.logger.error(
                        f"Error reading {file_info.filename}: {e}"
                    )
    
    def get_asset_for_release(
        self,
        release: Dict[str, Any],
        name_contains: str
    ) -> Optional[Dict[str, Any]]:
        """
        Find an asset in a release by name pattern.
        
        Args:
            release: Release dictionary
            name_contains: Substring to match in asset name
            
        Returns:
            Asset dictionary or None
        """
        for asset in release.get('assets', []):
            if name_contains in asset.get('name', ''):
                return asset
        return None
    
    def close(self) -> None:
        """Close the HTTP session."""
        self._session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
