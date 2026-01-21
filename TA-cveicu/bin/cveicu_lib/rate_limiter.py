"""
Rate Limiter for TA-cveicu

Handles GitHub API rate limits with automatic backoff and retry logic.
"""

import logging
import time
from typing import Optional, Dict, Any
from functools import wraps


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""
    
    def __init__(self, message: str, reset_time: Optional[int] = None):
        super().__init__(message)
        self.reset_time = reset_time


class RateLimiter:
    """
    Manages GitHub API rate limits with automatic backoff.
    
    GitHub API Rate Limits:
    - Unauthenticated: 60 requests/hour
    - Authenticated (PAT): 5,000 requests/hour
    
    This class tracks rate limit headers and implements automatic
    backoff when approaching limits.
    """
    
    # Rate limit thresholds
    WARNING_THRESHOLD = 100  # Warn when fewer than 100 requests remaining
    CRITICAL_THRESHOLD = 10  # Sleep when fewer than 10 requests remaining
    
    # Retry configuration
    MAX_RETRIES = 5
    BASE_DELAY = 1.0  # Base delay in seconds
    MAX_DELAY = 60.0  # Maximum delay in seconds
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the RateLimiter.
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger("ta_cveicu.rate_limiter")
        self.remaining: Optional[int] = None
        self.limit: Optional[int] = None
        self.reset_time: Optional[int] = None
        self.last_request_time: float = 0
        self._min_request_interval = 0.1  # Minimum 100ms between requests
    
    def update_from_headers(self, headers: Dict[str, str]) -> None:
        """
        Update rate limit state from GitHub API response headers.
        
        Args:
            headers: Response headers dictionary
        """
        try:
            if 'X-RateLimit-Remaining' in headers:
                self.remaining = int(headers['X-RateLimit-Remaining'])
            if 'X-RateLimit-Limit' in headers:
                self.limit = int(headers['X-RateLimit-Limit'])
            if 'X-RateLimit-Reset' in headers:
                self.reset_time = int(headers['X-RateLimit-Reset'])
                
            self.logger.debug(
                f"Rate limit: {self.remaining}/{self.limit} remaining, "
                f"resets at {self.reset_time}"
            )
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Could not parse rate limit headers: {e}")
    
    def check_rate_limit(self) -> None:
        """
        Check current rate limit status and take action if needed.
        
        Raises:
            RateLimitExceeded: If rate limit is exhausted
        """
        if self.remaining is None:
            return  # No rate limit info yet
        
        if self.remaining <= 0:
            sleep_seconds = self._get_sleep_seconds()
            raise RateLimitExceeded(
                f"GitHub rate limit exhausted. Resets in {sleep_seconds:.0f}s",
                reset_time=self.reset_time
            )
        
        if self.remaining < self.CRITICAL_THRESHOLD:
            sleep_seconds = self._get_sleep_seconds()
            self.logger.warning(
                f"GitHub rate limit critical ({self.remaining} remaining). "
                f"Sleeping for {sleep_seconds:.0f}s"
            )
            time.sleep(sleep_seconds)
        elif self.remaining < self.WARNING_THRESHOLD:
            self.logger.warning(
                f"GitHub rate limit low: {self.remaining}/{self.limit} remaining"
            )
    
    def _get_sleep_seconds(self) -> float:
        """Calculate how long to sleep until rate limit resets."""
        if self.reset_time is None:
            return 60.0  # Default wait time
        
        sleep_seconds = self.reset_time - time.time() + 10  # Add 10s buffer
        return max(0, min(sleep_seconds, 3600))  # Cap at 1 hour
    
    def wait_if_needed(self) -> None:
        """
        Enforce minimum interval between requests.
        
        This helps avoid hitting rate limits too quickly.
        """
        elapsed = time.time() - self.last_request_time
        if elapsed < self._min_request_interval:
            time.sleep(self._min_request_interval - elapsed)
        self.last_request_time = time.time()
    
    def get_retry_delay(self, attempt: int) -> float:
        """
        Calculate delay for retry attempt using exponential backoff.
        
        Args:
            attempt: Current attempt number (0-based)
            
        Returns:
            Delay in seconds
        """
        delay = self.BASE_DELAY * (2 ** attempt)
        return min(delay, self.MAX_DELAY)
    
    def should_retry(self, attempt: int, exception: Exception) -> bool:
        """
        Determine if request should be retried.
        
        Args:
            attempt: Current attempt number (0-based)
            exception: The exception that occurred
            
        Returns:
            True if should retry, False otherwise
        """
        if attempt >= self.MAX_RETRIES:
            return False
        
        # Retry on rate limit with sleep
        if isinstance(exception, RateLimitExceeded):
            if exception.reset_time:
                sleep_seconds = exception.reset_time - time.time() + 10
                if sleep_seconds > 0 and sleep_seconds < 3600:
                    self.logger.info(f"Rate limited. Sleeping for {sleep_seconds:.0f}s")
                    time.sleep(sleep_seconds)
                    return True
        
        # Retry on transient errors
        error_str = str(exception).lower()
        transient_errors = [
            'timeout', 'connection', 'temporary', 'unavailable',
            '502', '503', '504', 'bad gateway', 'service unavailable'
        ]
        
        for error in transient_errors:
            if error in error_str:
                return True
        
        return False


def with_retry(rate_limiter: RateLimiter):
    """
    Decorator that adds retry logic with rate limit handling.
    
    Args:
        rate_limiter: RateLimiter instance to use
        
    Returns:
        Decorated function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(rate_limiter.MAX_RETRIES + 1):
                try:
                    rate_limiter.wait_if_needed()
                    rate_limiter.check_rate_limit()
                    return func(*args, **kwargs)
                    
                except Exception as e:
                    last_exception = e
                    
                    if not rate_limiter.should_retry(attempt, e):
                        raise
                    
                    delay = rate_limiter.get_retry_delay(attempt)
                    rate_limiter.logger.warning(
                        f"Request failed (attempt {attempt + 1}): {e}. "
                        f"Retrying in {delay:.1f}s"
                    )
                    time.sleep(delay)
            
            raise last_exception
        
        return wrapper
    return decorator
