"""
Resource Manager for TA-cveicu

Monitors and enforces resource limits to prevent Splunk Cloud Watchdog termination.
Provides memory management and execution timeout handling.
"""

import gc
import logging
import time
from typing import Iterator, List, TypeVar, Optional, Callable, Any

# For Linux memory monitoring
try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    # Windows doesn't have resource module
    HAS_RESOURCE = False


T = TypeVar('T')


class ResourceManager:
    """
    Monitors and enforces resource limits to prevent Watchdog termination.
    
    Splunk Cloud enforces strict resource limits:
    - Modular inputs: ~512 MB per process
    - Search commands: ~1 GB
    
    This class provides memory monitoring and triggers garbage collection
    when approaching limits.
    """
    
    DEFAULT_MEMORY_LIMIT_MB = 512
    MEMORY_WARNING_THRESHOLD = 0.8  # 80% of limit
    MEMORY_CRITICAL_THRESHOLD = 0.9  # 90% of limit
    
    def __init__(
        self,
        max_memory_mb: int = DEFAULT_MEMORY_LIMIT_MB,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the ResourceManager.
        
        Args:
            max_memory_mb: Maximum memory usage in megabytes
            logger: Optional logger instance
        """
        self.max_memory_mb = max_memory_mb
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.logger = logger or logging.getLogger("ta_cveicu.resource_manager")
        self._last_gc_time = 0
        self._gc_cooldown = 30  # Minimum seconds between forced GC
    
    def get_memory_usage_mb(self) -> float:
        """
        Get current memory usage in megabytes.
        
        Returns:
            Current memory usage in MB, or 0 if unable to determine
        """
        if not HAS_RESOURCE:
            return 0.0
        
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)
            # ru_maxrss is in KB on Linux, bytes on macOS
            import platform
            if platform.system() == 'Darwin':
                return usage.ru_maxrss / (1024 * 1024)  # bytes to MB
            else:
                return usage.ru_maxrss / 1024  # KB to MB
        except Exception:
            return 0.0
    
    def check_memory_usage(self) -> bool:
        """
        Check current memory usage against limit.
        
        Returns:
            True if within safe limits, False if approaching limit
        """
        current_mb = self.get_memory_usage_mb()
        
        if current_mb == 0:
            # Can't determine memory usage - assume OK
            return True
        
        usage_ratio = current_mb / self.max_memory_mb
        
        if usage_ratio > self.MEMORY_CRITICAL_THRESHOLD:
            self.logger.warning(
                f"CRITICAL: Memory usage at {usage_ratio:.1%} of limit "
                f"({current_mb:.0f}MB / {self.max_memory_mb}MB)"
            )
            self._force_gc()
            return False
        
        if usage_ratio > self.MEMORY_WARNING_THRESHOLD:
            self.logger.warning(
                f"Memory usage at {usage_ratio:.1%} of limit "
                f"({current_mb:.0f}MB / {self.max_memory_mb}MB)"
            )
            self._force_gc()
            return True  # Warning but still OK
        
        return True
    
    def _force_gc(self) -> None:
        """Force garbage collection if cooldown has elapsed."""
        current_time = time.time()
        if current_time - self._last_gc_time >= self._gc_cooldown:
            gc.collect()
            self._last_gc_time = current_time
            self.logger.debug("Forced garbage collection")
    
    def stream_with_memory_check(
        self,
        items: Iterator[T],
        batch_size: int = 1000,
        on_memory_warning: Optional[Callable[[], None]] = None
    ) -> Iterator[List[T]]:
        """
        Process items in batches with memory checks between batches.
        
        Args:
            items: Iterator of items to process
            batch_size: Number of items per batch
            on_memory_warning: Optional callback when memory is high
            
        Yields:
            Lists of items (batches)
        """
        batch: List[T] = []
        
        for item in items:
            batch.append(item)
            
            if len(batch) >= batch_size:
                yield batch
                batch = []
                
                # Check memory between batches
                if not self.check_memory_usage():
                    if on_memory_warning:
                        on_memory_warning()
        
        # Yield remaining items
        if batch:
            yield batch


class TimeoutManager:
    """
    Manages execution timeouts to prevent Watchdog termination.
    
    Uses cooperative timeout checking (no signals in threaded context).
    The input should periodically call check_timeout() to determine
    if it should stop processing.
    """
    
    DEFAULT_TIMEOUT_SECONDS = 3600  # 1 hour max execution
    CHECKPOINT_INTERVAL = 300       # Save progress every 5 minutes
    WARNING_THRESHOLD = 60          # Warn when 60 seconds remaining
    
    def __init__(
        self,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        checkpoint_interval: int = CHECKPOINT_INTERVAL,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the TimeoutManager.
        
        Args:
            timeout_seconds: Maximum execution time in seconds
            checkpoint_interval: Interval between checkpoints in seconds
            logger: Optional logger instance
        """
        self.timeout_seconds = timeout_seconds
        self.checkpoint_interval = checkpoint_interval
        self.logger = logger or logging.getLogger("ta_cveicu.timeout_manager")
        self.start_time: Optional[float] = None
        self.last_checkpoint_time: Optional[float] = None
    
    def start(self) -> None:
        """Start the timeout timer."""
        self.start_time = time.time()
        self.last_checkpoint_time = self.start_time
        self.logger.debug(f"Timeout timer started: {self.timeout_seconds}s limit")
    
    def check_timeout(self) -> bool:
        """
        Check if execution is approaching timeout.
        
        Returns:
            True if safe to continue, False if should stop
        """
        if self.start_time is None:
            return True
        
        elapsed = time.time() - self.start_time
        remaining = self.timeout_seconds - elapsed
        
        if remaining <= 0:
            self.logger.error(
                f"Execution timeout exceeded ({self.timeout_seconds}s). "
                "Stopping immediately."
            )
            return False
        
        if remaining < self.WARNING_THRESHOLD:
            self.logger.warning(
                f"Approaching timeout: {remaining:.0f}s remaining. "
                "Stopping gracefully to save checkpoint."
            )
            return False
        
        return True
    
    def should_checkpoint(self) -> bool:
        """
        Check if it's time to save a checkpoint.
        
        Returns:
            True if checkpoint should be saved
        """
        if self.last_checkpoint_time is None:
            self.last_checkpoint_time = time.time()
            return True
        
        elapsed = time.time() - self.last_checkpoint_time
        
        if elapsed >= self.checkpoint_interval:
            self.last_checkpoint_time = time.time()
            return True
        
        return False
    
    def get_elapsed_time(self) -> float:
        """
        Get elapsed execution time in seconds.
        
        Returns:
            Elapsed time in seconds, or 0 if not started
        """
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time
    
    def get_remaining_time(self) -> float:
        """
        Get remaining execution time in seconds.
        
        Returns:
            Remaining time in seconds, or timeout_seconds if not started
        """
        if self.start_time is None:
            return float(self.timeout_seconds)
        return max(0.0, self.timeout_seconds - self.get_elapsed_time())
    
    def reset(self) -> None:
        """Reset the timer for a new execution."""
        self.start_time = None
        self.last_checkpoint_time = None
