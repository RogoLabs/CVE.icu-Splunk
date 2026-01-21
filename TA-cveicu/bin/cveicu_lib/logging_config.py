"""
Logging Configuration for TA-cveicu

Configures logging to TA-cveicu.log in Splunk's log directory.
AppInspect Compliant: Uses standard Python logging library.
"""

import logging
import logging.handlers
import os
from typing import Optional


def setup_logging(
    log_level: str = "INFO",
    log_name: str = "ta_cveicu",
    splunk_home: Optional[str] = None
) -> logging.Logger:
    """
    Configure logging to TA-cveicu.log in Splunk's log directory.
    
    Args:
        log_level: Logging verbosity level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_name: Logger name (default: ta_cveicu)
        splunk_home: Override SPLUNK_HOME path (default: from environment)
    
    Returns:
        Configured logger instance
    """
    # Determine Splunk log directory
    if splunk_home is None:
        splunk_home = os.environ.get('SPLUNK_HOME', '/opt/splunk')
    
    log_dir = os.path.join(splunk_home, 'var', 'log', 'splunk')
    log_file = os.path.join(log_dir, 'TA-cveicu.log')
    
    # Ensure log directory exists
    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError:
        # Fall back to current directory if we can't create log dir
        log_file = 'TA-cveicu.log'
    
    # Create logger
    logger = logging.getLogger(log_name)
    
    # Convert log level string to constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(numeric_level)
    
    # Prevent duplicate handlers on repeated calls
    if logger.handlers:
        return logger
    
    # Format: timestamp level [component] message
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S %z'
    )
    
    # File handler with rotation (10MB max, 5 backups)
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(numeric_level)
        logger.addHandler(file_handler)
    except (OSError, IOError) as e:
        # If we can't write to file, we'll just use stderr
        pass
    
    # Also log to stderr for splunkd.log capture
    # Modular inputs write stderr to splunkd.log
    stderr_handler = logging.StreamHandler()
    stderr_handler.setFormatter(formatter)
    stderr_handler.setLevel(numeric_level)
    logger.addHandler(stderr_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a child logger for a specific module.
    
    Args:
        name: Module name (will be prefixed with ta_cveicu.)
    
    Returns:
        Logger instance
    """
    return logging.getLogger(f"ta_cveicu.{name}")


class LogContext:
    """
    Context manager for adding contextual information to log messages.
    
    Usage:
        with LogContext(logger, cve_id="CVE-2026-1234"):
            logger.info("Processing CVE")  # Will include CVE ID in context
    """
    
    def __init__(self, logger: logging.Logger, **kwargs):
        self.logger = logger
        self.context = kwargs
        self.old_factory = None
    
    def __enter__(self):
        self.old_factory = logging.getLogRecordFactory()
        context = self.context
        
        def record_factory(*args, **kwargs):
            record = self.old_factory(*args, **kwargs)
            for key, value in context.items():
                setattr(record, key, value)
            return record
        
        logging.setLogRecordFactory(record_factory)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        logging.setLogRecordFactory(self.old_factory)
        return False
