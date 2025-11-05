"""
Logger Module
============
Enterprise-grade logging configuration with colored console and file rotation.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional

# Try to import colorlog for colored console output
try:
    import colorlog
    HAS_COLORLOG = True
except ImportError:
    HAS_COLORLOG = False
    print("Warning: colorlog not installed. Install with: pip install colorlog")


def setup_logger(
    name: str,
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    log_dir: Path = Path("logs"),
    max_bytes: int = 10485760,  # 10MB
    backup_count: int = 5
) -> logging.Logger:
    """
    Setup enterprise-grade logger with file and console handlers.
    
    Features:
    - Colored console output (if colorlog available)
    - File rotation (prevents log files from growing indefinitely)
    - Dual handlers (console + file)
    - Configurable log levels
    - Automatic log directory creation
    
    Args:
        name: Logger name (typically module name like "compliance_ai")
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional specific log file path
        log_dir: Directory for log files (default: "logs")
        max_bytes: Maximum size of each log file before rotation (default: 10MB)
        backup_count: Number of backup files to keep (default: 5)
    
    Returns:
        Configured logger instance
    
    Examples:
        >>> logger = setup_logger("my_module")
        >>> logger.info("This is an info message")
        >>> logger.error("This is an error message")
        
        >>> logger = setup_logger("audit", level=logging.DEBUG)
        >>> logger.debug("Debug message")
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()  # Clear any existing handlers to avoid duplicates
    
    # Prevent propagation to root logger (avoid duplicate logs)
    logger.propagate = False
    
    # ==========================================
    # CONSOLE HANDLER (with optional colors)
    # ==========================================
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    if HAS_COLORLOG:
        # Colored console output
        console_formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
            secondary_log_colors={},
            style='%'
        )
    else:
        # Plain console output (fallback if colorlog not available)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # ==========================================
    # FILE HANDLER (with rotation)
    # ==========================================
    if log_file is None:
        # Auto-generate log file path
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"{name}.log"
    else:
        # Use provided log file path
        log_file.parent.mkdir(parents=True, exist_ok=True)
    
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    
    # File output format (no colors needed in files)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Get existing logger or create new one with defaults.
    
    This is a convenience function that checks if a logger already exists
    with handlers. If it does, it returns the existing logger. Otherwise,
    it creates a new one with default settings.
    
    Args:
        name: Logger name
        level: Logging level (default: INFO)
    
    Returns:
        Logger instance
    
    Examples:
        >>> logger = get_logger("my_module")
        >>> logger.info("Using get_logger convenience function")
    """
    logger = logging.getLogger(name)
    
    # If logger has no handlers, set it up with defaults
    if not logger.handlers:
        return setup_logger(name, level=level)
    
    return logger


def configure_root_logger(level: int = logging.WARNING):
    """
    Configure the root logger to capture all unconfigured loggers.
    
    This is useful to ensure third-party libraries don't pollute your logs
    with too much information.
    
    Args:
        level: Root logger level (default: WARNING to suppress noise)
    
    Examples:
        >>> configure_root_logger(logging.ERROR)  # Only show errors from third-party libs
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Simple console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    root_logger.addHandler(handler)


def disable_third_party_logging():
    """
    Disable or reduce logging from common third-party libraries.
    
    This helps keep your logs clean by suppressing verbose output from
    libraries like matplotlib, PIL, urllib3, etc.
    
    Examples:
        >>> disable_third_party_logging()
    """
    # Common noisy libraries
    noisy_loggers = [
        'matplotlib',
        'PIL',
        'urllib3',
        'requests',
        'werkzeug',
        'asyncio',
        'tensorflow',
        'torch'
    ]
    
    for logger_name in noisy_loggers:
        logging.getLogger(logger_name).setLevel(logging.WARNING)


class LogContext:
    """
    Context manager for temporary log level changes.
    
    Useful for debugging specific sections of code without changing
    the global log level.
    
    Examples:
        >>> logger = setup_logger("my_module")
        >>> with LogContext(logger, logging.DEBUG):
        ...     logger.debug("This debug message will appear")
        >>> # Logger reverts to original level here
    """
    
    def __init__(self, logger: logging.Logger, level: int):
        """
        Initialize log context.
        
        Args:
            logger: Logger to modify
            level: Temporary log level
        """
        self.logger = logger
        self.level = level
        self.original_level = None
    
    def __enter__(self):
        """Enter context - save original level and set new level."""
        self.original_level = self.logger.level
        self.logger.setLevel(self.level)
        return self.logger
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context - restore original level."""
        self.logger.setLevel(self.original_level)


# Convenience constants for log levels
DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL


# Example usage and testing
if __name__ == "__main__":
    # Example 1: Basic logger
    logger = setup_logger("example", level=DEBUG)
    
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")
    
    # Example 2: With context manager
    logger2 = setup_logger("context_example", level=WARNING)
    
    logger2.debug("This won't appear (level is WARNING)")
    
    with LogContext(logger2, DEBUG):
        logger2.debug("This will appear (temporary DEBUG level)")
    
    logger2.debug("This won't appear again (reverted to WARNING)")
    
    # Example 3: Disable third-party logging
    disable_third_party_logging()
    
    print("\n✅ Logger module tested successfully!")
    print(f"📁 Log files saved to: {Path('logs').absolute()}")