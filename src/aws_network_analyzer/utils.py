#!/usr/bin/env python3
"""
Utilities Module for Multi-Cloud Network Analyzer

Provides common utility functions and classes used across all cloud providers:
- Retry decorators with exponential backoff
- Progress indicators
- Logging setup
- Signal handling
- CIDR calculations
- Thread-safe data structures
"""

import sys
import time
import signal
import logging
import threading
import ipaddress
from functools import wraps
from typing import List, Tuple, Dict, Any, Optional, Callable, TypeVar
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from .base import MAX_RETRIES, BASE_DELAY, MAX_DELAY, ExitCode, MAX_PARALLEL_REGIONS


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger('aws_network_analyzer')


def setup_logging(verbose: bool = False, log_file: Optional[str] = None, name: str = 'aws_network_analyzer'):
    """
    Configure logging based on verbosity level.
    
    Args:
        verbose: Enable debug-level logging
        log_file: Optional file path for logging
        name: Logger name
    """
    level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Get or create logger
    log = logging.getLogger(name)
    log.setLevel(level)
    
    # Remove existing handlers
    log.handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)
    
    # Optional file handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        log.addHandler(file_handler)
        log.info(f"Logging to file: {log_file}")
    
    return log


# =============================================================================
# Signal Handling
# =============================================================================

# Global shutdown flag
_shutdown_requested = False
_executor: Optional[ThreadPoolExecutor] = None


def is_shutdown_requested() -> bool:
    """Check if shutdown was requested."""
    return _shutdown_requested


def check_shutdown():
    """Check if shutdown was requested and raise exception if so."""
    if _shutdown_requested:
        raise KeyboardInterrupt("Shutdown requested")


def create_signal_handler():
    """
    Create and register signal handlers for graceful shutdown.
    
    Returns:
        Signal handler function
    """
    global _shutdown_requested, _executor
    
    def signal_handler(signum, frame):
        global _shutdown_requested, _executor
        
        signal_name = signal.Signals(signum).name
        logger.warning(f"\nReceived {signal_name}, initiating graceful shutdown...")
        _shutdown_requested = True
        
        # Cancel pending futures if executor exists
        if _executor:
            _executor.shutdown(wait=False, cancel_futures=True)
        
        print("\n⚠ Scan interrupted. Partial results may be available.", file=sys.stderr)
        sys.exit(ExitCode.INTERRUPTED.value)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    return signal_handler


def set_executor(executor: ThreadPoolExecutor):
    """Set the executor for cleanup during shutdown."""
    global _executor
    _executor = executor


# =============================================================================
# Retry Decorators
# =============================================================================

T = TypeVar('T')


def retry_with_backoff(
    max_retries: int = MAX_RETRIES,
    base_delay: float = BASE_DELAY,
    max_delay: float = MAX_DELAY,
    retryable_exceptions: Optional[Tuple] = None,
    retryable_error_codes: Optional[Tuple] = None
):
    """
    Decorator for retrying API calls with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Base delay between retries (seconds)
        max_delay: Maximum delay between retries (seconds)
        retryable_exceptions: Tuple of exception types to retry
        retryable_error_codes: Tuple of error codes to retry (for ClientError)
    
    Example:
        @retry_with_backoff(max_retries=5)
        def call_api():
            ...
    """
    # Default retryable error codes
    if retryable_error_codes is None:
        retryable_error_codes = (
            'RequestLimitExceeded', 'Throttling', 'ThrottlingException',
            'TooManyRequestsException', 'ServiceUnavailable',
            'InternalError', 'RequestTimeout'
        )
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            import random
            
            last_exception = None
            for attempt in range(max_retries):
                try:
                    check_shutdown()
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    # Check if this is a retryable exception
                    should_retry = False
                    
                    # Check error code for ClientError-like exceptions
                    if hasattr(e, 'response'):
                        error_code = e.response.get('Error', {}).get('Code', '')
                        if error_code in retryable_error_codes:
                            should_retry = True
                    
                    # Check HTTP status code
                    if hasattr(e, 'status_code'):
                        if e.status_code in (429, 500, 502, 503, 504):
                            should_retry = True
                    
                    # Check explicit retryable exceptions
                    if retryable_exceptions and isinstance(e, retryable_exceptions):
                        should_retry = True
                    
                    if should_retry and attempt < max_retries - 1:
                        delay = min(base_delay * (2 ** attempt) + random.uniform(0, 1), max_delay)
                        
                        # Try to get Retry-After header
                        if hasattr(e, 'retry_after') and e.retry_after:
                            delay = max(delay, float(e.retry_after))
                        
                        time.sleep(delay)
                        continue
                    
                    # Non-retryable or retries exhausted
                    raise
            
            # All retries exhausted
            if last_exception:
                raise last_exception
            return None
        
        return wrapper
    return decorator


def retry_api_call(
    func: Callable,
    *args,
    max_retries: int = MAX_RETRIES,
    base_delay: float = BASE_DELAY,
    max_delay: float = MAX_DELAY,
    **kwargs
) -> Any:
    """
    Execute an API call with retry logic.
    
    This is a non-decorator version for one-off calls.
    
    Args:
        func: Function to call
        *args: Arguments to pass to function
        max_retries: Maximum retry attempts
        base_delay: Base delay between retries
        max_delay: Maximum delay
        **kwargs: Keyword arguments to pass to function
    
    Returns:
        Result from function call
    """
    import random
    
    last_exception = None
    for attempt in range(max_retries):
        try:
            check_shutdown()
            return func(*args, **kwargs)
        except Exception as e:
            last_exception = e
            should_retry = False
            
            # Check for retryable conditions
            if hasattr(e, 'response'):
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code in ('RequestLimitExceeded', 'Throttling', 'ThrottlingException',
                                 'TooManyRequestsException', 'ServiceUnavailable'):
                    should_retry = True
            
            if hasattr(e, 'status_code') and e.status_code in (429, 500, 502, 503, 504):
                should_retry = True
            
            if should_retry and attempt < max_retries - 1:
                delay = min(base_delay * (2 ** attempt) + random.uniform(0, 1), max_delay)
                time.sleep(delay)
                continue
            
            raise
    
    if last_exception:
        raise last_exception


# =============================================================================
# Progress Indicators
# =============================================================================

class ProgressIndicator:
    """
    Thread-safe progress indicator with visual progress bar.
    
    Features:
    - Visual progress bar with percentage
    - Elapsed time tracking
    - Per-item status tracking
    - Thread-safe updates
    """
    
    def __init__(self, total: int, description: str = "Progress", quiet: bool = False):
        """
        Initialize progress indicator.
        
        Args:
            total: Total number of items
            description: Description prefix
            quiet: Suppress output
        """
        self.total = total
        self.description = description
        self.quiet = quiet
        self.completed = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.item_status: Dict[str, str] = {}
    
    def update(self, item: str, status: str = "done"):
        """
        Update progress after completing an item.
        
        Args:
            item: Item identifier (e.g., region name)
            status: Status string (e.g., "done", "error")
        """
        with self.lock:
            self.completed += 1
            self.item_status[item] = status
            if not self.quiet:
                self._print_progress(item)
    
    def _print_progress(self, item: str):
        """Print progress bar to stderr."""
        pct = (self.completed / self.total) * 100 if self.total > 0 else 0
        elapsed = time.time() - self.start_time
        
        bar_len = 30
        filled = int(bar_len * self.completed / self.total) if self.total > 0 else 0
        bar = '█' * filled + '░' * (bar_len - filled)
        
        sys.stderr.write(f"\r  [{bar}] {self.completed}/{self.total} ({pct:.0f}%) - {item} ({elapsed:.1f}s)")
        sys.stderr.flush()
        
        if self.completed == self.total:
            sys.stderr.write("\n")
    
    def message(self, msg: str):
        """Print a message (clears progress line first)."""
        if not self.quiet:
            sys.stderr.write(f"\r{' ' * 80}\r")  # Clear line
            print(msg, file=sys.stderr)
    
    def finish(self):
        """Finalize progress indicator."""
        elapsed = time.time() - self.start_time
        if not self.quiet:
            sys.stderr.write(f"\r{' ' * 80}\r")  # Clear line
            print(f"  ✓ Completed {self.completed}/{self.total} in {elapsed:.1f}s", file=sys.stderr)
    
    def get_elapsed(self) -> float:
        """Get elapsed time in seconds."""
        return time.time() - self.start_time


class ETAProgressTracker:
    """
    Enhanced progress tracker with ETA calculation.
    
    Features:
    - Visual progress bar
    - ETA calculation based on running average
    - Throughput calculation
    - Success/failure tracking
    """
    
    def __init__(self, total: int, description: str = "Progress", quiet: bool = False):
        self.total = total
        self.description = description
        self.quiet = quiet
        self.completed = 0
        self.successful = 0
        self.failed = 0
        self.start_time = time.time()
        self.item_times: List[float] = []
        self.lock = threading.Lock()
        self.current_item = ""
        self._last_print_time = 0
    
    def update(self, item_name: str, success: bool = True, duration: Optional[float] = None):
        """Update progress with a completed item."""
        with self.lock:
            self.completed += 1
            if success:
                self.successful += 1
            else:
                self.failed += 1
            
            if duration:
                self.item_times.append(duration)
            else:
                elapsed = time.time() - self.start_time
                avg_time = elapsed / self.completed if self.completed > 0 else 0
                self.item_times.append(avg_time)
            
            # Keep only last 20 for rolling average
            if len(self.item_times) > 20:
                self.item_times = self.item_times[-20:]
            
            self.current_item = item_name
            
            if not self.quiet:
                self._print_progress()
    
    def _print_progress(self):
        """Print progress bar with ETA."""
        now = time.time()
        if now - self._last_print_time < 0.1 and self.completed < self.total:
            return
        self._last_print_time = now
        
        elapsed = now - self.start_time
        pct = (self.completed / self.total) * 100 if self.total > 0 else 0
        
        # Calculate ETA
        if self.completed > 0 and self.item_times:
            avg_time = sum(self.item_times) / len(self.item_times)
            remaining = self.total - self.completed
            eta_seconds = remaining * avg_time
            eta_str = self._format_duration(eta_seconds)
        else:
            eta_str = "calculating..."
        
        # Throughput
        throughput = self.completed / elapsed if elapsed > 0 else 0
        throughput_str = f"{throughput:.1f}/s" if throughput >= 1 else f"{throughput*60:.1f}/min"
        
        # Progress bar
        bar_width = 30
        filled = int(bar_width * self.completed / self.total) if self.total > 0 else 0
        bar = '█' * filled + '░' * (bar_width - filled)
        
        # Status
        status_str = f" ✓{self.successful} ✗{self.failed}" if self.failed > 0 else ""
        
        # Truncate item name
        item_display = self.current_item[:25] + "..." if len(self.current_item) > 25 else self.current_item
        
        line = f"\r  [{bar}] {self.completed}/{self.total} ({pct:.0f}%){status_str} | {throughput_str} | ETA: {eta_str} | {item_display}"
        line = line.ljust(120)
        
        sys.stderr.write(line)
        sys.stderr.flush()
    
    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"
    
    def finish(self):
        """Mark progress as complete."""
        if not self.quiet:
            elapsed = time.time() - self.start_time
            sys.stderr.write(f"\r  Completed {self.completed}/{self.total} in {self._format_duration(elapsed)} (✓{self.successful} ✗{self.failed})\n")
            sys.stderr.flush()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get progress statistics."""
        elapsed = time.time() - self.start_time
        return {
            "total": self.total,
            "completed": self.completed,
            "successful": self.successful,
            "failed": self.failed,
            "elapsed_seconds": elapsed,
            "items_per_second": self.completed / elapsed if elapsed > 0 else 0
        }


# =============================================================================
# CIDR Utilities
# =============================================================================

def check_cidr_overlap(cidrs: List[str]) -> List[Tuple[str, str]]:
    """
    Check for overlapping CIDR blocks.
    
    Args:
        cidrs: List of CIDR strings
    
    Returns:
        List of overlapping CIDR pairs
    """
    overlaps = []
    networks = []
    
    for cidr in cidrs:
        try:
            networks.append(ipaddress.IPv4Network(cidr, strict=False))
        except (ValueError, ipaddress.AddressValueError):
            continue
    
    for i, net1 in enumerate(networks):
        for j, net2 in enumerate(networks):
            if i >= j:
                continue
            if net1.overlaps(net2):
                overlaps.append((str(net1), str(net2)))
    
    return overlaps


def cidr_contains_ip(cidr: str, ip: str) -> bool:
    """
    Check if a CIDR range contains an IP address.
    
    Args:
        cidr: CIDR string (e.g., "10.0.0.0/16")
        ip: IP address string
    
    Returns:
        True if IP is in CIDR range
    """
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        address = ipaddress.IPv4Address(ip)
        return address in network
    except (ValueError, ipaddress.AddressValueError):
        return False


def get_usable_host_count(cidr: str) -> int:
    """
    Get the number of usable host addresses in a CIDR range.
    
    Args:
        cidr: CIDR string
    
    Returns:
        Number of usable hosts (total - network - broadcast)
    """
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        return max(0, network.num_addresses - 2)
    except (ValueError, ipaddress.AddressValueError):
        return 0


# =============================================================================
# Parallel Execution Utilities
# =============================================================================

def parallel_execute(
    func: Callable,
    items: List[Any],
    max_workers: int = MAX_PARALLEL_REGIONS,
    progress_desc: str = "Processing",
    quiet: bool = False
) -> Dict[Any, Any]:
    """
    Execute a function in parallel across multiple items.
    
    Args:
        func: Function to execute (should take item as first argument)
        items: List of items to process
        max_workers: Maximum parallel workers
        progress_desc: Progress description
        quiet: Suppress progress output
    
    Returns:
        Dictionary mapping items to results
    """
    global _executor
    
    results = {}
    progress = ProgressIndicator(len(items), progress_desc, quiet)
    result_lock = threading.Lock()
    
    with ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as executor:
        _executor = executor
        futures = {executor.submit(func, item): item for item in items}
        
        for future in as_completed(futures):
            item = futures[future]
            try:
                result = future.result()
                with result_lock:
                    results[item] = result
                progress.update(str(item), "done")
            except Exception as e:
                with result_lock:
                    results[item] = {"error": str(e)}
                progress.update(str(item), "error")
        
        _executor = None
    
    progress.finish()
    return results


# =============================================================================
# Formatting Utilities
# =============================================================================

def format_bytes(size: int) -> str:
    """Format bytes to human-readable string."""
    size_float = float(size)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(size_float) < 1024:
            return f"{size_float:.1f} {unit}"
        size_float /= 1024
    return f"{size_float:.1f} PB"


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """Format datetime to ISO 8601 string."""
    if dt is None:
        dt = datetime.now()
    return dt.isoformat()


def truncate_string(s: str, max_length: int, suffix: str = "...") -> str:
    """Truncate string to max length with suffix."""
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def extract_name_from_id(resource_id: str, delimiter: str = "/") -> str:
    """Extract resource name from a resource ID."""
    if delimiter in resource_id:
        return resource_id.split(delimiter)[-1]
    return resource_id


def extract_name_from_tags(tags: List[Dict[str, str]], name_key: str = "Name") -> str:
    """Extract name from a list of tags."""
    for tag in tags:
        if tag.get('Key') == name_key or tag.get('key') == name_key:
            return tag.get('Value', tag.get('value', ''))
    return ""
