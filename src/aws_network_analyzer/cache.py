#!/usr/bin/env python3
"""
Cache and Resume Module for Multi-Cloud Network Analyzer

Provides:
- Caching of discovery data to speed up re-runs
- Resumable scans for interrupted org-wide scans
- Progress tracking with ETA for large organizations
"""

import json
import os
import hashlib
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, asdict
import threading
import sys


# Default cache directory
DEFAULT_CACHE_DIR = os.path.expanduser("~/.aws-network-analyzer/cache")
DEFAULT_STATE_DIR = os.path.expanduser("~/.aws-network-analyzer/state")
CACHE_TTL_HOURS = 24  # Cache validity period


@dataclass
class ScanProgress:
    """Tracks progress of an organization-wide scan."""
    scan_id: str
    cloud: str
    mode: str
    total_items: int  # accounts/subscriptions/projects
    completed_items: int
    successful_items: int
    failed_items: int
    current_item: str
    start_time: float
    last_update: float
    completed_item_ids: List[str]
    failed_item_ids: List[str]
    partial_results: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanProgress':
        return cls(**data)


class ProgressTracker:
    """
    Enhanced progress tracker with ETA calculation for large organizations.
    
    Features:
    - Visual progress bar with percentage
    - ETA calculation based on running average
    - Items per second throughput
    - Support for 100+ accounts
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
        
    def update(self, item_name: str, success: bool = True, duration: float = None):
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
                # Estimate duration from elapsed time
                elapsed = time.time() - self.start_time
                avg_time = elapsed / self.completed if self.completed > 0 else 0
                self.item_times.append(avg_time)
            
            # Keep only last 20 items for rolling average
            if len(self.item_times) > 20:
                self.item_times = self.item_times[-20:]
            
            self.current_item = item_name
            
            if not self.quiet:
                self._print_progress()
    
    def _print_progress(self):
        """Print progress bar with ETA."""
        # Rate limit printing to avoid flickering
        now = time.time()
        if now - self._last_print_time < 0.1 and self.completed < self.total:
            return
        self._last_print_time = now
        
        elapsed = time.time() - self.start_time
        pct = (self.completed / self.total) * 100 if self.total > 0 else 0
        
        # Calculate ETA
        if self.completed > 0 and len(self.item_times) > 0:
            avg_time = sum(self.item_times) / len(self.item_times)
            remaining = self.total - self.completed
            eta_seconds = remaining * avg_time
            eta_str = self._format_duration(eta_seconds)
        else:
            eta_str = "calculating..."
        
        # Calculate throughput
        if elapsed > 0:
            throughput = self.completed / elapsed
            throughput_str = f"{throughput:.1f}/s" if throughput >= 1 else f"{throughput*60:.1f}/min"
        else:
            throughput_str = "..."
        
        # Progress bar
        bar_width = 30
        filled = int(bar_width * self.completed / self.total) if self.total > 0 else 0
        bar = '█' * filled + '░' * (bar_width - filled)
        
        # Status indicators
        status_str = ""
        if self.failed > 0:
            status_str = f" ✓{self.successful} ✗{self.failed}"
        
        # Truncate current item name
        item_display = self.current_item[:30] + "..." if len(self.current_item) > 30 else self.current_item
        
        line = f"\r  [{bar}] {self.completed}/{self.total} ({pct:.0f}%){status_str} | {throughput_str} | ETA: {eta_str} | {item_display}"
        
        # Pad with spaces to clear previous longer lines
        line = line.ljust(120)
        
        sys.stderr.write(line)
        sys.stderr.flush()
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            mins = seconds / 60
            return f"{mins:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"
    
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


class ScanCache:
    """
    Cache manager for discovery results.
    
    Features:
    - Caches per-region discovery data
    - Configurable TTL
    - Automatic cache invalidation
    - Memory-efficient storage
    """
    
    def __init__(self, cache_dir: str = DEFAULT_CACHE_DIR, ttl_hours: int = CACHE_TTL_HOURS):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_hours = ttl_hours
        self.memory_cache: Dict[str, Any] = {}
    
    def _get_cache_key(self, cloud: str, account_id: str, region: str = None) -> str:
        """Generate a unique cache key."""
        key_parts = [cloud, account_id]
        if region:
            key_parts.append(region)
        key_str = ":".join(key_parts)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def _get_cache_path(self, cache_key: str) -> Path:
        """Get the file path for a cache key."""
        return self.cache_dir / f"{cache_key}.json"
    
    def get(self, cloud: str, account_id: str, region: str = None) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached data if valid.
        
        Returns None if cache miss or expired.
        """
        cache_key = self._get_cache_key(cloud, account_id, region)
        
        # Check memory cache first
        if cache_key in self.memory_cache:
            cached = self.memory_cache[cache_key]
            if self._is_valid(cached):
                return cached.get("data")
        
        # Check disk cache
        cache_path = self._get_cache_path(cache_key)
        if cache_path.exists():
            try:
                with open(cache_path, 'r') as f:
                    cached = json.load(f)
                
                if self._is_valid(cached):
                    # Populate memory cache
                    self.memory_cache[cache_key] = cached
                    return cached.get("data")
                else:
                    # Delete expired cache
                    cache_path.unlink()
            except (json.JSONDecodeError, IOError):
                pass
        
        return None
    
    def set(self, cloud: str, account_id: str, data: Dict[str, Any], region: str = None):
        """Cache discovery data."""
        cache_key = self._get_cache_key(cloud, account_id, region)
        
        cached = {
            "cloud": cloud,
            "account_id": account_id,
            "region": region,
            "timestamp": datetime.now().isoformat(),
            "ttl_hours": self.ttl_hours,
            "data": data
        }
        
        # Store in memory
        self.memory_cache[cache_key] = cached
        
        # Store on disk
        cache_path = self._get_cache_path(cache_key)
        try:
            with open(cache_path, 'w') as f:
                json.dump(cached, f)
        except IOError as e:
            print(f"Warning: Could not write cache file: {e}", file=sys.stderr)
    
    def _is_valid(self, cached: Dict[str, Any]) -> bool:
        """Check if cached data is still valid."""
        try:
            timestamp = datetime.fromisoformat(cached.get("timestamp", ""))
            ttl = cached.get("ttl_hours", self.ttl_hours)
            expiry = timestamp + timedelta(hours=ttl)
            return datetime.now() < expiry
        except (ValueError, TypeError):
            return False
    
    def invalidate(self, cloud: str, account_id: str, region: str = None):
        """Invalidate specific cache entry."""
        cache_key = self._get_cache_key(cloud, account_id, region)
        
        # Remove from memory
        self.memory_cache.pop(cache_key, None)
        
        # Remove from disk
        cache_path = self._get_cache_path(cache_key)
        if cache_path.exists():
            cache_path.unlink()
    
    def clear_all(self):
        """Clear all cached data."""
        self.memory_cache.clear()
        
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except IOError:
                pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        cache_files = list(self.cache_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in cache_files if f.exists())
        
        valid_count = 0
        expired_count = 0
        
        for cache_file in cache_files:
            try:
                with open(cache_file, 'r') as f:
                    cached = json.load(f)
                if self._is_valid(cached):
                    valid_count += 1
                else:
                    expired_count += 1
            except:
                expired_count += 1
        
        return {
            "total_entries": len(cache_files),
            "valid_entries": valid_count,
            "expired_entries": expired_count,
            "memory_entries": len(self.memory_cache),
            "disk_size_mb": total_size / (1024 * 1024),
            "cache_dir": str(self.cache_dir)
        }


class ScanStateManager:
    """
    Manager for resumable scan state.
    
    Features:
    - Save scan progress to disk
    - Resume interrupted scans
    - Track completed accounts
    - Merge partial results
    """
    
    def __init__(self, state_dir: str = DEFAULT_STATE_DIR):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
    
    def _generate_scan_id(self, cloud: str, mode: str) -> str:
        """Generate a unique scan ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{cloud}_{mode}_{timestamp}"
    
    def _get_state_path(self, scan_id: str) -> Path:
        """Get the state file path for a scan."""
        return self.state_dir / f"{scan_id}.state.json"
    
    def create_scan(self, cloud: str, mode: str, total_items: int, item_ids: List[str] = None) -> ScanProgress:
        """Create a new scan and return its progress tracker."""
        scan_id = self._generate_scan_id(cloud, mode)
        
        progress = ScanProgress(
            scan_id=scan_id,
            cloud=cloud,
            mode=mode,
            total_items=total_items,
            completed_items=0,
            successful_items=0,
            failed_items=0,
            current_item="",
            start_time=time.time(),
            last_update=time.time(),
            completed_item_ids=[],
            failed_item_ids=[],
            partial_results={}
        )
        
        self._save_state(progress)
        return progress
    
    def update_scan(self, progress: ScanProgress, item_id: str, success: bool, result: Any = None):
        """Update scan progress with a completed item."""
        progress.completed_items += 1
        progress.last_update = time.time()
        progress.current_item = item_id
        
        if success:
            progress.successful_items += 1
            progress.completed_item_ids.append(item_id)
            if result:
                progress.partial_results[item_id] = result
        else:
            progress.failed_items += 1
            progress.failed_item_ids.append(item_id)
        
        self._save_state(progress)
    
    def _save_state(self, progress: ScanProgress):
        """Save scan state to disk."""
        state_path = self._get_state_path(progress.scan_id)
        try:
            with open(state_path, 'w') as f:
                json.dump(progress.to_dict(), f, indent=2, default=str)
        except IOError as e:
            print(f"Warning: Could not save scan state: {e}", file=sys.stderr)
    
    def load_scan(self, scan_id: str) -> Optional[ScanProgress]:
        """Load a scan state from disk."""
        state_path = self._get_state_path(scan_id)
        if not state_path.exists():
            return None
        
        try:
            with open(state_path, 'r') as f:
                data = json.load(f)
            return ScanProgress.from_dict(data)
        except (json.JSONDecodeError, IOError, TypeError) as e:
            print(f"Warning: Could not load scan state: {e}", file=sys.stderr)
            return None
    
    def get_resumable_scans(self, cloud: str = None) -> List[Dict[str, Any]]:
        """Get list of scans that can be resumed."""
        resumable = []
        
        for state_file in self.state_dir.glob("*.state.json"):
            try:
                with open(state_file, 'r') as f:
                    data = json.load(f)
                
                if cloud and data.get("cloud") != cloud:
                    continue
                
                # Check if scan is incomplete
                if data.get("completed_items", 0) < data.get("total_items", 0):
                    resumable.append({
                        "scan_id": data.get("scan_id"),
                        "cloud": data.get("cloud"),
                        "mode": data.get("mode"),
                        "progress": f"{data.get('completed_items', 0)}/{data.get('total_items', 0)}",
                        "successful": data.get("successful_items", 0),
                        "failed": data.get("failed_items", 0),
                        "last_update": datetime.fromtimestamp(data.get("last_update", 0)).isoformat()
                    })
            except (json.JSONDecodeError, IOError):
                pass
        
        return sorted(resumable, key=lambda x: x.get("last_update", ""), reverse=True)
    
    def get_pending_items(self, progress: ScanProgress, all_item_ids: List[str]) -> List[str]:
        """Get list of items that still need to be processed."""
        completed = set(progress.completed_item_ids)
        failed = set(progress.failed_item_ids)
        processed = completed | failed
        return [item_id for item_id in all_item_ids if item_id not in processed]
    
    def complete_scan(self, progress: ScanProgress) -> Dict[str, Any]:
        """Mark scan as complete and return final results."""
        progress.last_update = time.time()
        self._save_state(progress)
        
        elapsed = progress.last_update - progress.start_time
        
        return {
            "scan_id": progress.scan_id,
            "cloud": progress.cloud,
            "mode": progress.mode,
            "total_items": progress.total_items,
            "successful": progress.successful_items,
            "failed": progress.failed_items,
            "elapsed_seconds": elapsed,
            "results": progress.partial_results
        }
    
    def delete_scan(self, scan_id: str):
        """Delete a scan state."""
        state_path = self._get_state_path(scan_id)
        if state_path.exists():
            state_path.unlink()
    
    def cleanup_old_scans(self, max_age_hours: int = 168):  # 1 week
        """Remove scan states older than max_age_hours."""
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        
        for state_file in self.state_dir.glob("*.state.json"):
            try:
                with open(state_file, 'r') as f:
                    data = json.load(f)
                
                last_update = datetime.fromtimestamp(data.get("last_update", 0))
                if last_update < cutoff:
                    state_file.unlink()
            except (json.JSONDecodeError, IOError):
                # Delete corrupt state files
                state_file.unlink()


# Convenience functions
_cache_instance: Optional[ScanCache] = None
_state_manager: Optional[ScanStateManager] = None


def get_cache() -> ScanCache:
    """Get the global cache instance."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = ScanCache()
    return _cache_instance


def get_state_manager() -> ScanStateManager:
    """Get the global state manager instance."""
    global _state_manager
    if _state_manager is None:
        _state_manager = ScanStateManager()
    return _state_manager


def enable_caching(cache_dir: str = DEFAULT_CACHE_DIR, ttl_hours: int = CACHE_TTL_HOURS):
    """Enable caching with custom settings."""
    global _cache_instance
    _cache_instance = ScanCache(cache_dir, ttl_hours)
    return _cache_instance


def disable_caching():
    """Disable caching."""
    global _cache_instance
    if _cache_instance:
        _cache_instance.clear_all()
    _cache_instance = None
