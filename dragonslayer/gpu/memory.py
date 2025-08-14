"""
Memory Manager
==============

Advanced GPU memory management with intelligent allocation strategies.
Consolidates memory management from the enterprise GPU engine.
"""

import threading
import logging
import time
import weakref
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import numpy as np

logger = logging.getLogger(__name__)

try:
    import cupy as cp
    CUDA_AVAILABLE = True
except ImportError:
    CUDA_AVAILABLE = False
    cp = None


@dataclass
class MemoryBlock:
    """GPU memory block information."""
    block_id: str
    size_bytes: int
    allocated_at: datetime
    access_count: int = 0
    last_accessed: datetime = field(default_factory=datetime.now)
    reference: Optional[Any] = None


@dataclass
class MemoryStats:
    """Memory pool statistics."""
    total_pool_bytes: int
    allocated_bytes: int
    free_bytes: int
    fragmentation_percent: float
    allocation_count: int
    deallocation_count: int
    peak_usage_bytes: int
    avg_block_size_bytes: float


class MemoryManager:
    """
    Advanced GPU memory manager with intelligent allocation strategies.
    
    Features:
    - Intelligent memory pool management
    - Automatic defragmentation
    - Memory usage tracking and optimization
    - Leak detection and cleanup
    - Performance analytics
    """
    
    def __init__(self, pool_size_mb: int = 1024, device_id: int = 0, 
                 enable_monitoring: bool = True):
        self.pool_size_bytes = pool_size_mb * 1024 * 1024
        self.device_id = device_id
        self.enable_monitoring = enable_monitoring
        
        # Memory tracking
        self.allocated_blocks: Dict[str, MemoryBlock] = {}
        self.free_blocks: List[Tuple[int, int]] = []  # (size, offset)
        self.allocation_history: deque = deque(maxlen=10000)
        self.peak_usage = 0
        self.total_allocations = 0
        self.total_deallocations = 0
        
        # Synchronization
        self._lock = threading.RLock()
        
        # Memory pool
        self.memory_pool = None
        self._initialize_memory_pool()
        
        # Monitoring
        if self.enable_monitoring:
            self._start_monitoring()
    
    def _initialize_memory_pool(self):
        """Initialize the GPU memory pool."""
        try:
            if CUDA_AVAILABLE:
                # Set device and initialize CuPy memory pool
                cp.cuda.Device(self.device_id).use()
                self.memory_pool = cp.get_default_memory_pool()
                self.memory_pool.set_limit(size=self.pool_size_bytes)
                
                # Pre-allocate pool to reduce fragmentation
                self._preallocate_pool()
                
                logger.info(f"Initialized CUDA memory pool: {self.pool_size_bytes // (1024*1024)}MB on device {self.device_id}")
            else:
                logger.info("CUDA not available, using CPU memory pool simulation")
                self.memory_pool = None
                
        except Exception as e:
            logger.error(f"Failed to initialize memory pool: {e}")
            self.memory_pool = None
    
    def _preallocate_pool(self):
        """Pre-allocate memory pool to reduce fragmentation."""
        if not CUDA_AVAILABLE or not self.memory_pool:
            return
        
        try:
            # Allocate and immediately free a large block to establish the pool
            temp_block = cp.cuda.alloc(self.pool_size_bytes // 2)
            del temp_block
            logger.info("Memory pool pre-allocated successfully")
        except Exception as e:
            logger.warning(f"Memory pool pre-allocation failed: {e}")
    
    def _start_monitoring(self):
        """Start memory usage monitoring."""
        def monitor_loop():
            while self.enable_monitoring:
                try:
                    self._update_usage_stats()
                    time.sleep(5.0)  # Monitor every 5 seconds
                except Exception as e:
                    logger.error(f"Memory monitoring error: {e}")
                    time.sleep(5.0)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("Memory usage monitoring started")
    
    def allocate(self, size_bytes: int, alignment: int = 256, 
                tag: str = "default") -> Optional[str]:
        """
        Allocate aligned GPU memory.
        
        Args:
            size_bytes: Size to allocate in bytes
            alignment: Memory alignment requirement
            tag: Tag for tracking allocation purpose
            
        Returns:
            Block ID if successful, None otherwise
        """
        with self._lock:
            try:
                # Align size
                aligned_size = ((size_bytes + alignment - 1) // alignment) * alignment
                
                # Generate unique block ID
                block_id = f"{tag}_{int(time.time() * 1000000)}"
                
                if CUDA_AVAILABLE and self.memory_pool:
                    # Allocate GPU memory
                    memory_ptr = cp.cuda.alloc(aligned_size)
                    
                    # Create memory block record
                    block = MemoryBlock(
                        block_id=block_id,
                        size_bytes=aligned_size,
                        allocated_at=datetime.now(),
                        reference=memory_ptr
                    )
                else:
                    # CPU fallback allocation
                    memory_array = np.zeros(aligned_size // 4, dtype=np.float32)
                    
                    block = MemoryBlock(
                        block_id=block_id,
                        size_bytes=aligned_size,
                        allocated_at=datetime.now(),
                        reference=memory_array
                    )
                
                # Record allocation
                self.allocated_blocks[block_id] = block
                self.total_allocations += 1
                
                # Update peak usage
                current_usage = self.get_allocated_bytes()
                if current_usage > self.peak_usage:
                    self.peak_usage = current_usage
                
                # Log allocation history
                self.allocation_history.append({
                    'action': 'allocate',
                    'block_id': block_id,
                    'size_bytes': aligned_size,
                    'timestamp': datetime.now(),
                    'tag': tag
                })
                
                logger.debug(f"Allocated {aligned_size} bytes, block_id: {block_id}")
                return block_id
                
            except Exception as e:
                logger.error(f"Memory allocation failed for {size_bytes} bytes: {e}")
                return None
    
    def deallocate(self, block_id: str) -> bool:
        """
        Deallocate GPU memory block.
        
        Args:
            block_id: ID of block to deallocate
            
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            if block_id not in self.allocated_blocks:
                logger.warning(f"Attempted to deallocate unknown block: {block_id}")
                return False
            
            try:
                block = self.allocated_blocks[block_id]
                
                # Free the memory reference (automatic cleanup via garbage collection)
                block.reference = None
                
                # Remove from allocated blocks
                del self.allocated_blocks[block_id]
                self.total_deallocations += 1
                
                # Log deallocation
                self.allocation_history.append({
                    'action': 'deallocate',
                    'block_id': block_id,
                    'size_bytes': block.size_bytes,
                    'timestamp': datetime.now(),
                    'lifetime_seconds': (datetime.now() - block.allocated_at).total_seconds()
                })
                
                logger.debug(f"Deallocated block: {block_id}")
                return True
                
            except Exception as e:
                logger.error(f"Deallocation failed for block {block_id}: {e}")
                return False
    
    def get_block_info(self, block_id: str) -> Optional[MemoryBlock]:
        """Get information about a memory block."""
        with self._lock:
            return self.allocated_blocks.get(block_id)
    
    def get_allocated_bytes(self) -> int:
        """Get total allocated bytes."""
        with self._lock:
            return sum(block.size_bytes for block in self.allocated_blocks.values())
    
    def get_free_bytes(self) -> int:
        """Get available free bytes."""
        return self.pool_size_bytes - self.get_allocated_bytes()
    
    def get_fragmentation_percent(self) -> float:
        """Calculate memory fragmentation percentage."""
        with self._lock:
            if not self.allocated_blocks:
                return 0.0
            
            # Simple fragmentation estimate based on block count vs utilization
            allocated_bytes = self.get_allocated_bytes()
            utilization = allocated_bytes / self.pool_size_bytes
            block_count = len(self.allocated_blocks)
            
            # More blocks with lower utilization indicates fragmentation
            if utilization > 0:
                fragmentation = min(100.0, (block_count / utilization) / 10.0)
                return fragmentation
            return 0.0
    
    def get_memory_stats(self) -> MemoryStats:
        """Get comprehensive memory statistics."""
        with self._lock:
            allocated_bytes = self.get_allocated_bytes()
            free_bytes = self.get_free_bytes()
            fragmentation = self.get_fragmentation_percent()
            
            avg_block_size = (allocated_bytes / len(self.allocated_blocks) 
                            if self.allocated_blocks else 0)
            
            return MemoryStats(
                total_pool_bytes=self.pool_size_bytes,
                allocated_bytes=allocated_bytes,
                free_bytes=free_bytes,
                fragmentation_percent=fragmentation,
                allocation_count=self.total_allocations,
                deallocation_count=self.total_deallocations,
                peak_usage_bytes=self.peak_usage,
                avg_block_size_bytes=avg_block_size
            )
    
    def optimize_memory(self) -> Dict[str, Any]:
        """Optimize memory usage and defragment if necessary."""
        with self._lock:
            stats_before = self.get_memory_stats()
            
            # Trigger garbage collection
            import gc
            gc.collect()
            
            if CUDA_AVAILABLE and self.memory_pool:
                # Force CuPy memory pool cleanup
                try:
                    self.memory_pool.free_all_blocks()
                    logger.info("Triggered GPU memory pool cleanup")
                except Exception as e:
                    logger.warning(f"Memory pool cleanup failed: {e}")
            
            stats_after = self.get_memory_stats()
            
            return {
                'optimization_completed': True,
                'freed_bytes': stats_before.allocated_bytes - stats_after.allocated_bytes,
                'fragmentation_before': stats_before.fragmentation_percent,
                'fragmentation_after': stats_after.fragmentation_percent,
                'stats_before': stats_before,
                'stats_after': stats_after
            }
    
    def detect_leaks(self, max_age_hours: float = 2.0) -> List[Dict[str, Any]]:
        """Detect potential memory leaks."""
        with self._lock:
            current_time = datetime.now()
            max_age = timedelta(hours=max_age_hours)
            
            potential_leaks = []
            for block_id, block in self.allocated_blocks.items():
                age = current_time - block.allocated_at
                if age > max_age and block.access_count == 0:
                    potential_leaks.append({
                        'block_id': block_id,
                        'size_bytes': block.size_bytes,
                        'age_hours': age.total_seconds() / 3600,
                        'allocated_at': block.allocated_at.isoformat(),
                        'access_count': block.access_count
                    })
            
            if potential_leaks:
                logger.warning(f"Detected {len(potential_leaks)} potential memory leaks")
            
            return potential_leaks
    
    def cleanup_leaks(self, max_age_hours: float = 2.0) -> int:
        """Clean up detected memory leaks."""
        leaks = self.detect_leaks(max_age_hours)
        cleaned_count = 0
        
        for leak in leaks:
            if self.deallocate(leak['block_id']):
                cleaned_count += 1
        
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} memory leaks")
        
        return cleaned_count
    
    def get_allocation_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent allocation history."""
        with self._lock:
            return list(self.allocation_history)[-limit:]
    
    def export_memory_report(self, filepath: str):
        """Export detailed memory report."""
        with self._lock:
            stats = self.get_memory_stats()
            leaks = self.detect_leaks()
            history = self.get_allocation_history()
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'device_id': self.device_id,
                'memory_stats': {
                    'total_pool_mb': stats.total_pool_bytes // (1024 * 1024),
                    'allocated_mb': stats.allocated_bytes // (1024 * 1024),
                    'free_mb': stats.free_bytes // (1024 * 1024),
                    'utilization_percent': (stats.allocated_bytes / stats.total_pool_bytes) * 100,
                    'fragmentation_percent': stats.fragmentation_percent,
                    'peak_usage_mb': stats.peak_usage_bytes // (1024 * 1024),
                    'total_allocations': stats.allocation_count,
                    'total_deallocations': stats.deallocation_count,
                    'active_blocks': len(self.allocated_blocks)
                },
                'potential_leaks': leaks,
                'recent_allocations': history
            }
            
            import json
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"Memory report exported to {filepath}")
    
    def _update_usage_stats(self):
        """Update internal usage statistics."""
        # This method is called by the monitoring thread
        # Can be extended for additional periodic tasks
        pass
    
    def cleanup(self):
        """Clean up all allocated memory and resources."""
        with self._lock:
            # Stop monitoring
            self.enable_monitoring = False
            
            # Deallocate all blocks
            block_ids = list(self.allocated_blocks.keys())
            for block_id in block_ids:
                self.deallocate(block_id)
            
            # Clean up memory pool
            if CUDA_AVAILABLE and self.memory_pool:
                try:
                    self.memory_pool.free_all_blocks()
                except Exception as e:
                    logger.error(f"Memory pool cleanup failed: {e}")
            
            logger.info("Memory manager cleaned up successfully")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


# Convenience functions
def create_memory_manager(pool_size_mb: int = 1024, device_id: int = 0) -> MemoryManager:
    """Create a memory manager instance."""
    return MemoryManager(pool_size_mb=pool_size_mb, device_id=device_id)


def get_memory_usage() -> Dict[str, Any]:
    """Get current GPU memory usage across all devices."""
    if not CUDA_AVAILABLE:
        return {'error': 'CUDA not available'}
    
    try:
        device_count = cp.cuda.runtime.getDeviceCount()
        memory_info = {}
        
        for device_id in range(device_count):
            meminfo = cp.cuda.runtime.memGetInfo()
            free_bytes, total_bytes = meminfo
            used_bytes = total_bytes - free_bytes
            
            memory_info[f'device_{device_id}'] = {
                'total_mb': total_bytes // (1024 * 1024),
                'used_mb': used_bytes // (1024 * 1024),
                'free_mb': free_bytes // (1024 * 1024),
                'utilization_percent': (used_bytes / total_bytes) * 100
            }
        
        return memory_info
    except Exception as e:
        return {'error': f'Failed to get memory usage: {e}'}
