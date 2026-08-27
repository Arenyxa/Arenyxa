"""Lightweight resource monitoring contracts."""
from dataclasses import dataclass

@dataclass(frozen=True)
class ResourceSnapshot:
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    disk_write_mb: float = 0.0

def check_stability(before: ResourceSnapshot, after: ResourceSnapshot) -> dict:
    return {
        "memory_growth_mb": max(0.0, after.memory_mb-before.memory_mb),
        "disk_write_delta_mb": max(0.0, after.disk_write_mb-before.disk_write_mb),
        "healthy": after.memory_mb >= 0 and after.disk_write_mb >= 0,
    }
