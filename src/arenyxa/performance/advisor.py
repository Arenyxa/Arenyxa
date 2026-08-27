"""Performance advisory helpers for deployment guidance."""
from dataclasses import dataclass

@dataclass(frozen=True)
class StorageAdvice:
    backend: str
    workers: int
    recommendation: str

def advise_storage(backend: str, workers: int) -> StorageAdvice:
    backend_name = (backend or "").lower()
    if backend_name == "sqlite" and workers > 16:
        return StorageAdvice(backend_name, workers, "Consider PostgreSQL for higher concurrency production workloads.")
    return StorageAdvice(backend_name or "unknown", workers, "Configuration is within local workload guidance.")
