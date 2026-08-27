from __future__ import annotations

import collections
import copy
import hashlib
import logging
import secrets
import threading
import time
from dataclasses import asdict, field
from pathlib import Path
from typing import Any, Callable, Mapping
from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id, utc_now
from arenyxa.enterprise.vault import (
    ENTERPRISE_PERMISSION_CATALOG,
    MAX_BACKUP_BYTES,
    MAX_VAULT_BYTES,
    EnterpriseVault,
    EnterpriseVaultHandle,
    password_verifier,
    verify_password,
    validate_payload,
)
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, read_bytes_limited
from arenyxa.enterprise.transport_security import (
    AuthThrottleIntegrityError, MAX_AUTH_THROTTLE_BYTES, auth_bucket_id, load_auth_throttle, save_auth_throttle,
)
from arenyxa.security import PolicyEffect, PolicyRule, SecurityKernel, Session, TrustDomain

ENTERPRISE_SESSION_TTL_SECONDS = 8 * 60 * 60
STEP_UP_MAX_AGE_SECONDS = 5 * 60
MAX_FAILURE_BUCKETS = 256
MAX_SERVICE_LEASES = 16
MAX_SERVICE_LEASE_TTL_SECONDS = 24 * 60 * 60

def _fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="ENTERPRISE", context=context)

@dataclass(frozen=True, slots=True)
class EnterpriseStatus:
    configured: bool
    unlocked: bool
    authenticated: bool
    enterprise_id: str = ""
    enterprise_name: str = ""
    account_id: str = ""
    username: str = ""
    roles: tuple[str, ...] = field(default_factory=tuple)
    permissions: tuple[str, ...] = field(default_factory=tuple)
    session_expires_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

