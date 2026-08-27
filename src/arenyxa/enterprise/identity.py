"""Enterprise identity service facade with authentication and account boundaries."""
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

from arenyxa.enterprise.identity_models import (
    EnterpriseStatus, _fail, ENTERPRISE_SESSION_TTL_SECONDS, STEP_UP_MAX_AGE_SECONDS, MAX_FAILURE_BUCKETS,
    MAX_SERVICE_LEASES, MAX_SERVICE_LEASE_TTL_SECONDS,
)
from arenyxa.enterprise.identity_auth import IdentityAuthMixin
from arenyxa.enterprise.identity_accounts import IdentityAccountMixin
from arenyxa.enterprise.identity_services import IdentityServiceMixin

class LocalEnterpriseIdentityService(IdentityAuthMixin, IdentityAccountMixin, IdentityServiceMixin):
    """Local enterprise identity authority composed from bounded identity service mixins."""
    def __init__(self, security: SecurityKernel, data_root: Path) -> None:
        self.security = security
        self.vault = EnterpriseVault(Path(data_root) / "enterprise" / "identity.aryxvault")
        self._lock = threading.Lock()
                                                                                            
        self._mutation_lock = threading.Lock()
        self._handle: EnterpriseVaultHandle | None = None
        self._session: Session | None = None
        self._account_id = ""
        self._identity_id = ""
        self._step_up_at = 0.0
        self._failures: "collections.OrderedDict[str, tuple[int, float]]" = collections.OrderedDict()
        self._auth_throttle_path = Path(data_root) / "enterprise" / "auth_throttle.json"
        self._service_leases: dict[str, dict[str, Any]] = {}
        self._install_policies()

