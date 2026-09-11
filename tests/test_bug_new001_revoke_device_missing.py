from __future__ import annotations

import pytest

from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.models import SecurityState, TrustDomain


def test_revoke_missing_device_raises_arenyxa_error_not_keyerror() -> None:
    state = SecurityState()
    with pytest.raises(ArenyxaError) as caught:
        state.revoke_device("missing-device-id")
    assert caught.value.code == "DEVICE_INVALID"
    assert caught.value.domain == "SECURITY"
    assert not isinstance(caught.value, KeyError)


def test_revoke_existing_device_succeeds() -> None:
    state = SecurityState()
    device = state.create_device(next(iter(TrustDomain)))
    assert device.revoked is False
    generation_before = device.generation
    state.revoke_device(device.id)
    loaded = state.device(device.id)
    assert loaded is not None
    assert loaded.revoked is True
    assert loaded.generation == generation_before + 1
