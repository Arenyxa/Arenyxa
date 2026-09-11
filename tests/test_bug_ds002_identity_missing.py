from __future__ import annotations

import pytest

from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.models import SecurityState, TrustDomain


def test_identity_lookup_missing_returns_none() -> None:
    state = SecurityState()
    assert state.identity("missing") is None


def test_disable_missing_identity_raises_arenyxa_error_not_keyerror() -> None:
    state = SecurityState()
    with pytest.raises(ArenyxaError) as caught:
        state.disable_identity("missing")
    assert caught.value.code == "IDENTITY_INVALID"
    assert not isinstance(caught.value, KeyError)


def test_bump_missing_identity_raises_arenyxa_error_not_keyerror() -> None:
    state = SecurityState()
    with pytest.raises(ArenyxaError) as caught:
        state.bump_identity_generation("missing")
    assert caught.value.code == "IDENTITY_INVALID"


def test_disable_and_bump_existing_identity() -> None:
    state = SecurityState()
    identity = state.create_identity(next(iter(TrustDomain)))
    state.bump_identity_generation(identity.id)
    state.disable_identity(identity.id)
    loaded = state.identity(identity.id)
    assert loaded is not None
    assert loaded.enabled is False
    assert loaded.generation >= 2
