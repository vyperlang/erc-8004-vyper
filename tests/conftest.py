import os

import boa
import boa.interpret
import pytest


@pytest.fixture(autouse=True, scope="session")
def _search_path():
    """Configure Vyper search paths for Snekmate module resolution."""
    boa.interpret._search_path = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "lib", "pypi"))
    ]


@pytest.fixture
def deployer():
    return boa.env.eoa


@pytest.fixture
def identity_registry():
    return boa.load("contracts/IdentityRegistry.vy")


@pytest.fixture
def reputation_registry(identity_registry):
    return boa.load("contracts/ReputationRegistry.vy", identity_registry.address)


@pytest.fixture
def validation_registry(identity_registry):
    return boa.load("contracts/ValidationRegistry.vy", identity_registry.address)
