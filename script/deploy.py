"""Deploy ERC-8004 registries in dependency order."""

from contracts import IdentityRegistry, ReputationRegistry, ValidationRegistry


def deploy():
    # NOTE: For live network deployment (e.g. Arc Testnet), add a network
    # section to moccasin.toml and run:
    #   mox run deploy --network arc-testnet --account <keystore>

    identity = IdentityRegistry.deploy()
    reputation = ReputationRegistry.deploy(identity.address)
    validation = ValidationRegistry.deploy(identity.address)

    print(f"IdentityRegistry:   {identity.address}")
    print(f"ReputationRegistry: {reputation.address}")
    print(f"ValidationRegistry: {validation.address}")

    return identity, reputation, validation


def moccasin_main():
    return deploy()
