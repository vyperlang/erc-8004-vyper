"""Tests for IdentityRegistry"""

from eth_utils import keccak
from eth_abi import decode
from eth_account import Account


# ── Helpers ──────────────────────────────────────────────────────────


METADATA_SET_SIG = keccak(text="MetadataSet(uint256,string,string,bytes)")
AGENT_WALLET_KEY_HASH = keccak(text="agentWallet")


def _log_name(log):
    """Return the event name for both decoded and raw log entries."""
    name = type(log).__name__
    if name != "RawLogEntry":
        return name
    # Identify by topic[0] (event signature hash)
    sig_int = int.from_bytes(METADATA_SET_SIG, "big")
    if len(log.topics) >= 1 and log.topics[0] == sig_int:
        return "MetadataSet"
    return "Unknown"


def _get_logs(contract):
    """Get logs with MetadataSet events surviving the indexed-string decode issue."""
    return contract.get_logs(strict=False)


def _filter_logs(contract, event_name):
    """Return only logs matching event_name."""
    return [l for l in _get_logs(contract) if _log_name(l) == event_name]


def _decode_metadata_set(raw_log):
    """Decode a raw MetadataSet log entry.

    Returns dict with agentId, metadataKey, metadataValue, indexedKeyHash.
    """
    assert _log_name(raw_log) == "MetadataSet"
    agent_id = raw_log.topics[1]
    indexed_key_hash = raw_log.topics[2].to_bytes(32, "big")
    key, value = decode(["string", "bytes"], raw_log.data)
    return {
        "agentId": agent_id,
        "metadataKey": key,
        "metadataValue": value,
        "indexedKeyHash": indexed_key_hash,
    }


# ── Tests ────────────────────────────────────────────────────────────


def test_register_no_args(identity_registry, deployer):
    """register() with no params: agentId=1, owner=sender, agentWallet=sender."""
    agent_id = identity_registry.register()
    assert agent_id == 1
    assert identity_registry.ownerOf(1) == deployer
    assert identity_registry.balanceOf(deployer) == 1
    assert identity_registry.totalSupply() == 1


def test_register_with_uri(identity_registry, deployer):
    """register("https://example.com") stores the URI."""
    uri = "https://example.com/agent.json"
    agent_id = identity_registry.register(uri)
    assert agent_id == 1

    # Verify via Registered event since tokenURI is not yet implemented
    registered = _filter_logs(identity_registry, "Registered")
    assert len(registered) == 1
    assert registered[0].agentURI == uri
    assert registered[0].agentId == 1
    assert registered[0].owner == deployer


def test_register_rejects_agent_wallet_key(identity_registry):
    """register() reverts if metadata contains the reserved 'agentWallet' key."""
    import boa

    with boa.reverts("IdentityRegistry: agentWallet is reserved"):
        identity_registry.register(
            "",
            [("agentWallet", b"\x01")],
        )


def test_register_increments_id(identity_registry, deployer):
    """Two register() calls produce agentId 1 and 2."""
    id1 = identity_registry.register()
    id2 = identity_registry.register()
    assert id1 == 1
    assert id2 == 2
    assert identity_registry.totalSupply() == 2
    assert identity_registry.ownerOf(1) == deployer
    assert identity_registry.ownerOf(2) == deployer


def test_register_event_order(identity_registry, deployer):
    """Events emitted in order: Transfer, MetadataSet(agentWallet), Registered."""
    identity_registry.register()
    logs = _get_logs(identity_registry)

    names = [_log_name(l) for l in logs]
    assert names == ["Transfer", "MetadataSet", "Registered"]

    # Verify Transfer
    transfer = logs[0]
    assert transfer.sender == "0x" + "00" * 20  # from zero address (mint)
    assert transfer.receiver == deployer
    assert transfer.token_id == 1

    # Verify MetadataSet (agentWallet)
    ms = _decode_metadata_set(logs[1])
    assert ms["agentId"] == 1
    assert ms["metadataKey"] == "agentWallet"
    assert ms["indexedKeyHash"] == AGENT_WALLET_KEY_HASH
    # Value is the 20-byte packed address
    assert ms["metadataValue"] == bytes.fromhex(deployer[2:].lower())

    # Verify Registered
    reg = logs[2]
    assert reg.agentId == 1
    assert reg.agentURI == ""
    assert reg.owner == deployer


def test_register_with_metadata_events(identity_registry, deployer):
    """register() with metadata entries emits MetadataSet for each."""
    metadata = [
        ("key1", b"\x01\x02\x03"),
        ("key2", b"\xaa\xbb"),
    ]
    agent_id = identity_registry.register("https://agent.io", metadata)
    assert agent_id == 1

    logs = _get_logs(identity_registry)
    names = [_log_name(l) for l in logs]
    assert names == [
        "Transfer",
        "MetadataSet",  # agentWallet
        "MetadataSet",  # key1
        "MetadataSet",  # key2
        "Registered",
    ]

    # Verify metadata entries (skip index 0=Transfer, 1=agentWallet)
    ms_key1 = _decode_metadata_set(logs[2])
    assert ms_key1["metadataKey"] == "key1"
    assert ms_key1["metadataValue"] == b"\x01\x02\x03"
    assert ms_key1["agentId"] == 1

    ms_key2 = _decode_metadata_set(logs[3])
    assert ms_key2["metadataKey"] == "key2"
    assert ms_key2["metadataValue"] == b"\xaa\xbb"

    # Verify Registered has URI
    reg = logs[4]
    assert reg.agentURI == "https://agent.io"


# ── Task 1.4: Metadata functions ─────────────────────────────────────


def test_set_agent_uri(identity_registry, deployer):
    """setAgentURI updates the URI, readable via tokenURI, emits URIUpdated."""
    identity_registry.register("https://old.io")
    identity_registry.setAgentURI(1, "https://new.io")

    # Capture logs before any view call (view calls reset the computation)
    logs = _get_logs(identity_registry)
    uri_events = [l for l in logs if _log_name(l) == "URIUpdated"]
    assert len(uri_events) == 1
    assert uri_events[0].agentId == 1
    assert uri_events[0].newURI == "https://new.io"
    assert uri_events[0].updatedBy == deployer

    assert identity_registry.tokenURI(1) == "https://new.io"


def test_set_agent_uri_access_control(identity_registry):
    """setAgentURI reverts when called by non-owner."""
    import boa

    identity_registry.register()
    other = boa.env.generate_address()
    with boa.env.prank(other):
        with boa.reverts("IdentityRegistry: caller is not owner or approved"):
            identity_registry.setAgentURI(1, "https://evil.io")


def test_token_uri_nonexistent(identity_registry):
    """tokenURI reverts for a non-existent token."""
    import boa

    with boa.reverts("erc721: invalid token ID"):
        identity_registry.tokenURI(999)


def test_token_uri_returns_stored_value(identity_registry):
    """tokenURI returns the URI set during register()."""
    identity_registry.register("https://example.com/agent.json")
    assert identity_registry.tokenURI(1) == "https://example.com/agent.json"


def test_set_metadata(identity_registry):
    """setMetadata stores a value, getMetadata retrieves it."""
    identity_registry.register()
    identity_registry.setMetadata(1, "description", b"An AI agent")

    result = identity_registry.getMetadata(1, "description")
    assert result == b"An AI agent"


def test_set_metadata_emits_event(identity_registry, deployer):
    """setMetadata emits MetadataSet with correct fields."""
    identity_registry.register()
    identity_registry.setMetadata(1, "version", b"\x01")

    logs = _get_logs(identity_registry)
    ms_events = [l for l in logs if _log_name(l) == "MetadataSet"]
    # Last MetadataSet is from setMetadata (earlier ones from register)
    ms = _decode_metadata_set(ms_events[-1])
    assert ms["agentId"] == 1
    assert ms["metadataKey"] == "version"
    assert ms["metadataValue"] == b"\x01"


def test_set_metadata_rejects_agent_wallet(identity_registry):
    """setMetadata reverts when key is the reserved 'agentWallet'."""
    import boa

    identity_registry.register()
    with boa.reverts("IdentityRegistry: agentWallet is reserved"):
        identity_registry.setMetadata(1, "agentWallet", b"\x01")


def test_set_metadata_access_control(identity_registry):
    """setMetadata reverts when called by non-owner."""
    import boa

    identity_registry.register()
    other = boa.env.generate_address()
    with boa.env.prank(other):
        with boa.reverts("IdentityRegistry: caller is not owner or approved"):
            identity_registry.setMetadata(1, "key", b"val")


def test_get_metadata_default(identity_registry):
    """getMetadata returns empty bytes for an unset key."""
    identity_registry.register()
    result = identity_registry.getMetadata(1, "nonexistent")
    assert result == b""


# ── Task 1.5: agentWallet functions ──────────────────────────────────


def _sign_agent_wallet(
    private_key, agent_id, new_wallet, owner, deadline, contract_address, chain_id=1
):
    """Build and sign an EIP-712 AgentWalletSet typed data message."""
    domain = {
        "name": "ERC8004IdentityRegistry",
        "version": "1",
        "chainId": chain_id,
        "verifyingContract": contract_address,
    }
    types = {
        "AgentWalletSet": [
            {"name": "agentId", "type": "uint256"},
            {"name": "newWallet", "type": "address"},
            {"name": "owner", "type": "address"},
            {"name": "deadline", "type": "uint256"},
        ],
    }
    message = {
        "agentId": agent_id,
        "newWallet": new_wallet,
        "owner": owner,
        "deadline": deadline,
    }
    signed = Account.sign_typed_data(
        private_key,
        domain_data=domain,
        message_types=types,
        message_data=message,
    )
    return signed.signature


def test_get_agent_wallet_after_register(identity_registry, deployer):
    """After register(), getAgentWallet returns msg.sender."""
    identity_registry.register()
    assert identity_registry.getAgentWallet(1) == deployer


def test_set_agent_wallet_eoa(identity_registry, deployer):
    """setAgentWallet with a valid EOA EIP-712 signature updates the wallet."""
    import boa
    import secrets

    identity_registry.register()

    wallet_key = secrets.token_hex(32)
    wallet_acct = Account.from_key(wallet_key)
    new_wallet = wallet_acct.address

    deadline = boa.env.evm.patch.timestamp + 120

    sig = _sign_agent_wallet(
        private_key=wallet_key,
        agent_id=1,
        new_wallet=new_wallet,
        owner=deployer,
        deadline=deadline,
        contract_address=identity_registry.address,
    )

    identity_registry.setAgentWallet(1, new_wallet, deadline, sig)
    assert identity_registry.getAgentWallet(1) == new_wallet


def test_set_agent_wallet_expired_deadline(identity_registry, deployer):
    """setAgentWallet reverts when deadline is in the past."""
    import boa
    import secrets

    identity_registry.register()

    wallet_key = secrets.token_hex(32)
    wallet_acct = Account.from_key(wallet_key)
    new_wallet = wallet_acct.address

    # Deadline in the past
    deadline = boa.env.evm.patch.timestamp - 1

    sig = _sign_agent_wallet(
        private_key=wallet_key,
        agent_id=1,
        new_wallet=new_wallet,
        owner=deployer,
        deadline=deadline,
        contract_address=identity_registry.address,
    )

    with boa.reverts("IdentityRegistry: expired deadline"):
        identity_registry.setAgentWallet(1, new_wallet, deadline, sig)


def test_set_agent_wallet_deadline_too_far(identity_registry, deployer):
    """setAgentWallet reverts when deadline is more than 5 minutes in the future."""
    import boa
    import secrets

    identity_registry.register()

    wallet_key = secrets.token_hex(32)
    wallet_acct = Account.from_key(wallet_key)
    new_wallet = wallet_acct.address

    # Deadline too far in the future (301 seconds)
    deadline = boa.env.evm.patch.timestamp + 301

    sig = _sign_agent_wallet(
        private_key=wallet_key,
        agent_id=1,
        new_wallet=new_wallet,
        owner=deployer,
        deadline=deadline,
        contract_address=identity_registry.address,
    )

    with boa.reverts("IdentityRegistry: deadline too far"):
        identity_registry.setAgentWallet(1, new_wallet, deadline, sig)


def test_set_agent_wallet_wrong_signer(identity_registry, deployer):
    """setAgentWallet reverts when signature is from wrong address."""
    import boa
    import secrets

    identity_registry.register()

    # Sign with wrong key (not newWallet's key)
    wrong_key = secrets.token_hex(32)
    wallet_key = secrets.token_hex(32)
    wallet_acct = Account.from_key(wallet_key)
    new_wallet = wallet_acct.address

    deadline = boa.env.evm.patch.timestamp + 120

    # Sign with wrong_key instead of wallet_key
    sig = _sign_agent_wallet(
        private_key=wrong_key,
        agent_id=1,
        new_wallet=new_wallet,
        owner=deployer,
        deadline=deadline,
        contract_address=identity_registry.address,
    )

    with boa.reverts("IdentityRegistry: invalid wallet signature"):
        identity_registry.setAgentWallet(1, new_wallet, deadline, sig)


def test_set_agent_wallet_access_control(identity_registry, deployer):
    """setAgentWallet reverts when called by non-owner."""
    import boa
    import secrets

    identity_registry.register()

    wallet_key = secrets.token_hex(32)
    wallet_acct = Account.from_key(wallet_key)
    new_wallet = wallet_acct.address
    deadline = boa.env.evm.patch.timestamp + 120

    sig = _sign_agent_wallet(
        private_key=wallet_key,
        agent_id=1,
        new_wallet=new_wallet,
        owner=deployer,
        deadline=deadline,
        contract_address=identity_registry.address,
    )

    other = boa.env.generate_address()
    with boa.env.prank(other):
        with boa.reverts("IdentityRegistry: caller is not owner or approved"):
            identity_registry.setAgentWallet(1, new_wallet, deadline, sig)


def test_set_agent_wallet_zero_address(identity_registry, deployer):
    """setAgentWallet reverts when newWallet is address(0)."""
    import boa

    identity_registry.register()

    zero = "0x" + "00" * 20
    deadline = boa.env.evm.patch.timestamp + 120
    with boa.reverts("IdentityRegistry: bad wallet"):
        identity_registry.setAgentWallet(1, zero, deadline, b"\x00" * 65)


def test_unset_agent_wallet(identity_registry, deployer):
    """unsetAgentWallet clears the wallet to address(0)."""
    identity_registry.register()
    assert identity_registry.getAgentWallet(1) == deployer

    identity_registry.unsetAgentWallet(1)
    assert identity_registry.getAgentWallet(1) == "0x" + "00" * 20


def test_unset_agent_wallet_access_control(identity_registry):
    """unsetAgentWallet reverts when called by non-owner."""
    import boa

    identity_registry.register()

    other = boa.env.generate_address()
    with boa.env.prank(other):
        with boa.reverts("IdentityRegistry: caller is not owner or approved"):
            identity_registry.unsetAgentWallet(1)


# ── Task 1.6: Transfer wrappers ─────────────────────────────────────


def test_transfer_clears_wallet(identity_registry, deployer):
    """transferFrom clears agentWallet to address(0)."""
    import boa

    identity_registry.register()
    assert identity_registry.getAgentWallet(1) == deployer

    recipient = boa.env.generate_address()
    identity_registry.transferFrom(deployer, recipient, 1)

    assert identity_registry.ownerOf(1) == recipient
    assert identity_registry.getAgentWallet(1) == "0x" + "00" * 20


def test_safe_transfer_clears_wallet(identity_registry, deployer):
    """safeTransferFrom clears agentWallet to address(0)."""
    import boa

    identity_registry.register()
    assert identity_registry.getAgentWallet(1) == deployer

    recipient = boa.env.generate_address()
    identity_registry.safeTransferFrom(deployer, recipient, 1)

    assert identity_registry.ownerOf(1) == recipient
    assert identity_registry.getAgentWallet(1) == "0x" + "00" * 20


def test_transfer_access_control(identity_registry, deployer):
    """transferFrom reverts when called by non-owner/non-approved."""
    import boa

    identity_registry.register()

    other = boa.env.generate_address()
    recipient = boa.env.generate_address()
    with boa.env.prank(other):
        with boa.reverts("erc721: caller is not token owner or approved"):
            identity_registry.transferFrom(deployer, recipient, 1)


def test_safe_transfer_with_data(identity_registry, deployer):
    """safeTransferFrom with data param works and clears wallet."""
    import boa

    identity_registry.register()

    recipient = boa.env.generate_address()
    identity_registry.safeTransferFrom(deployer, recipient, 1, b"\xde\xad")

    assert identity_registry.ownerOf(1) == recipient
    assert identity_registry.getAgentWallet(1) == "0x" + "00" * 20


def test_transfer_preserves_metadata(identity_registry, deployer):
    """Transfer clears agentWallet but preserves other metadata."""
    import boa

    metadata = [
        ("description", b"An AI agent"),
        ("version", b"\x01"),
    ]
    identity_registry.register("https://agent.io", metadata)

    assert identity_registry.getMetadata(1, "description") == b"An AI agent"
    assert identity_registry.getMetadata(1, "version") == b"\x01"
    assert identity_registry.getAgentWallet(1) == deployer

    recipient = boa.env.generate_address()
    identity_registry.transferFrom(deployer, recipient, 1)

    # Wallet cleared
    assert identity_registry.getAgentWallet(1) == "0x" + "00" * 20
    # Metadata preserved
    assert identity_registry.getMetadata(1, "description") == b"An AI agent"
    assert identity_registry.getMetadata(1, "version") == b"\x01"


# ── Phase A.1: isAuthorizedOrOwner ─────────────────────────────────


def test_is_authorized_or_owner_owner(identity_registry, deployer):
    """isAuthorizedOrOwner returns True for the owner."""
    identity_registry.register()
    assert identity_registry.isAuthorizedOrOwner(deployer, 1) is True


def test_is_authorized_or_owner_approved(identity_registry, deployer):
    """isAuthorizedOrOwner returns True for an approved address."""
    import boa

    identity_registry.register()
    approved = boa.env.generate_address()
    identity_registry.approve(approved, 1)
    assert identity_registry.isAuthorizedOrOwner(approved, 1) is True


def test_is_authorized_or_owner_operator(identity_registry, deployer):
    """isAuthorizedOrOwner returns True for an approved-for-all operator."""
    import boa

    identity_registry.register()
    operator = boa.env.generate_address()
    identity_registry.setApprovalForAll(operator, True)
    assert identity_registry.isAuthorizedOrOwner(operator, 1) is True


def test_is_authorized_or_owner_stranger(identity_registry, deployer):
    """isAuthorizedOrOwner returns False for an unauthorised address."""
    import boa

    identity_registry.register()
    stranger = boa.env.generate_address()
    assert identity_registry.isAuthorizedOrOwner(stranger, 1) is False


# ── Phase A.2: getVersion ──────────────────────────────────────────


def test_get_version(identity_registry):
    """getVersion returns '1.0.0'."""
    assert identity_registry.getVersion() == "1.0.0"
