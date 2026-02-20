# pragma version ~=0.4.3
"""
@title ERC-8004 Identity Registry
@custom:contract-name IdentityRegistry
@license UNLICENSED
@notice ERC-721 based agent identity registration with metadata,
        URI storage, and agent wallet management using EIP-712/ERC-1271
        signature verification. Implements the Identity Registry portion
        of the ERC-8004 Trustless Agents standard.
"""


# @dev We import and use the `ownable` module.
from snekmate.auth import ownable


# @dev We import and initialise the `erc721` module,
# injecting the `ownable` module as a dependency.
from snekmate.tokens import erc721

initializes: ownable
initializes: erc721[ownable := ownable]


# @dev We import the `message_hash_utils` module.
# It is stateless and does not require `uses:`.
from snekmate.utils import message_hash_utils


# @dev Selective ERC-721 exports. We exclude:
# - transferFrom, safeTransferFrom: wrapped for agentWallet clearing on transfer
# - tokenURI: overridden for URI_MAX=2048 (Snekmate caps at 512)
# - safe_mint, set_minter, is_minter, burn: minting controlled by register() only
# - permit, nonces, DOMAIN_SEPARATOR: EIP-4494 not in ERC-8004 spec
# - transfer_ownership, renounce_ownership: not in ERC-8004 spec
exports: (
    erc721.supportsInterface,
    erc721.balanceOf,
    erc721.ownerOf,
    erc721.approve,
    erc721.getApproved,
    erc721.setApprovalForAll,
    erc721.isApprovedForAll,
    erc721.totalSupply,
    erc721.tokenByIndex,
    erc721.tokenOfOwnerByIndex,
    erc721.name,
    erc721.symbol,
)


# @dev Max-size constants (UPPER_SNAKE_CASE, no leading underscore).
URI_MAX: constant(uint256) = 2048
KEY_MAX: constant(uint256) = 64
VALUE_MAX: constant(uint256) = 1024
SIG_MAX: constant(uint256) = 256
METADATA_MAX: constant(uint256) = 16


# @dev Reserved metadata key for agent wallet address.
_AGENT_WALLET_KEY: constant(String[11]) = "agentWallet"


# @dev EIP-712 type hash for the AgentWalletSet struct.
# Verified against IdentityRegistryUpgradeable.sol in erc-8004-contracts.
_AGENT_WALLET_SET_TYPEHASH: constant(bytes32) = keccak256(
    "AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)"
)


# @dev The 4-byte magic value returned by ERC-1271 `isValidSignature`.
_ERC1271_MAGIC: constant(bytes4) = 0x1626ba7e


# @dev Maximum deadline offset (5 minutes) for setAgentWallet signatures.
_MAX_DEADLINE_DELAY: constant(uint256) = 300


# @dev EIP-712 domain separator type hash.
_EIP712_TYPE_HASH: constant(bytes32) = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)


# @dev EIP-712 domain separator cache. We maintain our own cache
# because the eip712_domain_separator module is initialised by
# erc721 and not directly accessible from this contract.
_HASHED_NAME: immutable(bytes32)
_HASHED_VERSION: immutable(bytes32)
_CACHED_DOMAIN_SEPARATOR: immutable(bytes32)
_CACHED_CHAIN_ID: immutable(uint256)
_CACHED_SELF: immutable(address)


struct MetadataEntry:
    metadataKey: String[KEY_MAX]
    metadataValue: Bytes[VALUE_MAX]


event Registered:
    agentId: indexed(uint256)
    agentURI: String[URI_MAX]
    owner: indexed(address)


event URIUpdated:
    agentId: indexed(uint256)
    newURI: String[URI_MAX]
    updatedBy: indexed(address)


event MetadataSet:
    agentId: indexed(uint256)
    indexedMetadataKey: indexed(String[KEY_MAX])
    metadataKey: String[KEY_MAX]
    metadataValue: Bytes[VALUE_MAX]


# @dev Auto-incrementing agent ID counter, starting at 1.
_next_id: uint256


# @dev Agent URI storage. Separate from Snekmate's _token_uris
# (which caps at String[432]) to support URI_MAX=2048.
_agent_uris: HashMap[uint256, String[URI_MAX]]


# @dev Arbitrary metadata storage per agent, keyed by string.
_metadata: HashMap[uint256, HashMap[String[KEY_MAX], Bytes[VALUE_MAX]]]


# @dev Agent wallet address per agent ID.
_agent_wallets: HashMap[uint256, address]


@deploy
@payable
def __init__():
    """
    @dev To omit the opcodes for checking the `msg.value`
         in the creation-time EVM bytecode, the constructor
         is declared as `payable`.
    @notice Initialises the ERC-721 token with name
            "ERC8004IdentityRegistry" and symbol "AGENT",
            sets up the EIP-712 domain separator cache,
            and starts the agent ID counter at 0.
    """
    ownable.__init__()
    erc721.__init__(
        "AgentIdentity",
        "AGENT",
        "",
        "ERC8004IdentityRegistry",
        "1",
    )

    self._next_id = 0

    hashed_name: bytes32 = keccak256("ERC8004IdentityRegistry")
    hashed_version: bytes32 = keccak256("1")
    _HASHED_NAME = hashed_name
    _HASHED_VERSION = hashed_version
    _CACHED_CHAIN_ID = chain.id
    _CACHED_SELF = self
    _CACHED_DOMAIN_SEPARATOR = keccak256(
        abi_encode(
            _EIP712_TYPE_HASH,
            hashed_name,
            hashed_version,
            chain.id,
            self,
        )
    )


@internal
@view
def _domain_separator_v4() -> bytes32:
    """
    @dev Returns the domain separator for the current chain.
         Uses the cached value when chain ID and contract address
         match, recomputes otherwise (e.g. after a chain fork).
    @return bytes32 The 32-byte domain separator.
    """
    if self == _CACHED_SELF and chain.id == _CACHED_CHAIN_ID:
        return _CACHED_DOMAIN_SEPARATOR
    return keccak256(
        abi_encode(
            _EIP712_TYPE_HASH,
            _HASHED_NAME,
            _HASHED_VERSION,
            chain.id,
            self,
        )
    )


@internal
@view
def _hash_typed_data_v4(struct_hash: bytes32) -> bytes32:
    """
    @dev Returns the EIP-712 hash of a fully encoded message
         for this domain.
    @param struct_hash The 32-byte hashed struct.
    @return bytes32 The 32-byte typed data hash.
    """
    return message_hash_utils._to_typed_data_hash(
        self._domain_separator_v4(), struct_hash
    )


@internal
def _check_owner_or_approved(agentId: uint256):
    """
    @dev Reverts if `msg.sender` is not the owner of `agentId`,
         not approved for `agentId`, and not an approved operator
         for the owner. Also reverts if `agentId` does not exist
         (via the underlying `_owner_of` check in erc721).
    @param agentId The 32-byte agent identifier.
    """
    assert erc721._is_approved_or_owner(
        msg.sender, agentId
    ), "IdentityRegistry: caller is not owner or approved"


@internal
def _clear_agent_wallet(agentId: uint256):
    """
    @dev Clears the agent wallet for `agentId` by setting it to
         the zero address and emitting MetadataSet with an empty value.
    @param agentId The 32-byte agent identifier.
    """
    self._agent_wallets[agentId] = empty(address)
    log MetadataSet(
        agentId=agentId,
        indexedMetadataKey=_AGENT_WALLET_KEY,
        metadataKey=_AGENT_WALLET_KEY,
        metadataValue=b"",
    )


@external
@nonreentrant
def register(
    agentURI: String[URI_MAX] = "",
    metadata: DynArray[MetadataEntry, METADATA_MAX] = [],
) -> uint256:
    """
    @dev Registers a new agent identity. Mints an ERC-721 token to
         `msg.sender`, sets the agent URI, initialises the agent wallet
         to `msg.sender`, stores any additional metadata entries, and
         emits the required events in order.
    @notice Produces three ABI selectors via default parameters:
            `register()`, `register(string)`, and
            `register(string,(string,bytes)[])`.
    @param agentURI The URI for the agent (may be empty).
    @param metadata Additional metadata entries. The reserved key
           "agentWallet" is rejected.
    @return uint256 The newly assigned agent ID.
    """
    agentId: uint256 = self._next_id
    self._next_id = agentId + 1

    for entry: MetadataEntry in metadata:
        assert (
            entry.metadataKey != _AGENT_WALLET_KEY
        ), "IdentityRegistry: agentWallet is reserved"

    erc721._safe_mint(msg.sender, agentId, b"")

    self._agent_uris[agentId] = agentURI

    self._agent_wallets[agentId] = msg.sender
    wallet_value: Bytes[20] = slice(convert(msg.sender, bytes32), 12, 20)
    log MetadataSet(
        agentId=agentId,
        indexedMetadataKey=_AGENT_WALLET_KEY,
        metadataKey=_AGENT_WALLET_KEY,
        metadataValue=wallet_value,
    )

    for entry: MetadataEntry in metadata:
        self._metadata[agentId][entry.metadataKey] = entry.metadataValue
        log MetadataSet(
            agentId=agentId,
            indexedMetadataKey=entry.metadataKey,
            metadataKey=entry.metadataKey,
            metadataValue=entry.metadataValue,
        )

    log Registered(
        agentId=agentId,
        agentURI=agentURI,
        owner=msg.sender,
    )

    return agentId


@external
def setAgentURI(agentId: uint256, newURI: String[URI_MAX]):
    """
    @dev Updates the URI for `agentId`.
    @notice Only the owner or an approved operator can call this.
    @param agentId The 32-byte agent identifier.
    @param newURI The new URI string.
    """
    self._check_owner_or_approved(agentId)
    self._agent_uris[agentId] = newURI
    log URIUpdated(
        agentId=agentId,
        newURI=newURI,
        updatedBy=msg.sender,
    )


@external
@view
def tokenURI(tokenId: uint256) -> String[URI_MAX]:
    """
    @dev Returns the URI for `tokenId`.
    @notice Reverts if the token does not exist.
    @param tokenId The 32-byte token identifier.
    @return String The agent URI.
    """
    erc721._owner_of(tokenId)
    return self._agent_uris[tokenId]


@external
@view
def getMetadata(
    agentId: uint256, metadataKey: String[KEY_MAX]
) -> Bytes[VALUE_MAX]:
    """
    @dev Returns the metadata value for `agentId` and `metadataKey`.
         The reserved key "agentWallet" returns the 20-byte packed
         wallet address from the dedicated storage mapping.
    @param agentId The 32-byte agent identifier.
    @param metadataKey The metadata key string.
    @return Bytes The metadata value, or empty bytes if unset.
    """
    if metadataKey == _AGENT_WALLET_KEY:
        wallet: address = self._agent_wallets[agentId]
        if wallet != empty(address):
            return slice(convert(wallet, bytes32), 12, 20)
        return b""
    return self._metadata[agentId][metadataKey]


@external
def setMetadata(
    agentId: uint256,
    metadataKey: String[KEY_MAX],
    metadataValue: Bytes[VALUE_MAX],
):
    """
    @dev Sets a metadata entry for `agentId`.
    @notice Only the owner or an approved operator can call this.
            The reserved key "agentWallet" is rejected.
    @param agentId The 32-byte agent identifier.
    @param metadataKey The metadata key string.
    @param metadataValue The metadata value bytes.
    """
    self._check_owner_or_approved(agentId)
    assert (
        metadataKey != _AGENT_WALLET_KEY
    ), "IdentityRegistry: agentWallet is reserved"
    self._metadata[agentId][metadataKey] = metadataValue
    log MetadataSet(
        agentId=agentId,
        indexedMetadataKey=metadataKey,
        metadataKey=metadataKey,
        metadataValue=metadataValue,
    )


@external
@nonreentrant
def setAgentWallet(
    agentId: uint256,
    newWallet: address,
    deadline: uint256,
    signature: Bytes[SIG_MAX],
):
    """
    @dev Sets the agent wallet for `agentId` to `newWallet`, verified
         by an EIP-712 signature (EOA via ecrecover) or ERC-1271
         signature (contract wallet via isValidSignature).
    @notice Only the owner or an approved operator can call this.
            The signature must come from `newWallet` to prove ownership.
            Replay protection uses a tight deadline (max 5 minutes).
    @param agentId The 32-byte agent identifier.
    @param newWallet The new wallet address.
    @param deadline The signature expiration timestamp.
    @param signature The EIP-712 or ERC-1271 signature from `newWallet`.
    """
    self._check_owner_or_approved(agentId)

    assert newWallet != empty(address), "IdentityRegistry: bad wallet"
    assert block.timestamp <= deadline, "IdentityRegistry: expired deadline"
    assert (
        deadline <= block.timestamp + _MAX_DEADLINE_DELAY
    ), "IdentityRegistry: deadline too far"

    owner: address = erc721._owner_of(agentId)
    struct_hash: bytes32 = keccak256(
        abi_encode(
            _AGENT_WALLET_SET_TYPEHASH,
            agentId,
            newWallet,
            owner,
            deadline,
        )
    )
    digest: bytes32 = self._hash_typed_data_v4(struct_hash)

    # Try ECDSA recovery first (EOAs + EIP-7702 delegated EOAs).
    valid: bool = False
    if len(signature) >= 65:
        r: uint256 = extract32(signature, 0, output_type=uint256)
        s: uint256 = extract32(signature, 32, output_type=uint256)
        v: uint256 = convert(slice(signature, 64, 1), uint256)
        recovered: address = ecrecover(digest, v, r, s)
        if recovered == newWallet and recovered != empty(address):
            valid = True

    # If ECDSA failed or didn't match, try ERC-1271 (smart contract wallets).
    if not valid:
        success: bool = empty(bool)
        return_data: Bytes[32] = b""
        success, return_data = raw_call(
            newWallet,
            abi_encode(
                digest,
                signature,
                method_id=_ERC1271_MAGIC,
            ),
            max_outsize=32,
            is_static_call=True,
            revert_on_failure=False,
        )
        assert (
            success
            and len(return_data) == 32
            and convert(return_data, bytes32)
            == convert(_ERC1271_MAGIC, bytes32)
        ), "IdentityRegistry: invalid wallet signature"

    self._agent_wallets[agentId] = newWallet
    wallet_value: Bytes[20] = slice(convert(newWallet, bytes32), 12, 20)
    log MetadataSet(
        agentId=agentId,
        indexedMetadataKey=_AGENT_WALLET_KEY,
        metadataKey=_AGENT_WALLET_KEY,
        metadataValue=wallet_value,
    )


@external
@view
def getAgentWallet(agentId: uint256) -> address:
    """
    @dev Returns the agent wallet address for `agentId`.
    @param agentId The 32-byte agent identifier.
    @return address The agent wallet address, or zero if unset.
    """
    return self._agent_wallets[agentId]


@external
def unsetAgentWallet(agentId: uint256):
    """
    @dev Clears the agent wallet for `agentId`.
    @notice Only the owner or an approved operator can call this.
    @param agentId The 32-byte agent identifier.
    """
    self._check_owner_or_approved(agentId)
    self._clear_agent_wallet(agentId)


@external
def transferFrom(from_: address, to: address, tokenId: uint256):
    """
    @dev Transfers `tokenId` token from `from_` to `to`, then clears
         the agent wallet for `tokenId`.
    @notice Wraps the ERC-721 transfer with agentWallet clearing.
            Caller must be the owner or an approved operator.
    @param from_ The 20-byte sender address (must be current owner).
    @param to The 20-byte receiver address.
    @param tokenId The 32-byte token identifier.
    """
    assert erc721._is_approved_or_owner(
        msg.sender, tokenId
    ), "IdentityRegistry: caller is not owner or approved"
    self._clear_agent_wallet(tokenId)
    erc721._transfer(from_, to, tokenId)


@external
def safeTransferFrom(
    from_: address, to: address, tokenId: uint256, data: Bytes[1024] = b""
):
    """
    @dev Safely transfers `tokenId` token from `from_` to `to`, then
         clears the agent wallet for `tokenId`.
    @notice Wraps the ERC-721 safe transfer with agentWallet clearing.
            Caller must be the owner or an approved operator.
            If `to` is a contract, it must implement
            {IERC721Receiver-onERC721Received}.
            Default parameter produces both selectors:
            `safeTransferFrom(address,address,uint256)` and
            `safeTransferFrom(address,address,uint256,bytes)`.
    @param from_ The 20-byte sender address (must be current owner).
    @param to The 20-byte receiver address.
    @param tokenId The 32-byte token identifier.
    @param data The maximum 1,024-byte additional data
           with no specified format sent to `to`.
    """
    assert erc721._is_approved_or_owner(
        msg.sender, tokenId
    ), "IdentityRegistry: caller is not owner or approved"
    self._clear_agent_wallet(tokenId)
    erc721._safe_transfer(from_, to, tokenId, data)


@external
@view
def isAuthorizedOrOwner(spender: address, agentId: uint256) -> bool:
    """
    @dev Returns True if `spender` is the owner of `agentId`, is
         approved for `agentId`, or is an approved operator for the
         owner. Reverts if `agentId` does not exist.
    @param spender The address to check authorisation for.
    @param agentId The agent identifier.
    @return bool True if authorised, False otherwise.
    """
    owner: address = erc721._owner_of(agentId)
    return (
        spender == owner
        or erc721.isApprovedForAll[owner][spender]
        or erc721._get_approved(agentId) == spender
    )


@external
@pure
def get_version() -> String[8]:
    """
    @dev Returns the version of this contract.
    @return String[8] The version string.
    """
    return "1.0.0"
