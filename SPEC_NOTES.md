# ERC-8004 Spec Notes for Vyper Implementation

Source: https://eips.ethereum.org/EIPS/eip-8004
Status: Draft ERC, live on mainnet since Jan 29, 2026.
Requires: EIP-155, EIP-712, ERC-721, ERC-1271.


## Identity Registry

ERC-721 + URIStorage. `agentId` = tokenId (0-indexed), `agentURI` = tokenURI.

### Struct

```
MetadataEntry { metadataKey: string, metadataValue: bytes }
```

### Functions

```
register() → uint256 agentId
register(string agentURI) → uint256 agentId
register(string agentURI, MetadataEntry[] metadata) → uint256 agentId
setAgentURI(uint256 agentId, string newURI)
getMetadata(uint256 agentId, string metadataKey) → bytes
setMetadata(uint256 agentId, string metadataKey, bytes metadataValue)
setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes signature)
getAgentWallet(uint256 agentId) → address
unsetAgentWallet(uint256 agentId)
```

Plus ERC-721 inherited functions.

### Events

```
Registered(uint256 indexed agentId, string agentURI, address indexed owner)
URIUpdated(uint256 indexed agentId, string newURI, address indexed updatedBy)
MetadataSet(uint256 indexed agentId, string indexed indexedMetadataKey, string metadataKey, bytes metadataValue)
```

### Behavioral rules

- `agentWallet` is a reserved metadata key. Cannot be set via `setMetadata()` or during `register()`.
- On `register()`, `agentWallet` is set to `msg.sender`.
- `setAgentWallet` verifies EIP-712 signature (EOA) or ERC-1271 (contract wallet) from `newWallet`.
- On transfer, `agentWallet` is cleared to `address(0)` before the transfer (CEI pattern).
- `register()` emits: Transfer, MetadataSet (agentWallet), one MetadataSet per extra entry, Registered.
- Only owner or approved operator can call setAgentURI, setMetadata, unsetAgentWallet, setAgentWallet.


## Reputation Registry

### Functions

```
getIdentityRegistry() → address
giveFeedback(uint256 agentId, int128 value, uint8 valueDecimals, string tag1, string tag2, string endpoint, string feedbackURI, bytes32 feedbackHash)
revokeFeedback(uint256 agentId, uint64 feedbackIndex)
appendResponse(uint256 agentId, address clientAddress, uint64 feedbackIndex, string responseURI, bytes32 responseHash)
getSummary(uint256 agentId, address[] clientAddresses, string tag1, string tag2) → (uint64 count, int128 summaryValue, uint8 summaryValueDecimals)
readFeedback(uint256 agentId, address clientAddress, uint64 feedbackIndex) → (int128 value, uint8 valueDecimals, string tag1, string tag2, bool isRevoked)
readAllFeedback(uint256 agentId, address[] clientAddresses, string tag1, string tag2, bool includeRevoked) → (address[] clients, uint64[] feedbackIndexes, int128[] values, uint8[] valueDecimals, string[] tag1s, string[] tag2s, bool[] revokedStatuses)
getResponseCount(uint256 agentId, address clientAddress, uint64 feedbackIndex, address[] responders) → uint64
getClients(uint256 agentId) → address[]
getLastIndex(uint256 agentId, address clientAddress) → uint64
```

### Events

```
NewFeedback(uint256 indexed agentId, address indexed clientAddress, uint64 feedbackIndex, int128 value, uint8 valueDecimals, string indexed indexedTag1, string tag1, string tag2, string endpoint, string feedbackURI, bytes32 feedbackHash)
FeedbackRevoked(uint256 indexed agentId, address indexed clientAddress, uint64 indexed feedbackIndex)
ResponseAppended(uint256 indexed agentId, address indexed clientAddress, uint64 feedbackIndex, address indexed responder, string responseURI, bytes32 responseHash)
```

### Behavioral rules

- `valueDecimals` MUST be 0–18.
- `value` MUST be within ±1e38.
- Submitter MUST NOT be agent owner or approved operator.
- `agentId` must exist in the Identity Registry.
- `tag1`, `tag2`, `endpoint`, `feedbackURI`, `feedbackHash` are OPTIONAL (empty string / zero bytes).
- Stored: value, valueDecimals, tag1, tag2, isRevoked, feedbackIndex.
- Emitted only: endpoint, feedbackURI, feedbackHash.
- `feedbackIndex` is 1-indexed per (clientAddress, agentId) pair.
- Only original clientAddress can revoke.
- Anyone can appendResponse. Same responder can respond multiple times.
- `getSummary` requires non-empty clientAddresses. Uses WAD normalization and mode decimals.
- `readAllFeedback`: clientAddresses (pass `[]` for all clients), tag1/tag2 (pass `""` to skip), includeRevoked are optional filters. Revoked feedback omitted by default.
- `getResponseCount`: clientAddress (pass `address(0)` for all), feedbackIndex (pass `0` for all), responders (pass `[]` for all) are optional filters.


## Validation Registry

### Functions

```
getIdentityRegistry() → address
validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash)
validationResponse(bytes32 requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag)
getValidationStatus(bytes32 requestHash) → (address validatorAddress, uint256 agentId, uint8 response, bytes32 responseHash, string tag, uint256 lastUpdate)
getSummary(uint256 agentId, address[] validatorAddresses, string tag) → (uint64 count, uint8 averageResponse)
getAgentValidations(uint256 agentId) → bytes32[]
getValidatorRequests(address validatorAddress) → bytes32[]
```

### Events

```
ValidationRequest(address indexed validatorAddress, uint256 indexed agentId, string requestURI, bytes32 indexed requestHash)
ValidationResponse(address indexed validatorAddress, uint256 indexed agentId, bytes32 indexed requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag)
```

### Behavioral rules

- `validationRequest` MUST be called by owner or operator of agentId.
- `validationResponse` MUST be called by the validatorAddress from the original request.
- response: 0–100.
- `responseURI`, `responseHash`, `tag` are OPTIONAL in `validationResponse`.
- `requestHash` is caller-computed, stored on-chain as primary key. Must be unique per request.
- `validationResponse` can be called multiple times per requestHash (progressive validation).
- `getSummary`: validatorAddresses (pass `[]` for all), tag (pass `""` to skip) are optional filters.


## Vyper-specific extensions (not in spec)

```
get_version() → string
isAuthorizedOrOwner(address spender, uint256 agentId) → bool
```

- `get_version`: Non-spec convenience function, present in all three contracts. Uses snake_case per Vyper convention.
- `isAuthorizedOrOwner`: Non-spec convenience function exposed for integrators who know they're talking to this specific registry. The other contracts (ReputationRegistry, ValidationRegistry) do NOT call this; they use separate `ownerOf`/`getApproved`/`isApprovedForAll` calls directly, which is the correct pattern for interoperability with any compliant ERC-8004 registry.


## Vyper-specific design decisions

### register() overloading

Vyper default parameters produce multiple ABI selectors from a single function:

```vyper
@external
def register(agentURI: String[URI_MAX] = "", metadata: DynArray[MetadataEntry, 16] = []) -> uint256:
```

Selectors: `register()`, `register(string)`, `register(string,(string,bytes)[])`.

### ERC-721 base

Snekmate v0.1.2 `erc721.vy`. Vyper modules don't support virtual/override, so transfer functions are wrapped (not forked): `transferFrom` and `safeTransferFrom` call `_clear_agent_wallet` before `erc721._transfer`/`erc721._safe_transfer`.

### Constructor vs initialize()

The Solidity reference uses UUPS upgradeable proxies with `initialize()`. This Vyper implementation uses `__init__` constructors (non-upgradeable). The IdentityRegistry address is passed as an immutable constructor argument to ReputationRegistry and ValidationRegistry.

### EIP-712 domain

Domain name: `"ERC8004IdentityRegistry"`, version: `"1"`. The EIP-712 domain separator is cached at deploy time and recomputed on chain fork.

```
_AGENT_WALLET_SET_TYPEHASH: constant(bytes32) = keccak256("AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)")
```

### DynArray max sizes

| Constant | Value | Used for |
|----------|-------|----------|
| URI_MAX | 2048 | agentURI, newURI |
| KEY_MAX | 64 | metadataKey |
| TAG_MAX | 64 | tag1, tag2, tag |
| LINK_MAX | 512 | endpoint, feedbackURI, responseURI, requestURI |
| VALUE_MAX | 1024 | metadataValue (bytes) |
| SIG_MAX | 256 | signature (ERC-1271) |
| ARRAY_RETURN_MAX | 1024 | returned DynArrays |
| FILTER_ARRAY_MAX | 128 | input filter arrays |

### Indexed strings in events

`string indexed` params (indexedMetadataKey, indexedTag1) are stored as keccak256 in topics. Spec includes both indexed and non-indexed copies of the same data.

### Reentrancy

`@nonreentrant` on `register` (safeMint callback) and `setAgentWallet` (ERC-1271 call). Targeted, not global.


## Repo structure

```
erc-8004-vyper/
├── contracts/
│   ├── IdentityRegistry.vy
│   ├── ReputationRegistry.vy
│   ├── ValidationRegistry.vy
│   └── interfaces/
│       └── IIdentityRegistry.vyi
├── script/
│   └── deploy.py
├── tests/
│   ├── conftest.py
│   ├── test_identity_registry.py
│   ├── test_reputation_registry.py
│   └── test_validation_registry.py
├── .gitignore
├── .pre-commit-config.yaml
├── moccasin.toml
├── pyproject.toml
├── SPEC_NOTES.md
└── README.md
```
