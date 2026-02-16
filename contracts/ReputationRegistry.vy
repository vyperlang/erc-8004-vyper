# pragma version ~=0.4.3
"""
@title ERC-8004 Reputation Registry
@custom:contract-name ReputationRegistry
@license UNLICENSED
@notice On-chain feedback and reputation system for ERC-8004 agents.
        Tracks feedback entries per (agentId, clientAddress) pair with
        tag-based filtering, revocation, and response tracking.
        References the Identity Registry for agent existence and
        ownership checks via staticcall.
"""


from interfaces import IIdentityRegistry


# @dev Max-size constants (UPPER_SNAKE_CASE, no leading underscore).
TAG_MAX: constant(uint256) = 64
LINK_MAX: constant(uint256) = 512
ARRAY_RETURN_MAX: constant(uint256) = 1024
FILTER_ARRAY_MAX: constant(uint256) = 128


struct FeedbackEntry:
    value: int128
    valueDecimals: uint8
    tag1: String[TAG_MAX]
    tag2: String[TAG_MAX]
    isRevoked: bool


event NewFeedback:
    agentId: indexed(uint256)
    clientAddress: indexed(address)
    feedbackIndex: uint64
    value: int128
    valueDecimals: uint8
    indexedTag1: indexed(String[TAG_MAX])
    tag1: String[TAG_MAX]
    tag2: String[TAG_MAX]
    endpoint: String[LINK_MAX]
    feedbackURI: String[LINK_MAX]
    feedbackHash: bytes32


event FeedbackRevoked:
    agentId: indexed(uint256)
    clientAddress: indexed(address)
    feedbackIndex: indexed(uint64)


event ResponseAppended:
    agentId: indexed(uint256)
    clientAddress: indexed(address)
    feedbackIndex: uint64
    responder: indexed(address)
    responseURI: String[LINK_MAX]
    responseHash: bytes32


# @dev Address of the IdentityRegistry contract, set once at deploy time.
_IDENTITY_REGISTRY: immutable(IIdentityRegistry)


# @dev Feedback storage: agentId → clientAddress → feedbackIndex → FeedbackEntry.
_feedback: HashMap[uint256, HashMap[address, HashMap[uint64, FeedbackEntry]]]


# @dev Last feedback index per (agentId, clientAddress) pair. 1-indexed.
_last_index: HashMap[uint256, HashMap[address, uint64]]


# @dev List of unique client addresses per agentId.
_clients: HashMap[uint256, DynArray[address, ARRAY_RETURN_MAX]]


# @dev Quick lookup: whether an address is already a client for an agentId.
_is_client: HashMap[uint256, HashMap[address, bool]]


# @dev Response count per responder: agentId → clientAddress → feedbackIndex → responder → count.
_response_count: HashMap[uint256, HashMap[address, HashMap[uint64, HashMap[address, uint64]]]]


# @dev List of unique responders per feedback entry.
_responders: HashMap[uint256, HashMap[address, HashMap[uint64, DynArray[address, ARRAY_RETURN_MAX]]]]


# @dev Whether a responder is already tracked in the _responders list.
_responder_exists: HashMap[uint256, HashMap[address, HashMap[uint64, HashMap[address, bool]]]]


@deploy
@payable
def __init__(identityRegistry_: address):
    """
    @dev To omit the opcodes for checking the `msg.value`
         in the creation-time EVM bytecode, the constructor
         is declared as `payable`.
    @notice Initialises the Reputation Registry with a reference
            to the Identity Registry contract.
    @param identityRegistry_ The address of the Identity Registry.
    """
    _IDENTITY_REGISTRY = IIdentityRegistry(identityRegistry_)


@external
@view
def getIdentityRegistry() -> address:
    """
    @dev Returns the address of the Identity Registry contract.
    @return address The Identity Registry address.
    """
    return _IDENTITY_REGISTRY.address


@external
def giveFeedback(
    agentId: uint256,
    feedbackValue: int128,
    valueDecimals: uint8,
    tag1: String[TAG_MAX] = "",
    tag2: String[TAG_MAX] = "",
    endpoint: String[LINK_MAX] = "",
    feedbackURI: String[LINK_MAX] = "",
    feedbackHash: bytes32 = empty(bytes32),
):
    """
    @dev Submits feedback for `agentId`. The agent must exist in the
         Identity Registry. Feedback is indexed per (agentId, msg.sender)
         pair with 1-based indices.
    @notice tag1, tag2, endpoint, feedbackURI, and feedbackHash are
            all optional (pass empty string / zero bytes to omit).
            The parameter is named `feedbackValue` because `value` is
            reserved in Vyper (msg.value). The ABI selector is
            unaffected since it depends only on types.
    @param agentId The agent to give feedback for.
    @param feedbackValue The feedback score.
    @param valueDecimals The number of decimals in `feedbackValue` (0–18).
    @param tag1 Primary tag for categorisation (optional).
    @param tag2 Secondary tag for categorisation (optional).
    @param endpoint The endpoint URI related to the feedback (optional).
    @param feedbackURI URI pointing to off-chain feedback content (optional).
    @param feedbackHash keccak256 of content at feedbackURI (optional).
    """
    # Verify agent exists (reverts if token does not exist).
    owner: address = staticcall _IDENTITY_REGISTRY.ownerOf(agentId)

    assert valueDecimals <= 18, "ReputationRegistry: too many decimals"
    assert feedbackValue >= -100000000000000000000000000000000000000 and feedbackValue <= 100000000000000000000000000000000000000, "ReputationRegistry: value out of range"

    # Self-feedback prevention: caller must not be the owner, approved address,
    # or an approved-for-all operator for the agent.
    assert msg.sender != owner, "ReputationRegistry: self-feedback not allowed"
    assert msg.sender != staticcall _IDENTITY_REGISTRY.getApproved(agentId), "ReputationRegistry: self-feedback not allowed"
    assert not staticcall _IDENTITY_REGISTRY.isApprovedForAll(owner, msg.sender), "ReputationRegistry: self-feedback not allowed"

    idx: uint64 = self._last_index[agentId][msg.sender] + 1
    self._last_index[agentId][msg.sender] = idx

    self._feedback[agentId][msg.sender][idx] = FeedbackEntry(
        value=feedbackValue,
        valueDecimals=valueDecimals,
        tag1=tag1,
        tag2=tag2,
        isRevoked=False,
    )

    if not self._is_client[agentId][msg.sender]:
        self._is_client[agentId][msg.sender] = True
        self._clients[agentId].append(msg.sender)

    log NewFeedback(
        agentId=agentId,
        clientAddress=msg.sender,
        feedbackIndex=idx,
        value=feedbackValue,
        valueDecimals=valueDecimals,
        indexedTag1=tag1,
        tag1=tag1,
        tag2=tag2,
        endpoint=endpoint,
        feedbackURI=feedbackURI,
        feedbackHash=feedbackHash,
    )


@external
def revokeFeedback(agentId: uint256, feedbackIndex: uint64):
    """
    @dev Revokes a previously submitted feedback entry. Only the
         original client (msg.sender) who submitted the feedback
         can revoke it.
    @param agentId The agent the feedback was given for.
    @param feedbackIndex The 1-based index of the feedback entry.
    """
    assert feedbackIndex > 0 and feedbackIndex <= self._last_index[agentId][msg.sender], "ReputationRegistry: feedback does not exist"
    assert not self._feedback[agentId][msg.sender][feedbackIndex].isRevoked, "ReputationRegistry: already revoked"

    self._feedback[agentId][msg.sender][feedbackIndex].isRevoked = True

    log FeedbackRevoked(
        agentId=agentId,
        clientAddress=msg.sender,
        feedbackIndex=feedbackIndex,
    )


@external
def appendResponse(
    agentId: uint256,
    clientAddress: address,
    feedbackIndex: uint64,
    responseURI: String[LINK_MAX] = "",
    responseHash: bytes32 = empty(bytes32),
):
    """
    @dev Appends a response to a feedback entry. Anyone can respond,
         and the same responder may respond multiple times.
    @param agentId The agent the feedback was given for.
    @param clientAddress The address that submitted the feedback.
    @param feedbackIndex The 1-based index of the feedback entry.
    @param responseURI URI pointing to off-chain response content.
    @param responseHash keccak256 of content at responseURI (optional).
    """
    assert feedbackIndex > 0 and feedbackIndex <= self._last_index[agentId][clientAddress], "ReputationRegistry: feedback does not exist"
    assert len(responseURI) > 0, "ReputationRegistry: empty URI"

    if not self._responder_exists[agentId][clientAddress][feedbackIndex][msg.sender]:
        self._responders[agentId][clientAddress][feedbackIndex].append(msg.sender)
        self._responder_exists[agentId][clientAddress][feedbackIndex][msg.sender] = True

    self._response_count[agentId][clientAddress][feedbackIndex][msg.sender] += 1

    log ResponseAppended(
        agentId=agentId,
        clientAddress=clientAddress,
        feedbackIndex=feedbackIndex,
        responder=msg.sender,
        responseURI=responseURI,
        responseHash=responseHash,
    )


@internal
@view
def _count_responses(
    agentId: uint256,
    clientAddress: address,
    feedbackIndex: uint64,
    responders: DynArray[address, FILTER_ARRAY_MAX],
) -> uint64:
    """
    @dev Counts responses for a single feedback entry, optionally
         filtered by responders.
    """
    count: uint64 = 0
    if len(responders) == 0:
        for r: address in self._responders[agentId][clientAddress][feedbackIndex]:
            count += self._response_count[agentId][clientAddress][feedbackIndex][r]
    else:
        for r: address in responders:
            count += self._response_count[agentId][clientAddress][feedbackIndex][r]
    return count


@external
@view
def getResponseCount(
    agentId: uint256,
    clientAddress: address,
    feedbackIndex: uint64,
    responders: DynArray[address, FILTER_ARRAY_MAX] = [],
) -> uint64:
    """
    @dev Returns the total number of responses, with flexible aggregation.
         - clientAddress == address(0): count across all clients.
         - feedbackIndex == 0: count across all feedback for the client.
         - responders == []: count from all responders.
    @param agentId The agent the feedback was given for.
    @param clientAddress The client address (address(0) for all).
    @param feedbackIndex The feedback index (0 for all).
    @param responders Responder addresses to filter by (empty = all).
    @return uint64 The response count.
    """
    count: uint64 = 0

    if clientAddress == empty(address):
        for client: address in self._clients[agentId]:
            last: uint256 = convert(self._last_index[agentId][client], uint256)
            for i: uint256 in range(last, bound=ARRAY_RETURN_MAX):
                idx: uint64 = convert(i + 1, uint64)
                count += self._count_responses(agentId, client, idx, responders)
    elif feedbackIndex == 0:
        last: uint256 = convert(self._last_index[agentId][clientAddress], uint256)
        for i: uint256 in range(last, bound=ARRAY_RETURN_MAX):
            idx: uint64 = convert(i + 1, uint64)
            count += self._count_responses(agentId, clientAddress, idx, responders)
    else:
        count = self._count_responses(agentId, clientAddress, feedbackIndex, responders)

    return count


@external
@view
def readFeedback(agentId: uint256, clientAddress: address, feedbackIndex: uint64) -> (int128, uint8, String[TAG_MAX], String[TAG_MAX], bool):
    """
    @dev Returns the stored fields of a single feedback entry.
    @param agentId The agent the feedback was given for.
    @param clientAddress The address that submitted the feedback.
    @param feedbackIndex The 1-based index of the feedback entry.
    @return (value, valueDecimals, tag1, tag2, isRevoked).
    """
    assert feedbackIndex > 0 and feedbackIndex <= self._last_index[agentId][clientAddress], "ReputationRegistry: feedback does not exist"
    entry: FeedbackEntry = self._feedback[agentId][clientAddress][feedbackIndex]
    return (entry.value, entry.valueDecimals, entry.tag1, entry.tag2, entry.isRevoked)


@external
@view
def readAllFeedback(
    agentId: uint256,
    clientAddresses: DynArray[address, FILTER_ARRAY_MAX] = [],
    tag1: String[TAG_MAX] = "",
    tag2: String[TAG_MAX] = "",
    includeRevoked: bool = False,
) -> (
    DynArray[address, ARRAY_RETURN_MAX],
    DynArray[uint64, ARRAY_RETURN_MAX],
    DynArray[int128, ARRAY_RETURN_MAX],
    DynArray[uint8, ARRAY_RETURN_MAX],
    DynArray[String[TAG_MAX], ARRAY_RETURN_MAX],
    DynArray[String[TAG_MAX], ARRAY_RETURN_MAX],
    DynArray[bool, ARRAY_RETURN_MAX],
):
    """
    @dev Returns all feedback entries for `agentId` as parallel arrays,
         optionally filtered by client addresses, tags, and revocation status.
    @param agentId The agent to read feedback for.
    @param clientAddresses Client addresses to filter by (empty = all clients).
    @param tag1 Filter by tag1 (empty = no filter).
    @param tag2 Filter by tag2 (empty = no filter).
    @param includeRevoked Whether to include revoked feedback (default False).
    @return (clients, feedbackIndexes, values, valueDecimals, tag1s, tag2s, revokedStatuses).
    """
    out_clients: DynArray[address, ARRAY_RETURN_MAX] = []
    out_indexes: DynArray[uint64, ARRAY_RETURN_MAX] = []
    out_values: DynArray[int128, ARRAY_RETURN_MAX] = []
    out_decimals: DynArray[uint8, ARRAY_RETURN_MAX] = []
    out_tag1s: DynArray[String[TAG_MAX], ARRAY_RETURN_MAX] = []
    out_tag2s: DynArray[String[TAG_MAX], ARRAY_RETURN_MAX] = []
    out_revoked: DynArray[bool, ARRAY_RETURN_MAX] = []

    client_list: DynArray[address, ARRAY_RETURN_MAX] = []
    if len(clientAddresses) == 0:
        client_list = self._clients[agentId]
    else:
        for c: address in clientAddresses:
            client_list.append(c)

    filter_tag1: bool = len(tag1) > 0
    filter_tag2: bool = len(tag2) > 0

    for client: address in client_list:
        last: uint256 = convert(self._last_index[agentId][client], uint256)
        for i: uint256 in range(last, bound=ARRAY_RETURN_MAX):
            idx: uint64 = convert(i + 1, uint64)
            entry: FeedbackEntry = self._feedback[agentId][client][idx]

            if not includeRevoked and entry.isRevoked:
                continue
            if filter_tag1 and entry.tag1 != tag1:
                continue
            if filter_tag2 and entry.tag2 != tag2:
                continue

            out_clients.append(client)
            out_indexes.append(idx)
            out_values.append(entry.value)
            out_decimals.append(entry.valueDecimals)
            out_tag1s.append(entry.tag1)
            out_tag2s.append(entry.tag2)
            out_revoked.append(entry.isRevoked)

    return (out_clients, out_indexes, out_values, out_decimals, out_tag1s, out_tag2s, out_revoked)


@external
@view
def getSummary(
    agentId: uint256,
    clientAddresses: DynArray[address, FILTER_ARRAY_MAX],
    tag1: String[TAG_MAX] = "",
    tag2: String[TAG_MAX] = "",
) -> (uint64, int128, uint8):
    """
    @dev Aggregates feedback for `agentId`. Computes the average of
         non-revoked values after normalising to 18-decimal WAD precision,
         then scales the result to the mode (most frequent) valueDecimals.
    @param agentId The agent to summarise.
    @param clientAddresses Client addresses to aggregate (required, non-empty).
    @param tag1 Filter by tag1 (empty = no filter).
    @param tag2 Filter by tag2 (empty = no filter).
    @return (count, summaryValue, summaryValueDecimals).
    """
    assert len(clientAddresses) > 0, "ReputationRegistry: clientAddresses required"

    filter_tag1: bool = len(tag1) > 0
    filter_tag2: bool = len(tag2) > 0

    # WAD: 18 decimal fixed-point precision for internal math.
    wad_sum: int256 = 0
    count: uint64 = 0

    # Track frequency of each valueDecimals (0–18).
    decimal_counts: uint64[19] = empty(uint64[19])

    for client: address in clientAddresses:
        last: uint256 = convert(self._last_index[agentId][client], uint256)
        for i: uint256 in range(last, bound=ARRAY_RETURN_MAX):
            idx: uint64 = convert(i + 1, uint64)
            entry: FeedbackEntry = self._feedback[agentId][client][idx]

            if entry.isRevoked:
                continue
            if filter_tag1 and entry.tag1 != tag1:
                continue
            if filter_tag2 and entry.tag2 != tag2:
                continue

            factor: int256 = convert(10 ** convert(18 - entry.valueDecimals, uint256), int256)
            wad_sum += convert(entry.value, int256) * factor
            decimal_counts[entry.valueDecimals] += 1
            count += 1

    if count == 0:
        return (0, 0, 0)

    # Find mode (most frequent valueDecimals).
    mode_decimals: uint8 = 0
    max_count: uint64 = 0
    for d: uint256 in range(19):
        if decimal_counts[d] > max_count:
            max_count = decimal_counts[d]
            mode_decimals = convert(d, uint8)

    # Average in WAD, then scale to mode precision.
    avg_wad: int256 = wad_sum // convert(count, int256)
    scale_down: int256 = convert(10 ** convert(18 - mode_decimals, uint256), int256)
    summary_value: int128 = convert(avg_wad // scale_down, int128)

    return (count, summary_value, mode_decimals)


@external
@view
def getClients(agentId: uint256) -> DynArray[address, ARRAY_RETURN_MAX]:
    """
    @dev Returns the list of unique client addresses that have given
         feedback for `agentId`.
    @param agentId The agent identifier.
    @return DynArray of client addresses.
    """
    return self._clients[agentId]


@external
@view
def getLastIndex(agentId: uint256, clientAddress: address) -> uint64:
    """
    @dev Returns the last feedback index for the given
         (agentId, clientAddress) pair.
    @param agentId The agent identifier.
    @param clientAddress The client address.
    @return uint64 The last feedback index (0 if no feedback given).
    """
    return self._last_index[agentId][clientAddress]


@external
@pure
def getVersion() -> String[8]:
    """
    @dev Returns the version of this contract.
    @return String[8] The version string.
    """
    return "1.0.0"
