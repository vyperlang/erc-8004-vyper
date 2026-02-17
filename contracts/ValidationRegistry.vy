# pragma version ~=0.4.3
"""
@title ERC-8004 Validation Registry
@custom:contract-name ValidationRegistry
@license UNLICENSED
@notice On-chain validation system for ERC-8004 agents.
        Tracks validation requests keyed by caller-computed requestHash.
        Each request designates a specific validator who provides a
        0–100 response score. References the Identity Registry for
        agent existence and ownership checks via staticcall.
"""


from interfaces import IIdentityRegistry


# @dev Max-size constants (UPPER_SNAKE_CASE, no leading underscore).
TAG_MAX: constant(uint256) = 64
LINK_MAX: constant(uint256) = 512
ARRAY_RETURN_MAX: constant(uint256) = 1024
FILTER_ARRAY_MAX: constant(uint256) = 128


struct ValidationStatus:
    validatorAddress: address
    agentId: uint256
    response: uint8
    responseHash: bytes32
    tag: String[TAG_MAX]
    lastUpdate: uint256
    hasResponse: bool


event ValidationRequest:
    validatorAddress: indexed(address)
    agentId: indexed(uint256)
    requestURI: String[LINK_MAX]
    requestHash: indexed(bytes32)


event ValidationResponse:
    validatorAddress: indexed(address)
    agentId: indexed(uint256)
    requestHash: indexed(bytes32)
    response: uint8
    responseURI: String[LINK_MAX]
    responseHash: bytes32
    tag: String[TAG_MAX]


# @dev Address of the IdentityRegistry contract, set once at deploy time.
_IDENTITY_REGISTRY: immutable(IIdentityRegistry)


# @dev Primary storage: requestHash → ValidationStatus.
_validations: HashMap[bytes32, ValidationStatus]


# @dev List of requestHashes per agentId, for getSummary / getAgentValidations.
_agent_validations: HashMap[uint256, DynArray[bytes32, ARRAY_RETURN_MAX]]


# @dev List of requestHashes per validator, for getValidatorRequests.
_validator_requests: HashMap[address, DynArray[bytes32, ARRAY_RETURN_MAX]]


@deploy
@payable
def __init__(identityRegistry_: address):
    """
    @dev To omit the opcodes for checking the `msg.value`
         in the creation-time EVM bytecode, the constructor
         is declared as `payable`.
    @notice Initialises the Validation Registry with a reference
            to the Identity Registry contract.
    @param identityRegistry_ The address of the Identity Registry.
    """
    assert identityRegistry_ != empty(address), "ValidationRegistry: bad identity"
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
def validationRequest(
    validatorAddress: address,
    agentId: uint256,
    requestURI: String[LINK_MAX],
    requestHash: bytes32,
):
    """
    @dev Submits a validation request for `agentId`, designating
         `validatorAddress` as the only address that may respond.
         Caller must be the owner or an approved operator of `agentId`.
         The `requestHash` is the caller-computed primary key and must
         be unique.
    @param validatorAddress The designated validator address.
    @param agentId The agent to request validation for.
    @param requestURI URI pointing to off-chain request content.
    @param requestHash Unique identifier for this request.
    """
    assert validatorAddress != empty(address), "ValidationRegistry: bad validator"
    assert self._validations[requestHash].validatorAddress == empty(address), "ValidationRegistry: exists"

    # Authorization: caller must be owner, approved, or operator.
    # Uses only standard ERC-721 functions so this registry works with
    # any compliant IdentityRegistry.
    owner: address = staticcall _IDENTITY_REGISTRY.ownerOf(agentId)
    assert (
        msg.sender == owner
        or msg.sender == staticcall _IDENTITY_REGISTRY.getApproved(agentId)
        or staticcall _IDENTITY_REGISTRY.isApprovedForAll(owner, msg.sender)
    ), "ValidationRegistry: not authorized"

    self._validations[requestHash] = ValidationStatus(
        validatorAddress=validatorAddress,
        agentId=agentId,
        response=0,
        responseHash=empty(bytes32),
        tag="",
        lastUpdate=block.timestamp,
        hasResponse=False,
    )

    self._agent_validations[agentId].append(requestHash)
    self._validator_requests[validatorAddress].append(requestHash)

    log ValidationRequest(
        validatorAddress=validatorAddress,
        agentId=agentId,
        requestURI=requestURI,
        requestHash=requestHash,
    )


@external
def validationResponse(
    requestHash: bytes32,
    response: uint8,
    responseURI: String[LINK_MAX] = "",
    responseHash: bytes32 = empty(bytes32),
    tag: String[TAG_MAX] = "",
):
    """
    @dev Submits or updates a validation response for an existing request.
         Only the designated validator for the request may call this.
         Can be called multiple times (progressive validation).
    @param requestHash The unique identifier of the request.
    @param response The validation score (0–100).
    @param responseURI URI pointing to off-chain response content (optional).
    @param responseHash keccak256 of content at responseURI (optional).
    @param tag Tag for categorisation (optional).
    """
    s: ValidationStatus = self._validations[requestHash]
    assert s.validatorAddress != empty(address), "ValidationRegistry: unknown"
    assert msg.sender == s.validatorAddress, "ValidationRegistry: not validator"
    assert response <= 100, "ValidationRegistry: response > 100"

    self._validations[requestHash].response = response
    self._validations[requestHash].responseHash = responseHash
    self._validations[requestHash].tag = tag
    self._validations[requestHash].lastUpdate = block.timestamp
    self._validations[requestHash].hasResponse = True

    log ValidationResponse(
        validatorAddress=s.validatorAddress,
        agentId=s.agentId,
        requestHash=requestHash,
        response=response,
        responseURI=responseURI,
        responseHash=responseHash,
        tag=tag,
    )


@external
@view
def getValidationStatus(requestHash: bytes32) -> (address, uint256, uint8, bytes32, String[TAG_MAX], uint256):
    """
    @dev Returns the stored fields of a validation request.
    @param requestHash The unique identifier of the request.
    @return (validatorAddress, agentId, response, responseHash, tag, lastUpdate).
    """
    s: ValidationStatus = self._validations[requestHash]
    assert s.validatorAddress != empty(address), "ValidationRegistry: unknown"
    return (s.validatorAddress, s.agentId, s.response, s.responseHash, s.tag, s.lastUpdate)


@external
@view
def getAgentValidations(agentId: uint256) -> DynArray[bytes32, ARRAY_RETURN_MAX]:
    """
    @dev Returns the list of requestHashes for `agentId`.
    @param agentId The agent identifier.
    @return DynArray of requestHashes.
    """
    return self._agent_validations[agentId]


@external
@view
def getValidatorRequests(validatorAddress: address) -> DynArray[bytes32, ARRAY_RETURN_MAX]:
    """
    @dev Returns the list of requestHashes assigned to `validatorAddress`.
    @param validatorAddress The validator address.
    @return DynArray of requestHashes.
    """
    return self._validator_requests[validatorAddress]


@internal
@pure
def _match_validator(
    addr: address,
    validators: DynArray[address, FILTER_ARRAY_MAX],
) -> bool:
    """
    @dev Returns True if `addr` is found in `validators`.
    """
    for v: address in validators:
        if v == addr:
            return True
    return False


@external
@view
def getSummary(
    agentId: uint256,
    validatorAddresses: DynArray[address, FILTER_ARRAY_MAX] = [],
    tag: String[TAG_MAX] = "",
) -> (uint64, uint8):
    """
    @dev Aggregates validation responses for `agentId`, optionally
         filtered by validator addresses and/or tag. Only includes
         requests that have received a response.
    @param agentId The agent identifier.
    @param validatorAddresses Validators to filter by (empty = all).
    @param tag Tag to filter by (empty = no filter).
    @return (count, avgResponse).
    """
    filter_validators: bool = len(validatorAddresses) > 0
    filter_tag: bool = len(tag) > 0

    total_response: uint256 = 0
    count: uint64 = 0

    for h: bytes32 in self._agent_validations[agentId]:
        s: ValidationStatus = self._validations[h]

        if not s.hasResponse:
            continue

        if filter_validators:
            if not self._match_validator(s.validatorAddress, validatorAddresses):
                continue

        if filter_tag:
            if s.tag != tag:
                continue

        total_response += convert(s.response, uint256)
        count += 1

    avg_response: uint8 = 0
    if count > 0:
        avg_response = convert(total_response // convert(count, uint256), uint8)

    return (count, avg_response)


@external
@pure
def get_version() -> String[8]:
    """
    @dev Returns the version of this contract.
    @return String[8] The version string.
    """
    return "1.0.0"
