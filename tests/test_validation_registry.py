"""Tests for ValidationRegistry"""


# -- Tests ------------------------------------------------------------------


def test_get_identity_registry(validation_registry, identity_registry):
    """getIdentityRegistry returns the address passed to __init__."""
    assert validation_registry.getIdentityRegistry() == identity_registry.address


def test_get_version(validation_registry):
    """get_version returns '1.0.0'."""
    assert validation_registry.get_version() == "1.0.0"


# -- C.2: validationRequest ---------------------------------------------------


def test_validation_request_basic(validation_registry, identity_registry, deployer):
    """validationRequest by owner emits event."""
    import boa

    identity_registry.register()

    validator = boa.env.generate_address()
    req_hash = b"\x01" * 32
    validation_registry.validationRequest(validator, 0, "https://req.io/1", req_hash)

    logs = validation_registry.get_logs()
    assert len(logs) == 1
    assert logs[0].validatorAddress == validator
    assert logs[0].agentId == 0
    assert logs[0].requestURI == "https://req.io/1"
    assert logs[0].requestHash == req_hash


def test_validation_request_approved_operator(validation_registry, identity_registry, deployer):
    """validationRequest succeeds when called by an approved operator."""
    import boa

    identity_registry.register()
    operator = boa.env.generate_address()
    identity_registry.setApprovalForAll(operator, True)

    validator = boa.env.generate_address()
    req_hash = b"\x02" * 32
    with boa.env.prank(operator):
        validation_registry.validationRequest(validator, 0, "https://req.io/2", req_hash)


def test_validation_request_not_authorized(validation_registry, identity_registry, deployer):
    """validationRequest reverts when caller is not owner or approved."""
    import boa
    import pytest

    identity_registry.register()

    stranger = boa.env.generate_address()
    validator = boa.env.generate_address()
    req_hash = b"\x03" * 32
    with boa.env.prank(stranger):
        # Titanoboa repr() bug with struct-containing HashMaps
        with pytest.raises(Exception):
            validation_registry.validationRequest(validator, 0, "https://req.io/3", req_hash)


def test_validation_request_nonexistent_agent(validation_registry, identity_registry):
    """validationRequest reverts for a non-existent agent."""
    import boa
    import pytest

    validator = boa.env.generate_address()
    req_hash = b"\x04" * 32
    with pytest.raises(Exception):
        validation_registry.validationRequest(validator, 999, "https://req.io/4", req_hash)


def test_validation_request_duplicate_hash(validation_registry, identity_registry, deployer):
    """validationRequest reverts if requestHash already exists."""
    import boa
    import pytest

    identity_registry.register()

    validator = boa.env.generate_address()
    req_hash = b"\x05" * 32
    validation_registry.validationRequest(validator, 0, "https://req.io/5", req_hash)

    # Titanoboa repr() bug with struct-containing HashMaps
    with pytest.raises(Exception):
        validation_registry.validationRequest(validator, 0, "https://req.io/6", req_hash)


def test_validation_request_zero_validator(validation_registry, identity_registry, deployer):
    """validationRequest reverts when validatorAddress is zero."""
    import boa
    import pytest

    identity_registry.register()

    zero = "0x" + "00" * 20
    req_hash = b"\x06" * 32
    # Titanoboa repr() bug with struct-containing HashMaps
    with pytest.raises(Exception):
        validation_registry.validationRequest(zero, 0, "https://req.io/7", req_hash)


# -- C.3: validationResponse --------------------------------------------------


def test_validation_response_basic(validation_registry, identity_registry, deployer):
    """validationResponse by designated validator emits event and sets fields."""
    import boa

    identity_registry.register()

    validator = boa.env.generate_address()
    req_hash = b"\x10" * 32
    validation_registry.validationRequest(validator, 0, "https://req.io/10", req_hash)

    with boa.env.prank(validator):
        validation_registry.validationResponse(req_hash, 85, "https://resp.io/1", b"\xaa" * 32, "security")

    logs = validation_registry.get_logs()
    resp_logs = [l for l in logs if type(l).__name__ == "ValidationResponse"]
    assert len(resp_logs) == 1
    assert resp_logs[0].validatorAddress == validator
    assert resp_logs[0].agentId == 0
    assert resp_logs[0].requestHash == req_hash
    assert resp_logs[0].response == 85
    assert resp_logs[0].responseURI == "https://resp.io/1"
    assert resp_logs[0].responseHash == b"\xaa" * 32
    assert resp_logs[0].tag == "security"


def test_validation_response_not_validator(validation_registry, identity_registry, deployer):
    """validationResponse reverts when caller is not the designated validator."""
    import boa
    import pytest

    identity_registry.register()

    validator = boa.env.generate_address()
    req_hash = b"\x11" * 32
    validation_registry.validationRequest(validator, 0, "https://req.io/11", req_hash)

    other = boa.env.generate_address()
    with boa.env.prank(other):
        with pytest.raises(Exception):
            validation_registry.validationResponse(req_hash, 50)


def test_validation_response_over_100(validation_registry, identity_registry, deployer):
    """validationResponse reverts when response > 100."""
    import boa
    import pytest

    identity_registry.register()

    validator = boa.env.generate_address()
    req_hash = b"\x12" * 32
    validation_registry.validationRequest(validator, 0, "https://req.io/12", req_hash)

    with boa.env.prank(validator):
        with pytest.raises(Exception):
            validation_registry.validationResponse(req_hash, 101)


def test_validation_response_unknown_request(validation_registry, identity_registry):
    """validationResponse reverts for an unknown requestHash."""
    import pytest

    with pytest.raises(Exception):
        validation_registry.validationResponse(b"\xff" * 32, 50)


def test_validation_response_updatable(validation_registry, identity_registry, deployer):
    """validationResponse can be called multiple times to update the response."""
    import boa

    identity_registry.register()

    validator = boa.env.generate_address()
    req_hash = b"\x13" * 32
    validation_registry.validationRequest(validator, 0, "https://req.io/13", req_hash)

    with boa.env.prank(validator):
        validation_registry.validationResponse(req_hash, 50, "", b"\x00" * 32, "partial")
        validation_registry.validationResponse(req_hash, 95, "", b"\x00" * 32, "final")


# -- C.4: Query functions -----------------------------------------------------


def test_get_validation_status(validation_registry, identity_registry, deployer):
    """getValidationStatus returns stored fields after a response."""
    import boa

    identity_registry.register()

    validator = boa.env.generate_address()
    req_hash = b"\x20" * 32
    validation_registry.validationRequest(validator, 0, "https://req.io/20", req_hash)

    with boa.env.prank(validator):
        validation_registry.validationResponse(req_hash, 75, "https://resp.io/20", b"\xbb" * 32, "audit")

    addr, agent_id, resp, resp_hash, tag, last_update = validation_registry.getValidationStatus(req_hash)
    assert addr == validator
    assert agent_id == 0
    assert resp == 75
    assert resp_hash == b"\xbb" * 32
    assert tag == "audit"
    assert last_update > 0


def test_get_validation_status_unknown(validation_registry):
    """getValidationStatus reverts for an unknown requestHash."""
    import pytest

    with pytest.raises(Exception):
        validation_registry.getValidationStatus(b"\xff" * 32)


def test_get_agent_validations(validation_registry, identity_registry, deployer):
    """getAgentValidations returns the list of requestHashes for an agent."""
    import boa

    identity_registry.register()

    validator = boa.env.generate_address()
    h1 = b"\x21" * 32
    h2 = b"\x22" * 32
    validation_registry.validationRequest(validator, 0, "https://req.io/21", h1)
    validation_registry.validationRequest(validator, 0, "https://req.io/22", h2)

    hashes = validation_registry.getAgentValidations(0)
    assert len(hashes) == 2
    assert hashes[0] == h1
    assert hashes[1] == h2


def test_get_validator_requests(validation_registry, identity_registry, deployer):
    """getValidatorRequests returns the list of requestHashes for a validator."""
    import boa

    identity_registry.register()

    validator = boa.env.generate_address()
    h1 = b"\x23" * 32
    h2 = b"\x24" * 32
    validation_registry.validationRequest(validator, 0, "https://req.io/23", h1)
    validation_registry.validationRequest(validator, 0, "https://req.io/24", h2)

    hashes = validation_registry.getValidatorRequests(validator)
    assert len(hashes) == 2
    assert hashes[0] == h1
    assert hashes[1] == h2


# -- C.5: getSummary ----------------------------------------------------------


def test_get_summary_basic(validation_registry, identity_registry, deployer):
    """getSummary returns count and average response score."""
    import boa

    identity_registry.register()

    v1 = boa.env.generate_address()
    v2 = boa.env.generate_address()
    h1 = b"\x30" * 32
    h2 = b"\x31" * 32
    validation_registry.validationRequest(v1, 0, "https://req.io/30", h1)
    validation_registry.validationRequest(v2, 0, "https://req.io/31", h2)

    with boa.env.prank(v1):
        validation_registry.validationResponse(h1, 80)
    with boa.env.prank(v2):
        validation_registry.validationResponse(h2, 60)

    count, avg = validation_registry.getSummary(0)
    assert count == 2
    assert avg == 70  # (80 + 60) // 2


def test_get_summary_filter_validators(validation_registry, identity_registry, deployer):
    """getSummary filters by validator addresses when provided."""
    import boa

    identity_registry.register()

    v1 = boa.env.generate_address()
    v2 = boa.env.generate_address()
    h1 = b"\x32" * 32
    h2 = b"\x33" * 32
    validation_registry.validationRequest(v1, 0, "https://req.io/32", h1)
    validation_registry.validationRequest(v2, 0, "https://req.io/33", h2)

    with boa.env.prank(v1):
        validation_registry.validationResponse(h1, 90)
    with boa.env.prank(v2):
        validation_registry.validationResponse(h2, 40)

    count, avg = validation_registry.getSummary(0, [v1])
    assert count == 1
    assert avg == 90


def test_get_summary_filter_tag(validation_registry, identity_registry, deployer):
    """getSummary filters by tag when provided."""
    import boa

    identity_registry.register()

    v1 = boa.env.generate_address()
    h1 = b"\x34" * 32
    h2 = b"\x35" * 32
    validation_registry.validationRequest(v1, 0, "https://req.io/34", h1)
    validation_registry.validationRequest(v1, 0, "https://req.io/35", h2)

    with boa.env.prank(v1):
        validation_registry.validationResponse(h1, 100, "", b"\x00" * 32, "security")
        validation_registry.validationResponse(h2, 50, "", b"\x00" * 32, "quality")

    count, avg = validation_registry.getSummary(0, [], "security")
    assert count == 1
    assert avg == 100


def test_get_summary_no_responses(validation_registry, identity_registry, deployer):
    """getSummary returns (0, 0) when no responses exist."""
    import boa

    identity_registry.register()

    v1 = boa.env.generate_address()
    h1 = b"\x36" * 32
    validation_registry.validationRequest(v1, 0, "https://req.io/36", h1)

    count, avg = validation_registry.getSummary(0)
    assert count == 0
    assert avg == 0


def test_get_summary_empty_agent(validation_registry):
    """getSummary returns (0, 0) for an agent with no validations."""
    count, avg = validation_registry.getSummary(999)
    assert count == 0
    assert avg == 0


def test_get_summary_combined_filters(validation_registry, identity_registry, deployer):
    """getSummary filters by both validator and tag simultaneously."""
    import boa

    identity_registry.register()

    v1 = boa.env.generate_address()
    v2 = boa.env.generate_address()
    h1 = b"\x37" * 32
    h2 = b"\x38" * 32
    h3 = b"\x39" * 32
    validation_registry.validationRequest(v1, 0, "https://req.io/37", h1)
    validation_registry.validationRequest(v1, 0, "https://req.io/38", h2)
    validation_registry.validationRequest(v2, 0, "https://req.io/39", h3)

    with boa.env.prank(v1):
        validation_registry.validationResponse(h1, 80, "", b"\x00" * 32, "security")
        validation_registry.validationResponse(h2, 60, "", b"\x00" * 32, "quality")
    with boa.env.prank(v2):
        validation_registry.validationResponse(h3, 90, "", b"\x00" * 32, "security")

    # v1 + "security" -> only h1 (score 80)
    count, avg = validation_registry.getSummary(0, [v1], "security")
    assert count == 1
    assert avg == 80


# -- C.6: Additional coverage ------------------------------------------------


def test_get_validation_status_before_response(validation_registry, identity_registry, deployer):
    """getValidationStatus returns initial state before any response."""
    import boa

    identity_registry.register()

    validator = boa.env.generate_address()
    req_hash = b"\x40" * 32
    validation_registry.validationRequest(validator, 0, "https://req.io/40", req_hash)

    addr, agent_id, resp, resp_hash, tag, last_update = validation_registry.getValidationStatus(req_hash)
    assert addr == validator
    assert agent_id == 0
    assert resp == 0
    assert resp_hash == b"\x00" * 32
    assert tag == ""
    assert last_update > 0


def test_validation_response_update_verified(validation_registry, identity_registry, deployer):
    """validationResponse updates are reflected in getValidationStatus."""
    import boa

    identity_registry.register()

    validator = boa.env.generate_address()
    req_hash = b"\x41" * 32
    validation_registry.validationRequest(validator, 0, "https://req.io/41", req_hash)

    with boa.env.prank(validator):
        validation_registry.validationResponse(req_hash, 50, "", b"\xcc" * 32, "partial")

    _, _, resp1, hash1, tag1, _ = validation_registry.getValidationStatus(req_hash)
    assert resp1 == 50
    assert hash1 == b"\xcc" * 32
    assert tag1 == "partial"

    with boa.env.prank(validator):
        validation_registry.validationResponse(req_hash, 95, "", b"\xdd" * 32, "final")

    _, _, resp2, hash2, tag2, _ = validation_registry.getValidationStatus(req_hash)
    assert resp2 == 95
    assert hash2 == b"\xdd" * 32
    assert tag2 == "final"


def test_validation_response_boundary_values(validation_registry, identity_registry, deployer):
    """validationResponse accepts boundary values 0 and 100."""
    import boa

    identity_registry.register()

    validator = boa.env.generate_address()
    h1 = b"\x42" * 32
    h2 = b"\x43" * 32
    validation_registry.validationRequest(validator, 0, "https://req.io/42", h1)
    validation_registry.validationRequest(validator, 0, "https://req.io/43", h2)

    with boa.env.prank(validator):
        validation_registry.validationResponse(h1, 0)
        validation_registry.validationResponse(h2, 100)

    _, _, resp0, _, _, _ = validation_registry.getValidationStatus(h1)
    _, _, resp100, _, _, _ = validation_registry.getValidationStatus(h2)
    assert resp0 == 0
    assert resp100 == 100
