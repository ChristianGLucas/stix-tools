from gen.messages_pb2 import StixInput, ValidateResult
from nodes.validate_stix_object import validate_stix_object
from nodes._test_fixtures import (
    BUNDLE_JSON,
    INDICATOR_JSON,
    NOT_JSON,
    MISSING_TYPE_JSON,
    MISSING_REQUIRED_PROP_JSON,
    INDICATOR_ID,
    StixTestContext,
)


def test_validate_stix_object_valid_bundle():
    ax = StixTestContext()
    result = validate_stix_object(ax, StixInput(stix_json=BUNDLE_JSON))
    assert isinstance(result, ValidateResult)
    assert result.valid is True
    assert result.object_type == "bundle"
    assert len(result.errors) == 0


def test_validate_stix_object_valid_single_object():
    ax = StixTestContext()
    result = validate_stix_object(ax, StixInput(stix_json=INDICATOR_JSON))
    assert result.valid is True
    assert result.object_type == "indicator"
    assert result.object_id == INDICATOR_ID


def test_validate_stix_object_missing_required_property_is_invalid():
    ax = StixTestContext()
    result = validate_stix_object(ax, StixInput(stix_json=MISSING_REQUIRED_PROP_JSON))
    assert result.valid is False
    assert len(result.errors) == 1
    assert "pattern" in result.errors[0].message or "valid_from" in result.errors[0].message


def test_validate_stix_object_missing_type_is_invalid():
    ax = StixTestContext()
    result = validate_stix_object(ax, StixInput(stix_json=MISSING_TYPE_JSON))
    assert result.valid is False
    assert len(result.errors) == 1


def test_validate_stix_object_malformed_json_is_invalid_not_crash():
    ax = StixTestContext()
    result = validate_stix_object(ax, StixInput(stix_json=NOT_JSON))
    assert result.valid is False
    assert len(result.errors) == 1
    assert result.errors[0].message != ""
