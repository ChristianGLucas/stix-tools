from gen.messages_pb2 import StixInput, ParseBundleResult
from nodes.parse_bundle import parse_bundle
from nodes._test_fixtures import (
    BUNDLE_JSON,
    BUNDLE_WITH_CUSTOM_JSON,
    CUSTOM_SDO_ID,
    INDICATOR_JSON,
    NOT_JSON,
    BUNDLE_ID,
    INDICATOR_ID,
    independent_object_count,
    independent_type_counts,
    assert_valid_stix_id,
    StixTestContext,
)


def test_parse_bundle_golden():
    ax = StixTestContext()
    result = parse_bundle(ax, StixInput(stix_json=BUNDLE_JSON))
    assert isinstance(result, ParseBundleResult)
    assert result.ok is True
    assert result.error == ""
    assert result.bundle_id == BUNDLE_ID

    # Independent oracle: count/type-tally objects via plain json.loads,
    # bypassing stix2 entirely.
    assert len(result.objects) == independent_object_count(BUNDLE_JSON)
    type_counts = independent_type_counts(BUNDLE_JSON)
    got_counts = {}
    for o in result.objects:
        got_counts[o.type] = got_counts.get(o.type, 0) + 1
    assert got_counts == type_counts

    by_id = {o.id: o for o in result.objects}
    indicator = by_id[INDICATOR_ID]
    assert indicator.type == "indicator"
    assert indicator.name == "Malicious IP"
    assert indicator.spec_version == "2.1"
    assert indicator.created == "2024-01-01T00:00:00.000Z"
    assert '"pattern"' in indicator.raw_json
    assert_valid_stix_id(indicator.id, "indicator")

    relationship = [o for o in result.objects if o.type == "relationship"][0]
    assert relationship.name == ""  # Relationship has no 'name' property


def test_parse_bundle_tolerates_unrecognized_custom_object_type():
    # Regression: real-world STIX feeds commonly carry vendor-custom SDO
    # types ("x-"-prefixed per the spec's own naming convention). An earlier
    # version of this node rejected the WHOLE bundle (every object, not just
    # the unrecognized one) whenever it contained such an object, which
    # contradicted this node's own shipped description. Confirmed fixed:
    # allow_custom=True lets the custom object through as-is while a known
    # type with a genuinely missing required property is still caught (see
    # test_parse_bundle_malformed_returns_error_not_crash and
    # validate_stix_object_test.py's missing-required-property case).
    ax = StixTestContext()
    result = parse_bundle(ax, StixInput(stix_json=BUNDLE_WITH_CUSTOM_JSON))
    assert result.ok is True
    assert result.error == ""
    assert len(result.objects) == independent_object_count(BUNDLE_WITH_CUSTOM_JSON)
    by_id = {o.id: o for o in result.objects}
    custom = by_id[CUSTOM_SDO_ID]
    assert custom.type == "x-acme-custom-thing"
    assert custom.name == "Vendor Extension Object"
    assert '"acme_severity": "high"' in custom.raw_json


def test_parse_bundle_single_bare_object():
    ax = StixTestContext()
    result = parse_bundle(ax, StixInput(stix_json=INDICATOR_JSON))
    assert result.ok is True
    assert result.bundle_id == ""  # not a bundle
    assert len(result.objects) == 1
    assert result.objects[0].id == INDICATOR_ID


def test_parse_bundle_malformed_returns_error_not_crash():
    ax = StixTestContext()
    result = parse_bundle(ax, StixInput(stix_json=NOT_JSON))
    assert result.ok is False
    assert result.error != ""
    assert len(result.objects) == 0


def test_parse_bundle_empty_input_returns_error():
    ax = StixTestContext()
    result = parse_bundle(ax, StixInput(stix_json=""))
    assert result.ok is False
    assert result.error != ""


def test_parse_bundle_oversized_input_returns_error():
    ax = StixTestContext()
    huge = '{"type": "bundle", "id": "bundle--x", "objects": [' + ("1," * 400_000) + "1]}"
    result = parse_bundle(ax, StixInput(stix_json=huge))
    assert result.ok is False
    assert "cap" in result.error or "byte" in result.error
