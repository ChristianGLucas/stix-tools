from gen.messages_pb2 import RelationshipSpec, StixObjectResult
from nodes.build_relationship import build_relationship
from nodes._test_fixtures import assert_valid_stix_id, INDICATOR_ID, MALWARE_ID, StixTestContext
import json


def test_build_relationship_golden():
    ax = StixTestContext()
    result = build_relationship(
        ax,
        RelationshipSpec(
            relationship_type="indicates",
            source_ref=INDICATOR_ID,
            target_ref=MALWARE_ID,
            description="This indicator indicates this malware",
        ),
    )
    assert isinstance(result, StixObjectResult)
    assert result.ok is True
    assert result.object.type == "relationship"
    assert result.object.name == ""  # Relationship has no 'name' property
    assert_valid_stix_id(result.object.id, "relationship")
    as_dict = json.loads(result.object.raw_json)
    assert as_dict["relationship_type"] == "indicates"
    assert as_dict["source_ref"] == INDICATOR_ID
    assert as_dict["target_ref"] == MALWARE_ID


def test_build_relationship_missing_relationship_type_returns_error():
    ax = StixTestContext()
    result = build_relationship(ax, RelationshipSpec(source_ref=INDICATOR_ID, target_ref=MALWARE_ID))
    assert result.ok is False
    assert "relationship_type" in result.error


def test_build_relationship_missing_source_ref_returns_error():
    ax = StixTestContext()
    result = build_relationship(ax, RelationshipSpec(relationship_type="indicates", target_ref=MALWARE_ID))
    assert result.ok is False
    assert "source_ref" in result.error


def test_build_relationship_missing_target_ref_returns_error():
    ax = StixTestContext()
    result = build_relationship(ax, RelationshipSpec(relationship_type="indicates", source_ref=INDICATOR_ID))
    assert result.ok is False
    assert "target_ref" in result.error
