from gen.messages_pb2 import StixInput, RelationshipGraphResult
from nodes.resolve_relationships import resolve_relationships
from nodes._test_fixtures import (
    BUNDLE_JSON,
    NOT_JSON,
    INDICATOR_ID,
    MALWARE_ID,
    THREAT_ACTOR_ID,
    ATTACK_PATTERN_ID,
    IDENTITY_ID,
    REL_INDICATES_ID,
    REL_ATTRIBUTED_ID,
    SIGHTING_ID,
    StixTestContext,
)


def test_resolve_relationships_golden():
    ax = StixTestContext()
    result = resolve_relationships(ax, StixInput(stix_json=BUNDLE_JSON))
    assert isinstance(result, RelationshipGraphResult)
    assert result.ok is True

    # 5 non-relationship/sighting SDOs: indicator, malware, threat-actor, attack-pattern, identity
    node_ids = {n.id for n in result.nodes}
    assert node_ids == {INDICATOR_ID, MALWARE_ID, THREAT_ACTOR_ID, ATTACK_PATTERN_ID, IDENTITY_ID}

    edges_by_id = {e.id: e for e in result.edges}
    assert set(edges_by_id.keys()) == {REL_INDICATES_ID, REL_ATTRIBUTED_ID, SIGHTING_ID}

    indicates = edges_by_id[REL_INDICATES_ID]
    assert indicates.relationship_type == "indicates"
    assert indicates.source_ref == INDICATOR_ID
    assert indicates.target_ref == MALWARE_ID
    assert indicates.source_type == "indicator"
    assert indicates.target_type == "malware"
    assert indicates.is_sighting is False

    attributed = edges_by_id[REL_ATTRIBUTED_ID]
    assert attributed.relationship_type == "attributed-to"
    assert attributed.source_ref == MALWARE_ID
    assert attributed.target_ref == THREAT_ACTOR_ID

    sighting = edges_by_id[SIGHTING_ID]
    assert sighting.is_sighting is True
    assert sighting.relationship_type == "sighting-of"
    assert sighting.source_ref == INDICATOR_ID
    assert sighting.target_ref == IDENTITY_ID
    assert sighting.source_type == "indicator"
    assert sighting.target_type == "identity"


def test_resolve_relationships_dangling_ref_has_empty_type():
    ax = StixTestContext()
    import json

    bundle = json.loads(BUNDLE_JSON)
    bundle["objects"] = [
        o for o in bundle["objects"] if o["id"] not in (INDICATOR_ID,)
    ]  # drop the indicator but keep the relationship pointing at it
    result = resolve_relationships(ax, StixInput(stix_json=json.dumps(bundle)))
    assert result.ok is True
    indicates = [e for e in result.edges if e.relationship_type == "indicates"][0]
    assert indicates.source_ref == INDICATOR_ID
    assert indicates.source_type == ""  # dangling -- not present in this bundle


def test_resolve_relationships_malformed_returns_error_not_crash():
    ax = StixTestContext()
    result = resolve_relationships(ax, StixInput(stix_json=NOT_JSON))
    assert result.ok is False
    assert result.error != ""
    assert len(result.nodes) == 0
    assert len(result.edges) == 0
