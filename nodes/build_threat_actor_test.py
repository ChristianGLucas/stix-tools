from gen.messages_pb2 import ThreatActorSpec, StixObjectResult
from nodes.build_threat_actor import build_threat_actor
from nodes._test_fixtures import assert_valid_stix_id, StixTestContext
import json


def test_build_threat_actor_golden():
    ax = StixTestContext()
    result = build_threat_actor(
        ax,
        ThreatActorSpec(
            name="APT-Test",
            threat_actor_types=["nation-state"],
            sophistication="advanced",
            resource_level="government",
            primary_motivation="organizational-gain",
        ),
    )
    assert isinstance(result, StixObjectResult)
    assert result.ok is True
    assert result.object.type == "threat-actor"
    assert result.object.name == "APT-Test"
    assert_valid_stix_id(result.object.id, "threat-actor")
    as_dict = json.loads(result.object.raw_json)
    assert as_dict["threat_actor_types"] == ["nation-state"]
    assert as_dict["sophistication"] == "advanced"
    assert as_dict["resource_level"] == "government"
    assert as_dict["primary_motivation"] == "organizational-gain"


def test_build_threat_actor_custom_vocab_value_passes_through():
    ax = StixTestContext()
    result = build_threat_actor(ax, ThreatActorSpec(name="X", sophistication="totally-unheard-of-level"))
    assert result.ok is True
    as_dict = json.loads(result.object.raw_json)
    assert as_dict["sophistication"] == "totally-unheard-of-level"


def test_build_threat_actor_missing_name_returns_error():
    ax = StixTestContext()
    result = build_threat_actor(ax, ThreatActorSpec(threat_actor_types=["hacker"]))
    assert result.ok is False
    assert "name" in result.error
