from gen.messages_pb2 import AttackPatternSpec, KillChainPhase, StixObjectResult
from nodes.build_attack_pattern import build_attack_pattern
from nodes._test_fixtures import assert_valid_stix_id, StixTestContext
import json


def test_build_attack_pattern_golden():
    ax = StixTestContext()
    result = build_attack_pattern(
        ax,
        AttackPatternSpec(
            name="Spearphishing",
            description="Targeted phishing email with malicious attachment",
            kill_chain_phases=[
                KillChainPhase(kill_chain_name="lockheed-martin-cyber-kill-chain", phase_name="initial-access"),
            ],
        ),
    )
    assert isinstance(result, StixObjectResult)
    assert result.ok is True
    assert result.object.type == "attack-pattern"
    assert result.object.name == "Spearphishing"
    assert_valid_stix_id(result.object.id, "attack-pattern")
    as_dict = json.loads(result.object.raw_json)
    assert as_dict["kill_chain_phases"] == [
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "initial-access"}
    ]


def test_build_attack_pattern_no_kill_chain_phases_is_valid():
    ax = StixTestContext()
    result = build_attack_pattern(ax, AttackPatternSpec(name="Generic Attack"))
    assert result.ok is True
    as_dict = json.loads(result.object.raw_json)
    assert "kill_chain_phases" not in as_dict


def test_build_attack_pattern_missing_name_returns_error():
    ax = StixTestContext()
    result = build_attack_pattern(ax, AttackPatternSpec(description="no name given"))
    assert result.ok is False
    assert "name" in result.error
