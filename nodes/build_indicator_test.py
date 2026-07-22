from gen.messages_pb2 import IndicatorSpec, StixObjectResult
from nodes.build_indicator import build_indicator
from nodes._stix_common import validate_pattern_errors
from nodes._test_fixtures import assert_valid_stix_id, StixTestContext
import json


def test_build_indicator_golden():
    ax = StixTestContext()
    result = build_indicator(
        ax,
        IndicatorSpec(
            pattern="[ipv4-addr:value = '203.0.113.10']",
            pattern_type="stix",
            valid_from="2024-01-01T00:00:00Z",
            name="Malicious IP",
            indicator_types=["malicious-activity"],
            confidence=80,
        ),
    )
    assert isinstance(result, StixObjectResult)
    assert result.ok is True
    assert result.error == ""
    assert result.object.type == "indicator"
    assert result.object.name == "Malicious IP"
    assert_valid_stix_id(result.object.id, "indicator")

    as_dict = json.loads(result.object.raw_json)
    assert as_dict["pattern"] == "[ipv4-addr:value = '203.0.113.10']"
    assert as_dict["indicator_types"] == ["malicious-activity"]
    assert as_dict["confidence"] == 80
    assert as_dict["valid_from"] == "2024-01-01T00:00:00Z"

    # Independent oracle: the pattern we just built into this indicator is
    # itself syntactically valid per stix2-patterns' own grammar checker.
    assert validate_pattern_errors(as_dict["pattern"]) == []


def test_build_indicator_deterministic_id_override():
    ax = StixTestContext()
    fixed_id = "indicator--11111111-1111-4111-8111-111111111111"
    result = build_indicator(
        ax,
        IndicatorSpec(
            id=fixed_id,
            created="2024-01-01T00:00:00.000Z",
            modified="2024-01-01T00:00:00.000Z",
            pattern="[ipv4-addr:value = '203.0.113.10']",
            valid_from="2024-01-01T00:00:00Z",
        ),
    )
    assert result.ok is True
    assert result.object.id == fixed_id
    assert result.object.created == "2024-01-01T00:00:00.000Z"


def test_build_indicator_missing_pattern_returns_error():
    ax = StixTestContext()
    result = build_indicator(ax, IndicatorSpec(valid_from="2024-01-01T00:00:00Z"))
    assert result.ok is False
    assert "pattern" in result.error


def test_build_indicator_missing_valid_from_returns_error():
    ax = StixTestContext()
    result = build_indicator(ax, IndicatorSpec(pattern="[ipv4-addr:value = '1.2.3.4']"))
    assert result.ok is False
    assert "valid_from" in result.error


def test_build_indicator_malformed_pattern_returns_error_not_crash():
    ax = StixTestContext()
    result = build_indicator(
        ax,
        IndicatorSpec(pattern="not a valid pattern at all", valid_from="2024-01-01T00:00:00Z"),
    )
    assert result.ok is False
    assert result.error != ""
