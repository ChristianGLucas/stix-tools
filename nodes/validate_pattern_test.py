from gen.messages_pb2 import PatternInput, ValidatePatternResult
from nodes.validate_pattern import validate_pattern
from nodes._test_fixtures import StixTestContext


def test_validate_pattern_valid():
    ax = StixTestContext()
    result = validate_pattern(ax, PatternInput(pattern="[ipv4-addr:value = '203.0.113.10']"))
    assert isinstance(result, ValidatePatternResult)
    assert result.valid is True
    assert len(result.errors) == 0


def test_validate_pattern_missing_brackets_is_invalid():
    ax = StixTestContext()
    result = validate_pattern(ax, PatternInput(pattern="ipv4-addr:value = '203.0.113.10'"))
    assert result.valid is False
    assert len(result.errors) > 0


def test_validate_pattern_unbalanced_brackets_is_invalid():
    ax = StixTestContext()
    result = validate_pattern(ax, PatternInput(pattern="[ipv4-addr:value = '203.0.113.10'"))
    assert result.valid is False
    assert len(result.errors) > 0


def test_validate_pattern_empty_is_invalid():
    ax = StixTestContext()
    result = validate_pattern(ax, PatternInput(pattern=""))
    assert result.valid is False
    assert len(result.errors) > 0


def test_validate_pattern_unsupported_pattern_type():
    ax = StixTestContext()
    result = validate_pattern(ax, PatternInput(pattern="[a=b]", pattern_type="sigma"))
    assert result.valid is False
    assert "pattern_type" in result.errors[0]
