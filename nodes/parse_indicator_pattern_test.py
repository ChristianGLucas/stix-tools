from gen.messages_pb2 import PatternInput, ParsePatternResult
from nodes.parse_indicator_pattern import parse_indicator_pattern
from nodes._test_fixtures import StixTestContext


def test_parse_indicator_pattern_single_comparison():
    ax = StixTestContext()
    result = parse_indicator_pattern(ax, PatternInput(pattern="[ipv4-addr:value = '203.0.113.10']"))
    assert isinstance(result, ParsePatternResult)
    assert result.ok is True
    assert result.observation_expression_count == 1
    assert list(result.object_types_referenced) == ["ipv4-addr"]
    assert len(result.comparisons) == 1
    comp = result.comparisons[0]
    assert comp.object_path == "ipv4-addr:value"
    assert comp.operator == "="
    assert comp.value == "'203.0.113.10'"
    assert comp.negated is False


def test_parse_indicator_pattern_and_composition_two_object_types():
    ax = StixTestContext()
    pattern = "[ipv4-addr:value = '203.0.113.10' AND file:hashes.'SHA-256' = 'abcd1234']"
    result = parse_indicator_pattern(ax, PatternInput(pattern=pattern))
    assert result.ok is True
    # Independent oracle: the pattern text literally contains two '=' comparisons.
    assert pattern.count(" = ") == len(result.comparisons) == 2
    assert sorted(result.object_types_referenced) == ["file", "ipv4-addr"]
    paths = sorted(c.object_path for c in result.comparisons)
    assert paths == ["file:hashes.SHA-256", "ipv4-addr:value"]


def test_parse_indicator_pattern_negated_comparison():
    ax = StixTestContext()
    result = parse_indicator_pattern(ax, PatternInput(pattern="[ipv4-addr:value != '203.0.113.10']"))
    assert result.ok is True
    assert result.comparisons[0].operator == "!="
    assert result.comparisons[0].negated is False  # '!=' itself, not a NOT-wrapped '='


def test_parse_indicator_pattern_followedby_at_least_two_observations():
    ax = StixTestContext()
    pattern = "[ipv4-addr:value = '203.0.113.10'] FOLLOWEDBY [file:name = 'evil.exe']"
    result = parse_indicator_pattern(ax, PatternInput(pattern=pattern))
    assert result.ok is True
    assert result.observation_expression_count >= 2


def test_parse_indicator_pattern_syntax_error_returns_error_not_crash():
    ax = StixTestContext()
    result = parse_indicator_pattern(ax, PatternInput(pattern="ipv4-addr:value = '203.0.113.10'"))  # missing brackets
    assert result.ok is False
    assert result.error != ""
    assert len(result.comparisons) == 0


def test_parse_indicator_pattern_unsupported_pattern_type():
    ax = StixTestContext()
    result = parse_indicator_pattern(ax, PatternInput(pattern="[a-b]", pattern_type="pcre"))
    assert result.ok is False
    assert "pattern_type" in result.error
