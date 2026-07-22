from gen.messages_pb2 import PatternInput, ParsePatternResult, ComparisonExpression
from gen.axiom_context import AxiomContext
from nodes._stix_common import parse_pattern, inspect_pattern, StixToolsError


def parse_indicator_pattern(ax: AxiomContext, input: PatternInput) -> ParsePatternResult:
    """Parse a STIX 2.1 Indicator pattern (the domain-specific language used
    in Indicator.pattern, e.g. "[ipv4-addr:value = '1.2.3.4']") into its leaf
    comparisons -- object path, operator, and literal value for every
    condition the pattern tests -- plus how many top-level observation
    expressions it composes (more than one means it uses FOLLOWEDBY) and
    which STIX Cyber Observable object types it references. `ok` is false
    for a syntactically invalid pattern or an unsupported `pattern_type`
    (only "stix", the default, is parsed). AND/OR grouping and qualifiers
    (WITHIN/REPEATS/START-STOP) are not reconstructed in the output -- this
    is a flat inventory of what the pattern compares, not a full re-render
    of its expression tree.
    """
    out = ParsePatternResult()
    pattern_type = (input.pattern_type or "stix").strip().lower()
    if pattern_type not in ("", "stix"):
        out.ok = False
        out.error = f"unsupported pattern_type {input.pattern_type!r}; only 'stix' is parsed"
        return out

    try:
        compiled = parse_pattern(input.pattern)
        comparisons, obs_count, object_types = inspect_pattern(compiled)
    except StixToolsError as exc:
        out.ok = False
        out.error = str(exc)
        return out

    out.ok = True
    out.observation_expression_count = obs_count
    out.object_types_referenced.extend(object_types)
    for object_path, operator, value, negated in comparisons:
        out.comparisons.append(
            ComparisonExpression(object_path=object_path, operator=operator, value=value, negated=negated)
        )
    return out
