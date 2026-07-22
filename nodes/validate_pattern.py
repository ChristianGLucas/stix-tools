from gen.messages_pb2 import PatternInput, ValidatePatternResult
from gen.axiom_context import AxiomContext
from nodes._stix_common import validate_pattern_errors, check_size, StixToolsError


def validate_pattern(ax: AxiomContext, input: PatternInput) -> ValidatePatternResult:
    """Lint a STIX 2.1 Indicator pattern against the STIX Patterning grammar
    using stix2-patterns' own grammar-level validator -- a lighter-weight
    pass/fail check than ParseIndicatorPattern (no AST is built or
    returned), useful for validating many candidate patterns quickly.
    `valid` is true only when the pattern is syntactically well-formed;
    otherwise `errors` lists every syntax problem the grammar found (unlike
    ValidateStixObject, this genuinely can report more than one -- the
    ANTLR-based grammar checker collects all lexer/parser errors in a single
    pass rather than bailing at the first one).
    """
    out = ValidatePatternResult()
    pattern_type = (input.pattern_type or "stix").strip().lower()
    if pattern_type not in ("", "stix"):
        out.valid = False
        out.errors.append(f"unsupported pattern_type {input.pattern_type!r}; only 'stix' is validated")
        return out

    try:
        check_size(input.pattern, 64 * 1024, "pattern")
        errors = validate_pattern_errors(input.pattern)
        out.valid = len(errors) == 0
        out.errors.extend(errors)
        return out
    except StixToolsError as exc:
        out.valid = False
        out.errors.append(str(exc))
        return out
    except Exception as exc:  # noqa: BLE001 -- last-resort: never leak a raw traceback
        ax.log.error("validate_pattern: unexpected exception", error=str(exc))
        out.valid = False
        out.errors.append(f"unexpected error: {exc}")
        return out
