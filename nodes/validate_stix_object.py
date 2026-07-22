from gen.messages_pb2 import StixInput, ValidateResult, ValidationError
from gen.axiom_context import AxiomContext
from nodes._stix_common import parse_stix, obj_field, StixToolsError


def validate_stix_object(ax: AxiomContext, input: StixInput) -> ValidateResult:
    """Check whether `stix_json` -- a single STIX SDO/SCO/SRO or a full
    Bundle -- is structurally valid per the STIX 2.1 spec: valid JSON,
    recognized 'type', every required property present, and every property
    correctly typed (for a Bundle, every contained object is checked too,
    recursively). `valid` is true only when every check passes; otherwise
    `errors` lists what's wrong. This is a structural conformance check
    (required properties, types, enumerations, id format, pattern syntax for
    Indicators) -- it does not check cross-object semantics such as whether
    a Relationship's source_ref/target_ref actually exist elsewhere.
    """
    out = ValidateResult()
    try:
        parsed = parse_stix(input.stix_json, allow_custom=False)
        out.valid = True
        out.object_type = obj_field(parsed, "type")
        out.object_id = obj_field(parsed, "id")
        return out
    except StixToolsError as exc:
        out.valid = False
        out.errors.append(ValidationError(path="", message=str(exc)))
        return out
    except Exception as exc:  # noqa: BLE001 -- last-resort: never leak a raw traceback
        ax.log.error("validate_stix_object: unexpected exception", error=str(exc))
        out.valid = False
        out.errors.append(ValidationError(path="", message=f"unexpected error: {exc}"))
        return out
