from gen.messages_pb2 import IndicatorSpec, StixObjectResult, StixObject
from gen.axiom_context import AxiomContext
from nodes._stix_common import build_object, stix_object_fields, check_size, stix2, StixToolsError


def build_indicator(ax: AxiomContext, input: IndicatorSpec) -> StixObjectResult:
    """Construct a well-formed STIX 2.1 Indicator SDO from caller-supplied
    fields and serialize it. `pattern` and `valid_from` are REQUIRED (the
    STIX 2.1 spec requires both); `id`/`created`/`modified` are optional
    overrides -- leave them empty to let the library generate a fresh,
    spec-conformant id (a random UUIDv4) and use the current time, exactly
    as a hand-authored STIX tool would. `confidence` of 0 (the default)
    means "Not Specified" per the STIX 2.1 spec, not an error. The
    constructed object's `raw_json` can be fed directly into BuildBundle's
    `objects_json` to assemble a Bundle.
    """
    out = StixObjectResult()
    try:
        check_size(input.pattern, 64 * 1024, "pattern")
        if not input.pattern.strip():
            raise StixToolsError("pattern is required")
        if not input.valid_from.strip():
            raise StixToolsError("valid_from is required")
        obj = build_object(
            stix2.v21.Indicator,
            dict(
                id=input.id,
                created=input.created,
                modified=input.modified,
                pattern=input.pattern,
                pattern_type=input.pattern_type or "stix",
                valid_from=input.valid_from,
                name=input.name,
                description=input.description,
                indicator_types=list(input.indicator_types),
                confidence=input.confidence,
                labels=list(input.labels),
            ),
        )
        result_fields = stix_object_fields(obj)

        out.ok = True
        out.object.CopyFrom(StixObject(**result_fields))
        return out
    except StixToolsError as exc:
        out.ok = False
        out.error = str(exc)
        return out
    except Exception as exc:  # noqa: BLE001 -- last-resort: never leak a raw traceback
        ax.log.error("build_indicator: unexpected exception", error=str(exc))
        out.ok = False
        out.error = f"unexpected error: {exc}"
        return out
