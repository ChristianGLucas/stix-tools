from gen.messages_pb2 import BuildBundleInput, StixObjectResult, StixObject
from gen.axiom_context import AxiomContext
from nodes._stix_common import (
    parse_stix,
    build_object,
    stix_object_fields,
    stix2,
    StixToolsError,
    MAX_BUNDLE_OBJECTS,
    MAX_BUNDLE_TOTAL_BYTES,
)


def build_bundle(ax: AxiomContext, input: BuildBundleInput) -> StixObjectResult:
    """Assemble a well-formed STIX 2.1 Bundle from a list of
    already-serialized STIX objects -- e.g. the `object.raw_json` from
    previous BuildIndicator/BuildMalware/BuildThreatActor/
    BuildAttackPattern/BuildRelationship calls, or externally-authored STIX
    JSON. Every entry in `objects_json` is parsed and structurally validated
    before assembly; the first invalid entry aborts with a structured error
    naming its index. Bounded to 2000 objects and 512 KiB of total input
    text. `id` is an optional override; leave it empty to let the library
    generate a fresh bundle id.
    """
    out = StixObjectResult()
    try:
        entries = list(input.objects_json)
        if len(entries) > MAX_BUNDLE_OBJECTS:
            raise StixToolsError(
                f"objects_json exceeds {MAX_BUNDLE_OBJECTS}-object cap (got {len(entries)})"
            )
        total_bytes = sum(len(e.encode("utf-8", errors="ignore")) for e in entries)
        if total_bytes > MAX_BUNDLE_TOTAL_BYTES:
            raise StixToolsError(
                f"objects_json exceeds {MAX_BUNDLE_TOTAL_BYTES}-byte total cap (got {total_bytes} bytes)"
            )
        if not entries:
            raise StixToolsError("objects_json is empty")

        parsed_objs = []
        for idx, entry in enumerate(entries):
            try:
                parsed_objs.append(parse_stix(entry))
            except StixToolsError as exc:
                raise StixToolsError(f"objects_json[{idx}]: {exc}")

        bundle = build_object(stix2.v21.Bundle, dict(id=input.id, objects=parsed_objs))
    except StixToolsError as exc:
        out.ok = False
        out.error = str(exc)
        return out

    out.ok = True
    out.object.CopyFrom(StixObject(**stix_object_fields(bundle)))
    return out
