from gen.messages_pb2 import StixInput, ParseBundleResult, StixObject
from gen.axiom_context import AxiomContext
from nodes._stix_common import parse_stix, bundle_top_level_objects, stix_object_fields, StixToolsError


def parse_bundle(ax: AxiomContext, input: StixInput) -> ParseBundleResult:
    """Parse a STIX 2.1 Bundle (or a single bare SDO/SCO/SRO) from JSON text
    into its top-level objects. Each returned object carries its id, type,
    spec_version, created/modified timestamps, name (when it has one), and
    full serialized JSON. `ok` is false only when `stix_json` fails to parse
    as STIX content at all (invalid JSON, missing/unrecognized 'type', or a
    structurally invalid object) -- a bundle whose objects are individually
    well-formed always succeeds, even if you don't recognize every object
    type it contains.
    """
    out = ParseBundleResult()
    try:
        parsed = parse_stix(input.stix_json)
        bundle_id, spec_version, objs = bundle_top_level_objects(parsed)
    except StixToolsError as exc:
        out.ok = False
        out.error = str(exc)
        return out

    out.ok = True
    out.bundle_id = bundle_id
    out.spec_version = spec_version or ""
    for o in objs:
        out.objects.append(StixObject(**stix_object_fields(o)))
    return out
