from gen.messages_pb2 import FilterInput, FilterResult, StixObject
from gen.axiom_context import AxiomContext
from nodes._stix_common import parse_stix, bundle_top_level_objects, stix_object_fields, obj_field, StixToolsError


def filter_objects_by_type(ax: AxiomContext, input: FilterInput) -> FilterResult:
    """Extract every object of a given STIX type from a Bundle (or a single
    bare object) -- the way you'd enumerate all Indicators, all Malware, all
    Threat Actors, or all Attack Patterns in a feed. `type_filter` is matched
    case-insensitively against each object's own 'type' property (e.g.
    "indicator", "malware", "threat-actor", "attack-pattern",
    "relationship", "sighting"); leave it empty or set it to "all" to keep
    every object regardless of type. `ok` is false only when `stix_json`
    fails to parse as STIX content at all -- an empty match (0 objects of
    the requested type) is a normal, successful result, not an error.
    """
    out = FilterResult()
    try:
        parsed = parse_stix(input.stix_json)
        _, _, objs = bundle_top_level_objects(parsed)
    except StixToolsError as exc:
        out.ok = False
        out.error = str(exc)
        return out

    type_filter = (input.type_filter or "").strip().lower()
    keep_all = type_filter in ("", "all")
    for o in objs:
        if keep_all or obj_field(o, "type").lower() == type_filter:
            out.objects.append(StixObject(**stix_object_fields(o)))

    out.ok = True
    out.matched_count = len(out.objects)
    return out
