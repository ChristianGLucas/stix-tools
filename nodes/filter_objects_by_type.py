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
        # Build into a local list first, and only touch `out` after every
        # step below has succeeded -- so if something raises partway
        # through, `out` is never left holding a partial result on the
        # error path below.
        parsed = parse_stix(input.stix_json)
        _, _, objs = bundle_top_level_objects(parsed)

        type_filter = (input.type_filter or "").strip().lower()
        keep_all = type_filter in ("", "all")
        matched = [
            StixObject(**stix_object_fields(o))
            for o in objs
            if keep_all or obj_field(o, "type").lower() == type_filter
        ]

        out.ok = True
        out.matched_count = len(matched)
        out.objects.extend(matched)
        return out
    except StixToolsError as exc:
        out.ok = False
        out.error = str(exc)
        return out
    except Exception as exc:  # noqa: BLE001 -- last-resort: never leak a raw traceback
        ax.log.error("filter_objects_by_type: unexpected exception", error=str(exc))
        out.ok = False
        out.error = f"unexpected error: {exc}"
        return out
