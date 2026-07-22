"""Shared helpers for christiangeorgelucas/stix-tools.

Wires the vendored `stix2`/`stix2patterns` packages onto sys.path (see
requirements.txt and vendor/stix2/__init__.py for why they are vendored
rather than pip-installed) and provides small, reusable
parse/build/bounds-checking utilities used by every node.
"""

import os
import sys

_VENDOR_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vendor")
if _VENDOR_DIR not in sys.path:
    sys.path.insert(0, _VENDOR_DIR)

import simplejson as json  # noqa: E402  (must follow the sys.path patch above)
import stix2  # noqa: E402
import stix2.exceptions as stix2_exceptions  # noqa: E402
import stix2patterns.validator as pattern_validator  # noqa: E402
from stix2patterns.exceptions import ParseException as PatternParseException  # noqa: E402
from stix2patterns.inspector import INDEX_STAR  # noqa: E402
from stix2patterns.v21.pattern import Pattern as StixPattern21  # noqa: E402
from stix2patterns.v21.grammars.STIXPatternListener import STIXPatternListener  # noqa: E402

# ── Input bounds (well under Axiom's ~1 MiB deployed-ingress cap; a ~640 KiB
#    safe ceiling was the guidance, these are more conservative still) ──────
MAX_STIX_JSON_BYTES = 512 * 1024
MAX_PATTERN_BYTES = 64 * 1024
MAX_BUNDLE_OBJECTS = 2000
MAX_BUNDLE_TOTAL_BYTES = 512 * 1024


class StixToolsError(Exception):
    """Raised for any structured, caller-facing error condition. Every node
    catches this at its boundary and turns it into a `(ok=false, error=...)`
    result rather than letting it propagate as a crash.
    """


def check_size(text, max_bytes, field_name):
    encoded_len = len((text or "").encode("utf-8", errors="ignore"))
    if encoded_len > max_bytes:
        raise StixToolsError(
            f"{field_name} exceeds {max_bytes}-byte cap (got {encoded_len} bytes)"
        )


def parse_stix(stix_json, allow_custom=True):
    """Parse caller-supplied STIX JSON text into a stix2 object (a single
    SDO/SCO/SRO, or a Bundle), applying the package's size bound first.
    Raises StixToolsError with a human-readable message on any problem --
    malformed JSON, missing 'type', missing required properties, wrong
    property types, and so on.

    `allow_custom` defaults to True: a caller-defined property or an
    unrecognized ("custom"/vendor-extension, e.g. "x-acme-thing") object
    TYPE is accepted rather than rejected, matching real-world STIX feeds
    that commonly carry vendor extensions -- this does NOT waive required-
    property/type checking for RECOGNIZED object types, which is always
    enforced regardless of this flag (see stix2's own properties.py: a
    required=True property is checked unconditionally). Nodes that exist
    specifically to perform strict spec-conformance checking (e.g.
    ValidateStixObject) pass allow_custom=False explicitly to also reject
    undeclared custom properties/types.

    An object of an unrecognized type comes back from the underlying
    library as a plain dict rather than a stix2 object when allow_custom is
    True (this is stix2's own documented behavior, not something stix-tools
    does) -- see stix_object_fields() for how that's handled downstream.
    """
    check_size(stix_json, MAX_STIX_JSON_BYTES, "stix_json")
    if not stix_json or not stix_json.strip():
        raise StixToolsError("stix_json is empty")
    try:
        data = json.loads(stix_json)
    except ValueError as exc:
        raise StixToolsError(f"invalid JSON: {exc}")
    if not isinstance(data, dict):
        raise StixToolsError("stix_json must decode to a JSON object")
    try:
        return stix2.parse(data, allow_custom=allow_custom)
    except stix2_exceptions.STIXError as exc:
        raise StixToolsError(str(exc))
    except (KeyError, TypeError, ValueError) as exc:
        raise StixToolsError(f"not a valid STIX object: {exc}")


def obj_field(obj, name, default=""):
    try:
        if name in obj:
            return obj.get(name, default)
    except TypeError:
        pass
    return default


def stix_object_fields(obj):
    """Extract the common StixObject fields from a parsed stix2 object (or a
    plain dict -- see below) as a plain dict, suitable for
    `StixObject(**fields)`. Reads created/modified back out of the object's
    OWN serialized JSON (rather than formatting the live Python datetime
    ourselves) so the reported timestamp string is byte-identical to what
    `raw_json` carries -- e.g. "2020-01-01T00:00:00Z", not Python's
    "2020-01-01 00:00:00+00:00" repr.

    An object of an unrecognized ("custom") type parsed with
    allow_custom=True comes back from stix2 as a plain dict rather than a
    stix2 object (no `.serialize()` method) -- handled here by serializing
    it ourselves via simplejson instead.
    """
    if hasattr(obj, "serialize"):
        raw_json = obj.serialize()
        as_dict = json.loads(raw_json)
    else:
        as_dict = obj
        raw_json = json.dumps(obj, sort_keys=False)
    return {
        "id": as_dict.get("id", ""),
        "type": as_dict.get("type", ""),
        "spec_version": as_dict.get("spec_version", "2.1"),
        "created": as_dict.get("created", "") or "",
        "modified": as_dict.get("modified", "") or "",
        "name": as_dict.get("name", "") or "",
        "raw_json": raw_json,
    }


def bundle_top_level_objects(parsed):
    """Given a parsed stix2 object (either a Bundle or a single SDO/SCO/SRO),
    return (bundle_id, spec_version, list_of_objects).
    """
    if obj_field(parsed, "type") == "bundle":
        objs = list(obj_field(parsed, "objects", []) or [])
        spec_version = ""
        for o in objs:
            sv = obj_field(o, "spec_version")
            if sv:
                spec_version = sv
                break
        return obj_field(parsed, "id"), spec_version, objs
    else:
        return "", obj_field(parsed, "spec_version"), [parsed]


def build_object(stix_cls, kwargs, allow_custom=False):
    """Construct a stix2 v21 object, converting library errors into
    StixToolsError. Empty-string/empty-list/unset-zero fields are dropped so
    optional proto fields don't get passed as explicit empty overrides
    (letting the library apply its own defaults/auto-generation), except
    `is_family` where False is a genuine, meaningful value.

    `allow_custom` defaults to False for the BuildIndicator/BuildMalware/etc.
    nodes (their caller-supplied fields are all declared properties, so
    there is nothing "custom" to allow). BuildBundle passes True: a
    `objects` list assembled from BuildBundleInput.objects_json can
    legitimately contain an unrecognized ("custom") object type -- each
    entry was already independently parsed with allow_custom=True by
    parse_stix(), so re-validating the assembled Bundle at its default
    strictness would otherwise reject the very custom objects that were
    just accepted one line earlier.
    """
    clean_kwargs = {}
    for k, v in kwargs.items():
        if k == "is_family":
            clean_kwargs[k] = bool(v)
            continue
        if v in (None, "", [], 0):
            continue
        clean_kwargs[k] = v
    if allow_custom:
        clean_kwargs["allow_custom"] = True
    try:
        return stix_cls(**clean_kwargs)
    except stix2_exceptions.STIXError as exc:
        raise StixToolsError(str(exc))
    except (TypeError, ValueError) as exc:
        raise StixToolsError(str(exc))


def _render_object_path(path_list):
    parts = []
    for comp in path_list:
        if comp is INDEX_STAR:
            token = "[*]"
        elif isinstance(comp, int):
            token = f"[{comp}]"
        else:
            token = None
        if token is not None:
            if parts:
                parts[-1] = parts[-1] + token
            else:
                parts.append(token)
        else:
            parts.append(str(comp))
    return ".".join(parts)


def parse_pattern(pattern):
    """Parse a STIX 2.1 indicator pattern string, returning the compiled
    `stix2patterns.v21.pattern.Pattern`. Raises StixToolsError with a
    human-readable message on any syntax problem.
    """
    check_size(pattern, MAX_PATTERN_BYTES, "pattern")
    if not pattern or not pattern.strip():
        raise StixToolsError("pattern is empty")
    try:
        return StixPattern21(pattern)
    except PatternParseException as exc:
        raise StixToolsError(str(exc))


def inspect_pattern(compiled):
    """Given a compiled Pattern, return (comparisons, observation_expr_count,
    object_types) where `comparisons` is a flat list of
    (object_path, operator, value, negated) tuples.
    """
    data = compiled.inspect()
    comparisons = []
    object_types = sorted(data.comparisons.keys())
    for obj_type, entries in data.comparisons.items():
        for obj_path, op_str, value in entries:
            negated = op_str.startswith("NOT ")
            operator = op_str[4:] if negated else op_str
            comparisons.append(
                (f"{obj_type}:{_render_object_path(obj_path)}", operator, value, negated)
            )
    # FOLLOWEDBY splits the pattern into multiple observation expressions;
    # AND/OR compose comparisons WITHIN one observation expression and don't
    # add another. Every pattern has at least one observation expression.
    # stix2patterns' own InspectionListener only records FOLLOWEDBY as a set
    # membership flag (present/absent), not a count, so it can't tell "a
    # FOLLOWEDBY b" from "a FOLLOWEDBY b FOLLOWEDBY c" -- we walk the tree a
    # second time with our own tiny counting listener to get an exact count.
    observation_expression_count = 1 + _count_followedby(compiled)
    return comparisons, observation_expression_count, object_types


class _FollowedByCounter(STIXPatternListener):
    """Counts FOLLOWEDBY tokens across the whole pattern -- the number of
    top-level observation expressions is exactly 1 + this count.
    """

    def __init__(self):
        self.count = 0

    def exitObservationExpressions(self, ctx):
        followedby_tokens = ctx.FOLLOWEDBY()
        if followedby_tokens:
            self.count += len(followedby_tokens) if isinstance(followedby_tokens, list) else 1


def _count_followedby(compiled):
    counter = _FollowedByCounter()
    compiled.walk(counter)
    return counter.count


def validate_pattern_errors(pattern, stix_version="2.1"):
    check_size(pattern, MAX_PATTERN_BYTES, "pattern")
    if not pattern or not pattern.strip():
        return ["pattern is empty"]
    return pattern_validator.run_validator(pattern, stix_version=stix_version)
