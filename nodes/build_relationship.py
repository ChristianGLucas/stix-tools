from gen.messages_pb2 import RelationshipSpec, StixObjectResult, StixObject
from gen.axiom_context import AxiomContext
from nodes._stix_common import build_object, stix_object_fields, stix2, StixToolsError


def build_relationship(ax: AxiomContext, input: RelationshipSpec) -> StixObjectResult:
    """Construct a well-formed STIX 2.1 Relationship SRO from
    caller-supplied fields and serialize it. `relationship_type`,
    `source_ref`, and `target_ref` are all REQUIRED. `source_ref`/
    `target_ref` are taken as given and NOT checked for existence -- a
    Relationship may legitimately reference an object delivered in a
    separate bundle, so this node performs no cross-object lookup (use
    ResolveRelationships on an assembled bundle if you need endpoint
    resolution). `id`/`created`/`modified` are optional overrides -- leave
    them empty to let the library generate a fresh id and use the current
    time.
    """
    out = StixObjectResult()
    try:
        if not input.relationship_type.strip():
            raise StixToolsError("relationship_type is required")
        if not input.source_ref.strip():
            raise StixToolsError("source_ref is required")
        if not input.target_ref.strip():
            raise StixToolsError("target_ref is required")
        obj = build_object(
            stix2.v21.Relationship,
            dict(
                id=input.id,
                created=input.created,
                modified=input.modified,
                relationship_type=input.relationship_type,
                source_ref=input.source_ref,
                target_ref=input.target_ref,
                description=input.description,
            ),
        )
    except StixToolsError as exc:
        out.ok = False
        out.error = str(exc)
        return out

    out.ok = True
    out.object.CopyFrom(StixObject(**stix_object_fields(obj)))
    return out
