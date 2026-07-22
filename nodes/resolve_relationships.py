from gen.messages_pb2 import StixInput, RelationshipGraphResult, GraphNode, GraphEdge
from gen.axiom_context import AxiomContext
from nodes._stix_common import parse_stix, bundle_top_level_objects, obj_field, StixToolsError


def resolve_relationships(ax: AxiomContext, input: StixInput) -> RelationshipGraphResult:
    """Resolve the relationship graph embedded in a STIX Bundle: every
    non-relationship SDO/SCO becomes a graph vertex, and every Relationship
    or Sighting SRO becomes a directed edge between the objects it connects
    (source_ref -> target_ref for a Relationship; sighting_of_ref -> the
    first where_sighted_ref for a Sighting). An edge's source_type/
    target_type is resolved by matching against the bundle's own objects and
    left empty when the referenced id is not present in this bundle -- a
    dangling reference is common (STIX content is often delivered in
    separate bundles) and is not itself an error. `ok` is false only when
    `stix_json` fails to parse as STIX content at all.
    """
    out = RelationshipGraphResult()
    try:
        # Build into locals first, and only touch `out` after every step
        # below has succeeded -- so if something raises partway through,
        # `out` is never left holding a partial result on the error path.
        parsed = parse_stix(input.stix_json)
        _, _, objs = bundle_top_level_objects(parsed)

        id_to_type = {}
        for o in objs:
            oid = obj_field(o, "id")
            if oid:
                id_to_type[oid] = obj_field(o, "type")

        graph_nodes = []
        for o in objs:
            otype = obj_field(o, "type")
            if otype in ("relationship", "sighting"):
                continue
            graph_nodes.append(GraphNode(id=obj_field(o, "id"), type=otype, name=obj_field(o, "name")))

        graph_edges = []
        for o in objs:
            otype = obj_field(o, "type")
            if otype == "relationship":
                source_ref = obj_field(o, "source_ref")
                target_ref = obj_field(o, "target_ref")
                graph_edges.append(
                    GraphEdge(
                        id=obj_field(o, "id"),
                        relationship_type=obj_field(o, "relationship_type"),
                        source_ref=source_ref,
                        target_ref=target_ref,
                        source_type=id_to_type.get(source_ref, ""),
                        target_type=id_to_type.get(target_ref, ""),
                        confidence=obj_field(o, "confidence", 0) or 0,
                        is_sighting=False,
                    )
                )
            elif otype == "sighting":
                source_ref = obj_field(o, "sighting_of_ref")
                where = obj_field(o, "where_sighted_refs", []) or []
                target_ref = where[0] if where else ""
                graph_edges.append(
                    GraphEdge(
                        id=obj_field(o, "id"),
                        relationship_type="sighting-of",
                        source_ref=source_ref,
                        target_ref=target_ref,
                        source_type=id_to_type.get(source_ref, ""),
                        target_type=id_to_type.get(target_ref, ""),
                        confidence=0,
                        is_sighting=True,
                    )
                )

        out.ok = True
        out.nodes.extend(graph_nodes)
        out.edges.extend(graph_edges)
        return out
    except StixToolsError as exc:
        out.ok = False
        out.error = str(exc)
        return out
    except Exception as exc:  # noqa: BLE001 -- last-resort: never leak a raw traceback
        ax.log.error("resolve_relationships: unexpected exception", error=str(exc))
        out.ok = False
        out.error = f"unexpected error: {exc}"
        return out
