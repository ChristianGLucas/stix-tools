from gen.messages_pb2 import ThreatActorSpec, StixObjectResult, StixObject
from gen.axiom_context import AxiomContext
from nodes._stix_common import build_object, stix_object_fields, stix2, StixToolsError


def build_threat_actor(ax: AxiomContext, input: ThreatActorSpec) -> StixObjectResult:
    """Construct a well-formed STIX 2.1 Threat Actor SDO from caller-supplied
    fields and serialize it. `name` is REQUIRED. `sophistication` and
    `resource_level` are STIX open-vocabulary strings (e.g. "advanced",
    "government") and are not checked against the vocabulary list -- an
    unrecognized value is passed through as a custom vocabulary entry, which
    the STIX 2.1 spec explicitly permits for open vocabularies.
    `id`/`created`/`modified` are optional overrides -- leave them empty to
    let the library generate a fresh id and use the current time.
    """
    out = StixObjectResult()
    try:
        if not input.name.strip():
            raise StixToolsError("name is required")
        obj = build_object(
            stix2.v21.ThreatActor,
            dict(
                id=input.id,
                created=input.created,
                modified=input.modified,
                name=input.name,
                threat_actor_types=list(input.threat_actor_types),
                description=input.description,
                roles=list(input.roles),
                sophistication=input.sophistication,
                resource_level=input.resource_level,
                primary_motivation=input.primary_motivation,
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
        ax.log.error("build_threat_actor: unexpected exception", error=str(exc))
        out.ok = False
        out.error = f"unexpected error: {exc}"
        return out
