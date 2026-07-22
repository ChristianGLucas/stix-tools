from gen.messages_pb2 import AttackPatternSpec, StixObjectResult, StixObject
from gen.axiom_context import AxiomContext
from nodes._stix_common import build_object, stix_object_fields, stix2, StixToolsError


def build_attack_pattern(ax: AxiomContext, input: AttackPatternSpec) -> StixObjectResult:
    """Construct a well-formed STIX 2.1 Attack Pattern SDO from
    caller-supplied fields and serialize it. `name` is REQUIRED.
    `kill_chain_phases` (kill_chain_name + phase_name pairs, e.g.
    "lockheed-martin-cyber-kill-chain" / "reconnaissance") is optional and
    may be repeated. `id`/`created`/`modified` are optional overrides --
    leave them empty to let the library generate a fresh id and use the
    current time.
    """
    out = StixObjectResult()
    try:
        if not input.name.strip():
            raise StixToolsError("name is required")
        try:
            kill_chain_phases = [
                stix2.v21.KillChainPhase(kill_chain_name=p.kill_chain_name, phase_name=p.phase_name)
                for p in input.kill_chain_phases
            ]
        except (TypeError, ValueError) as exc:
            raise StixToolsError(f"invalid kill_chain_phases: {exc}")
        obj = build_object(
            stix2.v21.AttackPattern,
            dict(
                id=input.id,
                created=input.created,
                modified=input.modified,
                name=input.name,
                description=input.description,
                kill_chain_phases=kill_chain_phases,
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
        ax.log.error("build_attack_pattern: unexpected exception", error=str(exc))
        out.ok = False
        out.error = f"unexpected error: {exc}"
        return out
