# christiangeorgelucas/stix-tools

Composable [Axiom](https://axiomide.com) nodes for **STIX 2.1** (Structured
Threat Information eXpression) cyber threat intelligence object parsing,
validation, construction, and relationship-graph resolution.

Wraps the OASIS reference `stix2` library
([cti-python-stix2](https://github.com/oasis-open/cti-python-stix2),
BSD-3-Clause) and its `stix2-patterns` indicator-pattern grammar
(BSD-3-Clause). Both are **vendored** under `vendor/` rather than
pip-installed (see `requirements.txt` and the patch comment in
`vendor/stix2/__init__.py`) — upstream `stix2` unconditionally depends on
`requests` solely to support an unused TAXII network-client module, and
`requests` transitively pulls in `certifi` (MPL-2.0, copyleft). Dropping that
one unused module keeps this package's entire installed dependency closure
permissive (BSD/MIT only, verified with `pip-licenses`).

## Nodes

- **ParseBundle** — parse a STIX Bundle (or a single bare object) into its
  top-level objects.
- **ValidateStixObject** — structural spec-conformance validation of a STIX
  object or Bundle.
- **FilterObjectsByType** — enumerate objects of a given STIX type
  (indicator, malware, threat-actor, attack-pattern, relationship, ...).
- **ResolveRelationships** — resolve the Relationship/Sighting graph
  embedded in a Bundle into vertices and directed edges.
- **ParseIndicatorPattern** — parse a STIX Indicator pattern into its leaf
  comparisons and referenced observable types.
- **ValidatePattern** — lint a STIX Indicator pattern's syntax.
- **BuildIndicator** / **BuildMalware** / **BuildThreatActor** /
  **BuildAttackPattern** / **BuildRelationship** — construct well-formed STIX
  2.1 SDOs/SRO from caller-supplied fields.
- **BuildBundle** — assemble already-serialized STIX objects into a Bundle.

Every node is a pure, stateless function over caller-supplied JSON/text — no
network calls, no persistence. Every input is bounded well under Axiom's
deployed-ingress cap, and malformed or oversized input returns a structured
error rather than crashing.

Built for the Axiom marketplace.

## License

MIT (this package). Vendored `stix2`/`stix2-patterns` retain their own
BSD-3-Clause license — see `vendor/stix2/LICENSE` and
`vendor/stix2patterns/LICENSE`.
