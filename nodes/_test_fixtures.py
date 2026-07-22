"""Test-only fixtures for christiangeorgelucas/stix-tools.

BUNDLE_JSON below is a hand-built STIX 2.1 Bundle -- assembled with plain
`json.dumps` over Python dicts, NOT using stix2 -- so tests asserting the
vendored stix2/stix2-patterns parse of this text against the values below
are checking the library's behavior against ground truth we control
byte-for-byte, not merely round-tripping the library against itself. IDs are
fixed, valid UUIDv4s so tests are fully reproducible.
"""
import json
import re

INDICATOR_ID = "indicator--0510477a-a878-4f62-a21f-6016898133dc"
MALWARE_ID = "malware--ec809bad-9dd2-4464-b251-02779b82c8bd"
THREAT_ACTOR_ID = "threat-actor--70233252-9a8e-4a37-be15-82c3720cbd82"
ATTACK_PATTERN_ID = "attack-pattern--851b0129-d024-45d6-ab24-6c5f8ab590b8"
REL_INDICATES_ID = "relationship--e3d5fe74-1552-4058-b5a9-c00723c6d2cc"
REL_ATTRIBUTED_ID = "relationship--73cf79b5-e6f4-4514-b4fa-1200b00f5d3e"
SIGHTING_ID = "sighting--24e782ea-9847-4cc4-94f9-bce885517e6f"
IDENTITY_ID = "identity--380ceff0-1518-456f-9974-3d047bf51fbc"
BUNDLE_ID = "bundle--3f9a6b0e-2222-4a11-9a11-9a119a119a11"

INDICATOR_PATTERN = "[ipv4-addr:value = '203.0.113.10']"

_INDICATOR = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": INDICATOR_ID,
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "Malicious IP",
    "indicator_types": ["malicious-activity"],
    "pattern": INDICATOR_PATTERN,
    "pattern_type": "stix",
    "valid_from": "2024-01-01T00:00:00Z",
}

_MALWARE = {
    "type": "malware",
    "spec_version": "2.1",
    "id": MALWARE_ID,
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "Emotet",
    "is_family": True,
    "malware_types": ["trojan"],
}

_THREAT_ACTOR = {
    "type": "threat-actor",
    "spec_version": "2.1",
    "id": THREAT_ACTOR_ID,
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "APT-Test",
    "threat_actor_types": ["nation-state"],
}

_ATTACK_PATTERN = {
    "type": "attack-pattern",
    "spec_version": "2.1",
    "id": ATTACK_PATTERN_ID,
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "Spearphishing",
    "kill_chain_phases": [
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "initial-access"},
    ],
}

_REL_INDICATES = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": REL_INDICATES_ID,
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "relationship_type": "indicates",
    "source_ref": INDICATOR_ID,
    "target_ref": MALWARE_ID,
}

_REL_ATTRIBUTED = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": REL_ATTRIBUTED_ID,
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "relationship_type": "attributed-to",
    "source_ref": MALWARE_ID,
    "target_ref": THREAT_ACTOR_ID,
}

_IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": IDENTITY_ID,
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "Test Org SOC",
    "identity_class": "organization",
}

_SIGHTING = {
    "type": "sighting",
    "spec_version": "2.1",
    "id": SIGHTING_ID,
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "sighting_of_ref": INDICATOR_ID,
    # where_sighted_refs is restricted BY THE SPEC to identity/location
    # objects only (not an arbitrary SDO) -- confirmed the hard way when an
    # earlier draft of this fixture pointed it at a threat-actor and the
    # vendored stix2 library correctly rejected it.
    "where_sighted_refs": [IDENTITY_ID],
}

_ALL_OBJECTS = [
    _INDICATOR,
    _MALWARE,
    _THREAT_ACTOR,
    _ATTACK_PATTERN,
    _IDENTITY,
    _REL_INDICATES,
    _REL_ATTRIBUTED,
    _SIGHTING,
]

_BUNDLE = {
    "type": "bundle",
    "id": BUNDLE_ID,
    "objects": _ALL_OBJECTS,
}

BUNDLE_JSON = json.dumps(_BUNDLE)
INDICATOR_JSON = json.dumps(_INDICATOR)
MALWARE_JSON = json.dumps(_MALWARE)

NOT_JSON = "{not valid json at all"
MISSING_TYPE_JSON = json.dumps({"id": "indicator--0510477a-a878-4f62-a21f-6016898133dc"})

CUSTOM_SDO_ID = "x-acme-custom-thing--9c3b8f1e-2b4a-4d90-9d0e-4a1b2c3d4e5f"
_CUSTOM_SDO = {
    "type": "x-acme-custom-thing",
    "spec_version": "2.1",
    "id": CUSTOM_SDO_ID,
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "Vendor Extension Object",
    "acme_severity": "high",
}
CUSTOM_SDO_JSON = json.dumps(_CUSTOM_SDO)

# A realistic real-world bundle: the standard fixture PLUS one vendor-custom
# SDO type ("x-"-prefixed per STIX 2.1 naming convention for custom objects)
# -- exercises that ParseBundle/FilterObjectsByType/ResolveRelationships
# never choke on an unrecognized-but-legal object type.
BUNDLE_WITH_CUSTOM_JSON = json.dumps({**_BUNDLE, "objects": _ALL_OBJECTS + [_CUSTOM_SDO]})
MISSING_REQUIRED_PROP_JSON = json.dumps(
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": INDICATOR_ID,
        "created": "2024-01-01T00:00:00.000Z",
        "modified": "2024-01-01T00:00:00.000Z",
        # 'pattern' and 'valid_from' deliberately omitted -- both required
        "name": "Missing required props",
    }
)

_STIX_ID_RE = re.compile(r"^[a-z][a-z0-9-]*--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def assert_valid_stix_id(id_str, expected_type=None):
    """Independent oracle: verify `id_str` matches the STIX 2.1
    "<type>--<UUID>" identifier shape using a plain regex, WITHOUT calling
    back into stix2's own id validator.
    """
    assert _STIX_ID_RE.match(id_str), f"{id_str!r} is not a valid STIX id shape"
    if expected_type is not None:
        assert id_str.startswith(expected_type + "--"), f"{id_str!r} does not have type prefix {expected_type!r}"


def independent_object_count(bundle_json):
    """Independent oracle: count top-level objects in a bundle via plain
    `json.loads`, bypassing stix2 entirely.
    """
    return len(json.loads(bundle_json)["objects"])


def independent_type_counts(bundle_json):
    """Independent oracle: count objects per STIX type via plain
    `json.loads`, bypassing stix2 entirely.
    """
    counts = {}
    for obj in json.loads(bundle_json)["objects"]:
        counts[obj["type"]] = counts.get(obj["type"], 0) + 1
    return counts


class StixTestContext:
    """Minimal AxiomContext implementation shared by every node test."""

    class _Logger:
        def debug(self, msg: str, **attrs) -> None: pass
        def info(self, msg: str, **attrs) -> None: pass
        def warn(self, msg: str, **attrs) -> None: pass
        def error(self, msg: str, **attrs) -> None: pass

    class _Secrets:
        def __init__(self, m: dict, revoked: set) -> None:
            self._m = m or {}
            self._revoked = revoked or set()

        def get(self, name: str):
            v = self._m.get(name)
            return (v, True) if v is not None else ("", False)

        def status(self, name: str):
            from gen.axiom_context import SecretStatus
            if name in self._m:
                return SecretStatus.AVAILABLE
            if name in self._revoked:
                return SecretStatus.REVOKED
            return SecretStatus.UNSET

    def __init__(self, secrets_map: dict = None, revoked_names: set = None) -> None:
        self.log = self._Logger()
        self.secrets = self._Secrets(secrets_map or {}, revoked_names)
        self.execution_id = "test-execution-id"
        self.flow_id = "test-flow-id"
        self.tenant_id = "test-tenant-id"
