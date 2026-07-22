from gen.messages_pb2 import BuildBundleInput, StixObjectResult
from nodes.build_bundle import build_bundle
from nodes._test_fixtures import (
    INDICATOR_JSON,
    MALWARE_JSON,
    NOT_JSON,
    CUSTOM_SDO_JSON,
    CUSTOM_SDO_ID,
    INDICATOR_ID,
    MALWARE_ID,
    assert_valid_stix_id,
    StixTestContext,
)
import json


def test_build_bundle_golden():
    ax = StixTestContext()
    result = build_bundle(ax, BuildBundleInput(objects_json=[INDICATOR_JSON, MALWARE_JSON]))
    assert isinstance(result, StixObjectResult)
    assert result.ok is True
    assert result.object.type == "bundle"
    assert_valid_stix_id(result.object.id, "bundle")

    # Independent oracle: re-parse the bundle's own raw_json with plain
    # json.loads (bypassing stix2) and confirm both input objects made it in
    # byte-identically (same ids), i.e. the library didn't drop/alter them.
    as_dict = json.loads(result.object.raw_json)
    assert len(as_dict["objects"]) == 2
    ids = {o["id"] for o in as_dict["objects"]}
    assert ids == {INDICATOR_ID, MALWARE_ID}


def test_build_bundle_id_override():
    ax = StixTestContext()
    fixed_id = "bundle--22222222-2222-4222-8222-222222222222"
    result = build_bundle(ax, BuildBundleInput(objects_json=[INDICATOR_JSON], id=fixed_id))
    assert result.ok is True
    assert result.object.id == fixed_id


def test_build_bundle_empty_list_returns_error():
    ax = StixTestContext()
    result = build_bundle(ax, BuildBundleInput(objects_json=[]))
    assert result.ok is False
    assert result.error != ""


def test_build_bundle_invalid_entry_names_its_index():
    ax = StixTestContext()
    result = build_bundle(ax, BuildBundleInput(objects_json=[INDICATOR_JSON, NOT_JSON]))
    assert result.ok is False
    assert "objects_json[1]" in result.error


def test_build_bundle_over_object_cap_returns_error():
    ax = StixTestContext()
    result = build_bundle(ax, BuildBundleInput(objects_json=[INDICATOR_JSON] * 2001))
    assert result.ok is False
    assert "cap" in result.error


def test_build_bundle_tolerates_unrecognized_custom_object_type():
    # Regression: found in a second independent review pass -- BuildBundle
    # parsed each entry with allow_custom=True (fine) but then re-validated
    # the ASSEMBLED Bundle at the library's own default strictness
    # (allow_custom=False), silently re-rejecting the very custom object
    # that had just been accepted one line earlier. This matters because
    # ParseBundle/FilterObjectsByType now legitimately emit custom-typed
    # StixObjects (see their own tests), and this package's own docs say a
    # Build* node's object.raw_json can be fed straight into
    # BuildBundle.objects_json.
    ax = StixTestContext()
    result = build_bundle(ax, BuildBundleInput(objects_json=[INDICATOR_JSON, CUSTOM_SDO_JSON]))
    assert result.ok is True
    as_dict = json.loads(result.object.raw_json)
    ids = {o["id"] for o in as_dict["objects"]}
    assert ids == {INDICATOR_ID, CUSTOM_SDO_ID}
