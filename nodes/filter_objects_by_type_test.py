from gen.messages_pb2 import FilterInput, FilterResult
from nodes.filter_objects_by_type import filter_objects_by_type
from nodes._test_fixtures import BUNDLE_JSON, NOT_JSON, INDICATOR_ID, StixTestContext


def test_filter_objects_by_type_indicator():
    ax = StixTestContext()
    result = filter_objects_by_type(ax, FilterInput(stix_json=BUNDLE_JSON, type_filter="indicator"))
    assert isinstance(result, FilterResult)
    assert result.ok is True
    assert result.matched_count == 1
    assert result.objects[0].id == INDICATOR_ID
    assert result.objects[0].type == "indicator"


def test_filter_objects_by_type_relationship_matches_two():
    ax = StixTestContext()
    result = filter_objects_by_type(ax, FilterInput(stix_json=BUNDLE_JSON, type_filter="relationship"))
    assert result.ok is True
    assert result.matched_count == 2
    assert all(o.type == "relationship" for o in result.objects)


def test_filter_objects_by_type_case_insensitive():
    ax = StixTestContext()
    result = filter_objects_by_type(ax, FilterInput(stix_json=BUNDLE_JSON, type_filter="INDICATOR"))
    assert result.matched_count == 1


def test_filter_objects_by_type_all_returns_every_object():
    ax = StixTestContext()
    result = filter_objects_by_type(ax, FilterInput(stix_json=BUNDLE_JSON, type_filter="all"))
    assert result.matched_count == 8  # indicator, malware, threat-actor, attack-pattern, identity, 2 relationships, 1 sighting


def test_filter_objects_by_type_empty_filter_returns_every_object():
    ax = StixTestContext()
    result = filter_objects_by_type(ax, FilterInput(stix_json=BUNDLE_JSON, type_filter=""))
    assert result.matched_count == 8


def test_filter_objects_by_type_no_match_is_not_an_error():
    ax = StixTestContext()
    result = filter_objects_by_type(ax, FilterInput(stix_json=BUNDLE_JSON, type_filter="campaign"))
    assert result.ok is True
    assert result.error == ""
    assert result.matched_count == 0


def test_filter_objects_by_type_malformed_returns_error_not_crash():
    ax = StixTestContext()
    result = filter_objects_by_type(ax, FilterInput(stix_json=NOT_JSON, type_filter="indicator"))
    assert result.ok is False
    assert result.error != ""
