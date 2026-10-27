"""Tests for Wazuh decoder and rule XML generation."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import replace

import pytest

from wdecodex.analyzer import analyze_lines
from wdecodex.errors import GenerationError
from wdecodex.generators import (
    build_decoder,
    build_rules,
    generate_decoder_xml,
    generate_rules_xml,
    render_rules_xml,
)


def _analysis(fixture: str, read_fixture, name: str = "myapp"):
    lines = read_fixture(f"{fixture}.log").splitlines()
    return analyze_lines(lines, name=name)


def test_decoder_xml_is_valid(read_fixture):
    analysis = _analysis("text", read_fixture)
    decoder_xml = generate_decoder_xml(analysis)
    root = ET.fromstring(decoder_xml)

    assert root.tag == "decoder"
    assert root.attrib["name"] == "myapp"
    assert root.findtext("prematch") == analysis.regex
    assert root.findtext("regex") == analysis.regex
    assert root.findtext("order") == "log_timestamp, level, component, message"


def test_program_name_is_used_for_syslog(read_fixture):
    analysis = _analysis("syslog", read_fixture, name="payment")
    decoder = build_decoder(analysis)

    assert decoder.program_name == "payment-api"
    assert decoder.prematch is None
    root = ET.fromstring(generate_decoder_xml(analysis))
    assert root.findtext("program_name") == "^payment-api$"


def test_json_decoder_uses_plugin(read_fixture):
    analysis = _analysis("json", read_fixture)
    decoder = build_decoder(analysis)

    assert decoder.plugin_decoder == "JSON_Decoder"
    assert decoder.regex is None
    assert decoder.order == ()
    root = ET.fromstring(generate_decoder_xml(analysis))
    assert root.findtext("plugin_decoder") == "JSON_Decoder"
    assert root.findtext("prematch") == r"^\{"


def test_decoder_xml_escapes_regex_characters():
    analysis = analyze_lines(
        ["<svc>&api first", "<svc>&api second"],
        name="brackets",
    )
    decoder_xml = generate_decoder_xml(analysis)
    root = ET.fromstring(decoder_xml)

    assert "&lt;" in decoder_xml
    assert "&amp;" in decoder_xml
    assert root.findtext("prematch") == analysis.prematch
    assert root.findtext("regex") == analysis.regex


def test_rules_xml_escapes_descriptions(read_fixture):
    analysis = _analysis("text", read_fixture)
    rules = build_rules(analysis)
    altered = (replace(rules[0], description="a & b < c"),)
    rules_xml = render_rules_xml(altered, "demo")
    root = ET.fromstring(rules_xml)

    assert root.findtext("rule/description") == "a & b < c"
    assert "&amp;" in rules_xml


def test_rules_xml_is_valid_and_grouped(read_fixture):
    analysis = _analysis("text", read_fixture)
    rules = build_rules(analysis)
    rules_xml = generate_rules_xml(analysis)
    root = ET.fromstring(rules_xml)

    assert root.tag == "group"
    assert root.attrib["name"] == "myapp,"
    assert len(root.findall("rule")) == len(rules)


def test_rule_ids_are_sequential(read_fixture):
    analysis = _analysis("text", read_fixture)
    rules = build_rules(analysis, base_rule_id=100100)

    assert [rule.id for rule in rules] == list(range(100100, 100100 + len(rules)))


def test_base_rule_uses_decoded_as(read_fixture):
    analysis = _analysis("text", read_fixture)
    rules = build_rules(analysis)

    assert rules[0].id == 100000
    assert rules[0].level == 0
    assert rules[0].decoded_as == "myapp"


def test_text_rules_use_level_field(read_fixture):
    analysis = _analysis("text", read_fixture)
    rules = build_rules(analysis)
    level_rules = [rule for rule in rules if rule.field_name == "level"]

    assert len(level_rules) == 4
    assert {rule.level for rule in level_rules} == {3, 5, 7, 12}
    assert all(rule.if_sid == (100000,) for rule in level_rules)


def test_rules_without_level_field_use_match():
    analysis = analyze_lines(
        ["plain message one", "plain message two"],
        name="plain",
    )
    rules = build_rules(analysis)

    assert analysis.level_field is None
    assert any(rule.match for rule in rules if rule.if_sid)


def test_json_rules_include_native_json_base(read_fixture):
    analysis = _analysis("json", read_fixture)
    rules = build_rules(analysis)

    assert rules[0].decoded_as == "myapp"
    assert rules[1].decoded_as == "json"
    severity_rules = [rule for rule in rules if rule.if_sid]
    assert all(rule.if_sid == (100000, 100001) for rule in severity_rules)


def test_numeric_levels_use_numeric_ranges():
    analysis = analyze_lines(
        [
            '{"severity": 2, "message": "one"}',
            '{"severity": 5, "message": "two"}',
            '{"severity": 9, "message": "three"}',
        ],
        name="numeric",
    )
    rules = build_rules(analysis)
    severity_rules = [rule for rule in rules if rule.field_name == "severity"]

    assert analysis.level_numeric is True
    assert len(severity_rules) == 4
    assert any("0-3" in rule.field_regex for rule in severity_rules)
    assert any("9" in rule.field_regex for rule in severity_rules)


def test_access_rules_use_status_field(read_fixture):
    analysis = _analysis("access", read_fixture)
    rules = build_rules(analysis)
    status_rules = [rule for rule in rules if rule.field_name == "status"]

    assert len(status_rules) == 3
    assert {rule.level for rule in status_rules} == {5, 7, 8}
    assert any(rule.field_regex == r"^(?:401|403)$" for rule in status_rules)
    assert status_rules[0].field_regex == r"^(?:401|403)$"


def test_failure_rule_precedes_severity_rules(read_fixture):
    analysis = _analysis("text", read_fixture)
    rules = build_rules(analysis)
    conditional = [rule for rule in rules if rule.if_sid]

    assert conditional[0].level == 8
    assert "failure" in conditional[0].description


def test_custom_base_rule_id(read_fixture):
    analysis = _analysis("text", read_fixture)
    rules = build_rules(analysis, base_rule_id=110000)

    assert rules[0].id == 110000


def test_invalid_base_rule_id_is_rejected(read_fixture):
    analysis = _analysis("text", read_fixture)
    with pytest.raises(GenerationError):
        build_rules(analysis, base_rule_id=99999)
    with pytest.raises(GenerationError):
        build_rules(analysis, base_rule_id=120001)


def test_rule_range_overflow_is_rejected():
    analysis = analyze_lines(
        [
            '{"level": "INFO", "message": "one"}',
            '{"level": "ERROR", "message": "two"}',
        ],
        name="overflow",
    )
    with pytest.raises(GenerationError):
        build_rules(analysis, base_rule_id=119999)


def test_rules_reference_existing_base_ids(read_fixture):
    for fixture in ("text", "syslog", "access", "json", "kv"):
        analysis = _analysis(fixture, read_fixture)
        rules = build_rules(analysis)
        ids = {rule.id for rule in rules}
        for rule in rules:
            assert all(reference in ids for reference in rule.if_sid)


def test_rule_descriptions_include_app_name(read_fixture):
    analysis = _analysis("text", read_fixture, name="orders")
    rules = build_rules(analysis)

    assert all(rule.description.startswith("orders:") for rule in rules)
