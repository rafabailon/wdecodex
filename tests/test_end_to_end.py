"""End-to-end tests over the bundled sample logs."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import pytest

from wdecodex import generate

FIXTURES = ("text", "syslog", "access", "json", "kv")


@pytest.mark.parametrize("fixture", FIXTURES)
def test_generate_produces_valid_artifacts(read_fixture, fixture):
    artifacts = generate(read_fixture(f"{fixture}.log"), name="myapp")

    decoder_root = ET.fromstring(artifacts.decoder_xml)
    rules_root = ET.fromstring(artifacts.rules_xml)

    assert decoder_root.tag == "decoder"
    assert decoder_root.attrib["name"] == "myapp"
    assert rules_root.tag == "group"
    assert rules_root.attrib["name"] == "myapp,"
    assert artifacts.analysis.total_lines > 0


@pytest.mark.parametrize("fixture", FIXTURES)
def test_generated_decoder_matches_its_sample(read_fixture, fixture):
    artifacts = generate(read_fixture(f"{fixture}.log"), name="myapp")
    analysis = artifacts.analysis

    if analysis.regex is None:
        assert "JSON_Decoder" in artifacts.decoder_xml
        return
    compiled = re.compile(analysis.regex)
    assert all(compiled.fullmatch(line) for line in analysis.sample_lines)


@pytest.mark.parametrize("fixture", FIXTURES)
def test_rules_are_unique_and_connected(read_fixture, fixture):
    artifacts = generate(read_fixture(f"{fixture}.log"), name="myapp")
    rules = ET.fromstring(artifacts.rules_xml).findall("rule")
    ids = [int(rule.attrib["id"]) for rule in rules]

    assert len(ids) == len(set(ids))
    assert ids == list(range(ids[0], ids[0] + len(ids)))
    known = set(ids)
    for rule in rules:
        if_sid = rule.findtext("if_sid")
        if if_sid:
            for reference in if_sid.split(","):
                assert int(reference.strip()) in known


def test_custom_name_is_used_everywhere(read_fixture):
    artifacts = generate(read_fixture("text.log"), name="orders-api")

    assert 'name="orders-api"' in artifacts.decoder_xml
    assert 'name="orders-api,"' in artifacts.rules_xml
    assert "<decoded_as>orders-api</decoded_as>" in artifacts.rules_xml


def test_custom_base_rule_id(read_fixture):
    artifacts = generate(read_fixture("text.log"), name="app", base_rule_id=110500)
    rules = ET.fromstring(artifacts.rules_xml).findall("rule")

    assert rules[0].attrib["id"] == "110500"
