"""Tests for log format detection and decoder inference."""

from __future__ import annotations

import re

import pytest

from wdecodex.analyzer import analyze_lines
from wdecodex.errors import AnalysisError, GenerationError

FIXTURE_NAMES = ("text", "syslog", "access", "json", "kv")


def test_detects_json_logs(read_fixture):
    analysis = analyze_lines(read_fixture("json.log").splitlines(), name="myapp")

    assert analysis.log_format == "json"
    assert analysis.level_field == "level"
    assert analysis.message_field == "message"
    assert analysis.level_numeric is False
    assert analysis.regex is None
    assert analysis.prematch == r"^\{"


def test_detects_nested_numeric_json_level():
    lines = [
        '{"alert": {"severity": 8}, "message": "blocked"}',
        '{"alert": {"severity": 10}, "message": "dropped"}',
        '{"alert": {"severity": 2}, "message": "allowed"}',
    ]

    analysis = analyze_lines(lines, name="suricata")

    assert analysis.log_format == "json"
    assert analysis.level_field == "alert.severity"
    assert analysis.level_numeric is True


def test_json_without_level_has_no_level_field():
    lines = [
        '{"message": "one", "service": "demo"}',
        '{"message": "two", "service": "demo"}',
    ]

    analysis = analyze_lines(lines, name="demo")

    assert analysis.log_format == "json"
    assert analysis.level_field is None
    assert analysis.message_field == "message"


def test_detects_access_logs(read_fixture):
    analysis = analyze_lines(read_fixture("access.log").splitlines(), name="web")

    assert analysis.log_format == "access"
    assert analysis.order[:6] == (
        "srcip",
        "srcuser",
        "log_timestamp",
        "method",
        "url",
        "status",
    )
    assert analysis.regex is not None
    assert re.compile(analysis.regex).groups == len(analysis.order)


def test_partial_access_sample_keeps_access_decoder(read_fixture):
    lines = [*read_fixture("access.log").splitlines()[:4], "server starting"]
    analysis = analyze_lines(lines, name="web")

    assert analysis.log_format == "access"
    assert analysis.regex is not None
    assert re.compile(analysis.regex).fullmatch(lines[0])
    assert not re.compile(analysis.regex).fullmatch(lines[-1])
    assert any("4 of 5 sampled lines" in note for note in analysis.notes)


def test_detects_key_value_logs(read_fixture):
    analysis = analyze_lines(read_fixture("kv.log").splitlines(), name="payments")

    assert analysis.log_format == "kv"
    assert analysis.level_field == "level"
    assert analysis.message_field == "message"
    assert "log_timestamp" in analysis.order
    assert "time" not in analysis.order
    assert "dstuser" in analysis.order
    assert analysis.regex is not None
    assert re.compile(analysis.regex).groups == len(analysis.order)


def test_detects_structured_text_logs(read_fixture):
    analysis = analyze_lines(read_fixture("text.log").splitlines(), name="app")

    assert analysis.log_format == "text"
    assert analysis.order == ("log_timestamp", "level", "component", "message")
    assert analysis.level_field == "level"
    assert analysis.message_field == "message"
    assert analysis.program_name is None
    assert analysis.regex is not None
    compiled = re.compile(analysis.regex)
    assert compiled.groups == len(analysis.order)
    assert all(compiled.fullmatch(line) for line in read_fixture("text.log").splitlines())


def test_syslog_header_is_removed_and_program_is_kept(read_fixture):
    lines = read_fixture("syslog.log").splitlines()
    analysis = analyze_lines(lines, name="payment")

    assert analysis.log_format == "text"
    assert analysis.program_name == "payment-api"
    assert analysis.order == ("level", "message")
    assert analysis.prematch is None
    assert analysis.regex is not None
    assert all(
        re.compile(analysis.regex).fullmatch(line)
        for line in (
            "INFO User alice logged in",
            "WARN Failed login attempt for bob",
            "ERROR Database connection failed",
            "INFO Health check completed",
        )
    )


def test_free_text_falls_back_to_message_field():
    lines = (
        "first free text message from the service",
        "second free text message from the service",
    )

    analysis = analyze_lines(lines, name="free")

    assert analysis.log_format == "text"
    assert analysis.order == ("message",)
    assert analysis.regex == r"^(.*)$"
    assert analysis.prematch is not None
    assert re.compile(analysis.regex).fullmatch(lines[0])


def test_ansi_escape_sequences_are_removed():
    lines = ["\x1b[31m2026-10-25 10:00:01 ERROR failed request\x1b[0m"]

    analysis = analyze_lines(lines, name="ansi")

    assert "\x1b" not in analysis.sample_lines[0]
    assert analysis.level_field == "level"


def test_empty_input_is_rejected():
    with pytest.raises(AnalysisError):
        analyze_lines(["", "   "], name="empty")


def test_max_lines_limits_the_sample():
    lines = [f"INFO event number {index}" for index in range(10)]

    analysis = analyze_lines(lines, name="limited", max_lines=3)

    assert analysis.total_lines == 10
    assert len(analysis.sample_lines) == 3


def test_invalid_max_lines_is_rejected():
    with pytest.raises(GenerationError):
        analyze_lines(["INFO one"], name="bad", max_lines=0)


def test_forced_json_rejects_text():
    with pytest.raises(AnalysisError):
        analyze_lines(["not json"], name="bad", log_format="json")


def test_forced_access_rejects_text():
    with pytest.raises(AnalysisError):
        analyze_lines(["not an access log"], name="bad", log_format="access")


def test_forced_kv_rejects_text():
    with pytest.raises(AnalysisError):
        analyze_lines(["not a key value log"], name="bad", log_format="kv")


def test_invalid_format_is_rejected():
    with pytest.raises(AnalysisError):
        analyze_lines(["INFO one"], name="bad", log_format="xml")


def test_name_is_sanitized():
    analysis = analyze_lines(["INFO one"], name="My Cool App!")

    assert analysis.name == "my-cool-app"


@pytest.mark.parametrize("fixture", FIXTURE_NAMES)
def test_regex_group_count_matches_order(read_fixture, fixture):
    analysis = analyze_lines(read_fixture(f"{fixture}.log").splitlines(), name="demo")

    if analysis.regex is None:
        assert analysis.order == ()
        return
    assert re.compile(analysis.regex).groups == len(analysis.order)


@pytest.mark.parametrize("fixture", FIXTURE_NAMES)
def test_generated_regex_matches_sample_lines(read_fixture, fixture):
    analysis = analyze_lines(read_fixture(f"{fixture}.log").splitlines(), name="demo")

    if analysis.regex is None:
        return
    compiled = re.compile(analysis.regex)
    assert all(compiled.fullmatch(line) for line in analysis.sample_lines)
