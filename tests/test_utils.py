"""Tests for shared helpers."""

from __future__ import annotations

import pytest

from wdecodex.errors import GenerationError, InputError
from wdecodex.utils import (
    common_literal_prefix,
    default_name,
    read_log,
    regex_literal,
    sanitize_field_name,
    sanitize_name,
    unique_name,
    validate_positive_int,
    validate_rule_id,
    xml_attr,
    xml_text,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("My App", "my-app"),
        ("Payment API", "payment-api"),
        ("  Weird__Name!!  ", "weird-name"),
        ("123app", "app-123app"),
        ("", "custom"),
        ("!!!", "custom"),
    ],
)
def test_sanitize_name(value, expected):
    assert sanitize_name(value) == expected


def test_sanitize_name_truncates_long_values():
    assert len(sanitize_name("a" * 100)) == 64


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Source IP", "source_ip"),
        ("user.name", "user_name"),
        ("123", "field_123"),
        ("!!!", "field"),
    ],
)
def test_sanitize_field_name(value, expected):
    assert sanitize_field_name(value) == expected


def test_unique_name():
    used = {"level"}
    assert unique_name("level", used) == "level_2"
    assert unique_name("level", used) == "level_3"
    assert used == {"level", "level_2", "level_3"}


def test_xml_escaping():
    assert xml_text("a & b < c > d") == "a &amp; b &lt; c &gt; d"
    assert xml_attr('a "b" & c') == "a &quot;b&quot; &amp; c"


def test_regex_literal_makes_spaces_flexible():
    assert regex_literal("two words") == r"two\s+words"


def test_common_literal_prefix():
    lines = ("myapp started ok", "myapp stopped now", "other value")
    assert common_literal_prefix(lines) == ""


def test_common_literal_prefix_keeps_full_words():
    lines = ("myapp: started", "myapp: stopped")
    assert common_literal_prefix(lines) == "myapp:"


def test_default_name_for_file(tmp_path):
    assert default_name(str(tmp_path / "My App.log")) == "my-app"
    assert default_name("-") == "custom"


def test_read_log_from_file(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("INFO one\n", encoding="utf-8")
    assert read_log(str(path)) == "INFO one\n"


def test_read_log_missing_file(tmp_path):
    with pytest.raises(InputError):
        read_log(str(tmp_path / "missing.log"))


def test_read_log_directory(tmp_path):
    with pytest.raises(InputError):
        read_log(str(tmp_path))


def test_validate_rule_id():
    validate_rule_id(100000, 5)
    validate_rule_id(120000, 1)
    with pytest.raises(GenerationError):
        validate_rule_id(99999, 1)
    with pytest.raises(GenerationError):
        validate_rule_id(120001, 1)
    with pytest.raises(GenerationError):
        validate_rule_id(120000, 2)


def test_validate_positive_int():
    validate_positive_int(1, "value")
    with pytest.raises(GenerationError):
        validate_positive_int(0, "value")
