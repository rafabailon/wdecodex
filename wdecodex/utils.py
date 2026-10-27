"""Small helpers used across WDecodex."""

from __future__ import annotations

import re
from pathlib import Path
from xml.sax.saxutils import escape

from .errors import GenerationError, InputError

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_SAFE_NAME_RE = re.compile(r"[^a-z0-9]+")
_SAFE_FIELD_RE = re.compile(r"[^a-z0-9_]+")


def strip_ansi(text: str) -> str:
    """Remove common ANSI terminal escape sequences from a log line."""

    return _ANSI_RE.sub("", text)


def sanitize_name(value: str) -> str:
    """Create a Wazuh friendly decoder and group name from user input."""

    candidate = _SAFE_NAME_RE.sub("-", value.strip().lower()).strip("-")
    if not candidate:
        return "custom"
    if candidate[0].isdigit():
        candidate = f"app-{candidate}"
    return candidate[:64]


def sanitize_field_name(value: str) -> str:
    """Create a valid dynamic field name from a log key."""

    candidate = _SAFE_FIELD_RE.sub("_", value.strip().lower()).strip("_")
    if not candidate:
        return "field"
    if candidate[0].isdigit():
        candidate = f"field_{candidate}"
    return candidate[:64]


def unique_name(name: str, used: set[str]) -> str:
    """Return a unique name by adding a numeric suffix when required."""

    if name not in used:
        used.add(name)
        return name
    index = 2
    while f"{name}_{index}" in used:
        index += 1
    result = f"{name}_{index}"
    used.add(result)
    return result


def xml_text(value: str) -> str:
    """Escape text for use inside an XML element."""

    return escape(value)


def xml_attr(value: str) -> str:
    """Escape text for use inside a double quoted XML attribute."""

    return escape(value, {'"': "&quot;"})


def regex_literal(value: str) -> str:
    """Escape a literal and make whitespace runs flexible."""

    escaped = re.escape(value)
    return escaped.replace(r"\ ", r"\s+")


def read_log(path: str) -> str:
    """Read a log file, using standard input when path is a dash."""

    if path == "-":
        import sys

        return sys.stdin.read()

    candidate = Path(path)
    if not candidate.exists():
        raise InputError(f"input file does not exist: {path}")
    if not candidate.is_file():
        raise InputError(f"input path is not a regular file: {path}")
    try:
        return candidate.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise InputError(f"cannot read input file {path}: {exc}") from exc


def default_name(path: str) -> str:
    """Derive a decoder name from an input path."""

    if path == "-":
        return "custom"
    return sanitize_name(Path(path).stem)


def common_literal_prefix(lines: tuple[str, ...]) -> str:
    """Find a useful literal prefix shared by all sample lines."""

    if not lines:
        return ""
    prefix = lines[0]
    for line in lines[1:]:
        limit = min(len(prefix), len(line))
        index = 0
        while index < limit and prefix[index] == line[index]:
            index += 1
        prefix = prefix[:index]
        if not prefix:
            break
    prefix = prefix.strip()
    if " " in prefix:
        prefix = prefix.rsplit(" ", 1)[0].strip()
    return prefix if len(prefix) >= 4 else ""


def validate_rule_id(base_rule_id: int, rule_count: int) -> None:
    """Validate the custom rule ID range used by Wazuh."""

    if base_rule_id < 100000 or base_rule_id > 120000:
        raise GenerationError("base rule id must be between 100000 and 120000")
    if base_rule_id + rule_count - 1 > 120000:
        raise GenerationError(
            "the generated rules would exceed the Wazuh custom rule range 100000-120000"
        )


def validate_positive_int(value: int, label: str) -> None:
    """Reject non-positive numeric command line values."""

    if value <= 0:
        raise GenerationError(f"{label} must be greater than zero")
