"""Heuristic analysis of sample logs.

The analyzer is intentionally conservative. It uses only the standard library and
produces a baseline decoder, not a complete parser for every possible log format.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from .errors import AnalysisError
from .models import Analysis, DecodedField, LogFormat
from .utils import (
    common_literal_prefix,
    regex_literal,
    sanitize_field_name,
    sanitize_name,
    strip_ansi,
    unique_name,
    validate_positive_int,
)

LEVEL_WORDS = (
    "trace",
    "debug",
    "info",
    "notice",
    "warn",
    "warning",
    "error",
    "err",
    "crit",
    "critical",
    "alert",
    "emerg",
    "emergency",
    "fatal",
    "panic",
    "verbose",
)
LEVEL_ALT = "|".join(sorted(LEVEL_WORDS, key=len, reverse=True))

ISO_TIMESTAMP = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
CLF_TIMESTAMP = r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?"
DMY_TIMESTAMP = r"\d{2}[-/]\d{2}[-/]\d{4}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
TIME_ONLY = r"\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"

_TIMESTAMP_PATTERNS = (
    (re.compile(rf"^{ISO_TIMESTAMP}"), ISO_TIMESTAMP),
    (re.compile(rf"^{CLF_TIMESTAMP}"), CLF_TIMESTAMP),
    (re.compile(rf"^{DMY_TIMESTAMP}"), DMY_TIMESTAMP),
    (re.compile(rf"^{TIME_ONLY}"), TIME_ONLY),
)

SYSLOG_HEADER_RE = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+"
    r"\d{2}:\d{2}:\d{2}\s+\S+\s+"
    r"(?P<program>[^\s:\[]+)(?:\[\d+\])?:\s?"
)

LEVEL_TOKEN_RE = re.compile(
    rf"(?P<open>[\[<]?)(?P<level>(?i:{LEVEL_ALT}))"
    r"(?![A-Za-z0-9_])(?P<close>[\]>]?)"
)

BRACKET_RE = re.compile(r"^\[([^\]]+)\]")
COMPONENT_RE = re.compile(r"\[([A-Za-z][A-Za-z0-9_.\-]{0,63})\]")
BRACKET_TIMESTAMP_RE = re.compile(r"^\[([^\]]+)\]")

ACCESS_REGEX = (
    r"^(\S+) \S+ (\S+) \[([^\]]+)\] "
    r"\"(\S+) (\S+) [^\"]*\" "
    r"(\d{3}) (\S+)"
    r"(?: \"([^\"]*)\" \"([^\"]*)\")?$"
)
ACCESS_FIELDS = (
    ("srcip", r"(\S+)"),
    ("srcuser", r"(\S+)"),
    ("log_timestamp", r"([^\]]+)"),
    ("method", r"(\S+)"),
    ("url", r"(\S+)"),
    ("status", r"(\d{3})"),
    ("bytes", r"(\S+)"),
    ("referrer", r"([^\"]*)"),
    ("user_agent", r"([^\"]*)"),
)
ACCESS_RE = re.compile(ACCESS_REGEX)

KV_RE = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)="
    r"(?P<value>\"(?:[^\"\\]|\\.)*\"|'[^']*'|[^\s,;]+)"
)

LEVEL_KEY_CANDIDATES = (
    "level",
    "severity",
    "loglevel",
    "log_level",
    "priority",
    "severity_label",
)
MESSAGE_KEY_CANDIDATES = (
    "message",
    "msg",
    "text",
    "event.message",
    "description",
    "log",
)

KV_FIELD_MAP = {
    "time": "log_timestamp",
    "timestamp": "log_timestamp",
    "datetime": "log_timestamp",
    "ts": "log_timestamp",
    "level": "level",
    "severity": "level",
    "loglevel": "level",
    "log_level": "level",
    "priority": "level",
    "message": "message",
    "msg": "message",
    "text": "message",
    "user": "dstuser",
    "username": "dstuser",
    "account": "dstuser",
    "srcuser": "srcuser",
    "source_user": "srcuser",
    "srcip": "srcip",
    "source_ip": "srcip",
    "client_ip": "srcip",
    "remote_addr": "srcip",
    "ip": "srcip",
    "dstip": "dstip",
    "destination_ip": "dstip",
    "dest_ip": "dstip",
    "action": "action",
    "status": "status",
    "result": "status",
    "url": "url",
    "path": "url",
    "request": "url",
    "id": "id",
    "request_id": "id",
    "trace_id": "id",
    "correlation_id": "id",
    "component": "component",
    "logger": "component",
    "module": "component",
    "service": "service",
    "program": "program",
    "app": "program",
}


@dataclass(frozen=True)
class _Candidate:
    regex: str
    fields: tuple[DecodedField, ...]


def _strip_syslog_header(line: str) -> tuple[str, str | None]:
    match = SYSLOG_HEADER_RE.match(line)
    if not match:
        return line, None
    return line[match.end() :], match.group("program")


def _flatten_json(value: object, prefix: str = "") -> list[tuple[str, object]]:
    if not isinstance(value, dict):
        return []
    items: list[tuple[str, object]] = []
    for key, item in value.items():
        path = f"{prefix}{key}"
        if isinstance(item, dict):
            items.extend(_flatten_json(item, f"{path}."))
        else:
            items.append((path, item))
    return items


def _looks_like_timestamp(value: str) -> bool:
    if not re.search(r"\d", value):
        return False
    return bool(
        re.search(r"\d{1,2}:\d{2}:\d{2}", value) or re.search(r"\d{4}[-/]\d{2}[-/]\d{2}", value)
    )


def _match_timestamp(line: str, position: int) -> tuple[str, str, int] | None:
    if position == 0 and line.startswith("["):
        bracket = BRACKET_TIMESTAMP_RE.match(line)
        if bracket and _looks_like_timestamp(bracket.group(1)):
            return bracket.group(1), r"\[([^\]]+)\]", bracket.end()

    for pattern, fragment in _TIMESTAMP_PATTERNS:
        match = pattern.match(line, position)
        if match:
            return match.group(0), f"({fragment})", match.end()
    return None


def _match_level(line: str, position: int) -> tuple[str, str, int] | None:
    match = LEVEL_TOKEN_RE.match(line, position)
    if not match:
        return None
    opening = match.group("open")
    closing = match.group("close")
    value = match.group("level")
    fragment = f"((?i:{LEVEL_ALT}))"
    return value, f"{re.escape(opening)}{fragment}{re.escape(closing)}", match.end()


def _match_component(line: str, position: int) -> tuple[str, str, int] | None:
    match = COMPONENT_RE.match(line, position)
    if not match:
        return None
    return match.group(1), r"\[([A-Za-z][A-Za-z0-9_.\-]{0,63})\]", match.end()


def _consume_gap(line: str, position: int) -> tuple[int, bool, str]:
    start = position
    while position < len(line) and line[position].isspace():
        position += 1
    separator = ""
    if position < len(line) and line[position] in ":-|":
        separator = line[position]
        position += 1
        while position < len(line) and line[position].isspace():
            position += 1
    return position, position > start, separator


def _append_gap(parts: list[str], had_space: bool, separator: str) -> None:
    if separator:
        parts.append(f"{re.escape(separator)}\\s*")
    elif had_space:
        parts.append(r"\s+")


def _build_text_candidate(line: str) -> _Candidate | None:
    parts = ["^"]
    fields: list[DecodedField] = []
    position = 0

    timestamp = _match_timestamp(line, position)
    if timestamp:
        sample, fragment, position = timestamp
        parts.append(fragment)
        fields.append(DecodedField("log_timestamp", fragment, sample))
        position, had_space, separator = _consume_gap(line, position)
        _append_gap(parts, had_space, separator)

    level = _match_level(line, position)
    if level:
        sample, fragment, position = level
        parts.append(fragment)
        fields.append(DecodedField("level", fragment, sample))
        position, had_space, separator = _consume_gap(line, position)
        _append_gap(parts, had_space, separator)

    component = _match_component(line, position)
    if component:
        sample, fragment, position = component
        parts.append(fragment)
        fields.append(DecodedField("component", fragment, sample))
        position, had_space, separator = _consume_gap(line, position)
        _append_gap(parts, had_space, separator)
        if not level:
            level = _match_level(line, position)
            if level:
                sample, fragment, position = level
                parts.append(fragment)
                fields.append(DecodedField("level", fragment, sample))
                position, had_space, separator = _consume_gap(line, position)
                _append_gap(parts, had_space, separator)

    if position < len(line):
        parts.append("(.*)$")
        fields.append(DecodedField("message", "(.*)", line[position:]))
    elif fields:
        parts.append("$")
    else:
        parts.append("(.*)$")
        fields.append(DecodedField("message", "(.*)", line))

    regex = "".join(parts)
    try:
        compiled = re.compile(regex)
    except re.error:
        return None
    if compiled.groups != len(fields):
        raise AssertionError("text candidate has a capture group mismatch")
    return _Candidate(regex, tuple(fields))


def _candidate_match_count(candidate: _Candidate, lines: tuple[str, ...]) -> int:
    try:
        compiled = re.compile(candidate.regex)
    except re.error:
        return 0
    if compiled.groups != len(candidate.fields):
        return 0
    return sum(1 for line in lines if compiled.fullmatch(line))


def _choose_text_candidate(lines: tuple[str, ...]) -> _Candidate:
    best: _Candidate | None = None
    best_score = (-1, -1)
    seen: set[str] = set()
    considered = 0
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        considered += 1
        if considered > 30:
            break
        candidate = _build_text_candidate(line)
        if candidate is None:
            continue
        score = (_candidate_match_count(candidate, lines), len(candidate.fields))
        if score > best_score:
            best = candidate
            best_score = score

    if best is not None and best_score[0] == len(lines):
        return best

    # A partially matching decoder is worse than a permissive message decoder.
    fallback = _Candidate(r"^(.*)$", (DecodedField("message", "(.*)", lines[0]),))
    return fallback


def _all_json(lines: tuple[str, ...]) -> bool:
    if not lines:
        return False
    for line in lines:
        try:
            parsed = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return False
        if not isinstance(parsed, dict):
            return False
    return True


def _access_match_ratio(lines: tuple[str, ...]) -> float:
    if not lines:
        return 0.0
    return sum(1 for line in lines if ACCESS_RE.fullmatch(line)) / len(lines)


def _kv_match_ratio(lines: tuple[str, ...]) -> float:
    if not lines:
        return 0.0
    return sum(1 for line in lines if KV_RE.search(line)) / len(lines)


def _detect_format(lines: tuple[str, ...]) -> LogFormat:
    if _all_json(lines):
        return "json"
    if _access_match_ratio(lines) >= 0.8:
        return "access"
    if _kv_match_ratio(lines) >= 0.6:
        return "kv"
    return "text"


def _choose_json_key(
    objects: list[dict[str, object]],
    candidates: tuple[str, ...],
) -> tuple[str | None, list[object]]:
    counts: Counter[str] = Counter()
    values: dict[str, list[object]] = defaultdict(list)
    for item in objects:
        for path, value in _flatten_json(item):
            leaf = path.rsplit(".", 1)[-1].lower()
            lower_path = path.lower()
            if lower_path in candidates or leaf in candidates:
                counts[path] += 1
                values[path].append(value)

    if not counts:
        return None, []

    minimum = max(1, math.ceil(len(objects) * 0.6))

    def rank(path: str) -> tuple[int, int, str]:
        lower_path = path.lower()
        leaf = lower_path.rsplit(".", 1)[-1]
        if lower_path in candidates:
            preference = candidates.index(lower_path)
        elif leaf in candidates:
            preference = candidates.index(leaf) + len(candidates)
        else:
            preference = len(candidates) * 2
        return (-counts[path], preference, path)

    selected = sorted(counts, key=rank)[0]
    if counts[selected] < minimum:
        return None, []
    return selected, values[selected]


def _analyze_json(
    lines: tuple[str, ...],
    name: str,
    program_name: str | None,
    total_lines: int,
    notes: list[str],
) -> Analysis:
    objects: list[dict[str, object]] = []
    for line in lines:
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AnalysisError(f"invalid JSON log line: {exc}") from exc
        if not isinstance(parsed, dict):
            raise AnalysisError("JSON log lines must contain objects")
        objects.append(parsed)

    level_field, level_values = _choose_json_key(objects, LEVEL_KEY_CANDIDATES)
    message_field, _ = _choose_json_key(objects, MESSAGE_KEY_CANDIDATES)
    level_numeric = bool(level_values) and all(
        isinstance(value, (int, float)) and not isinstance(value, bool) for value in level_values
    )

    local_notes = list(notes)
    local_notes.append("JSON objects are decoded with the JSON decoder plugin.")
    if level_field is None:
        local_notes.append("No common severity field was found; severity rules use text matches.")
    elif level_numeric:
        local_notes.append("Numeric severity values use generic ranges in the generated rules.")
    if program_name:
        local_notes.append("A syslog program name was detected and is used as a decoder condition.")

    return Analysis(
        name=name,
        log_format="json",
        prematch=r"^\{" if not program_name else None,
        program_name=program_name,
        level_field=level_field,
        level_numeric=level_numeric,
        message_field=message_field,
        sample_lines=lines,
        total_lines=total_lines,
        notes=tuple(local_notes),
    )


def _analyze_access(
    lines: tuple[str, ...],
    name: str,
    program_name: str | None,
    total_lines: int,
    notes: list[str],
) -> Analysis | None:
    matches = [ACCESS_RE.fullmatch(line) for line in lines]
    matched = sum(1 for match in matches if match is not None)
    if matched / len(lines) < 0.8:
        return None

    first = next(match for match in matches if match is not None)
    fields = tuple(
        DecodedField(field, pattern, first.group(index + 1) or "")
        for index, (field, pattern) in enumerate(ACCESS_FIELDS)
    )
    local_notes = list(notes)
    local_notes.append("Combined or common web access log format detected.")
    if matched < len(lines):
        local_notes.append(
            f"{matched} of {len(lines)} sampled lines matched the access log format."
        )
    return Analysis(
        name=name,
        log_format="access",
        fields=fields,
        regex=ACCESS_REGEX,
        prematch=ACCESS_REGEX if not program_name else None,
        program_name=program_name,
        sample_lines=lines,
        total_lines=total_lines,
        notes=tuple(local_notes),
    )


def _select_kv_keys(matches: list[list[re.Match[str]]], line_count: int) -> list[str]:
    counts: Counter[str] = Counter()
    first_seen: dict[str, int] = {}
    index = 0
    for line_matches in matches:
        seen_in_line: set[str] = set()
        for match in line_matches:
            key = match.group("key")
            if key in seen_in_line:
                continue
            seen_in_line.add(key)
            counts[key] += 1
            first_seen.setdefault(key, index)
            index += 1

    minimum = max(1, math.ceil(line_count * 0.6))
    eligible = [key for key, count in counts.items() if count >= minimum]
    if not eligible:
        return []
    eligible.sort(key=lambda key: (-counts[key], first_seen[key]))
    eligible = eligible[:12]
    eligible.sort(key=first_seen.__getitem__)
    return eligible


def _kv_value_pattern(samples: list[str]) -> tuple[str, bool]:
    if samples and all(value.startswith('"') and value.endswith('"') for value in samples):
        return r'"([^"]*)"', True
    if samples and all(value.startswith("'") and value.endswith("'") for value in samples):
        return r"'([^']*)'", True
    return r"([^\s,;]+)", False


def _clean_kv_sample(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _analyze_kv(
    lines: tuple[str, ...],
    name: str,
    program_name: str | None,
    total_lines: int,
    notes: list[str],
) -> Analysis | None:
    matches = [list(KV_RE.finditer(line)) for line in lines]
    if not any(matches):
        return None

    keys = _select_kv_keys(matches, len(lines))
    if not keys:
        return None

    values_by_key: dict[str, list[str]] = defaultdict(list)
    for line_matches in matches:
        for match in line_matches:
            values_by_key[match.group("key")].append(match.group("value"))

    used_fields: set[str] = set()
    field_names: dict[str, str] = {}
    fields: list[DecodedField] = []
    parts = ["^"]

    for key in keys:
        mapped = KV_FIELD_MAP.get(key.lower(), sanitize_field_name(key))
        mapped = unique_name(mapped, used_fields)
        field_names[key] = mapped
        value_pattern, _ = _kv_value_pattern(values_by_key[key])
        samples = [_clean_kv_sample(value) for value in values_by_key[key]]
        fields.append(DecodedField(mapped, value_pattern, samples[0] if samples else ""))
        segment = rf".*?\b{re.escape(key)}={value_pattern}"
        frequency = sum(
            1
            for line_matches in matches
            if any(match.group("key") == key for match in line_matches)
        )
        parts.append(f"(?:{segment})?" if frequency < len(lines) else segment)

    parts.append(".*$")
    regex = "".join(parts)
    try:
        compiled = re.compile(regex)
    except re.error:
        return None
    if compiled.groups != len(fields):
        return None
    if sum(1 for line in lines if compiled.fullmatch(line)) < len(lines) * 0.8:
        return None

    level_field = None
    message_field = None
    for key, mapped in field_names.items():
        if level_field is None and key.lower() in {
            "level",
            "severity",
            "loglevel",
            "log_level",
            "priority",
        }:
            level_field = mapped
        if message_field is None and key.lower() in {"message", "msg", "text"}:
            message_field = mapped

    local_notes = list(notes)
    local_notes.append("Key-value fields were detected and mapped to Wazuh field names.")
    return Analysis(
        name=name,
        log_format="kv",
        fields=tuple(fields),
        regex=regex,
        prematch=regex if not program_name else None,
        program_name=program_name,
        level_field=level_field,
        message_field=message_field,
        sample_lines=lines,
        total_lines=total_lines,
        notes=tuple(local_notes),
    )


def _analyze_text(
    lines: tuple[str, ...],
    name: str,
    program_name: str | None,
    total_lines: int,
    notes: list[str],
) -> Analysis:
    candidate = _choose_text_candidate(lines)
    fields = list(candidate.fields)
    level_field = "level" if any(field.name == "level" for field in fields) else None
    message_field = "message" if any(field.name == "message" for field in fields) else None

    if candidate.regex == r"^(.*)$":
        prefix = common_literal_prefix(lines)
        prematch = f"^{regex_literal(prefix)}" if prefix else "^"
        local_notes = list(notes)
        local_notes.append(
            "No stable structured prefix was found; the whole event is stored in the message field."
        )
    else:
        prematch = candidate.regex
        local_notes = list(notes)
        local_notes.append("Structured text fields were inferred from the sample lines.")

    return Analysis(
        name=name,
        log_format="text",
        fields=tuple(fields),
        regex=candidate.regex,
        prematch=prematch if not program_name else None,
        program_name=program_name,
        level_field=level_field,
        message_field=message_field,
        sample_lines=lines,
        total_lines=total_lines,
        notes=tuple(local_notes),
    )


def _prepare_lines(lines: Iterable[str], max_lines: int) -> tuple[tuple[str, ...], int]:
    cleaned: list[str] = []
    total = 0
    for raw in lines:
        total += 1
        line = strip_ansi(str(raw)).strip()
        if not line:
            continue
        if len(cleaned) < max_lines:
            cleaned.append(line)
    if not cleaned:
        raise AnalysisError("the input does not contain any non-empty log lines")
    return tuple(cleaned), total


def analyze_lines(
    lines: Iterable[str],
    name: str = "custom",
    log_format: str = "auto",
    max_lines: int = 5000,
) -> Analysis:
    """Analyze log lines and return a decoder oriented description of the format."""

    validate_positive_int(max_lines, "max lines")
    chosen_format = log_format.lower()
    if chosen_format not in {"auto", "json", "text", "access", "kv"}:
        raise AnalysisError(f"unsupported log format: {log_format}")

    cleaned, total = _prepare_lines(lines, max_lines)
    payloads: list[str] = []
    programs: list[str] = []
    stripped = 0
    for line in cleaned:
        payload, program = _strip_syslog_header(line)
        payloads.append(payload if payload else line)
        if program:
            programs.append(program)
            stripped += 1

    use_payloads = stripped >= max(1, len(cleaned) // 2)
    working = tuple(payloads) if use_payloads else cleaned

    program_name = None
    if programs:
        program, count = Counter(programs).most_common(1)[0]
        if count >= math.ceil(len(cleaned) * 0.8):
            program_name = program

    notes: list[str] = []
    if total > len(cleaned):
        notes.append(f"Only the first {len(cleaned)} non-empty lines were analyzed.")
    if use_payloads:
        notes.append(
            "Syslog headers were detected and removed before building the decoder expression."
        )

    if chosen_format == "auto":
        chosen_format = _detect_format(working)

    if chosen_format == "json":
        if not _all_json(working):
            raise AnalysisError("the input could not be parsed as one JSON object per line")
        return _analyze_json(working, sanitize_name(name), program_name, total, notes)

    if chosen_format == "access":
        analysis = _analyze_access(working, sanitize_name(name), program_name, total, notes)
        if analysis is None:
            raise AnalysisError("the input does not match a supported access log format")
        return analysis

    if chosen_format == "kv":
        analysis = _analyze_kv(working, sanitize_name(name), program_name, total, notes)
        if analysis is None:
            if log_format.lower() == "kv":
                raise AnalysisError("the input does not contain consistent key-value fields")
            return _analyze_text(working, sanitize_name(name), program_name, total, notes)
        return analysis

    return _analyze_text(working, sanitize_name(name), program_name, total, notes)
