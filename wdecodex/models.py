"""Data structures shared by the analysis and generation stages."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

LogFormat = Literal["json", "access", "kv", "text"]


@dataclass(frozen=True)
class DecodedField:
    """A single capture group produced by a decoder regular expression."""

    name: str
    pattern: str
    sample: str


@dataclass(frozen=True)
class Analysis:
    """The result of inspecting a sample log."""

    name: str
    log_format: LogFormat
    fields: tuple[DecodedField, ...] = ()
    regex: str | None = None
    prematch: str | None = None
    program_name: str | None = None
    level_field: str | None = None
    level_numeric: bool = False
    message_field: str | None = None
    sample_lines: tuple[str, ...] = ()
    total_lines: int = 0
    notes: tuple[str, ...] = ()

    @property
    def order(self) -> tuple[str, ...]:
        """Return decoder field names in capture-group order."""

        return tuple(item.name for item in self.fields)


@dataclass(frozen=True)
class DecoderSpec:
    """A decoder ready to be rendered as Wazuh XML."""

    name: str
    regex: str | None = None
    order: tuple[str, ...] = ()
    prematch: str | None = None
    program_name: str | None = None
    plugin_decoder: str | None = None


@dataclass(frozen=True)
class RuleSpec:
    """A Wazuh rule ready to be rendered as XML."""

    id: int
    level: int
    description: str
    decoded_as: str | None = None
    if_sid: tuple[int, ...] = ()
    field_name: str | None = None
    field_regex: str | None = None
    match: str | None = None


@dataclass(frozen=True)
class GeneratedArtifacts:
    """The complete output of a WDecodex run."""

    analysis: Analysis
    decoder_xml: str
    rules_xml: str
    extra: dict[str, str] = field(default_factory=dict)
