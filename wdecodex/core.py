"""High level API for WDecodex."""

from __future__ import annotations

from .analyzer import analyze_lines
from .generators import generate_decoder_xml, generate_rules_xml
from .models import Analysis, GeneratedArtifacts


def generate(
    log_text: str,
    name: str = "custom",
    log_format: str = "auto",
    base_rule_id: int = 100000,
    max_lines: int = 5000,
) -> GeneratedArtifacts:
    """Generate a Wazuh decoder and rule set from raw log text."""

    analysis = analyze_lines(
        log_text.splitlines(),
        name=name,
        log_format=log_format,
        max_lines=max_lines,
    )
    return GeneratedArtifacts(
        analysis=analysis,
        decoder_xml=generate_decoder_xml(analysis),
        rules_xml=generate_rules_xml(analysis, base_rule_id),
    )


def generate_from_analysis(analysis: Analysis, base_rule_id: int = 100000) -> GeneratedArtifacts:
    """Generate XML artifacts from an existing analysis object."""

    return GeneratedArtifacts(
        analysis=analysis,
        decoder_xml=generate_decoder_xml(analysis),
        rules_xml=generate_rules_xml(analysis, base_rule_id),
    )
