"""Render Wazuh decoder and rule XML from an analysis result."""

from __future__ import annotations

from .errors import GenerationError
from .models import Analysis, DecoderSpec, RuleSpec
from .utils import validate_rule_id, xml_attr, xml_text

TEXT_SEVERITIES = (
    (
        3,
        "informational",
        r"(?i)^(?:trace|debug|info|notice|verbose)$",
        r"(?i)\b(?:trace|debug|info|notice|verbose)\b",
    ),
    (5, "warning", r"(?i)^(?:warn|warning)$", r"(?i)\b(?:warn|warning)\b"),
    (7, "error", r"(?i)^(?:err|error)$", r"(?i)\b(?:err|error)\b"),
    (
        12,
        "critical",
        r"(?i)^(?:crit|critical|alert|emerg|emergency|fatal|panic)$",
        r"(?i)\b(?:crit|critical|alert|emerg|emergency|fatal|panic)\b",
    ),
)

NUMERIC_SEVERITIES = (
    (3, "informational", r"^(?:[0-3])$"),
    (5, "warning", r"^(?:[4-6])$"),
    (7, "error", r"^(?:[7-8])$"),
    (12, "critical", r"^(?:9|[1-9][0-9]+)$"),
)

FAILURE_MATCH = r"(?i)\b(?:failed|failure|denied|unauthorized|forbidden|invalid)\b"


def build_decoder(analysis: Analysis) -> DecoderSpec:
    """Build a decoder specification for the detected log format."""

    if analysis.log_format == "json":
        return DecoderSpec(
            name=analysis.name,
            prematch=analysis.prematch,
            program_name=analysis.program_name,
            plugin_decoder="JSON_Decoder",
        )

    if not analysis.regex:
        raise GenerationError("the analysis did not produce a decoder expression")
    return DecoderSpec(
        name=analysis.name,
        regex=analysis.regex,
        order=analysis.order,
        prematch=analysis.prematch,
        program_name=analysis.program_name,
    )


def render_decoder_xml(decoder: DecoderSpec) -> str:
    """Serialize a decoder specification as Wazuh decoder XML."""

    lines = [
        "<!-- WDecodex baseline decoder. Review it with wazuh-logtest before deployment. -->",
        f'<decoder name="{xml_attr(decoder.name)}">',
    ]
    if decoder.program_name:
        lines.append(
            f'  <program_name type="pcre2">^{xml_text(decoder.program_name)}$</program_name>'
        )
    if decoder.prematch:
        lines.append(f'  <prematch type="pcre2">{xml_text(decoder.prematch)}</prematch>')
    if decoder.plugin_decoder:
        lines.append(f"  <plugin_decoder>{xml_text(decoder.plugin_decoder)}</plugin_decoder>")
    if decoder.regex:
        lines.append(f'  <regex type="pcre2">{xml_text(decoder.regex)}</regex>')
    if decoder.order:
        lines.append(f"  <order>{xml_text(', '.join(decoder.order))}</order>")
    lines.append("</decoder>")
    return "\n".join(lines) + "\n"


def _base_rules(analysis: Analysis, base_rule_id: int) -> list[RuleSpec]:
    rules: list[RuleSpec] = [
        RuleSpec(
            id=base_rule_id,
            level=0,
            description=f"{analysis.name}: events decoded by the custom decoder.",
            decoded_as=analysis.name,
        )
    ]
    if analysis.log_format == "json":
        rules.append(
            RuleSpec(
                id=base_rule_id + 1,
                level=0,
                description=(f"{analysis.name}: JSON events decoded by the built-in json decoder."),
                decoded_as="json",
            )
        )
    return rules


def _severity_rules(analysis: Analysis, base_ids: tuple[int, ...], next_id: int) -> list[RuleSpec]:
    rules: list[RuleSpec] = []

    if analysis.log_format == "access":
        status_conditions = (
            (8, "authentication or authorization failure.", r"^(?:401|403)$"),
            (5, "client error response.", r"^4\d{2}$"),
            (7, "server error response.", r"^5\d{2}$"),
        )
        for level, description, pattern in status_conditions:
            rules.append(
                RuleSpec(
                    id=next_id,
                    level=level,
                    description=f"{analysis.name}: {description}",
                    if_sid=base_ids,
                    field_name="status",
                    field_regex=pattern,
                )
            )
            next_id += 1
        return rules

    rules.append(
        RuleSpec(
            id=next_id,
            level=8,
            description=f"{analysis.name}: failure or denied operation.",
            if_sid=base_ids,
            match=FAILURE_MATCH,
        )
    )
    next_id += 1

    if analysis.level_field:
        if analysis.level_numeric:
            for level, description, pattern in NUMERIC_SEVERITIES:
                rules.append(
                    RuleSpec(
                        id=next_id,
                        level=level,
                        description=f"{analysis.name}: {description} event.",
                        if_sid=base_ids,
                        field_name=analysis.level_field,
                        field_regex=pattern,
                    )
                )
                next_id += 1
        else:
            for level, description, pattern, _ in TEXT_SEVERITIES:
                rules.append(
                    RuleSpec(
                        id=next_id,
                        level=level,
                        description=f"{analysis.name}: {description} event.",
                        if_sid=base_ids,
                        field_name=analysis.level_field,
                        field_regex=pattern,
                    )
                )
                next_id += 1
    else:
        for level, description, _, pattern in TEXT_SEVERITIES:
            rules.append(
                RuleSpec(
                    id=next_id,
                    level=level,
                    description=f"{analysis.name}: {description} event.",
                    if_sid=base_ids,
                    match=pattern,
                )
            )
            next_id += 1

    return rules


def build_rules(analysis: Analysis, base_rule_id: int = 100000) -> tuple[RuleSpec, ...]:
    """Build a small baseline rule set for the detected log format."""

    rules = _base_rules(analysis, base_rule_id)
    base_ids = tuple(rule.id for rule in rules)
    next_id = max(base_ids) + 1
    rules.extend(_severity_rules(analysis, base_ids, next_id))
    validate_rule_id(base_rule_id, len(rules))
    return tuple(rules)


def render_rules_xml(rules: tuple[RuleSpec, ...], name: str) -> str:
    """Serialize rule specifications as Wazuh rule XML."""

    lines = [
        "<!-- WDecodex baseline rules. Adjust levels and descriptions before deployment. -->",
        f'<group name="{xml_attr(name)},">',
    ]
    rendered: list[str] = []
    for rule in rules:
        block = [f'  <rule id="{rule.id}" level="{rule.level}">']
        if rule.decoded_as:
            block.append(f"    <decoded_as>{xml_text(rule.decoded_as)}</decoded_as>")
        if rule.if_sid:
            ids = ", ".join(str(item) for item in rule.if_sid)
            block.append(f"    <if_sid>{ids}</if_sid>")
        if rule.field_name and rule.field_regex:
            block.append(
                f'    <field name="{xml_attr(rule.field_name)}" '
                f'type="pcre2">{xml_text(rule.field_regex)}</field>'
            )
        if rule.match:
            block.append(f'    <match type="pcre2">{xml_text(rule.match)}</match>')
        block.append(f"    <description>{xml_text(rule.description)}</description>")
        block.append("  </rule>")
        rendered.append("\n".join(block))

    lines.append("\n\n".join(rendered))
    lines.append("</group>")
    return "\n".join(lines) + "\n"


def generate_decoder_xml(analysis: Analysis) -> str:
    """Build and render the decoder for an analysis."""

    return render_decoder_xml(build_decoder(analysis))


def generate_rules_xml(analysis: Analysis, base_rule_id: int = 100000) -> str:
    """Build and render the rules for an analysis."""

    rules = build_rules(analysis, base_rule_id)
    return render_rules_xml(rules, analysis.name)
