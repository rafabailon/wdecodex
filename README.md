# WDecodex

WDecodex reads a sample application log and generates a baseline Wazuh decoder together with a small starter rule set. It is meant for the first pass of a log onboarding task, when the format is still unfamiliar and a working draft is more useful than a blank editor. The generated files are valid Wazuh XML, but they are deliberately conservative and should always be reviewed with `wazuh-logtest` before they reach production.

The tool uses only the Python standard library at runtime. It does not call the Wazuh API, does not upload anything, and does not need network access.

## Features

- Automatic detection of JSON lines, web access logs, key-value logs, structured text, and free text.
- Syslog header removal with a `program_name` decoder condition when a common program is present.
- PCRE2 decoder expressions, capture groups, field order, and prematch filters.
- A custom base rule plus generic severity, failure, and HTTP status rules.
- Safe custom rule IDs in the Wazuh range 100000 to 120000.
- Stable command line interface, importable Python API, and XML-safe output.
- Complete test suite with sample logs for every supported format.

## Requirements

WDecodex requires Python 3.10 or newer. Wazuh is not required to generate the files, but it is required to test them.

## Installation

Create a virtual environment and install the project in editable mode with the development tools.

```
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[dev]"
```

The `wdecodex` command becomes available after installation. The package can also be run directly from the repository with `python3 -m wdecodex`.

## Quick start

Create a small sample file named `orders.log`.

```
2026-10-25 10:00:01 INFO [auth] User alice logged in from 10.0.0.5
2026-10-25 10:00:02 WARN [auth] Failed login attempt for user bob from 10.0.0.9
2026-10-25 10:00:03 ERROR [db] Connection failed: timeout after 30s
2026-10-25 10:00:04 INFO [api] Request GET /health completed with status 200
```

Run the generator.

```
wdecodex orders.log
```

The command detects structured text, writes `wdecodex-output/orders_decoder.xml` and `wdecodex-output/orders_rules.xml`, and prints a short summary. The generated decoder for this sample contains a timestamp field, a level field, a component field, and a message field.

```
<decoder name="orders">
  <prematch type="pcre2">^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+((?i:emergency|critical|warning|verbose|notice|trace|debug|error|alert|emerg|fatal|panic|info|warn|crit|err))\s+\[([A-Za-z][A-Za-z0-9_.\-]{0,63})\]\s+(.*)$</prematch>
  <regex type="pcre2">^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+((?i:emergency|critical|warning|verbose|notice|trace|debug|error|alert|emerg|fatal|panic|info|warn|crit|err))\s+\[([A-Za-z][A-Za-z0-9_.\-]{0,63})\]\s+(.*)$</regex>
  <order>log_timestamp, level, component, message</order>
</decoder>
```

The rule file starts with a level 0 base rule that is tied to the custom decoder. Its children add severity and failure detection. The following excerpt shows the base rule and the failure rule.

```
<group name="orders,">
  <rule id="100000" level="0">
    <decoded_as>orders</decoded_as>
    <description>orders: events decoded by the custom decoder.</description>
  </rule>

  <rule id="100001" level="8">
    <if_sid>100000</if_sid>
    <match type="pcre2">(?i)\b(?:failed|failure|denied|unauthorized|forbidden|invalid)\b</match>
    <description>orders: failure or denied operation.</description>
  </rule>
</group>
```

The full rule file also contains informational, warning, error, and critical rules that match the decoded `level` field.

## Command line reference

The only positional argument is the input path. A dash means standard input, and standard input is also the default when no path is given.

- `-n, --name NAME` sets the decoder name, rule group, and file prefix. The name is sanitized to lowercase letters, digits, and hyphens.
- `-o, --output-dir DIR` selects the output directory. The default is `wdecodex-output`.
- `--format auto|json|text|access|kv` forces a format instead of using detection. The default is `auto`.
- `--base-rule-id ID` sets the first custom rule ID. The default is 100000 and the valid range is 100000 to 120000.
- `--max-lines N` limits how many non-empty lines are analyzed. The default is 5000.
- `--stdout` prints both XML documents to standard output and does not write files.
- `--version` prints the package version.

Some examples.

```
wdecodex app.log --name payment-api
wdecodex app.log --format json --base-rule-id 110000
wdecodex - < app.log --stdout
cat app.log | wdecodex - --name app --output-dir build/wazuh
```

Errors are written to standard error and return exit code 2. A successful run returns exit code 0.

## Format detection

Detection runs on the cleaned sample lines after ANSI escape sequences and empty lines are removed.

JSON is selected when every sampled line parses as a JSON object. A JSON array or a scalar value does not count as a JSON log line.

Web access is selected when at least 80 percent of the lines match the combined log format or the common log format with a request, status, size, and optional referrer and user agent. The decoder uses the shape of the first matching line and leaves any other lines for other decoders. The generated fields are `srcip`, `srcuser`, `log_timestamp`, `method`, `url`, `status`, `bytes`, `referrer`, and `user_agent`.

Key-value is selected when at least 60 percent of the lines contain at least one `key=value` pair and a stable set of keys can be found. Keys that appear in at least 60 percent of the lines are kept, up to twelve fields. Common keys are mapped to Wazuh style names such as `srcip`, `dstuser`, `level`, `status`, `url`, and `log_timestamp`.

Structured text is the fallback. The analyzer tries to recognize an ISO timestamp, a common log timestamp, a day first timestamp, a time only value, a severity word, and a bracketed component name at the start of the line. The rest of the line becomes the message field.

Free text is used when no structured prefix matches every sample line. The whole line is stored in a message field and the prematch is built from the longest useful literal prefix shared by the sample. If there is no useful prefix, the prematch is simply `^`.

A standard syslog header is removed when at least half of the lines contain one. If a single program name appears in at least 80 percent of the lines, the decoder uses `program_name` and the regular expression is applied to the payload without the header.

## Generated rules

Every rule file begins with a level 0 base rule for the custom decoder. A JSON rule file also contains a level 0 base rule for the built-in `json` decoder, because the custom JSON decoder and the native decoder can both handle the event.

For logs with a decoded level field, the analyzer adds informational, warning, error, and critical rules at levels 3, 5, 7, and 12. Text levels are matched case insensitively. Numeric levels are grouped into 0 to 3, 4 to 6, 7 to 8, and 9 or higher.

For logs without a level field, the same four severities are matched against the raw event text instead of a field.

A separate level 8 rule matches common failure words such as failed, failure, denied, unauthorized, forbidden, and invalid.

Access logs use HTTP status rules instead of text severity rules. A level 8 rule covers authentication and authorization failures on 401 and 403, a level 5 rule covers 4xx responses, and a level 7 rule covers 5xx responses.

Rule IDs are sequential from the chosen base ID. The generator refuses a base ID that is outside the custom range or a rule set that would overflow the range. The default rule file uses 100000 and a small number of following IDs.

## Python API

The high level function accepts raw log text and returns an analysis object with both XML documents.

```
from pathlib import Path

from wdecodex import generate

sample = Path("orders.log").read_text(encoding="utf-8")
artifacts = generate(sample, name="orders", base_rule_id=100000)

print(artifacts.analysis.log_format)
print(artifacts.analysis.order)
print(artifacts.decoder_xml)
print(artifacts.rules_xml)
```

The analysis object exposes the detected format, decoded fields, regular expression, prematch, program name, level field, message field, sampled lines, original line count, and human readable notes. `generate_from_analysis` can render XML again from an existing analysis without repeating detection.

All input and generation failures derive from `WDecodexError`. Callers that need precise handling can catch `InputError`, `AnalysisError`, or `GenerationError`.

## Wazuh deployment

Copy the decoder and rule files into the manager configuration. The exact path depends on the Wazuh installation. A common layout is the following.

```
sudo cp wdecodex-output/orders_decoder.xml /var/ossec/etc/decoders/
sudo cp wdecodex-output/orders_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/decoders/orders_decoder.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/orders_rules.xml
sudo /var/ossec/bin/wazuh-logtest
```

Paste a real log line into `wazuh-logtest` and confirm the decoder name, the extracted fields, and the selected rule. After validation, restart the manager with `sudo systemctl restart wazuh-manager` or the service command used by the installation. Container deployments usually mount these directories from the host, so copy the files to the mounted configuration path instead.

Do not treat the generated levels as a security policy. Review every rule, adjust the descriptions and levels, and remove rules that do not fit the environment.

## Project layout

```
wdecodex/
├── .github/workflows/tests.yml
├── .gitignore
├── ANALYSIS.md
├── GH_DATA.md
├── LICENSE
├── README.md
├── pyproject.toml
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   ├── test_analyzer.py
│   ├── test_cli.py
│   ├── test_end_to_end.py
│   ├── test_generators.py
│   └── test_utils.py
└── wdecodex/
    ├── __init__.py
    ├── __main__.py
    ├── analyzer.py
    ├── cli.py
    ├── core.py
    ├── errors.py
    ├── generators.py
    ├── models.py
    └── utils.py
```

## Testing

Run the full suite and the style checks from the repository root.

```
python3 -m pytest -q
python3 -m ruff check .
python3 -m ruff format --check .
```

The suite covers format detection, field inference, XML generation, rule construction, command line behavior, error paths, and end to end generation for the five bundled sample logs.

## Limitations

WDecodex is a baseline generator, not a full log parser. It assumes one event per line and does not join stack traces or multi line records.

Detection is statistical and depends on the sample. A sample that contains only one kind of line can hide variants that appear later in production.

The generated regular expressions are designed to match the sample and are not guaranteed to be minimal, complete, or safe for very large inputs.

JSON handling delegates to the Wazuh JSON decoder. Nested fields are used for level detection, but the rule file references the flat field name that Wazuh exposes.

The tool does not validate the XML against a live Wazuh installation, does not assign MITRE ATT&CK metadata, and does not generate compliance mappings.

## Documentation

`ANALYSIS.md` describes the purpose, architecture, algorithms, and design decisions in more detail. `GH_DATA.md` contains suggested GitHub repository metadata and commands for publishing the project.

## License

WDecodex is released under the MIT License. See `LICENSE`.
