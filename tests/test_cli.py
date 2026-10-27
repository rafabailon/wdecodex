"""Tests for the command line interface."""

from __future__ import annotations

import io
import sys

import pytest

from wdecodex.cli import main


def test_cli_writes_output_files(tmp_path, read_fixture, capsys):
    log_path = tmp_path / "orders.log"
    log_path.write_text(read_fixture("text.log"), encoding="utf-8")
    output_dir = tmp_path / "out"

    exit_code = main([str(log_path), "--name", "orders", "--output-dir", str(output_dir)])

    assert exit_code == 0
    assert (output_dir / "orders_decoder.xml").is_file()
    assert (output_dir / "orders_rules.xml").is_file()
    captured = capsys.readouterr()
    assert "Analyzed 4 log lines" in captured.out
    assert "orders_decoder.xml" in captured.out
    assert "orders_rules.xml" in captured.out


def test_cli_reads_standard_input(tmp_path, monkeypatch, read_fixture, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(read_fixture("json.log")))
    output_dir = tmp_path / "out"

    exit_code = main(["-", "--name", "events", "--output-dir", str(output_dir)])

    assert exit_code == 0
    decoder = (output_dir / "events_decoder.xml").read_text(encoding="utf-8")
    assert "JSON_Decoder" in decoder


def test_cli_stdout_prints_xml_without_writing_files(tmp_path, read_fixture, capsys):
    log_path = tmp_path / "app.log"
    log_path.write_text(read_fixture("text.log"), encoding="utf-8")

    exit_code = main([str(log_path), "--name", "app", "--stdout"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "<decoder" in captured.out
    assert "<group" in captured.out
    assert not list(tmp_path.glob("*.xml"))


def test_cli_default_output_directory(tmp_path, monkeypatch, read_fixture):
    monkeypatch.chdir(tmp_path)
    log_path = tmp_path / "app.log"
    log_path.write_text(read_fixture("text.log"), encoding="utf-8")

    exit_code = main([str(log_path)])

    assert exit_code == 0
    assert (tmp_path / "wdecodex-output" / "app_decoder.xml").is_file()
    assert (tmp_path / "wdecodex-output" / "app_rules.xml").is_file()


def test_cli_derives_name_from_input_file(tmp_path, read_fixture, capsys):
    log_path = tmp_path / "Payment API.log"
    log_path.write_text(read_fixture("text.log"), encoding="utf-8")

    exit_code = main([str(log_path), "--output-dir", str(tmp_path / "out")])

    assert exit_code == 0
    assert (tmp_path / "out" / "payment-api_decoder.xml").is_file()


def test_cli_missing_file_returns_error(tmp_path, capsys):
    exit_code = main([str(tmp_path / "missing.log")])

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "does not exist" in captured.err


def test_cli_empty_input_returns_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))

    exit_code = main(["-"])

    assert exit_code == 2
    assert "non-empty" in capsys.readouterr().err


def test_cli_invalid_rule_id_returns_error(tmp_path, read_fixture, capsys):
    log_path = tmp_path / "app.log"
    log_path.write_text(read_fixture("text.log"), encoding="utf-8")

    exit_code = main([str(log_path), "--base-rule-id", "99999"])

    assert exit_code == 2
    assert "base rule id" in capsys.readouterr().err


def test_cli_forced_format(tmp_path, read_fixture):
    log_path = tmp_path / "app.log"
    log_path.write_text(read_fixture("text.log"), encoding="utf-8")
    output_dir = tmp_path / "out"

    exit_code = main(
        [str(log_path), "--format", "text", "--name", "app", "--output-dir", str(output_dir)]
    )

    assert exit_code == 0
    rules = (output_dir / "app_rules.xml").read_text(encoding="utf-8")
    assert 'name="level"' in rules


def test_cli_forced_invalid_format_returns_error(tmp_path, read_fixture, capsys):
    log_path = tmp_path / "app.log"
    log_path.write_text(read_fixture("json.log"), encoding="utf-8")

    exit_code = main([str(log_path), "--format", "access"])

    assert exit_code == 2
    assert "access log format" in capsys.readouterr().err


def test_cli_version_exits_successfully(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])

    assert excinfo.value.code == 0
    assert "wdecodex 0.1.0" in capsys.readouterr().out
