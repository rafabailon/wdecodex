"""Shared test helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def read_fixture():
    """Return a function that reads one of the sample logs."""

    def _read(name: str) -> str:
        return (FIXTURES / name).read_text(encoding="utf-8")

    return _read
