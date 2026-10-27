"""Application specific exceptions."""

from __future__ import annotations


class WDecodexError(Exception):
    """Base class for errors that should be reported to the user."""


class InputError(WDecodexError):
    """Raised when the input cannot be read or is empty."""


class AnalysisError(WDecodexError):
    """Raised when the sample log cannot be analyzed."""


class GenerationError(WDecodexError):
    """Raised when the generated configuration would be invalid."""
