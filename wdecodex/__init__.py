"""WDecodex generates baseline Wazuh decoders and rules from sample logs."""

from __future__ import annotations

__version__ = "0.1.0"

from .core import generate, generate_from_analysis
from .models import Analysis, GeneratedArtifacts

__all__ = [
    "Analysis",
    "GeneratedArtifacts",
    "__version__",
    "generate",
    "generate_from_analysis",
]
