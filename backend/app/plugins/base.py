"""
Core plugin contract for CTF Nexus.

Every analysis module (crypto, stego, web, misc, reverse, forensics, osint)
implements Plugin and registers itself with the global `registry`. Routers
never import a specific plugin directly - they go through the registry so
new plugins can be dropped into a `plugins/<category>/` folder without
touching the API layer.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class Finding:
    """A single piece of evidence produced by a plugin."""

    label: str                     # short machine-ish name, e.g. "base64"
    summary: str                   # human-readable one-liner
    confidence: float = 0.5        # 0.0 - 1.0
    data: Optional[str] = None     # decoded/extracted content, if any
    detail: Dict[str, Any] = field(default_factory=dict)
    flags_found: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "summary": self.summary,
            "confidence": round(self.confidence, 3),
            "data": self.data,
            "detail": self.detail,
            "flags_found": self.flags_found,
        }


@dataclass
class AnalysisResult:
    """What a plugin returns for one run."""

    plugin: str
    category: str
    findings: List[Finding] = field(default_factory=list)
    tool_log: List[str] = field(default_factory=list)   # commands actually executed
    next_steps: List[str] = field(default_factory=list)  # recommended follow-ups
    duration_ms: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin": self.plugin,
            "category": self.category,
            "findings": [f.to_dict() for f in self.findings],
            "tool_log": self.tool_log,
            "next_steps": self.next_steps,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


class Registry:
    """Holds every plugin, keyed by category."""

    def __init__(self) -> None:
        self._plugins: Dict[str, Callable[..., AnalysisResult]] = {}

    def register(self, category: str):
        def decorator(fn: Callable[..., AnalysisResult]):
            self._plugins[category] = fn
            return fn
        return decorator

    def run(self, category: str, *args, **kwargs) -> AnalysisResult:
        if category not in self._plugins:
            return AnalysisResult(
                plugin="unknown",
                category=category,
                error=f"no plugin registered for category '{category}'",
            )
        start = time.time()
        result = self._plugins[category](*args, **kwargs)
        result.duration_ms = int((time.time() - start) * 1000)
        return result

    def categories(self) -> List[str]:
        return list(self._plugins.keys())


registry = Registry()


def timed(fn):
    """Small helper decorator plugins can use internally for tool_log timing."""

    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapper
