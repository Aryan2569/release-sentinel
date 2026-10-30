"""Pydantic data models for Release Sentinel.

Public surface:
    Severity     – LOW / MEDIUM / HIGH / CRITICAL
    Decision     – ALLOW / WARN / BLOCK
    ReleaseRef   – Identifies a specific published version of an npm package.
    Evidence     – A single, explainable finding from a release comparison.
    Report       – The full output of a diff analysis.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Severity levels for individual evidence items."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Decision(StrEnum):
    """Overall gate decision for a release diff."""

    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


class ReleaseRef(BaseModel):
    """Identifies a specific published version of an npm package.

    Attributes:
        name:         The npm package name (e.g. ``"lodash"``).
        version:      The exact version string (e.g. ``"4.17.21"``).
        published_at: UTC datetime when this version was published to the registry.
    """

    name: str = Field(..., description="npm package name")
    version: str = Field(..., description="Exact version string")
    published_at: datetime = Field(..., description="UTC publish time from the registry")


class Evidence(BaseModel):
    """A single, explainable finding from a release comparison.

    Attributes:
        id:                  Machine-readable evidence identifier (e.g. ``"install_script_added"``).
        severity:            How alarming this finding is.
        file:                Package-relative path of the affected file, or ``None`` for
                             package-level findings (e.g. dependency changes).
        explanation:         Plain-English description of what was found and why it matters.
        legitimate_use_note: Common, non-malicious reasons this pattern occurs, so the
                             reader can calibrate their concern.
    """

    id: Annotated[str, Field(description="Machine-readable evidence ID")]
    severity: Severity
    file: str | None = Field(None, description="Package-relative path of affected file")
    explanation: str = Field(..., description="Plain-English description of the finding")
    legitimate_use_note: str = Field(
        ..., description="Common legitimate reasons this pattern occurs"
    )


class Report(BaseModel):
    """The full output of a diff analysis between two npm releases.

    Attributes:
        old_release:   The release being upgraded *from*.
        new_release:   The release being upgraded *to*.
        decision:      Gate decision: ALLOW / WARN / BLOCK.
        evidence:      Ordered list of findings; empty means nothing suspicious was detected.
        limitations:   Explicit list of things that *could not* be inspected in this analysis.
                       Absence of evidence is never silence — it is reported here.
        as_of:         The timestamp used to filter external data (registry metadata, etc.).
                       All external data used was published before this timestamp.
        generated_at:  UTC timestamp when this report was produced.
    """

    old_release: ReleaseRef
    new_release: ReleaseRef
    decision: Decision
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    as_of: datetime = Field(..., description="External data cut-off timestamp")
    generated_at: datetime = Field(..., description="UTC timestamp when report was produced")
