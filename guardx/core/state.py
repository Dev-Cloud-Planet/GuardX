"""Agent state management."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Phase(str, Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    REPORT = "report"
    REMEDIATE = "remediate"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    confirmed: bool = False


@dataclass
class AgentState:
    target: str
    phase: Phase = Phase.RECON
    findings: list[Finding] = field(default_factory=list)
    tool_history: list[dict] = field(default_factory=list)
    messages: list[dict] = field(default_factory=list)
    ssh_host: Optional[str] = None
    ssh_user: Optional[str] = None
    ssh_key_path: Optional[str] = None
