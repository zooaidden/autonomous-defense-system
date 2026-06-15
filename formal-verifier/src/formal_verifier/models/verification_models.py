from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RuleSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConstraintIssue(BaseModel):
    code: str
    description: str
    severity: RuleSeverity
    reason: str | None = None


class DefenseAction(BaseModel):
    type: str
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class StrategyScope(BaseModel):
    assets: list[str] = Field(default_factory=list)
    namespaces: list[str] = Field(default_factory=list)
    tenantId: str | None = None


class RollbackPlan(BaseModel):
    planId: str
    steps: list[str] = Field(default_factory=list)
    triggerCondition: str


class DefenseStrategy(BaseModel):
    strategyId: str
    threatType: str
    targetLayer: str
    actions: list[DefenseAction] = Field(default_factory=list)
    scope: StrategyScope = Field(default_factory=StrategyScope)
    ttl: int | None = None
    rollbackPlan: RollbackPlan | None = None
    confidence: float = Field(ge=0, le=1, default=0.0)
    rationale: str = ""
    generatedBy: str = "UNKNOWN"
    approved: bool = False


class VerificationResult(BaseModel):
    passed: bool
    violatedConstraints: list[ConstraintIssue] = Field(default_factory=list)
    warnings: list[ConstraintIssue] = Field(default_factory=list)
    reason: str
    suggestedFixes: list[str] = Field(default_factory=list)

