from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    SIEM = "SIEM"
    EDR = "EDR"
    NDR = "NDR"
    WAF = "WAF"
    FIREWALL = "FIREWALL"
    CLOUD_AUDIT = "CLOUD_AUDIT"
    THREAT_INTEL = "THREAT_INTEL"
    MANUAL = "MANUAL"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DebateStatus(str, Enum):
    INIT = "INIT"
    IN_PROGRESS = "IN_PROGRESS"
    NEEDS_REVISION = "NEEDS_REVISION"
    READY_FOR_DECISION = "READY_FOR_DECISION"
    CLOSED = "CLOSED"


class DecisionType(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    ESCALATE = "ESCALATE"
    NEED_MORE_EVIDENCE = "NEED_MORE_EVIDENCE"


class ThreatType(str, Enum):
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    BRUTE_FORCE = "BRUTE_FORCE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DDOS = "DDOS"
    UNKNOWN = "UNKNOWN"


class TargetLayer(str, Enum):
    NETWORK = "NETWORK"
    ENDPOINT = "ENDPOINT"
    IDENTITY = "IDENTITY"
    WORKLOAD = "WORKLOAD"
    KUBERNETES = "KUBERNETES"
    APPLICATION = "APPLICATION"
    DATA = "DATA"


class ActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    BLOCK_DOMAIN = "BLOCK_DOMAIN"
    ISOLATE_HOST = "ISOLATE_HOST"
    REVOKE_TOKEN = "REVOKE_TOKEN"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    APPLY_WAF_RULE = "APPLY_WAF_RULE"
    APPLY_FIREWALL_RULE = "APPLY_FIREWALL_RULE"
    SCALE_PROTECTION = "SCALE_PROTECTION"


class GeneratedBy(str, Enum):
    PLANNER = "PLANNER"
    COORDINATOR = "COORDINATOR"
    HUMAN_ANALYST = "HUMAN_ANALYST"
    HYBRID = "HYBRID"


class ExecutorType(str, Enum):
    K8S = "K8S"
    WAF = "WAF"
    FIREWALL = "FIREWALL"
    SOAR = "SOAR"
    MANUAL = "MANUAL"


class ExecutionStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"


class RollbackStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    AVAILABLE = "AVAILABLE"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class SecurityEvent(BaseModel):
    eventId: str
    timestamp: datetime
    sourceType: SourceType
    subject: str
    action: str
    object: str
    context: dict[str, Any] = Field(default_factory=dict)
    severity: Severity
    riskScore: float = Field(ge=0, le=1)
    labels: list[str] = Field(default_factory=list)


class DefenseAction(BaseModel):
    type: ActionType
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
    threatType: ThreatType
    targetLayer: TargetLayer
    actions: list[DefenseAction] = Field(default_factory=list)
    scope: StrategyScope
    ttl: int = Field(gt=0)
    rollbackPlan: RollbackPlan
    confidence: float = Field(ge=0, le=1)
    generatedBy: GeneratedBy
    approved: bool = False


class FinalDecision(BaseModel):
    decision: DecisionType
    owner: str
    rationale: str
    decidedAt: datetime


class DebateTurn(BaseModel):
    round: int = Field(ge=1)
    actor: str
    message: str
    timestamp: datetime


class DebateState(BaseModel):
    debateId: str
    securityEvent: SecurityEvent
    retrievedContext: list[str] = Field(default_factory=list)
    plannerProposal: DefenseStrategy | None = None
    redTeamChallenges: list[str] = Field(default_factory=list)
    revisedProposal: DefenseStrategy | None = None
    round: int = Field(ge=0, default=0)
    status: DebateStatus = DebateStatus.INIT
    finalDecision: FinalDecision | None = None
    history: list[DebateTurn] = Field(default_factory=list)


class VerificationResult(BaseModel):
    passed: bool
    violatedConstraints: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    reason: str
    suggestedFixes: list[str] = Field(default_factory=list)


class ExecutionRecord(BaseModel):
    executionId: str
    strategyId: str
    executorType: ExecutorType
    status: ExecutionStatus
    startTime: datetime
    endTime: datetime | None = None
    resultMessage: str
    rollbackStatus: RollbackStatus = RollbackStatus.NOT_REQUIRED

