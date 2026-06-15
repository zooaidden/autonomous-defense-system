package com.autonomous.defense.shared.domain.enums;

public final class DomainEnums {

    private DomainEnums() {
    }

    public enum SourceType {
        SIEM,
        EDR,
        NDR,
        WAF,
        FIREWALL,
        CLOUD_AUDIT,
        THREAT_INTEL,
        MANUAL
    }

    public enum Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    public enum DebateStatus {
        INIT,
        IN_PROGRESS,
        NEEDS_REVISION,
        READY_FOR_DECISION,
        CLOSED
    }

    public enum DecisionType {
        APPROVE,
        REJECT,
        ESCALATE,
        NEED_MORE_EVIDENCE
    }

    public enum ThreatType {
        MALWARE,
        PHISHING,
        BRUTE_FORCE,
        DATA_EXFILTRATION,
        PRIVILEGE_ESCALATION,
        LATERAL_MOVEMENT,
        DDOS,
        UNKNOWN
    }

    public enum TargetLayer {
        NETWORK,
        ENDPOINT,
        IDENTITY,
        WORKLOAD,
        KUBERNETES,
        APPLICATION,
        DATA
    }

    public enum ActionType {
        BLOCK_IP,
        BLOCK_DOMAIN,
        ISOLATE_HOST,
        REVOKE_TOKEN,
        DISABLE_ACCOUNT,
        APPLY_WAF_RULE,
        APPLY_FIREWALL_RULE,
        SCALE_PROTECTION
    }

    public enum GeneratedBy {
        PLANNER,
        COORDINATOR,
        HUMAN_ANALYST,
        HYBRID
    }

    public enum ExecutorType {
        K8S,
        WAF,
        FIREWALL,
        SOAR,
        MANUAL
    }

    public enum ExecutionStatus {
        PENDING,
        RUNNING,
        SUCCEEDED,
        FAILED,
        PARTIAL_SUCCESS
    }

    public enum RollbackStatus {
        NOT_REQUIRED,
        AVAILABLE,
        RUNNING,
        SUCCEEDED,
        FAILED
    }
}

