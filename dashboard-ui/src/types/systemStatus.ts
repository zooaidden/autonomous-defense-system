// TypeScript shapes for GET /system/status (agent-brain).

export interface SystemPlatformInfo {
  system: string;
  release: string;
  version: string;
  machine: string;
  node: string;
  hostname: string;
  python: string;
  kylinVersion: string | null;
  osPretty: string | null;
  isLoongArch: boolean;
}

export interface SystemServiceEntry {
  name: string;
  port: number;
  status: "up" | "down" | "unknown" | string;
  url?: string;
}

export interface SystemMcpClient {
  enabled: boolean;
  mode: string;
  serverPath: string | null;
  mcpSdkInstalled?: boolean;
  tools?: string[];
  note?: string;
}

export interface SystemStatusResponse {
  platform: SystemPlatformInfo;
  services: SystemServiceEntry[];
  mcpClients: Record<string, SystemMcpClient>;
  executor: {
    whitelist: string[];
    policy?: string;
  };
  guards?: {
    promptInjectionEnabled?: boolean;
    systemConfigGuardEnabled?: boolean;
    intentValidatorEnabled?: boolean;
  };
  auditFile?: {
    enabled: boolean;
    directory: string;
  };
  eventIngest?: EventIngestStatus;
}

export interface EventIngestStatus {
  enabled: boolean;
  running: boolean;
  topic: string;
  bootstrapServers: string;
  groupId: string;
  autoOffsetReset: string;
  processedCount: number;
  failedCount: number;
  lastEventId: string | null;
  lastProcessedAt: string | null;
  lastError: string | null;
}
