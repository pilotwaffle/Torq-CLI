export enum NodeStatus {
  Active = "Active",
  Idle = "Idle",
  Offline = "Offline",
}

export interface ModelNode {
  id: string;
  name: string;
  provider: string;
  role: string;
  costPerHr: number;
  status: NodeStatus;
  description: string;
}

export interface StageDetails {
  id: string; // "init", "generate", "refine", "review", "export"
  name: string;
  label: string;
  description: string;
}

export interface StageExecution {
  stageId: string;
  status: "idle" | "running" | "completed" | "failed" | "blocked" | "skipped";
  modelId: string | "system";
  modelName: string;
  output: string;
  logs: string[];
  durationMs: number;
  tokensUsed: number;
  cost: number;
}

export interface IntegrityLog {
  timestamp: string;
  type: "conflict_detected" | "substitution_enforced" | "policy_override" | "bypass_attempt";
  message: string;
  blockedNodeId?: string;
  substitutedNodeId?: string;
  stageId: string;
}

export interface PipelineRun {
  id: string;
  title: string;
  prompt: string;
  status: "idle" | "running" | "completed" | "failed" | "blocked";
  createdAt: string;
  modelAssignments: Record<string, string>; // stageId -> modelId
  stageExecutions: Record<string, StageExecution>;
  integrityLogs: IntegrityLog[];
  totalTokens: number;
  totalCost: number;
  enforcementMode: "auto_substitute" | "strict_block";
  liveFallbackTriggered?: boolean;
  liveFallbackReason?: string;
}
