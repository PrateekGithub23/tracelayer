// Types mirroring the backend's Pydantic response models (backend/app/schemas.py).
// Keeping them in one file makes API drift easy to spot in review.

export type Severity = "low" | "medium" | "high" | "critical";
export type Verdict =
  | "verified_observation"
  | "heuristic_correlation"
  | "ai_hypothesis"
  | "missing_evidence"
  | "unsupported_claim"
  | "contradictory_finding";

export interface Entity { type: "user" | "host" | "ip" | string; value: string; detections?: number }

export interface EventItem {
  id: string;
  timestamp: string;
  event_type: string;
  outcome: string;
  host: string | null;
  username: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  process: string | null;
  command_line: string | null;
  bytes_out: number | null;
  country: string | null;
  message: string | null;
  attributes: Record<string, unknown>;
  tags: string[];
  source: string;
  parser: string;
  batch_id: string;
  content_hash: string;
}

export interface Batch {
  id: string;
  seq: number;
  source: string;
  parser: string;
  received_at: string;
  accepted_count: number;
  duplicate_count: number;
  rejected_count: number;
  merkle_root: string;
  prev_chain_hash: string;
  chain_hash: string;
  duration_ms: number;
}

export interface EventDetail extends EventItem {
  raw: Record<string, unknown>;
  ingested_at: string;
  batch: Batch;
  detections: { id: string; rule_name: string; severity: Severity }[];
  investigations: { id: string; title: string; role: string }[];
}

export interface EventPage { items: EventItem[]; total: number; next_cursor: string | null }

export interface Detection {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  confidence: number;
  tactic: string;
  technique: string;
  first_seen: string;
  last_seen: string;
  entities: Entity[];
  summary: string;
  evidence_count: number;
  investigation_id: string | null;
  created_at: string;
}

export interface Investigation {
  id: string;
  title: string;
  status: string;
  severity: Severity;
  score: number;
  score_breakdown: Record<string, number | string>;
  first_seen: string;
  last_seen: string;
  entities: Entity[];
  tactics: string[];
  assignee: string | null;
  approved_analysis_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface InvestigationListItem extends Investigation { detection_count: number; event_count: number }

export interface CoverageGap { host: string; present: string[]; missing: string[] }

export interface InvestigationDetail extends Investigation {
  detections: Detection[];
  event_counts: { evidence: number; context: number };
  coverage_gaps: CoverageGap[];
  analyses: { id: string; engine: string; model: string; status: string; created_at: string; integrity: Integrity }[];
}

export interface Integrity {
  claims: number;
  verdicts: Record<Verdict, number>;
  integrity_score: number;
  unsafe_claims: number;
  citations_given: number;
  citations_fabricated: number;
  citations_out_of_scope: number;
  summary_issues?: string[];
  recommendations?: string[];
  validation_ms?: number;
  generation_ms?: number;
  generator_meta?: Record<string, unknown>;
}

export interface Claim {
  id: string;
  ordinal: number;
  text: string;
  declared_kind: string;
  citations: string[];
  raw_citations: string[];
  verdict: Verdict;
  reasons: string[];
  checks: Record<string, unknown>;
  review_status: "pending" | "accepted" | "rejected";
  review_note: string | null;
}

export interface Analysis {
  id: string;
  investigation_id: string;
  engine: string;
  model: string;
  status: "pending_review" | "approved" | "rejected";
  summary: string;
  prompt_sha256: string | null;
  evidence_pack_sha256: string;
  fallback_reason: string | null;
  latency_ms: number;
  integrity: Integrity;
  created_at: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_note: string | null;
  claims: Claim[];
}

export interface TimelineEvent {
  id: string;
  ref: string; // short citation label (E1..En) shared with the integrity validator
  timestamp: string;
  event_type: string;
  outcome: string;
  host: string | null;
  username: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  bytes_out: number | null;
  process: string | null;
  tags: string[];
  role: "evidence" | "context";
}

export interface Timeline {
  first_seen: string;
  last_seen: string;
  events: TimelineEvent[];
  detections: Pick<Detection, "id" | "rule_id" | "rule_name" | "severity" | "tactic" | "first_seen" | "last_seen" | "summary">[];
}

export interface GraphNode { id: string; type: string; label: string; events: number; external: boolean; detections: string[] }
export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  count: number;
  failures: number;
  bytes: number;
  first_seen: string;
  last_seen: string;
  event_ids: string[];
  flagged: boolean;
}
export interface Graph { nodes: GraphNode[]; edges: GraphEdge[] }

export interface AuditEntry {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  target_type: string;
  target_id: string;
  details: Record<string, unknown>;
  entry_hash: string;
}

export interface Run {
  id: string;
  kind: string;
  status: "queued" | "running" | "succeeded" | "failed";
  params: Record<string, unknown>;
  stats: Record<string, any>;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface Report { id: string; kind: string; created_at: string; payload: Record<string, any> }

export interface Overview {
  totals: Record<string, number>;
  event_volume: Record<string, number | string>[];
  latest_event: string | null;
  detections_by_severity: Partial<Record<Severity, number>>;
  detections_by_rule: { rule_id: string; rule_name: string; count: number }[];
  investigations_by_status: Record<string, number>;
  open_investigations_by_severity: Partial<Record<Severity, number>>;
  claim_verdicts: Partial<Record<Verdict, number>>;
  analyses_by_status: Record<string, number>;
  analyses_by_engine: Record<string, number>;
  top_failed_login_sources: { ip: string; count: number }[];
  top_investigations: { id: string; title: string; severity: Severity; score: number; status: string; last_seen: string }[];
  ledger: { seq: number; chain_head: string | null; last_verification: (Record<string, any> & { at: string }) | null };
}

export interface SystemStatus {
  version: string;
  database: string;
  auth_required: boolean;
  background_jobs: boolean;
  llm: {
    reachable: boolean;
    model_available?: boolean;
    models?: string[];
    error?: string | null;
    disabled?: boolean;
    mode: string;
    url: string;
    configured_model: string;
  };
}
