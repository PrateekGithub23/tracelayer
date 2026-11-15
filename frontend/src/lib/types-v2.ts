// v2 types: accounts, sessions, administration, case collaboration, datasets and LLM status.
// Mirrors backend/app/api/{auth,admin,cases,datasets,llm}.py.

export type Role = "admin" | "analyst" | "viewer";

export interface UserInfo {
  id: string; email: string; display_name: string; role: Role; status: "active" | "disabled";
  must_change_password: boolean; is_demo: boolean; created_at: string; last_login_at: string | null;
  password_changed_at: string;
}

export interface Me {
  user: UserInfo;
  permissions: string[];
  csrf_token: string;
  session: { id: string; created_at: string; expires_at: string; absolute_expires_at: string };
}

export interface AuthConfig { registration_mode: "disabled" | "invite" | "open"; has_users: boolean; cookie_secure: boolean; demo?: boolean }

export interface SessionInfo {
  id: string; created_at: string; last_seen_at: string; expires_at: string; revoked_at: string | null;
  revoked_reason: string | null; ip: string | null; user_agent: string | null; current: boolean; active: boolean;
}

export interface LoginRecord { id: number; created_at: string; success: boolean; reason: string; ip: string | null; user_agent: string | null }

export interface AdminUser extends UserInfo { active_sessions?: number }

export interface Invitation {
  id: string; email: string | null; role: Role; created_at: string; expires_at: string; used_at: string | null;
  revoked_at: string | null; state?: "pending" | "used" | "revoked" | "expired";
}

export interface AppSettings {
  registration_mode: "disabled" | "invite" | "open"; llm_mode: "auto" | "ollama" | "deterministic"; ollama_model: string;
  ollama_url: string; ollama_timeout_s: number; session_idle_minutes: number; session_absolute_hours: number;
  cookie_secure: boolean; allow_synthetic: boolean; env: string;
}

export interface Queues { open: number; mine: number; needs_review: number; unassigned: number }

export interface ActivityEntry {
  id: number; timestamp: string; actor: string; action: string; target_id: string;
  details: Record<string, any>; comment: string | null; entry_hash: string;
}

export interface CaseComment {
  id: string; kind: "comment" | "note"; author_id: string; author_name: string | null; body: string | null;
  created_at: string; edited_at: string | null; deleted: boolean;
}

export interface PinnedEvidence {
  event_id: string; note: string | null; added_by: string | null; created_at: string; event_type: string;
  timestamp: string; host: string | null; username: string | null; content_hash: string;
}

export interface DirectoryUser { id: string; display_name: string; role: Role; assignable: boolean }

export interface SavedFilter { id: string; name: string; scope: "investigations" | "events"; params: Record<string, any>; created_at: string }

export interface DatasetInfo {
  id: string; name: string; source_url: string; license: string; license_url: string; description: string;
  attribution: string; environment: string; labels: string; redistribution: string; format: string;
  expected_sha256: string; status: string; event_count: number | null; imported_at: string | null;
  processing_ms: number | null; batch_ids: string[]; field_mapping: { source: string; target: string; note?: string }[];
  results: Record<string, any> | null; local_file_present?: boolean; error?: string | null;
  role: "development" | "held-out"; techniques: string[]; duplicates?: number | null; rejected?: number | null;
  archive_sha256?: string | null; import_id?: string | null;
}

export interface LlmStatus {
  mode: string; configured_model: string; url: string; reachable: boolean; model_available: boolean;
  models: string[]; version?: string | null; error?: string | null; timeout_s: number; last_latency_ms?: number | null;
}
