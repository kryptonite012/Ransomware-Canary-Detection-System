export type Role = "admin" | "analyst" | "viewer";
export type RiskLevel = "normal" | "low" | "elevated" | "high" | "critical";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface User {
  id: number; username: string; email: string; role: Role;
  is_active: boolean; last_login: string | null; created_at: string;
}
export interface TokenResponse {
  access_token: string; refresh_token: string; token_type: string;
  expires_at: string; user: User;
}
export interface Overview {
  status: string; risk_score: number; risk_level: RiskLevel; risk_details: RiskDetails | null;
  endpoints_total: number; endpoints_online: number; monitored_files: number;
  files_modified_last_hour: number; active_canaries: number; triggered_canaries: number;
  suspicious_processes: number; total_alerts: number; open_alerts: number; alerts_last_24h: number;
  open_incidents: number; protected_directories: number; monitored_directories: number;
  generated_at: string;
}
export interface RiskContribution {
  signal_type: string; points: number; base_weight: number; count: number;
  description: string; severity_hint: string; age_seconds: number; evidence: Record<string, unknown>;
}
export interface RiskDetails {
  score: number; level: RiskLevel; peak_score: number; peak_level: RiskLevel;
  active_signals: RiskContribution[]; correlation_bonus: number; distinct_signals: number;
}
export interface Endpoint {
  id: number; hostname: string; operating_system: string; agent_version: string;
  status: string; last_seen: string | null; current_risk_score: number;
  current_risk_level: RiskLevel; policy_version: number | null;
}
export interface AgentHealth {
  id: number; hostname: string; operating_system: string; agent_version: string;
  status: string; last_seen: string | null; risk_score: number; risk_level: RiskLevel;
  health: Record<string, any> | null; capabilities: Record<string, any> | null;
  policy_version: number | null;
}
export interface Directory {
  id: number; endpoint_id: number; directory_path: string; recursive: boolean;
  monitoring_enabled: boolean; status: string; status_detail: string | null;
  protected: boolean; created_at: string;
}
export interface Canary {
  id: number; endpoint_id: number; file_path: string; directory: string; canary_type: string;
  status: string; last_verified: string | null; last_interaction: string | null;
  last_interaction_type: string | null; trigger_count: number; generation: number; created_at: string;
}
export interface Alert {
  id: number; endpoint_id: number; incident_id: number | null; alert_type: string;
  severity: Severity; risk_score: number; risk_level: RiskLevel | null; title: string;
  description: string; signals: RiskContribution[] | null; file_paths: string[] | null;
  process_info: Record<string, any> | null; timestamp: string; status: string; feedback: string | null;
}
export interface FileEvent {
  id: number; file_path: string; dest_path: string | null; event_type: string;
  process_id: number | null; process_name: string | null; attribution: string | null;
  file_size: number | null; timestamp: string;
}
export interface EntropyRow {
  id: number; file_path: string; file_category: string | null; previous_entropy: number | null;
  current_entropy: number; entropy_delta: number | null; max_chunk_entropy: number | null;
  magic_ok: boolean | null; suspicious: boolean; reason: string | null; timestamp: string;
}
export interface ProcessRow {
  id: number; process_id: number; process_name: string; executable_path: string | null;
  parent_process_id: number | null; username: string | null; is_running: boolean;
  cpu_percent: number | null; memory_rss: number | null; write_bytes_rate: number | null;
  files_modified: number; suspicious: boolean; risk_score: number;
  suspicion_reasons: string[] | null; first_seen: string; last_seen: string;
}
export interface Incident {
  id: number; endpoint_id: number; title: string; severity: Severity; risk_score: number;
  summary: string | null; affected_files: string[] | null; affected_directories: string[] | null;
  affected_processes: Record<string, any>[] | null; signals: RiskContribution[] | null;
  response_status: string; response_level: string | null; created_at: string; updated_at: string;
  resolution_note: string | null;
}
export interface ResponseAction {
  id: number; endpoint_id: number; incident_id: number | null; response_level: string;
  action_type: string; target: Record<string, any> | null; status: string;
  requires_approval: boolean; requested_by: string; reason: string | null;
  result: Record<string, any> | null; created_at: string; executed_at: string | null;
  expires_at: string | null;
}
export interface Evidence {
  id: number; incident_id: number | null; item_type: string; original_path: string | null;
  sha256: string | null; size: number | null; details: Record<string, any> | null; created_at: string;
}
export interface IncidentDetail {
  incident: Incident; alerts: Alert[]; actions: ResponseAction[]; evidence: Evidence[];
}
export interface Statistics {
  window_hours: number;
  event_type_distribution: Record<string, number>;
  alert_severity_distribution: Record<string, number>;
  alert_type_distribution: Record<string, number>;
  file_category_distribution: Record<string, number>;
  generated_at: string;
}
export interface ActivityPoint {
  bucket_start: string; events: number; alerts: number; critical_alerts: number;
}
