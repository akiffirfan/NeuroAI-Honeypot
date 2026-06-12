import { apiFetch } from "./client";

export type Run = {
  run_id: string;
  model_name: string;
  status: string;
  duration_min: number | null;
  gpu_hours: number | null;
  started_by: string;
  started_at: string;
  error_log: string | null;
};

export type Model = {
  model_name: string;
  version: string;
  customer: string;
  status: string;
  drift_score: number | null;
  last_check: string;
};

export type Dataset = {
  name: string;
  source: string;
  format: string;
  row_count: string;
  size_display: string;
  uploaded_at: string;
  tags: string[];
};

export type Notification = {
  id: number;
  severity: string;
  title: string;
  body: string;
  created_at: string;
  is_read: boolean;
};

export type TeamMember = {
  email: string;
  role: string;
  display_name: string;
  last_active: string | null;
};

export type ApiKey = {
  id: number;
  name: string;
  key_prefix: string;
  key_masked: string;
  key_full: string;
  scope: string;
  created_at: string;
  last_used_at: string | null;
};

export type ArtifactEntry = {
  name: string;
  size: string;
  modified: string;
  type: string;
  checksum?: string;
};

export const fetchRuns = async (): Promise<Run[]> => {
  const r = await apiFetch<{ runs: Run[] } | Run[]>("/runs");
  return (Array.isArray(r) ? r : (r as any).runs) ?? [];
};
export const fetchModels = async (): Promise<Model[]> => {
  const r = await apiFetch<{ models: Model[] } | Model[]>("/models");
  return (Array.isArray(r) ? r : (r as any).models) ?? [];
};
export const fetchDatasets = async (): Promise<Dataset[]> => {
  const r = await apiFetch<{ datasets: Dataset[] } | Dataset[]>("/datasets");
  return (Array.isArray(r) ? r : (r as any).datasets) ?? [];
};
export const fetchNotifications = async (): Promise<Notification[]> => {
  const r = await apiFetch<{ notifications: Notification[] } | Notification[]>("/notifications");
  return (Array.isArray(r) ? r : (r as any).notifications) ?? [];
};
export const fetchTeam = async (): Promise<TeamMember[]> => {
  const r = await apiFetch<{ members: TeamMember[] } | TeamMember[]>("/team");
  return (Array.isArray(r) ? r : (r as any).members) ?? [];
};
export const fetchApiKeys = async (): Promise<ApiKey[]> => {
  const r = await apiFetch<{ apiKeys: ApiKey[] } | ApiKey[]>("/api-keys");
  return (Array.isArray(r) ? r : (r as any).apiKeys) ?? [];
};
export const fetchArtifacts = async (path?: string): Promise<ArtifactEntry[]> => {
  const r = await apiFetch<{ artifacts: ArtifactEntry[] } | ArtifactEntry[]>(
    `/artifacts${path ? `?path=${encodeURIComponent(path)}` : ""}`
  );
  return (Array.isArray(r) ? r : (r as any).artifacts ?? (r as any).entries) ?? [];
};

export type AllowlistEntry = { cidr: string; description: string; active: boolean };
export type AllowlistState = { enabled: boolean; entries: AllowlistEntry[] };

export const fetchAllowlist = async (): Promise<AllowlistState> =>
  apiFetch<AllowlistState>("/security/allowlist");

export type SshKey = {
  name: string;
  fingerprint: string;
  added_at: string | null;
  last_used_at: string | null;
};

export const fetchSshKeys = async (): Promise<SshKey[]> => {
  const r = await apiFetch<{ keys: SshKey[] }>("/profile/ssh-keys");
  return r.keys ?? [];
};
