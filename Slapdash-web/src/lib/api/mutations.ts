import { apiFetch } from "./client";

export async function submitJob(payload: {
  job_name: string;
  base_model: string;
  gpu_allocation: string;
  startup_script?: string;
  description?: string;
  _csrf?: string;
}) {
  return apiFetch<{ status: string; job_id: string; run_id: string }>(
    "/training/jobs",
    { method: "POST", body: JSON.stringify(payload) },
  );
}

export async function createApiKey(payload: {
  name: string;
  scope: string;
  _csrf?: string;
}) {
  return apiFetch<{
    status: string;
    key: {
      id: number;
      name: string;
      key_prefix: string;
      key_masked: string;
      key_full: string;
      scope: string;
      created_at: string;
      last_used_at: string | null;
    };
  }>("/api-keys", { method: "POST", body: JSON.stringify(payload) });
}

export async function revokeApiKey(payload: {
  key_id: number;
  _csrf?: string;
}) {
  return apiFetch<{ status: string }>("/api-keys/revoke", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function testWebhook(payload: { url: string; _csrf?: string }) {
  return apiFetch<{
    status: string;
    http_status?: number;
    error?: string;
    relay?: string;
    relay_node?: string;
    latency_ms?: number;
  }>("/integrations/webhook/test", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function importDataset(payload: {
  url: string;
  dataset_name: string;
  format: string;
  _csrf?: string;
}) {
  return apiFetch<{ status: string; job_id: string; estimated_completion?: string }>(
    "/data/import",
    { method: "POST", body: JSON.stringify(payload) },
  );
}

export async function inviteTeamMember(payload: {
  email: string;
  role: string;
  _csrf?: string;
}) {
  return apiFetch<{ status: string; email: string }>("/team/invite", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function removeTeamMember(payload: {
  email: string;
  _csrf?: string;
}) {
  return apiFetch<{ status: string }>("/team/remove", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function submitSshKey(payload: {
  name: string;
  key: string;
  _csrf?: string;
}) {
  return apiFetch<{ status: string; name: string; fingerprint: string; added_at: string; message: string }>("/profile/ssh-keys", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function toggleMfa(payload: {
  password: string;
  _csrf?: string;
}) {
  return apiFetch<{ error?: string; message?: string }>("/security/mfa/toggle", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function revokeSession(payload: {
  session_id: string;
  _csrf?: string;
}) {
  return apiFetch<{ status: string }>("/security/session/revoke", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function addAllowlistEntry(payload: {
  cidr: string;
  description: string;
  _csrf?: string;
}) {
  return apiFetch<{ status: string; message: string }>("/security/allowlist/add", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function toggleAllowlist(payload: {
  enabled: boolean;
  _csrf?: string;
}) {
  return apiFetch<{ status: string; message: string }>("/security/allowlist/toggle", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateProfile(payload: {
  full_name: string;
  display_name: string;
  timezone: string;
  language: string;
  _csrf?: string;
}) {
  return apiFetch<{ status: string; display_name: string; full_name: string; timezone: string; language: string }>(
    "/profile/update",
    { method: "POST", body: JSON.stringify(payload) },
  );
}

export async function rotateKeys(payload: { _csrf?: string } = {}) {
  return apiFetch<{ status: string; affected_keys: number; note: string }>(
    "/security/keys/rotate",
    { method: "POST", body: JSON.stringify(payload) },
  );
}

export async function adminTenantAction(
  action: string,
  body: Record<string, unknown> = {},
) {
  return apiFetch<{
    error: string;
    message: string;
    requires: string;
    incident_ref: string;
  }>(`/admin/tenant/${action}`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}
