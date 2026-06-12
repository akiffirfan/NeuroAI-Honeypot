import { apiFetch } from "./client";

export type SessionUser = {
  email: string;
  full_name: string;
  display_name: string;
  role: "customer_user" | "customer_admin" | "cyveera_support";
  ip: string;
  user_agent_parsed: string;
  timezone: string;
  language: string;
  workspace: { id: string; name: string; plan?: string };
  csrf_token?: string;
};

export type LoginResponse = {
  token: string;
  role: string;
  redirect_to: string;
  workspace_id: string;
  expires_at: string;
};

export async function login(email: string, password: string): Promise<LoginResponse> {
  return apiFetch<LoginResponse>("/auth/token", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function logout(): Promise<{ ok: boolean; redirect_to?: string }> {
  return apiFetch("/auth/logout", { method: "GET" });
}

export async function getMe(): Promise<SessionUser> {
  return apiFetch<SessionUser>("/auth/me");
}

export async function initiateSso(): Promise<{ error: string }> {
  return apiFetch<{ error: string }>("/auth/sso/initiate", { method: "POST" });
}
