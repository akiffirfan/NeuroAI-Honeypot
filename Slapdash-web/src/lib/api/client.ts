const API_BASE = "/api/v2";

type ApiError = { status: number; detail: string; data?: unknown };

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {}),
    },
    ...options,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const raw = body.detail;
    let detail: string;
    if (typeof raw === "string") {
      detail = raw;
    } else if (Array.isArray(raw)) {
      // FastAPI 422 validation errors: [{loc, msg, type}]
      detail = raw.map((d: Record<string, unknown>) => d?.msg ?? String(d)).join("; ");
    } else if (raw != null && typeof raw === "object") {
      // HTTPException(detail={error, message}) pattern
      const r = raw as Record<string, unknown>;
      detail = String(r.message ?? r.error ?? res.statusText);
    } else {
      detail = res.statusText;
    }
    const err: ApiError = { status: res.status, detail, data: body };
    throw err;
  }
  return res.json() as Promise<T>;
}

export function isApiError(e: unknown): e is ApiError {
  return (
    typeof e === "object" && e !== null && "status" in e && "detail" in e
  );
}
