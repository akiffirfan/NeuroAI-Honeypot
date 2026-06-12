import { apiFetch } from "./client";

export function beacon(event: string, props: Record<string, unknown> = {}) {
  // fire-and-forget — never await, never block UI
  apiFetch("/telemetry", {
    method: "POST",
    body: JSON.stringify({ event, ...props, ts: Date.now() }),
  }).catch(() => {});
}
