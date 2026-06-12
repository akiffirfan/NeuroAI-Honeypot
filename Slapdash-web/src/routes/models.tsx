import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { useQuery } from "@tanstack/react-query";
import { fetchModels, type Model } from "@/lib/api/data";
import { useState } from "react";
import { Search } from "lucide-react";
import { DriftChart } from "@/components/DriftChart";

export const Route = createFileRoute("/models")({
  component: ModelsPage,
  head: () => ({ meta: [{ title: "Models — Neuro" }] }),
});

const STATUS_BADGE: Record<string, string> = {
  Healthy: "nro-badge--accent",
  "Drift Alert": "nro-badge--danger",
  Degraded: "nro-badge--amber",
};

function driftColor(d: number) {
  if (d < 0.1) return "var(--accent)";
  if (d < 0.25) return "var(--amber)";
  return "var(--danger)";
}

function ModelsPage() {
  const { data: models = [], isLoading } = useQuery({
    queryKey: ["models"],
    queryFn: fetchModels,
  });
  const [open, setOpen] = useState<string | null>(null);
  const [tab, setTab] = useState<"history" | "config" | "alerts">("history");
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();

  const filtered = models.filter(
    (m: Model) =>
      !q ||
      m.model_name.toLowerCase().includes(q) ||
      m.customer.toLowerCase().includes(q) ||
      m.version.toLowerCase().includes(q),
  );

  return (
    <AppLayout title="Models">
      <AppPageHeader
        title="Models registry."
        description="Every deployed model with live drift scoring, baseline configuration, and routed alert channels. Click a row to inspect its 30-day drift history."
      />
      <div className="mb-4 relative max-w-md">
        <Search
          size={14}
          className="absolute left-3 top-1/2 -translate-y-1/2 text-[color:var(--text-secondary)]"
        />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search by model, version, or customer…"
          className="w-full pl-9 pr-3 py-2 rounded-md bg-[color:var(--elevated)] border border-[color:var(--border)] text-[13px] text-white placeholder:text-[color:var(--text-secondary)] focus:outline-none focus:border-[color:var(--accent)]"
        />
      </div>
      {isLoading ? (
        <div className="nro-card p-8 text-center text-[14px] text-[color:var(--text-secondary)]">
          Loading…
        </div>
      ) : (
        <div className="nro-card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr>
                {[
                  "Model Name",
                  "Version",
                  "Customer",
                  "Status",
                  "Last Drift Check",
                  "Drift Score",
                  "Action",
                ].map((h) => (
                  <th key={h} className="nro-th">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((m: Model) => (
                <>
                  <tr
                    key={m.model_name}
                    className="nro-row cursor-pointer"
                    onClick={() =>
                      setOpen(open === m.model_name ? null : m.model_name)
                    }
                  >
                    <td className="nro-td font-mono text-[13px]">
                      {m.model_name}
                    </td>
                    <td className="nro-td">{m.version}</td>
                    <td className="nro-td">{m.customer}</td>
                    <td className="nro-td">
                      <span
                        className={`nro-badge ${STATUS_BADGE[m.status] ?? "nro-badge--slate"}`}
                      >
                        {m.status}
                      </span>
                    </td>
                    <td className="nro-td text-[color:var(--text-secondary)]">
                      {m.last_check
                        ? m.last_check.replace("T", " ").slice(0, 16)
                        : "—"}
                    </td>
                    <td
                      className="nro-td font-bold"
                      style={{
                        color: driftColor(m.drift_score ?? 0),
                      }}
                    >
                      {m.drift_score != null
                        ? m.drift_score.toFixed(2)
                        : "—"}
                    </td>
                    <td className="nro-td">
                      <button className="nro-btn-secondary !py-1 !px-3 text-[12px]">
                        {open === m.model_name ? "Hide" : "Inspect"}
                      </button>
                    </td>
                  </tr>
                  {open === m.model_name && (
                    <tr key={m.model_name + "-detail"}>
                      <td
                        colSpan={7}
                        className="border-t border-[color:var(--border)] bg-[color:var(--canvas)] p-6"
                      >
                        <div className="flex gap-6 border-b border-[color:var(--border)] mb-4">
                          {(
                            [
                              ["history", "Drift History"],
                              ["config", "Configuration"],
                              ["alerts", "Alerts"],
                            ] as const
                          ).map(([k, l]) => (
                            <button
                              key={k}
                              onClick={() => setTab(k)}
                              className="pb-2 text-[14px] border-b-2"
                              style={{
                                borderColor:
                                  tab === k ? "var(--accent)" : "transparent",
                                color:
                                  tab === k ? "white" : "var(--text-secondary)",
                              }}
                            >
                              {l}
                            </button>
                          ))}
                        </div>
                        {tab === "history" && (
                          <DriftChart
                            modelName={m.model_name}
                            drift={m.drift_score ?? 0}
                            threshold={0.15}
                          />
                        )}
                        {tab === "config" && (
                          <pre
                            className="font-mono text-[12px] p-4 rounded-md"
                            style={{ background: "var(--surface)" }}
                          >
                            {`baseline_dataset: vantara-biometric-train-v3\ndrift_metric: cosine_similarity\nthreshold: 0.15\ncheck_interval_hours: 2\nalert_channels: [slack-#ml-alerts, pagerduty-oncall]`}
                          </pre>
                        )}
                        {tab === "alerts" && (
                          <div className="text-[14px] text-[color:var(--text-secondary)]">
                            No active alert rules beyond the defaults above.
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </AppLayout>
  );
}
