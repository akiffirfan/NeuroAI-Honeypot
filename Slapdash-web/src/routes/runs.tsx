import { createFileRoute, Link } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { RunsTable } from "@/components/RunsTable";
import { useQuery } from "@tanstack/react-query";
import { fetchRuns, type Run } from "@/lib/api/data";
import { Search, Zap } from "lucide-react";
import { useState } from "react";

export const Route = createFileRoute("/runs")({
  component: RunsPage,
  head: () => ({ meta: [{ title: "Runs — Neuro" }] }),
});

const FILTERS = ["All", "Running", "Completed", "Failed", "Queued"];

function RunsPage() {
  const { data: runsData = [], isLoading } = useQuery({
    queryKey: ["runs"],
    queryFn: fetchRuns,
  });
  const [filter, setFilter] = useState("All");
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();

  const runs = runsData.filter((r: Run) => {
    const matchesFilter = filter === "All" || r.status === filter;
    const matchesQuery =
      !q ||
      r.run_id.toLowerCase().includes(q) ||
      r.model_name.toLowerCase().includes(q) ||
      r.started_by.toLowerCase().includes(q);
    return matchesFilter && matchesQuery;
  });

  const counts = FILTERS.reduce<Record<string, number>>((acc, f) => {
    acc[f] =
      f === "All"
        ? runsData.length
        : runsData.filter((r: Run) => r.status === f).length;
    return acc;
  }, {});

  return (
    <AppLayout title="Training Runs">
      <AppPageHeader
        title="Training runs."
        description="Every fine-tune, eval, and re-baseline launched in this workspace. Filter by status and dive into any run for full GPU + loss telemetry."
        actions={
          <Link
            to="/jobs"
            className="nro-btn-primary text-sm inline-flex items-center gap-1.5"
          >
            <Zap size={14} /> New run
          </Link>
        }
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
          placeholder="Search by run ID, model, or user…"
          className="w-full pl-9 pr-3 py-2 rounded-md bg-[color:var(--elevated)] border border-[color:var(--border)] text-[13px] text-white placeholder:text-[color:var(--text-secondary)] focus:outline-none focus:border-[color:var(--accent)]"
        />
      </div>
      <div className="flex flex-wrap gap-2 mb-6">
        {FILTERS.map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-4 py-1.5 rounded-full text-[13px] border inline-flex items-center gap-2 transition-colors ${
              filter === f
                ? "bg-[color:var(--accent)] text-white border-[color:var(--accent)]"
                : "border-[color:var(--border)] text-[color:var(--text-secondary)] hover:text-white hover:border-[color:var(--accent)]/50"
            }`}
          >
            {f}
            <span
              className={`text-[11px] px-1.5 py-0.5 rounded-full ${
                filter === f
                  ? "bg-white/20 text-white"
                  : "bg-[color:var(--elevated)] text-[color:var(--text-secondary)]"
              }`}
            >
              {counts[f] ?? 0}
            </span>
          </button>
        ))}
      </div>
      {isLoading ? (
        <div className="nro-card p-8 text-center text-[14px] text-[color:var(--text-secondary)]">
          Loading…
        </div>
      ) : (
        <RunsTable runs={runs} />
      )}
    </AppLayout>
  );
}
