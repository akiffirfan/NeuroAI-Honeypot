import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { RunsTable } from "@/components/RunsTable";
import { useQuery } from "@tanstack/react-query";
import { fetchRuns, type Run } from "@/lib/api/data";
import { Activity, Cpu, Database, Play, Zap } from "lucide-react";
import { Link } from "@tanstack/react-router";
import { useRef, useState } from "react";

export const Route = createFileRoute("/dashboard")({
  component: DashboardPage,
  head: () => ({ meta: [{ title: "Dashboard — Neuro" }] }),
});

function DashboardPage() {
  const { data: runsData } = useQuery({ queryKey: ["runs"], queryFn: fetchRuns });
  const runs: Run[] = (runsData ?? []).slice(0, 8);
  return (
    <AppLayout title="Dashboard">
      <AppPageHeader
        title="Mission control."
        description="Live status across every training run, production endpoint, and dataset ingestion pipeline in your workspace."
        actions={
          <>
            <Link to="/jobs" className="nro-btn-secondary text-sm inline-flex items-center gap-1.5">
              <Zap size={14} /> New job
            </Link>
            <Link to="/runs" className="nro-btn-primary text-sm">
              View all runs
            </Link>
          </>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <KpiCard
          Icon={Play}
          accent="var(--accent)"
          number="7"
          label="Active training runs"
          subtext="Running across 2 clusters"
          subColor="var(--accent)"
        >
          <VolumeBars
            data={[3, 5, 2, 6, 4, 5, 7]}
            labels={["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Today"]}
            accent="var(--accent)"
          />
        </KpiCard>

        <KpiCard
          Icon={Cpu}
          accent="var(--amber)"
          number="12"
          label="Models in production"
          subtext="2 with drift alerts"
          subColor="var(--amber)"
        >
          <HealthBar healthy={10} alerts={2} />
        </KpiCard>

        <KpiCard
          Icon={Database}
          accent="var(--accent)"
          number="14.2 GB"
          label="Data ingested (7 days)"
          subtext="↑ 4.1 GB from prior week"
          subColor="var(--accent)"
        >
          <StepArea
            data={[2.1, 2.1, 5.4, 5.4, 5.4, 9.8, 14.2]}
            labels={["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Today"]}
            accent="var(--accent)"
          />
        </KpiCard>
      </div>

      <div className="mt-10 flex items-center justify-between">
        <div>
          <div className="nro-section-label flex items-center gap-2">
            <Activity size={12} /> Recent activity
          </div>
          <h2 className="font-bold text-[18px] mt-1.5">Latest training runs</h2>
        </div>
        <Link to="/runs" className="text-[13px] text-[color:var(--text-secondary)] hover:text-white">
          See all →
        </Link>
      </div>
      <div className="mt-4">
        <RunsTable runs={runs} />
      </div>
    </AppLayout>
  );
}

function KpiCard({
  Icon,
  accent,
  number,
  label,
  subtext,
  subColor,
  children,
}: {
  Icon: React.ComponentType<{ size?: number; className?: string }>;
  accent: string;
  number: string;
  label: string;
  subtext: string;
  subColor: string;
  children: React.ReactNode;
}) {
  return (
    <div className="nro-card nro-card-hover p-6 flex flex-col gap-5">
      <div className="flex items-center gap-3">
        <div
          className="inline-flex items-center justify-center rounded-lg shrink-0"
          style={{
            width: 32,
            height: 32,
            background: `color-mix(in oklab, ${accent} 12%, transparent)`,
            color: accent,
            border: `1px solid color-mix(in oklab, ${accent} 22%, transparent)`,
          }}
        >
          <Icon size={16} />
        </div>
        <div
          className="text-[11px] uppercase tracking-[0.12em] text-[color:var(--text-secondary)]"
        >
          {label}
        </div>
      </div>

      <div
        className="font-bold text-white"
        style={{ fontSize: 44, lineHeight: 1, letterSpacing: "-0.03em" }}
      >
        {number}
      </div>

      <div className="mt-auto">{children}</div>

      <div className="text-[12px]" style={{ color: subColor }}>
        {subtext}
      </div>
    </div>
  );
}

/* ---------- Card 1: 7-day volume bars ---------- */
function VolumeBars({
  data,
  labels,
  accent,
}: {
  data: number[];
  labels: string[];
  accent: string;
}) {
  const max = Math.max(...data, 1);
  const [hover, setHover] = useState<number | null>(null);
  return (
    <div className="relative h-12">
      <div className="flex items-end gap-1.5 h-full">
        {data.map((v, i) => {
          const isToday = i === data.length - 1;
          const h = (v / max) * 100;
          const active = hover === i;
          return (
            <div
              key={i}
              className="flex-1 h-full flex items-end cursor-default"
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(null)}
            >
              <div
                className="w-full rounded-sm transition-all"
                style={{
                  height: `${h}%`,
                  background: isToday ? accent : "var(--elevated)",
                  border: isToday
                    ? "none"
                    : "1px solid color-mix(in oklab, var(--text-secondary) 20%, transparent)",
                  opacity: active ? 1 : isToday ? 1 : 0.85,
                  boxShadow: active && isToday ? `0 0 12px ${accent}` : "none",
                }}
              />
            </div>
          );
        })}
      </div>
      {hover != null && (
        <div
          className="absolute -top-7 px-2 py-1 rounded-md text-[11px] font-mono whitespace-nowrap pointer-events-none"
          style={{
            left: `${((hover + 0.5) / data.length) * 100}%`,
            transform: "translateX(-50%)",
            background: "var(--elevated)",
            border: "1px solid var(--border)",
            color: "var(--text-primary)",
          }}
        >
          {labels[hover]}: {data[hover]} runs
        </div>
      )}
    </div>
  );
}

/* ---------- Card 2: Health distribution bar ---------- */
function HealthBar({ healthy, alerts }: { healthy: number; alerts: number }) {
  const total = healthy + alerts;
  const healthyPct = (healthy / total) * 100;
  const alertPct = (alerts / total) * 100;
  const [hover, setHover] = useState<"healthy" | "alerts" | null>(null);
  return (
    <div className="relative">
      <div
        className="flex h-2 w-full rounded-full overflow-hidden"
        style={{ background: "var(--elevated)" }}
      >
        <div
          style={{ width: `${healthyPct}%`, background: "var(--accent)" }}
          onMouseEnter={() => setHover("healthy")}
          onMouseLeave={() => setHover(null)}
          className="transition-all hover:brightness-110"
        />
        <div
          style={{ width: `${alertPct}%`, background: "var(--amber)" }}
          onMouseEnter={() => setHover("alerts")}
          onMouseLeave={() => setHover(null)}
          className="transition-all hover:brightness-110"
        />
      </div>
      <div className="mt-3 flex items-center justify-between text-[11px] text-[color:var(--text-secondary)]">
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full" style={{ background: "var(--accent)" }} />
          {healthy} healthy
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full" style={{ background: "var(--amber)" }} />
          {alerts} drift alert{alerts === 1 ? "" : "s"}
        </span>
      </div>
      {hover && (
        <div
          className="absolute -top-8 px-2 py-1 rounded-md text-[11px] font-mono whitespace-nowrap pointer-events-none"
          style={{
            left: hover === "healthy" ? `${healthyPct / 2}%` : `${healthyPct + alertPct / 2}%`,
            transform: "translateX(-50%)",
            background: "var(--elevated)",
            border: "1px solid var(--border)",
            color: "var(--text-primary)",
          }}
        >
          {hover === "healthy" ? `${healthy} healthy` : `${alerts} drifting`}
        </div>
      )}
    </div>
  );
}

/* ---------- Card 3: Cumulative step area ---------- */
function StepArea({
  data,
  labels,
  accent,
}: {
  data: number[];
  labels: string[];
  accent: string;
}) {
  const W = 100;
  const H = 36;
  const max = Math.max(...data);
  const min = 0;
  const range = Math.max(1, max - min);
  // Build step path
  const stepPts: { x: number; y: number; v: number; i: number }[] = [];
  data.forEach((v, i) => {
    const x = (i / (data.length - 1)) * W;
    const y = H - ((v - min) / range) * (H - 4) - 2;
    if (i > 0) {
      stepPts.push({ x, y: stepPts[stepPts.length - 1].y, v, i });
    }
    stepPts.push({ x, y, v, i });
  });
  const linePath = stepPts.map((p, i) => `${i === 0 ? "M" : "L"}${p.x},${p.y}`).join(" ");
  const areaPath = `${linePath} L${W},${H} L0,${H} Z`;

  const [hover, setHover] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const gradId = `step-grad-${Math.random().toString(36).slice(2, 8)}`;

  function onMove(e: React.MouseEvent<SVGSVGElement>) {
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const xRel = ((e.clientX - rect.left) / rect.width) * W;
    let nearest = 0;
    let best = Infinity;
    for (let i = 0; i < data.length; i++) {
      const x = (i / (data.length - 1)) * W;
      const d = Math.abs(x - xRel);
      if (d < best) {
        best = d;
        nearest = i;
      }
    }
    setHover(nearest);
  }

  const activeX = hover != null ? (hover / (data.length - 1)) * W : null;
  const activeY =
    hover != null ? H - ((data[hover] - min) / range) * (H - 4) - 2 : null;

  return (
    <div className="relative">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        className="w-full h-12 block"
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
      >
        <defs>
          <linearGradient id={gradId} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={accent} stopOpacity="0.35" />
            <stop offset="100%" stopColor={accent} stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={areaPath} fill={`url(#${gradId})`} />
        <path d={linePath} fill="none" stroke={accent} strokeWidth="1.5" />
        {activeX != null && activeY != null && (
          <>
            <line
              x1={activeX}
              x2={activeX}
              y1={0}
              y2={H}
              stroke="var(--text-secondary)"
              strokeWidth="0.5"
              strokeDasharray="2 2"
              opacity="0.6"
            />
            <circle cx={activeX} cy={activeY} r={2} fill={accent} />
          </>
        )}
      </svg>
      {hover != null && (
        <div
          className="absolute -top-7 px-2 py-1 rounded-md text-[11px] font-mono whitespace-nowrap pointer-events-none"
          style={{
            left: `${(hover / (data.length - 1)) * 100}%`,
            transform: "translateX(-50%)",
            background: "var(--elevated)",
            border: "1px solid var(--border)",
            color: "var(--text-primary)",
          }}
        >
          {labels[hover]}: {data[hover]} GB
        </div>
      )}
    </div>
  );
}
