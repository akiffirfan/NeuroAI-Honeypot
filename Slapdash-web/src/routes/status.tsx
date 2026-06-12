import { createFileRoute } from "@tanstack/react-router";
import { MarketingLayout } from "@/components/layouts/MarketingLayout";
import { PageHero } from "@/components/ui/PageHero";

export const Route = createFileRoute("/status")({
  component: StatusPage,
  head: () => ({
    meta: [
      { title: "System Status — Neuro" },
      { name: "description", content: "Real-time status for all Neuro platform services." },
    ],
  }),
});

function StatusPage() {
  return (
    <MarketingLayout>
      <PageHero
        title={
          <>
            All systems{" "}
            <span className="text-[color:var(--accent)]">operational.</span>
          </>
        }
        description="Real-time health for every Neuro platform service. Subscribe to incident notifications at status@cyveera.ai."
      >
        <div className="inline-flex items-center gap-3 nro-card px-5 py-3 bg-[color:var(--surface)]/70 backdrop-blur">
          <span
            className="w-3 h-3 rounded-full nro-pulse-dot"
            style={{ background: "var(--accent)" }}
          />
          <span className="text-[13px] text-[color:var(--text-secondary)]">
            Last probe 4 min ago · 99.94% uptime over the last 30 days
          </span>
        </div>
      </PageHero>

      <div className="mx-auto max-w-[960px] px-6" style={{ paddingTop: 48, paddingBottom: 80 }}>


        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-8">
          <ServiceCard
            color="accent"
            name="Training API"
            statusLabel="Operational"
            lines={[
              "99.94% (30 days)",
              <span key="ep" className="font-mono">api.neuro.cyveera.com</span>,
              "avg 142ms (p95: 380ms)",
            ]}
          />
          <ServiceCard
            color="accent"
            name="GPU Cluster (neuro-train-01/02)"
            statusLabel="Operational"
            lines={[
              "8× NVIDIA A100 80GB · 3 active training jobs · 71% VRAM utilization.",
              <span key="m1" className="font-mono text-[12px]">neuro-svc@neuro-train-01.internal</span>,
              <span key="m2" className="font-mono text-[11px]">mgmt: neuro-svc@10.31.4.22</span>,
            ]}
          />
          <ServiceCard
            color="accent"
            name="Data Pipeline"
            statusLabel="Operational"
            lines={[
              "Kafka ingestion · 1.2M events/hr · 0 consumer lag.",
              "Primary region: us-east-1",
            ]}
          />
          <ServiceCard
            color="amber"
            name="Auth Service"
            statusLabel="Degraded"
            lines={[
              "Google Workspace SSO experiencing elevated latency. Password auth unaffected.",
              "See INC-2026-047 below.",
              <span key="sa" className="font-mono text-[12px]">svc-deploy@neuro.cyveera.com</span>,
            ]}
          />
        </div>

        <h2 className="font-bold mt-12" style={{ fontSize: 20 }}>
          Incident History (30 days)
        </h2>
        <div className="mt-4 space-y-4">
          <Incident
            color="amber"
            code="INC-2026-047"
            title="Auth Service SSO Elevated Latency"
            date="2026-06-03 18:42 UTC"
            status="Ongoing — Monitoring"
            body="Google OAuth callback latency spiked to 8.2s for EU-region logins. Password authentication unaffected. Root cause: upstream Google Workspace rate limiting. Engineering investigating."
          />
          <Incident
            color="accent"
            code="INC-2026-031"
            title="GPU Node Memory Fault"
            date="2026-05-28 03:14 UTC → Resolved 2026-05-28 05:51 UTC"
            status="Resolved"
            body="neuro-train-01 experienced a CUDA OOM condition during the Ardentix nightly fine-tune job. Node rebooted and returned to service. Job re-queued automatically. No data loss."
          />
          <Incident
            color="accent"
            code="INC-2026-019"
            title="Data Pipeline Consumer Lag"
            date="2026-05-11 14:28 UTC → Resolved 2026-05-11 16:05 UTC"
            status="Resolved"
            body="Kafka consumer group fell behind by ~4 minutes during a dataset import spike from Vantara Health. Lag cleared after partition rebalancing."
          />
        </div>

        <p className="text-center mt-12 text-[12px] text-[color:var(--text-secondary)]">
          Neuro Status · Powered by Cyveera Infrastructure · Incident
          notifications: status@cyveera.ai
        </p>
      </div>
    </MarketingLayout>
  );
}

function ServiceCard({
  color,
  name,
  statusLabel,
  lines,
}: {
  color: "accent" | "amber" | "danger";
  name: string;
  statusLabel: string;
  lines: React.ReactNode[];
}) {
  const badgeClass =
    color === "accent" ? "nro-badge--accent" : color === "amber" ? "nro-badge--amber" : "nro-badge--danger";
  const dotColor = `var(--${color})`;
  return (
    <div className="nro-card p-5">
      <div className="flex items-center gap-3">
        <span
          className="rounded-full"
          style={{ width: 14, height: 14, background: dotColor }}
        />
        <div className="flex-1 font-bold text-[16px]">{name}</div>
        <span className={`nro-badge ${badgeClass}`}>{statusLabel}</span>
      </div>
      <div className="mt-3 space-y-1">
        {lines.map((l, i) => (
          <div key={i} className="text-[13px] text-[color:var(--text-secondary)]">
            {l}
          </div>
        ))}
      </div>
    </div>
  );
}

function Incident({
  color,
  code,
  title,
  date,
  status,
  body,
}: {
  color: "accent" | "amber" | "danger";
  code: string;
  title: string;
  date: string;
  status: string;
  body: string;
}) {
  const borderColor = `var(--${color})`;
  const badge =
    color === "accent" ? "nro-badge--accent" : color === "amber" ? "nro-badge--amber" : "nro-badge--danger";
  return (
    <div
      className="nro-card p-5"
      style={{ borderLeft: `4px solid ${borderColor}` }}
    >
      <div className="flex flex-wrap items-center gap-3">
        <div className="font-bold text-[15px]">
          {code}: {title}
        </div>
        <span className={`nro-badge ${badge}`}>{status}</span>
      </div>
      <div className="text-[12px] text-[color:var(--text-secondary)] mt-1">{date}</div>
      <p className="mt-3 text-[14px] text-[color:var(--text-primary)]">{body}</p>
    </div>
  );
}
