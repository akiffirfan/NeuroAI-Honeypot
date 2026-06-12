import { createFileRoute, Link } from "@tanstack/react-router";
import { MarketingLayout } from "@/components/layouts/MarketingLayout";
import {
  Waves,
  Layers,
  Code2,
  Activity,
  Shield,
  GitBranch,
  Zap,
  Terminal,
  ArrowRight,
} from "lucide-react";

export const Route = createFileRoute("/")({
  component: HomePage,
  head: () => ({
    meta: [
      { title: "Neuro by Cyveera — ML Observability for teams shipping LLMs" },
      {
        name: "description",
        content:
          "Your AI models break in production. Neuro tells you first. Drift detection, training pipeline observability, and API-first integration — built for teams running LLMs at scale.",
      },
    ],
  }),
});

function HomePage() {
  return (
    <MarketingLayout>
      <Hero />
      <LogoStrip />
      <MetricStrip />
      <Features />
      <CodeAndDrift />
      <HowItWorks />
      <DashboardPreview />
      <Testimonials />
      <SecurityStrip />
      <FinalCTA />
    </MarketingLayout>
  );
}

/* ---------------- HERO ---------------- */

function Hero() {
  return (
    <section
      className="relative w-full overflow-hidden bg-[color:var(--canvas)]"
      style={{ paddingTop: 140, paddingBottom: 96 }}
    >
      {/* layered backdrop */}
      <div className="pointer-events-none absolute inset-0 nro-grid-bg nro-radial-fade opacity-40" />
      <div className="pointer-events-none absolute inset-0 nro-accent-glow" />
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-px"
        style={{
          background:
            "linear-gradient(90deg, transparent, color-mix(in oklab, var(--accent) 60%, transparent), transparent)",
        }}
      />

      <div className="relative mx-auto max-w-[840px] px-6 text-center">
        <Link
          to="/changelog"
          className="inline-flex items-center gap-2 nro-badge"
          style={{
            border: "1px solid color-mix(in oklab, var(--accent) 50%, var(--border))",
            background: "color-mix(in oklab, var(--accent) 10%, var(--elevated))",
            color: "var(--accent)",
          }}
        >
          <span
            className="w-1.5 h-1.5 rounded-full nro-pulse-dot"
            style={{ background: "var(--accent)" }}
          />
          Neuro v2.4.1 is live — embedding drift gets 3× more accurate
          <ArrowRight size={12} />
        </Link>

        <h1
          className="font-bold mt-6 tracking-tight"
          style={{ fontSize: 64, lineHeight: 1.05, letterSpacing: "-0.025em" }}
        >
          <span className="nro-text-gradient">Your AI models break in production.</span>
          <br />
          <span style={{ color: "var(--accent)" }}>Neuro tells you first.</span>
        </h1>

        <p
          className="mt-6 text-[color:var(--text-secondary)] mx-auto"
          style={{ fontSize: 19, maxWidth: 640, lineHeight: 1.55 }}
        >
          Real-time drift detection, training pipeline observability, and an
          API-first surface that drops into your existing stack — purpose-built
          for teams running LLMs and embedding models at scale.
        </p>

        <div className="mt-10 flex items-center justify-center gap-3 flex-wrap">
          <Link
            to="/login"
            className="nro-btn-primary inline-flex items-center gap-2"
            style={{
              fontSize: 16,
              padding: "14px 26px",
              boxShadow:
                "0 0 0 1px color-mix(in oklab, var(--accent) 50%, transparent), 0 10px 40px -10px color-mix(in oklab, var(--accent) 60%, transparent)",
            }}
          >
            Start free trial
            <ArrowRight size={16} />
          </Link>
          <a
            href="#preview"
            className="nro-btn-secondary inline-flex items-center gap-2"
            style={{ fontSize: 16, padding: "14px 26px" }}
          >
            <Terminal size={16} />
            See a live demo
          </a>
        </div>
        <p className="mt-5 text-[13px] text-[color:var(--text-secondary)]">
          No credit card · 14-day trial · SOC 2 Type II · GDPR ready
        </p>
      </div>
    </section>
  );
}

/* ---------------- LOGO STRIP (marquee) ---------------- */

function LogoStrip() {
  const names = [
    "Vantara Health",
    "Merisol",
    "Quelaris",
    "Ardentix",
    "Lumira",
    "Denova",
    "Phoria Labs",
    "Northbeam",
    "Selene AI",
  ];
  return (
    <section style={{ paddingTop: 32, paddingBottom: 40 }}>
      <div className="mx-auto max-w-[1100px] px-6">
        <p className="text-center text-[12px] tracking-[0.18em] uppercase text-[color:var(--text-secondary)]">
          ML teams shipping with Neuro
        </p>
        <div
          className="relative mt-6 overflow-hidden"
          style={{
            maskImage:
              "linear-gradient(90deg, transparent, #000 12%, #000 88%, transparent)",
            WebkitMaskImage:
              "linear-gradient(90deg, transparent, #000 12%, #000 88%, transparent)",
          }}
        >
          <div className="flex gap-x-14 w-max nro-marquee">
            {[...names, ...names].map((n, i) => (
              <span
                key={i}
                className="font-bold text-[color:var(--text-secondary)] opacity-50 whitespace-nowrap"
                style={{ fontSize: 17, letterSpacing: "-0.01em" }}
              >
                {n}
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ---------------- METRIC STRIP ---------------- */

function MetricStrip() {
  const stats: [string, string, string][] = [
    ["1.4B+", "Predictions monitored / month", "across production endpoints"],
    ["< 9s", "Median time-to-alert on drift", "from event to pager"],
    ["99.94%", "Platform uptime (rolling 90d)", "see status.neuro.cyveera.com"],
    ["47%", "Reduction in MTTR", "reported by Pro customers"],
  ];
  return (
    <section style={{ paddingTop: 24, paddingBottom: 80 }}>
      <div className="mx-auto max-w-[1100px] px-6">
        <div
          className="nro-card grid grid-cols-2 md:grid-cols-4 divide-x divide-y md:divide-y-0"
          style={{ borderColor: "var(--border)" }}
        >
          {stats.map(([n, l, s], i) => (
            <div
              key={i}
              className="p-6"
              style={{ borderColor: "var(--border)" }}
            >
              <div
                className="font-bold"
                style={{
                  fontSize: 34,
                  letterSpacing: "-0.02em",
                  color: "var(--accent)",
                }}
              >
                {n}
              </div>
              <div className="mt-1 text-[14px] text-[color:var(--text-primary)] font-medium">
                {l}
              </div>
              <div className="mt-1 text-[12px] text-[color:var(--text-secondary)]">
                {s}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---------------- FEATURES (6) ---------------- */

function Features() {
  return (
    <section style={{ paddingTop: 32, paddingBottom: 80 }}>
      <div className="mx-auto max-w-[1100px] px-6">
        <div className="text-center max-w-[700px] mx-auto">
          <div className="nro-section-label" style={{ color: "var(--accent)" }}>
            Platform
          </div>
          <h2
            className="font-bold mt-3"
            style={{ fontSize: 40, letterSpacing: "-0.02em", lineHeight: 1.1 }}
          >
            Stop discovering model failures from your customers.
          </h2>
          <p
            className="mt-4 text-[color:var(--text-secondary)]"
            style={{ fontSize: 17 }}
          >
            Six primitives. One unified surface. Every signal your ML team
            needs from the first commit to the 3 a.m. pager.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-12">
          <FeatureCard
            icon={<Waves size={22} />}
            title="Drift Detection at Scale"
            body="Population, feature, and embedding-level drift baselines computed continuously. Configurable thresholds, automatic baseline migration, and Slack alerts before a single ticket is filed."
          />
          <FeatureCard
            icon={<Layers size={22} />}
            title="Training Pipeline Observability"
            body="Hook into SageMaker, Vertex AI, or raw Kubernetes jobs. GPU utilization, per-epoch loss, checkpoint validation — unified, without touching your training code."
          />
          <FeatureCard
            icon={<Code2 size={22} />}
            title="API-First Integration"
            body="Push metrics from any framework in two lines of Python. Pull run history, model versions, and alert state via REST. Webhooks, Slack, PagerDuty, custom endpoints — all first-class."
          />
          <FeatureCard
            icon={<Activity size={22} />}
            title="Live Inference Telemetry"
            body="Latency, throughput, token-cost, and per-tenant breakdowns streamed in real time. Slice by model version, region, or deployment ring with sub-second query latency."
          />
          <FeatureCard
            icon={<GitBranch size={22} />}
            title="Model Lineage & Versions"
            body="Every artifact tied back to the dataset, training run, code commit, and reviewer that produced it. Roll back a regression in one click — auditable end-to-end."
          />
          <FeatureCard
            icon={<Shield size={22} />}
            title="Compliance by Default"
            body="SOC 2 Type II, GDPR-ready data handling, tenant isolation, SAML SSO, and an immutable audit log shipped to your SIEM. Enterprise-grade without the enterprise tax."
          />
        </div>
      </div>
    </section>
  );
}

function FeatureCard({
  icon,
  title,
  body,
}: {
  icon: React.ReactNode;
  title: string;
  body: string;
}) {
  return (
    <div className="nro-card nro-card-hover" style={{ padding: 26 }}>
      <div
        className="inline-flex items-center justify-center rounded-md mb-4"
        style={{
          width: 42,
          height: 42,
          background:
            "color-mix(in oklab, var(--accent) 14%, var(--elevated))",
          color: "var(--accent)",
          border:
            "1px solid color-mix(in oklab, var(--accent) 30%, var(--border))",
        }}
      >
        {icon}
      </div>
      <h3 className="font-bold mb-2" style={{ fontSize: 17 }}>
        {title}
      </h3>
      <p
        className="text-[color:var(--text-secondary)]"
        style={{ fontSize: 13.5, lineHeight: 1.6 }}
      >
        {body}
      </p>
    </div>
  );
}

/* ---------------- CODE + DRIFT (split) ---------------- */

function CodeAndDrift() {
  return (
    <section
      className="w-full"
      style={{
        paddingTop: 80,
        paddingBottom: 80,
        background:
          "linear-gradient(180deg, var(--canvas) 0%, var(--surface) 50%, var(--canvas) 100%)",
      }}
    >
      <div className="mx-auto max-w-[1100px] px-6 grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
        <div>
          <div className="nro-section-label" style={{ color: "var(--accent)" }}>
            Two lines. Zero ceremony.
          </div>
          <h2
            className="font-bold mt-3"
            style={{ fontSize: 36, letterSpacing: "-0.02em", lineHeight: 1.15 }}
          >
            Instrument any model in under a minute.
          </h2>
          <p
            className="mt-4 text-[color:var(--text-secondary)]"
            style={{ fontSize: 16, lineHeight: 1.6 }}
          >
            No agents to deploy. No sidecars to babysit. Drop the SDK into your
            inference loop and Neuro starts streaming distributional baselines,
            drift scores, and tail-latency percentiles within seconds.
          </p>
          <ul className="mt-5 space-y-2 text-[14px]">
            {[
              "PyTorch, TensorFlow, JAX, scikit-learn, vLLM, llama.cpp",
              "Synchronous and async batching — zero added p99 latency",
              "Auto-redacts PII before metrics leave your VPC",
            ].map((l) => (
              <li key={l} className="flex gap-2 text-[color:var(--text-primary)]">
                <Zap
                  size={14}
                  className="mt-1 shrink-0"
                  style={{ color: "var(--accent)" }}
                />
                <span>{l}</span>
              </li>
            ))}
          </ul>
          <div className="mt-7 flex gap-3">
            <Link to="/docs" className="nro-btn-primary inline-flex items-center gap-2">
              Read the docs <ArrowRight size={14} />
            </Link>
            <Link to="/pricing" className="nro-btn-secondary">
              See pricing
            </Link>
          </div>
        </div>

        <div className="nro-card overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[color:var(--border)] bg-[color:var(--elevated)]">
            <span className="w-2.5 h-2.5 rounded-full bg-[#ef4444]" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#f59e0b]" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#10b981]" />
            <span className="ml-2 font-mono text-[12px] text-[color:var(--text-secondary)]">
              vantara_risk_v3.py
            </span>
          </div>
          <pre
            className="p-5 text-[12.5px] leading-relaxed font-mono overflow-x-auto"
            style={{ color: "var(--text-primary)", background: "var(--canvas)" }}
          >
{`from neuro import Client
client = Client(api_key=os.environ["NEURO_KEY"])

@client.monitor(model="vantara-risk-v3")
def predict(features: dict) -> float:
    x = preprocess(features)
    y = model(x)               # your existing inference
    return float(y)

# That's it. Neuro now tracks:
#   • input distribution drift  (PSI + KL on 47 features)
#   • output distribution drift (cosine baseline)
#   • p50 / p95 / p99 latency   (rolling 5m window)
#   • per-tenant prediction volume
#
# Alerts fire to #ml-oncall when drift > 0.18 for 10m`}
          </pre>
        </div>
      </div>
    </section>
  );
}

/* ---------------- HOW IT WORKS ---------------- */

function HowItWorks() {
  const steps: [string, string, string][] = [
    [
      "01",
      "Connect",
      "Drop the SDK or hit the REST API. Neuro auto-discovers your endpoints, datasets, and training jobs across SageMaker, Vertex, and Kubernetes.",
    ],
    [
      "02",
      "Baseline",
      "We learn each model's signature in the first 24 hours — feature distributions, output ranges, latency envelopes — and pin them to your model version.",
    ],
    [
      "03",
      "Alert",
      "When production diverges from the baseline beyond your threshold, your on-call gets a structured alert with the offending features, sample inputs, and a one-click rollback.",
    ],
  ];
  return (
    <section style={{ paddingTop: 96, paddingBottom: 80 }}>
      <div className="mx-auto max-w-[1100px] px-6">
        <div className="text-center max-w-[640px] mx-auto">
          <div className="nro-section-label" style={{ color: "var(--accent)" }}>
            How it works
          </div>
          <h2
            className="font-bold mt-3"
            style={{ fontSize: 36, letterSpacing: "-0.02em" }}
          >
            From `pip install` to a paged on-call in under an hour.
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-12 relative">
          <div
            className="hidden md:block absolute top-[42px] left-[10%] right-[10%] h-px"
            style={{
              background:
                "linear-gradient(90deg, transparent, color-mix(in oklab, var(--accent) 50%, transparent), transparent)",
            }}
          />
          {steps.map(([n, t, b]) => (
            <div key={n} className="nro-card p-6 relative">
              <div
                className="inline-flex items-center justify-center w-10 h-10 rounded-full font-mono font-bold text-[13px] mb-4"
                style={{
                  background: "var(--canvas)",
                  color: "var(--accent)",
                  border:
                    "1px solid color-mix(in oklab, var(--accent) 40%, var(--border))",
                }}
              >
                {n}
              </div>
              <h3 className="font-bold text-[18px]">{t}</h3>
              <p
                className="mt-2 text-[13.5px] text-[color:var(--text-secondary)]"
                style={{ lineHeight: 1.6 }}
              >
                {b}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---------------- DASHBOARD PREVIEW (kept, polished) ---------------- */

function DashboardPreview() {
  return (
    <section
      id="preview"
      className="relative w-full overflow-hidden bg-[color:var(--surface)]"
      style={{ paddingTop: 96, paddingBottom: 96 }}
    >
      <div className="pointer-events-none absolute inset-0 nro-accent-glow opacity-50" />
      <div className="relative mx-auto max-w-[1280px] px-6 text-center">
        <div className="nro-section-label" style={{ color: "var(--accent)" }}>
          Platform preview
        </div>
        <h2
          className="font-bold mt-3"
          style={{ fontSize: 40, letterSpacing: "-0.02em" }}
        >
          Everything your model team needs, in one place.
        </h2>
        <p
          className="mt-4 mx-auto text-[color:var(--text-secondary)]"
          style={{ fontSize: 17, maxWidth: 640 }}
        >
          From experiment tracking to production drift alerts, Neuro covers
          the full lifecycle of every model you ship.
        </p>

        <div
          className="mx-auto mt-12 nro-card overflow-hidden text-left"
          style={{
            maxWidth: 1200,
            background: "var(--canvas)",
            boxShadow:
              "0 30px 80px -30px color-mix(in oklab, var(--accent) 35%, transparent)",
          }}
        >
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[color:var(--border)] bg-[color:var(--elevated)]">
            <span className="w-3 h-3 rounded-full bg-[#ef4444]" />
            <span className="w-3 h-3 rounded-full bg-[#f59e0b]" />
            <span className="w-3 h-3 rounded-full bg-[#10b981]" />
            <div className="mx-auto px-4 py-1 rounded text-[12px] text-[color:var(--text-secondary)] font-mono bg-[color:var(--surface)]">
              neuro.cyveera.com/dashboard
            </div>
          </div>
          <div
            className="grid grid-cols-[200px_1fr]"
            style={{ minHeight: 540 }}
          >
            <div className="border-r border-[color:var(--border)] p-4 space-y-1 bg-[color:var(--surface)]">
              {["Dashboard", "Runs", "Models", "Datasets", "Pipelines", "Artifacts", "Alerts", "Team"].map(
                (s, i) => (
                  <div
                    key={s}
                    className={`text-[13px] px-3 py-1.5 rounded ${
                      i === 0
                        ? "bg-[color:var(--elevated)] text-[color:var(--text-primary)] font-medium"
                        : "text-[color:var(--text-secondary)]"
                    }`}
                  >
                    {s}
                  </div>
                )
              )}
            </div>
            <div className="p-6">
              <div className="grid grid-cols-3 gap-4">
                {[
                  ["7", "Active runs", "+2 vs yesterday"],
                  ["12", "Models in prod", "3 versions pinned"],
                  ["34", "Datasets (7d)", "1.2 TB ingested"],
                ].map(([n, l, s]) => (
                  <div key={l} className="nro-card p-4">
                    <div
                      className="font-bold"
                      style={{ fontSize: 28, letterSpacing: "-0.02em" }}
                    >
                      {n}
                    </div>
                    <div className="text-[12px] text-[color:var(--text-secondary)] mt-0.5">
                      {l}
                    </div>
                    <div
                      className="text-[11px] mt-2"
                      style={{ color: "var(--accent)" }}
                    >
                      {s}
                    </div>
                  </div>
                ))}
              </div>
              <div className="nro-card mt-4 p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-[13px] text-[color:var(--text-secondary)]">
                    Drift score · vantara-risk-v3 (30d)
                  </div>
                  <span className="nro-badge nro-badge--accent">healthy</span>
                </div>
                <svg viewBox="0 0 600 140" className="w-full h-32">
                  <defs>
                    <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
                      <stop
                        offset="0%"
                        stopColor="var(--accent)"
                        stopOpacity="0.35"
                      />
                      <stop
                        offset="100%"
                        stopColor="var(--accent)"
                        stopOpacity="0"
                      />
                    </linearGradient>
                  </defs>
                  <path
                    d="M0,110 L60,108 L120,100 L180,104 L240,90 L300,95 L360,80 L420,85 L480,60 L540,40 L600,28 L600,140 L0,140 Z"
                    fill="url(#g1)"
                  />
                  <polyline
                    fill="none"
                    stroke="var(--accent)"
                    strokeWidth="2"
                    points="0,110 60,108 120,100 180,104 240,90 300,95 360,80 420,85 480,60 540,40 600,28"
                  />
                </svg>
              </div>
              <div className="nro-card mt-4">
                <table className="w-full">
                  <thead>
                    <tr>
                      <th className="nro-th">Run</th>
                      <th className="nro-th">Status</th>
                      <th className="nro-th">GPU h</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      ["run-...002", "Running", "33.6"],
                      ["run-...019", "Completed", "94.0"],
                      ["run-...031", "Failed", "3.1"],
                    ].map(([r, s, g]) => (
                      <tr key={r}>
                        <td className="nro-td font-mono text-[12px]">{r}</td>
                        <td className="nro-td">
                          <span
                            className={`nro-badge ${
                              s === "Running"
                                ? "nro-badge--accent"
                                : s === "Failed"
                                ? "nro-badge--danger"
                                : "nro-badge--slate"
                            }`}
                          >
                            {s}
                          </span>
                        </td>
                        <td className="nro-td">{g}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ---------------- TESTIMONIALS ---------------- */

function Testimonials() {
  const quotes: { quote: string; name: string; role: string }[] = [
    {
      quote:
        "We caught a 14% drop in our fraud model's precision four hours before our payments team noticed the false-positive spike. Neuro paid for itself the first week.",
      name: "Priya Raman",
      role: "Staff ML Engineer, Vantara Health",
    },
    {
      quote:
        "I've used every major MLOps tool. Neuro is the first one that didn't require a six-week integration. Two lines of Python and we had drift baselines on 19 endpoints.",
      name: "Marco Tellini",
      role: "Head of Platform, Merisol",
    },
    {
      quote:
        "The lineage graph alone is worth it. Our auditors stopped asking us to dig through Jupyter notebooks — they just open Neuro.",
      name: "Avery Chen",
      role: "Director of ML, Ardentix",
    },
  ];
  return (
    <section style={{ paddingTop: 96, paddingBottom: 80 }}>
      <div className="mx-auto max-w-[1100px] px-6">
        <div className="text-center max-w-[640px] mx-auto">
          <div className="nro-section-label" style={{ color: "var(--accent)" }}>
            From the trenches
          </div>
          <h2
            className="font-bold mt-3"
            style={{ fontSize: 36, letterSpacing: "-0.02em" }}
          >
            Built with the teams who page at 3 a.m.
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-12">
          {quotes.map((q) => (
            <figure
              key={q.name}
              className="nro-card p-6 flex flex-col justify-between"
              style={{ minHeight: 240 }}
            >
              <blockquote
                className="text-[15px] text-[color:var(--text-primary)]"
                style={{ lineHeight: 1.55 }}
              >
                <span
                  className="font-bold mr-1"
                  style={{ color: "var(--accent)", fontSize: 22 }}
                >
                  “
                </span>
                {q.quote}
              </blockquote>
              <figcaption className="mt-6 flex items-center gap-3">
                <div
                  className="w-9 h-9 rounded-full flex items-center justify-center font-bold text-[13px]"
                  style={{
                    background:
                      "color-mix(in oklab, var(--accent) 18%, var(--elevated))",
                    color: "var(--accent)",
                    border:
                      "1px solid color-mix(in oklab, var(--accent) 35%, var(--border))",
                  }}
                >
                  {q.name
                    .split(" ")
                    .map((n) => n[0])
                    .slice(0, 2)
                    .join("")}
                </div>
                <div>
                  <div className="text-[13px] font-medium">{q.name}</div>
                  <div className="text-[12px] text-[color:var(--text-secondary)]">
                    {q.role}
                  </div>
                </div>
              </figcaption>
            </figure>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---------------- SECURITY STRIP ---------------- */

function SecurityStrip() {
  const items = [
    "SOC 2 Type II",
    "GDPR Ready",
    "SAML / SCIM SSO",
    "Tenant Isolation",
    "Immutable Audit Log",
    "EU & US Data Residency",
    "99.9% Uptime SLA",
  ];
  return (
    <section style={{ paddingTop: 32, paddingBottom: 64 }}>
      <div className="mx-auto max-w-[1100px] px-6">
        <div
          className="nro-card flex flex-wrap items-center justify-between gap-x-8 gap-y-4 px-6 py-5"
          style={{
            background:
              "linear-gradient(135deg, var(--surface), color-mix(in oklab, var(--accent) 4%, var(--surface)))",
          }}
        >
          <div className="flex items-center gap-3">
            <Shield
              size={20}
              style={{ color: "var(--accent)" }}
              aria-hidden
            />
            <span className="font-medium text-[14px]">
              Enterprise-grade security on every plan.
            </span>
          </div>
          <div className="flex flex-wrap gap-x-5 gap-y-2">
            {items.map((i) => (
              <span
                key={i}
                className="text-[12px] text-[color:var(--text-secondary)]"
              >
                · {i}
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ---------------- FINAL CTA ---------------- */

function FinalCTA() {
  return (
    <section
      className="relative w-full overflow-hidden"
      style={{ paddingTop: 80, paddingBottom: 120 }}
    >
      <div className="pointer-events-none absolute inset-0 nro-grid-bg nro-radial-fade opacity-30" />
      <div className="pointer-events-none absolute inset-0 nro-accent-glow opacity-80" />
      <div className="relative mx-auto max-w-[820px] px-6 text-center">
        <h2
          className="font-bold"
          style={{ fontSize: 48, letterSpacing: "-0.025em", lineHeight: 1.05 }}
        >
          The next drift incident is already in your logs.
          <br />
          <span style={{ color: "var(--accent)" }}>
            Be the first to know.
          </span>
        </h2>
        <p
          className="mt-5 text-[color:var(--text-secondary)] mx-auto"
          style={{ fontSize: 17, maxWidth: 560 }}
        >
          Start a 14-day trial. Wire up your first model in under an hour. If
          Neuro doesn't catch something your dashboards missed, we'll refund
          your first month — no questions.
        </p>
        <div className="mt-9 flex items-center justify-center gap-3 flex-wrap">
          <Link
            to="/login"
            className="nro-btn-primary inline-flex items-center gap-2"
            style={{
              fontSize: 16,
              padding: "14px 28px",
              boxShadow:
                "0 0 0 1px color-mix(in oklab, var(--accent) 50%, transparent), 0 10px 40px -10px color-mix(in oklab, var(--accent) 70%, transparent)",
            }}
          >
            Start free trial <ArrowRight size={16} />
          </Link>
          <a
            href="mailto:enterprise@cyveera.ai"
            className="nro-btn-secondary"
            style={{ fontSize: 16, padding: "14px 28px" }}
          >
            Talk to the founders
          </a>
        </div>
        <p className="mt-6 text-[12px] text-[color:var(--text-secondary)]">
          Trusted by 200+ ML teams · Pricing from $0 · No credit card required
        </p>
      </div>
    </section>
  );
}
