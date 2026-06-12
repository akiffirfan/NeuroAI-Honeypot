import { createFileRoute } from "@tanstack/react-router";
import { MarketingLayout } from "@/components/layouts/MarketingLayout";
import { PageHero } from "@/components/ui/PageHero";
import { Check, Sparkles } from "lucide-react";
import { useState } from "react";

export const Route = createFileRoute("/pricing")({
  component: PricingPage,
  head: () => ({
    meta: [
      { title: "Pricing — Neuro by Cyveera" },
      {
        name: "description",
        content: "Simple, transparent pricing. Start free. Scale with your team.",
      },
    ],
  }),
});

function PricingPage() {
  const [annual, setAnnual] = useState(true);
  return (
    <MarketingLayout>
      <PageHero
        title={<>Priced like infrastructure. <span className="text-[color:var(--accent)]">Not like SaaS.</span></>}
        description="Start free. Scale with your team. No hidden metering fees, no per-prediction surcharges, no surprise overage bills at 2am."
      >
        <div className="flex justify-center">
          <div className="inline-flex items-center gap-1 p-1 rounded-full border border-[color:var(--border)] bg-[color:var(--surface)]/70 backdrop-blur">
            <button
              onClick={() => setAnnual(false)}
              className={`px-5 py-1.5 text-sm rounded-full transition-colors ${
                !annual ? "bg-[color:var(--elevated)] text-white" : "text-[color:var(--text-secondary)]"
              }`}
            >
              Monthly
            </button>
            <button
              onClick={() => setAnnual(true)}
              className={`px-5 py-1.5 text-sm rounded-full inline-flex items-center gap-2 transition-colors ${
                annual ? "bg-[color:var(--elevated)] text-white" : "text-[color:var(--text-secondary)]"
              }`}
            >
              Annual
              <span className="nro-badge nro-badge--accent !text-[11px]">−20%</span>
            </button>
          </div>
        </div>
      </PageHero>

      <div className="mx-auto max-w-[1180px] px-6" style={{ paddingTop: 56, paddingBottom: 80 }}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-stretch">
          <PlanCard
            badge={<span className="nro-badge nro-badge--slate">Free</span>}
            price="$0"
            unit="per month, up to 2 seats."
            features={[
              "Up to 2 model endpoints monitored",
              "7-day metric retention",
              "10,000 predictions tracked/month",
              "Email alerts only",
              "Community support",
              "1 workspace",
            ]}
            cta="Join Waitlist"
            ctaHref="/contact"
          />
          <PlanCard
            highlighted
            badge={
              <span className="nro-badge nro-badge--accent inline-flex items-center gap-1.5">
                <Sparkles size={11} /> Most popular
              </span>
            }
            price={annual ? "$300" : "$375"}
            unit={annual ? "per seat / month, billed annually." : "per seat / month, billed monthly."}
            sub={annual ? "or $375/seat billed month-to-month" : "save 20% with annual billing"}
            features={[
              "Up to 20 model endpoints",
              "90-day metric retention",
              "Unlimited predictions tracked",
              "Slack, PagerDuty, and webhook alerts",
              "Priority email support (4-hour SLA)",
              "5 workspaces",
              "Drift detection + custom thresholds",
              "API access (500k requests/month)",
              "SSO (Google Workspace)",
            ]}
            cta="Request Demo"
            ctaHref="/contact"
          />
          <PlanCard
            badge={<span className="nro-badge nro-badge--slate">Enterprise</span>}
            price="Custom"
            priceSize={40}
            unit="Volume pricing for teams of 10+."
            features={[
              "Everything in Pro",
              "Unlimited model endpoints",
              "Custom data retention (up to 5 years)",
              "Dedicated Slack channel support",
              "SLA guarantees (99.9% uptime)",
              "SAML/SCIM SSO",
              "Custom MSA and DPA",
              "Tenant isolation and private deployment",
              "SOC 2 Type II audit report on request",
            ]}
            cta="Talk to sales"
            ctaHref="/contact"
            ctaSecondary
          />
        </div>

        <div className="mt-16 nro-card p-8 grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
          {[
            ["SOC 2 Type II", "Audited annually"],
            ["GDPR + DPA", "EU & UK ready"],
            ["99.9% uptime", "Contractual SLA"],
            ["US-East-1", "Default data residency"],
          ].map(([t, s]) => (
            <div key={t}>
              <div className="font-bold text-white">{t}</div>
              <div className="text-[12px] text-[color:var(--text-secondary)] mt-1">{s}</div>
            </div>
          ))}
        </div>

        <p className="text-center mt-10 text-[13px] text-[color:var(--text-secondary)]">
          All plans include unlimited ingestion bandwidth. Need EU-region deployment, on-prem, or air-gapped?{" "}
          <a href="mailto:enterprise@cyveera.ai" className="text-[color:var(--accent)]">
            Get in touch.
          </a>
        </p>
      </div>
    </MarketingLayout>
  );
}

function PlanCard({
  badge,
  price,
  priceSize = 48,
  unit,
  sub,
  features,
  cta,
  ctaHref,
  ctaSecondary,
  highlighted,
}: {
  badge: React.ReactNode;
  price: string;
  priceSize?: number;
  unit: string;
  sub?: string;
  features: string[];
  cta: string;
  ctaHref?: string;
  ctaSecondary?: boolean;
  highlighted?: boolean;
}) {
  return (
    <div
      className="nro-card nro-card-hover flex flex-col relative"
      style={{
        padding: 28,
        border: highlighted ? "1px solid color-mix(in oklab, var(--accent) 70%, var(--border))" : undefined,
        background: highlighted
          ? "linear-gradient(180deg, color-mix(in oklab, var(--accent) 6%, var(--surface)) 0%, var(--surface) 60%)"
          : undefined,
      }}
    >
      {highlighted && (
        <div
          aria-hidden
          className="absolute -inset-px rounded-[10px] pointer-events-none"
          style={{
            background:
              "linear-gradient(180deg, color-mix(in oklab, var(--accent) 30%, transparent), transparent 40%)",
            maskImage: "linear-gradient(180deg, #000, transparent 50%)",
            opacity: 0.6,
          }}
        />
      )}
      <div className="relative">{badge}</div>
      <div className="relative font-bold mt-4 nro-text-gradient" style={{ fontSize: priceSize, letterSpacing: "-0.02em" }}>
        {price}
      </div>
      <div className="relative text-[color:var(--text-secondary)] text-[14px] mt-1">{unit}</div>
      {sub && (
        <div className="relative text-[color:var(--text-secondary)] text-[12px] mt-1">{sub}</div>
      )}
      <ul className="relative mt-6 space-y-3 flex-1">
        {features.map((f) => (
          <li key={f} className="flex gap-2 text-[14px]">
            <Check size={16} className="mt-0.5 shrink-0" style={{ color: "var(--accent)" }} />
            <span>{f}</span>
          </li>
        ))}
      </ul>
      <a
        href={ctaHref ?? "/login"}
        className={`relative mt-8 text-center ${ctaSecondary ? "nro-btn-secondary" : "nro-btn-primary"}`}
        style={{ width: "100%", display: "block" }}
      >
        {cta}
      </a>
    </div>
  );
}
