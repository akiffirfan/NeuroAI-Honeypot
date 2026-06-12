import { createFileRoute } from "@tanstack/react-router";
import { MarketingLayout } from "@/components/layouts/MarketingLayout";
import { useState } from "react";
import { apiFetch } from "@/lib/api/client";

export const Route = createFileRoute("/contact")({
  component: ContactPage,
  head: () => ({
    meta: [
      { title: "Contact Sales — Neuro by Cyveera" },
      {
        name: "description",
        content: "Talk to our team about deploying Neuro in your organisation.",
      },
    ],
  }),
});

const COMPANY_SIZES = [
  "1–10 employees",
  "11–50 employees",
  "51–200 employees",
  "201–500 employees",
  "501–1,000 employees",
  "1,000+ employees",
];

function ContactPage() {
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const form = new FormData(e.currentTarget);
    try {
      await apiFetch("/contact", {
        method: "POST",
        body: JSON.stringify({
          first_name: form.get("first_name"),
          last_name: form.get("last_name"),
          work_email: form.get("work_email"),
          company_size: form.get("company_size"),
          message: form.get("message"),
        }),
      });
      setSubmitted(true);
    } catch {
      setError("Something went wrong. Please try again or email us at hello@cyveera.ai");
    } finally {
      setLoading(false);
    }
  };

  return (
    <MarketingLayout>
      <div className="relative min-h-[88vh] flex items-center justify-center px-4 overflow-hidden">
        <div aria-hidden className="absolute inset-0 nro-grid-bg nro-radial-fade opacity-40" />
        <div
          aria-hidden
          className="absolute pointer-events-none"
          style={{
            top: "10%",
            right: "15%",
            width: 500,
            height: 500,
            borderRadius: "50%",
            background: "var(--accent)",
            filter: "blur(140px)",
            opacity: 0.07,
          }}
        />

        <div
          className="nro-card relative z-10 bg-[color:var(--surface)]/85 backdrop-blur-xl w-full"
          style={{ maxWidth: 560, padding: 44 }}
        >
          {submitted ? (
            <SuccessState />
          ) : (
            <>
              <div className="mb-6">
                <span className="nro-badge nro-badge--accent mb-4 inline-block">Talk to Sales</span>
                <h1 className="font-bold nro-text-gradient" style={{ fontSize: 26, letterSpacing: "-0.02em" }}>
                  Let's find the right plan for your team.
                </h1>
                <p className="mt-2 text-[14px] text-[color:var(--text-secondary)]">
                  Fill in your details and a Cyveera deployment engineer will reach out within 24–48 hours to provision your sandbox cluster.
                </p>
              </div>

              <form onSubmit={onSubmit} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="nro-label">First name</label>
                    <input
                      className="nro-input mt-2"
                      type="text"
                      name="first_name"
                      placeholder="Jane"
                      required
                    />
                  </div>
                  <div>
                    <label className="nro-label">Last name</label>
                    <input
                      className="nro-input mt-2"
                      type="text"
                      name="last_name"
                      placeholder="Smith"
                      required
                    />
                  </div>
                </div>

                <div>
                  <label className="nro-label">Work email</label>
                  <input
                    className="nro-input mt-2"
                    type="email"
                    name="work_email"
                    placeholder="jane@yourcompany.com"
                    required
                  />
                </div>

                <div>
                  <label className="nro-label">Company size</label>
                  <select className="nro-input mt-2" name="company_size" required>
                    <option value="">Select…</option>
                    {COMPANY_SIZES.map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="nro-label">What are you looking to monitor?</label>
                  <textarea
                    className="nro-input mt-2"
                    name="message"
                    rows={4}
                    placeholder="Tell us about your models, infrastructure, and team size…"
                    required
                    style={{ resize: "vertical" }}
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="nro-btn-primary w-full mt-2"
                >
                  {loading ? "Submitting…" : "Request access"}
                </button>

                {error && (
                  <p className="text-sm text-[color:var(--danger)] mt-2">{error}</p>
                )}
              </form>

              <p className="text-center mt-6 text-[12px] text-[color:var(--text-secondary)]">
                Already have an account?{" "}
                <a href="/login" className="text-[color:var(--accent)] hover:underline">
                  Sign in
                </a>
              </p>
            </>
          )}
        </div>
      </div>
    </MarketingLayout>
  );
}

function SuccessState() {
  return (
    <div className="text-center py-8">
      <div
        className="mx-auto mb-6 flex items-center justify-center rounded-full"
        style={{
          width: 56,
          height: 56,
          background: "color-mix(in oklab, var(--accent) 15%, transparent)",
          border: "1px solid color-mix(in oklab, var(--accent) 40%, transparent)",
        }}
      >
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ color: "var(--accent)" }}>
          <polyline points="20 6 9 17 4 12" />
        </svg>
      </div>
      <h2 className="font-bold text-white text-xl mb-3">Request received.</h2>
      <p className="text-[color:var(--text-secondary)] text-[14px] leading-relaxed max-w-[380px] mx-auto">
        A Cyveera deployment engineer will review your request and contact you within <strong className="text-white">24–48 hours</strong> to provision your cluster.
      </p>
      <div className="mt-6 p-4 rounded-lg text-left" style={{ background: "var(--elevated)", border: "1px solid var(--border)" }}>
        <p className="text-[12px] text-[color:var(--text-secondary)]">
          In the meantime, explore the{" "}
          <a href="/docs" className="text-[color:var(--accent)]">API documentation</a>
          {" "}or check our{" "}
          <a href="/status" className="text-[color:var(--accent)]">system status</a>.
        </p>
      </div>
    </div>
  );
}
