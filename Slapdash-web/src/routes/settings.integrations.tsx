import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { Eye, EyeOff, Slack, Bell, Webhook } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { testWebhook } from "@/lib/api/mutations";
import { isApiError } from "@/lib/api/client";
import { useAuth } from "@/lib/auth.context";
import { useState } from "react";

export const Route = createFileRoute("/settings/integrations")({
  component: IntegrationsPage,
  head: () => ({ meta: [{ title: "Integrations — Neuro" }] }),
});

function IntegrationsPage() {
  return (
    <AppLayout title="Integrations">
      <AppPageHeader
        title="Integrations."
        description="Wire Neuro into your incident routing, notification, and observability stack with signed webhooks and short-lived OAuth tokens."
      />
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <IntegrationCard
          icon={<Slack size={24} />}
          name="Slack"
          desc="Send drift alerts, training run status, and billing notifications to any Slack channel."
          status="Not configured"
          statusKind="slate"
          ctaLabel="Connect Slack"
        />
        <IntegrationCard
          icon={<Bell size={24} />}
          name="PagerDuty"
          desc="Route critical model drift alerts and infrastructure failures to your on-call rotation."
          status="Not configured"
          statusKind="slate"
          ctaLabel="Connect PagerDuty"
        />
        <WebhookCard />
      </div>
    </AppLayout>
  );
}

function IntegrationCard({
  icon,
  name,
  desc,
  status,
  statusKind,
  ctaLabel,
}: {
  icon: React.ReactNode;
  name: string;
  desc: string;
  status: string;
  statusKind: "slate" | "accent";
  ctaLabel: string;
}) {
  const [toast, setToast] = useState(false);
  return (
    <div className="nro-card p-6 flex flex-col">
      <div className="flex items-center gap-3">
        <div
          className="inline-flex items-center justify-center rounded-md"
          style={{
            width: 40,
            height: 40,
            background: "var(--elevated)",
            color: "var(--accent)",
          }}
        >
          {icon}
        </div>
        <h3 className="font-bold text-[16px]">{name}</h3>
        <span
          className={`ml-auto nro-badge ${
            statusKind === "slate" ? "nro-badge--slate" : "nro-badge--accent"
          }`}
        >
          {status}
        </span>
      </div>
      <p className="mt-3 text-[14px] text-[color:var(--text-secondary)] flex-1">
        {desc}
      </p>
      <button
        onClick={() => {
          setToast(true);
          setTimeout(() => setToast(false), 2200);
        }}
        className="nro-btn-primary w-full mt-5"
      >
        {ctaLabel}
      </button>
      {toast && (
        <p className="mt-3 text-[12px] text-[color:var(--danger)]">
          {name} connection temporarily unavailable. Try again later.
        </p>
      )}
    </div>
  );
}

function WebhookCard() {
  const { user } = useAuth();
  const [reveal, setReveal] = useState(false);
  const [url, setUrl] = useState(
    "https://hooks.vantarahealth.internal/neuro/events",
  );

  const testMutation = useMutation({
    mutationFn: testWebhook,
  });

  const handleTest = () => {
    testMutation.mutate({ url, _csrf: user?.csrf_token });
  };

  const resp = testMutation.data
    ? JSON.stringify(testMutation.data, null, 2)
    : testMutation.error && isApiError(testMutation.error) && (testMutation.error as any).data
    ? JSON.stringify((testMutation.error as any).data, null, 2)
    : null;

  return (
    <div className="nro-card p-6 lg:col-span-3">
      <div className="flex items-center gap-3">
        <div
          className="inline-flex items-center justify-center rounded-md"
          style={{
            width: 40,
            height: 40,
            background: "var(--elevated)",
            color: "var(--accent)",
          }}
        >
          <Webhook size={24} />
        </div>
        <h3 className="font-bold text-[16px]">Custom Webhook</h3>
        <span className="ml-auto nro-badge nro-badge--accent">Configured</span>
      </div>
      <p className="mt-3 text-[14px] text-[color:var(--text-secondary)]">
        Send Neuro events to any HTTP endpoint. Supports HMAC-SHA256 signature
        verification.
      </p>

      <div className="mt-6 space-y-4">
        <div>
          <label className="nro-label">Endpoint URL</label>
          <input
            className="nro-input mt-2 font-mono !text-[13px]"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        </div>
        <div>
          <label className="nro-label">HMAC Secret</label>
          <div className="relative mt-2">
            <input
              className="nro-input pr-10 font-mono !text-[13px]"
              type={reveal ? "text" : "password"}
              defaultValue="wh_sec_8d2f4c1a9e7b3f5d"
            />
            <button
              type="button"
              onClick={() => setReveal((v) => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-[color:var(--text-secondary)] hover:text-white"
            >
              {reveal ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </div>
        <div>
          <div className="nro-label">Event types</div>
          <div className="mt-2 space-y-1.5 text-[14px]">
            {[
              ["job.completed", true],
              ["job.failed", true],
              ["model.drift.alert", true],
              ["billing.quota.80pct", false],
              ["team.member.added", false],
            ].map(([n, c]) => (
              <label key={String(n)} className="flex items-center gap-2">
                <input
                  type="checkbox"
                  defaultChecked={c as boolean}
                  className="accent-[color:var(--accent)]"
                />
                <span className="font-mono">{n}</span>
              </label>
            ))}
          </div>
        </div>
        <div>
          <button
            onClick={handleTest}
            disabled={testMutation.isPending}
            className="nro-btn-secondary"
          >
            {testMutation.isPending ? "Testing…" : "Test Webhook"}
          </button>
          {resp && (
            <pre
              className="nro-card font-mono text-[12px] p-4 mt-3"
              style={{ background: "var(--canvas)" }}
            >
              {resp}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
