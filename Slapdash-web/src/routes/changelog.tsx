import { createFileRoute } from "@tanstack/react-router";
import { MarketingLayout } from "@/components/layouts/MarketingLayout";
import { PageHero } from "@/components/ui/PageHero";

export const Route = createFileRoute("/changelog")({
  component: ChangelogPage,
  head: () => ({
    meta: [
      { title: "Changelog — Neuro by Cyveera" },
      { name: "description", content: "New features, improvements, and fixes — shipped regularly." },
    ],
  }),
});

const ENTRIES: {
  version: string;
  date: string;
  breaking?: boolean;
  bullets: React.ReactNode[];
}[] = [
  {
    version: "v2.4.1",
    date: "June 4, 2026",
    bullets: [
      "Improved drift detection accuracy for embedding models using cosine similarity baselines (was Euclidean). Existing thresholds are automatically migrated.",
      <>Fixed: webhook test endpoint was returning 200 even when the target URL was unreachable. Now correctly returns 504 with <code>{`{"error":"upstream_timeout"}`}</code>.</>,
      "UI: Notification bell now shows accurate unread count immediately after dismiss without requiring a page refresh.",
    ],
  },
  {
    version: "v2.4.0",
    date: "May 19, 2026",
    breaking: true,
    bullets: [
      <><b>Breaking:</b> The <code>/api/v2/data/exports</code> endpoint now returns <code>artifact_path</code> instead of <code>s3_key</code> in download response objects. Update any integrations that parse this field.</>,
      "Added: Remote dataset import from URL — paste any publicly accessible dataset URL and Neuro will ingest it on your behalf. Supports CSV, JSONL, Parquet, and HuggingFace Hub paths.",
      "Added: Script-upload field on job creation — attach a custom initialization shell script that runs before your training container starts.",
    ],
  },
  {
    version: "v2.3.9",
    date: "April 30, 2026",
    bullets: [
      "Auth: Google SSO now surfaces clearer error messages when the user's Google account does not belong to an authorized domain.",
      <>Training runs now log <code>startup_script</code> exit codes to the job event stream. Previously, a failed init script would silently continue.</>,
      "Fixed: Model detail page was not loading drift charts for models with more than 90 days of history.",
    ],
  },
  {
    version: "v2.3.7",
    date: "April 7, 2026",
    bullets: [
      <>Added <code>/status</code> page — public real-time health check for all Neuro platform services.</>,
      <>Dataset import now supports S3-compatible endpoints (MinIO, Backblaze B2) via the <code>endpoint_url</code> parameter.</>,
      "UI: Sidebar navigation redesigned with clearer section groupings.",
    ],
  },
  {
    version: "v2.3.5",
    date: "March 14, 2026",
    bullets: [
      "Added MFA (TOTP-based) for all workspace members. Existing users are prompted on next login. Recovery codes are stored hashed and cannot be retrieved after initial display.",
      "Webhook delivery now retries up to 3 times with exponential backoff on 5xx responses.",
      <>Security: All session cookies now carry <code>SameSite=Lax; HttpOnly</code>. Previous <code>SameSite=None</code> behavior is deprecated.</>,
    ],
  },
  {
    version: "v2.3.0",
    date: "January 21, 2026",
    bullets: [
      "Initial general availability release. Public sign-up enabled.",
      "Core features: training run tracking, production drift monitoring, alert routing, API key management.",
      "14-day free trial, no credit card required.",
    ],
  },
];

function ChangelogPage() {
  return (
    <MarketingLayout>
      <PageHero
        title={<>What we shipped <span className="text-[color:var(--accent)]">this quarter.</span></>}
        description="New features, improvements, and fixes — shipped weekly to neuro.cyveera.com. Breaking changes are flagged and migrated automatically when we can."
      />

      <div className="mx-auto max-w-[820px] px-6" style={{ paddingTop: 56, paddingBottom: 96 }}>
        <div className="relative">
          <div aria-hidden className="absolute left-[7px] top-2 bottom-2 w-px bg-[color:var(--border)]" />
          <div className="space-y-10">
          {ENTRIES.map((e) => (
            <div key={e.version} className="relative pl-8">
              <span
                className="absolute left-0 top-2 w-[15px] h-[15px] rounded-full border-2"
                style={{ borderColor: e.breaking ? "var(--amber)" : "var(--accent)", background: "var(--canvas)" }}
              />
              <div className="flex items-baseline gap-3 flex-wrap">
                <span className="font-bold text-[18px]">{e.version}</span>
                <span className="text-[color:var(--text-secondary)] text-[14px]">— {e.date}</span>
                {e.breaking && (
                  <span
                    className="text-[11px] font-bold px-2 py-0.5 rounded text-white"
                    style={{ background: "var(--amber)" }}
                  >
                    BREAKING CHANGE
                  </span>
                )}
              </div>
              <ul className="mt-3 space-y-2 text-[14px] text-[color:var(--text-primary)]">
                {e.bullets.map((b, i) => (
                  <li key={i} className="flex gap-2">
                    <span style={{ color: "var(--accent)" }}>•</span>
                    <span>{b}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
          </div>
        </div>
        <p className="mt-12 text-center text-[12px] text-[color:var(--text-secondary)]">
          Subscribe to the changelog RSS · changelog@cyveera.ai
        </p>
      </div>
    </MarketingLayout>
  );
}
