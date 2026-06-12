import { createFileRoute } from "@tanstack/react-router";
import { MarketingLayout } from "@/components/layouts/MarketingLayout";
import { useTelemetry } from "@/hooks/useTelemetry";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { ChevronDown, ChevronRight, Copy, Check } from "lucide-react";

export const Route = createFileRoute("/docs")({
  component: ApiDocsPage,
  head: () => ({ meta: [{ title: "API Docs — Neuro" }] }),
});

type Lang = "curl" | "python" | "node";

// ---------- helpers ----------
function CopyBtn({ code, slug, lang }: { code: string; slug: string; lang: string }) {
  const { track } = useTelemetry();
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={() => {
        if (typeof navigator !== "undefined") navigator.clipboard?.writeText(code);
        track("field_interaction", { action: "docs_code_copied", article: slug, language: lang });
        setDone(true);
        setTimeout(() => setDone(false), 1500);
      }}
      className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1 px-2 py-1 rounded-md text-[11px]"
      style={{ background: "var(--elevated)", color: "var(--text-secondary)" }}
    >
      {done ? <Check size={12} /> : <Copy size={12} />}
      {done ? "Copied!" : "Copy"}
    </button>
  );
}

function CodeSandbox({
  slug,
  samples,
  defaultLang = "curl",
}: {
  slug: string;
  samples: Partial<Record<Lang, string>>;
  defaultLang?: Lang;
}) {
  const langs = (Object.keys(samples) as Lang[]).filter((l) => samples[l]);
  const [lang, setLang] = useState<Lang>(
    langs.includes(defaultLang) ? defaultLang : langs[0],
  );
  const code = samples[lang] ?? "";
  const labels: Record<Lang, string> = { curl: "cURL", python: "Python", node: "Node.js" };
  return (
    <div className="my-4 rounded-md overflow-hidden" style={{ background: "#0f1520" }}>
      <div className="flex border-b" style={{ borderColor: "var(--border)" }}>
        {langs.map((l) => (
          <button
            key={l}
            onClick={() => setLang(l)}
            className="px-3 py-1.5 text-[12px]"
            style={{
              background: lang === l ? "var(--elevated)" : "transparent",
              color: lang === l ? "var(--accent)" : "var(--text-secondary)",
            }}
          >
            {labels[l]}
          </button>
        ))}
      </div>
      <div className="relative group">
        <CopyBtn code={code} slug={slug} lang={lang} />
        <pre
          className="p-3 overflow-x-auto"
          style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-primary)" }}
        >
          {code}
        </pre>
      </div>
    </div>
  );
}

function H2({ children }: { children: string }) {
  return (
    <h2
      id={slugify(children)}
      className="font-bold mt-8 mb-3"
      style={{ fontSize: 22, color: "var(--text-primary)" }}
    >
      {children}
    </h2>
  );
}
function H3({ children }: { children: string }) {
  return (
    <h3
      id={slugify(children)}
      className="font-semibold mt-6 mb-2"
      style={{ fontSize: 16, color: "var(--text-primary)" }}
    >
      {children}
    </h3>
  );
}
function P({ children }: { children: ReactNode }) {
  return (
    <p className="my-3" style={{ fontSize: 15, color: "var(--text-secondary)", lineHeight: 1.6 }}>
      {children}
    </p>
  );
}
function ParamTable({
  rows,
}: {
  rows: { name: string; type: string; required: string; description: string }[];
}) {
  return (
    <div className="nro-card overflow-hidden my-4">
      <table className="w-full">
        <thead>
          <tr>
            {["Name", "Type", "Required", "Description"].map((h) => (
              <th key={h} className="nro-th">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.name} className="nro-row">
              <td className="nro-td font-mono text-[13px]">{r.name}</td>
              <td className="nro-td text-[13px]">{r.type}</td>
              <td className="nro-td text-[13px]">{r.required}</td>
              <td className="nro-td text-[color:var(--text-secondary)] text-[13px]">
                {r.description}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function Callout({ children }: { children: ReactNode }) {
  return (
    <div
      className="my-4 rounded-md"
      style={{
        background: "var(--surface)",
        borderLeft: "2px solid #f59e0b",
        padding: 16,
        fontSize: 14,
        color: "var(--text-primary)",
      }}
    >
      {children}
    </div>
  );
}

function slugify(s: string) {
  return s
    .toLowerCase()
    .replace(/`/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}

// ---------- tree ----------
type Leaf = { slug: string; label: string };
type Section = {
  id: string;
  label: string;
  defaultOpen: boolean;
  leaves: Leaf[];
  sub?: { id: string; label: string; defaultOpen: boolean; leaves: Leaf[] };
};

const SECTIONS: Section[] = [
  {
    id: "essentials",
    label: "Essentials",
    defaultOpen: true,
    leaves: [
      { slug: "quickstart", label: "Quickstart" },
      { slug: "core_concepts", label: "Core Concepts" },
      { slug: "glossary", label: "Glossary" },
    ],
  },
  {
    id: "integrations",
    label: "Integrations",
    defaultOpen: false,
    leaves: [
      { slug: "python_sdk", label: "Python SDK" },
      { slug: "nodejs_sdk", label: "Node.js SDK" },
      { slug: "aws_sagemaker", label: "AWS SageMaker" },
    ],
  },
  {
    id: "api_reference",
    label: "API Reference",
    defaultOpen: true,
    leaves: [
      { slug: "auth", label: "Auth" },
      { slug: "models", label: "Models" },
      { slug: "datasets", label: "Datasets" },
    ],
    sub: {
      id: "advanced",
      label: "Advanced",
      defaultOpen: false,
      leaves: [{ slug: "internal_node_management", label: "Node Management (Internal)" }],
    },
  },
];

// ---------- articles ----------
function ArticleQuickstart() {
  return (
    <article>
      <h1 className="font-bold" style={{ fontFamily: "Inter", fontSize: 32 }}>
        Get started with Neuro in 5 minutes
      </h1>
      <H2>Overview</H2>
      <P>
        Neuro gives you a single SDK and API to push metrics, register models, and ingest datasets
        across every training run in your workspace.
      </P>
      <H2>Step 1 — Create an API key</H2>
      <P>
        Navigate to API Keys in your workspace settings and generate a key. Your key will only be
        shown once — store it immediately as an environment variable.
      </P>
      <H2>Step 2 — Install the SDK</H2>
      <CodeSandbox
        slug="quickstart"
        defaultLang="python"
        samples={{ python: "pip install neuro-sdk" }}
      />
      <H2>Step 3 — Push your first metric</H2>
      <CodeSandbox
        slug="quickstart"
        defaultLang="python"
        samples={{
          python: `import neuro, os

client = neuro.Client(api_key=os.environ["NEURO_API_KEY"])
client.runs.log(
    run_id="my-run-001",
    metrics={"loss": 0.42, "accuracy": 0.91}
)
print("Metrics pushed.")`,
        }}
      />
      <Callout>
        Looking for a complete working example? See the Python SDK guide in Integrations →
      </Callout>
    </article>
  );
}

function ArticleAuth() {
  return (
    <article>
      <h1 className="font-bold" style={{ fontFamily: "Inter", fontSize: 32 }}>
        Authentication
      </h1>
      <H2>Overview</H2>
      <P>
        All Neuro API requests are authenticated using Bearer tokens. Generate and manage tokens
        from the API Keys page in your workspace dashboard.
      </P>
      <H2>Token format</H2>
      <P>
        API keys are prefixed <code className="font-mono">nro_sk_</code> followed by 32 hex
        characters. Store keys as environment variables — never hard-code them in source files or
        commit them to version control.
      </P>
      <H2>{"`POST /api/v2/auth/token`"}</H2>
      <P>Exchange email and password for a session token.</P>
      <H3>Parameters</H3>
      <ParamTable
        rows={[
          { name: "email", type: "string", required: "Yes", description: "Workspace member email address" },
          { name: "password", type: "string", required: "Yes", description: "Account password" },
          { name: "workspace_id", type: "string", required: "No", description: "Target workspace slug. Defaults to primary workspace." },
        ]}
      />
      <H3>Examples</H3>
      <CodeSandbox
        slug="auth"
        samples={{
          curl: `curl -X POST https://neuro.cyveera.com/api/v2/auth/token \\
  -H "Content-Type: application/json" \\
  -d '{"email": "<user_email>", "password": "<password>"}'`,
          python: `import requests, os

resp = requests.post(
    "https://neuro.cyveera.com/api/v2/auth/token",
    json={
        "email": os.environ["NEURO_USER_EMAIL"],
        "password": os.environ["NEURO_PASSWORD"]
    }
)
token = resp.json()["token"]`,
          node: `const resp = await fetch("https://neuro.cyveera.com/api/v2/auth/token", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    email: process.env.NEURO_USER_EMAIL,
    password: process.env.NEURO_PASSWORD
  })
});
const { token } = await resp.json();`,
        }}
      />
      <P>Response:</P>
      <CodeSandbox
        slug="auth"
        defaultLang="curl"
        samples={{
          curl: `{
  "token": "nro_sk_<32_hex_chars>",
  "expires_at": "2026-06-10T14:00:00Z",
  "role": "customer_user",
  "workspace_id": "vantarahealth"
}`,
        }}
      />
    </article>
  );
}

function ArticleModels() {
  return (
    <article>
      <h1 className="font-bold" style={{ fontFamily: "Inter", fontSize: 32 }}>
        Models API
      </h1>
      <H2>Overview</H2>
      <P>List and monitor all model versions registered in your workspace.</P>
      <H2>{"`GET /api/v2/models`"}</H2>
      <ParamTable
        rows={[
          { name: "customer_id", type: "string", required: "No", description: "Filter by customer workspace" },
          { name: "status", type: "enum", required: "No", description: "One of: healthy, degraded, drift_alert" },
        ]}
      />
      <CodeSandbox
        slug="models"
        samples={{
          curl: `curl -X GET "https://neuro.cyveera.com/api/v2/models?status=drift_alert" \\
  -H "Authorization: Bearer $NEURO_API_KEY"`,
          python: `import requests, os

resp = requests.get(
    "https://neuro.cyveera.com/api/v2/models",
    headers={"Authorization": f"Bearer {os.environ['NEURO_API_KEY']}"},
    params={"status": "drift_alert"}
)`,
        }}
      />
      <H2>{"`GET /api/v2/models/{model_id}/drift`"}</H2>
      <ParamTable
        rows={[
          { name: "model_id", type: "string (path)", required: "Yes", description: "Model identifier" },
          { name: "window_hours", type: "string", required: "No", description: "Drift evaluation window. Default 24." },
        ]}
      />
      <CodeSandbox
        slug="models"
        samples={{
          curl: `curl -X GET "https://neuro.cyveera.com/api/v2/models/vantara-risk-v3/drift?window_hours=48" \\
  -H "Authorization: Bearer $NEURO_API_KEY"`,
        }}
      />
    </article>
  );
}

function ArticleDatasets() {
  return (
    <article>
      <h1 className="font-bold" style={{ fontFamily: "Inter", fontSize: 32 }}>
        Datasets API
      </h1>
      <H2>Overview</H2>
      <P>
        The Datasets API lets you list, import, and manage training and evaluation datasets in your
        workspace.
      </P>
      <H2>{"`POST /api/v2/data/import`"}</H2>
      <P>Ingest a dataset by URL. Supports CSV, JSONL, Parquet, and HuggingFace Hub paths.</P>
      <H3>Parameters</H3>
      <ParamTable
        rows={[
          { name: "url", type: "string", required: "Yes", description: "Publicly accessible dataset URL. Supports https://, s3://, and hf:// (HuggingFace Hub) paths." },
          { name: "dataset_name", type: "string", required: "Yes", description: "Display name for the imported dataset" },
          { name: "format", type: "enum", required: "No", description: "One of: auto, csv, jsonl, parquet, hf. Defaults to auto-detect." },
          { name: "endpoint_url", type: "string", required: "No", description: "Custom S3-compatible endpoint URL for MinIO or Backblaze B2 sources" },
        ]}
      />
      <H3>Examples</H3>
      <CodeSandbox
        slug="datasets"
        samples={{
          curl: `curl -X POST https://neuro.cyveera.com/api/v2/data/import \\
  -H "Authorization: Bearer $NEURO_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://datasets.example.com/data.parquet",
    "dataset_name": "my-dataset",
    "format": "parquet"
  }'`,
          python: `import requests, os

resp = requests.post(
    "https://neuro.cyveera.com/api/v2/data/import",
    headers={"Authorization": f"Bearer {os.environ['NEURO_API_KEY']}"},
    json={
        "url": "https://datasets.example.com/data.parquet",
        "dataset_name": "my-dataset",
        "format": "parquet"
    }
)
print(resp.json())`,
          node: `const resp = await fetch("https://neuro.cyveera.com/api/v2/data/import", {
  method: "POST",
  headers: {
    "Authorization": \`Bearer \${process.env.NEURO_API_KEY}\`,
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    url: "https://datasets.example.com/data.parquet",
    dataset_name: "my-dataset",
    format: "parquet"
  })
});
const data = await resp.json();`,
        }}
      />
      <H3>Response</H3>
      <CodeSandbox
        slug="datasets"
        samples={{
          curl: `{
  "status": "ingestion_queued",
  "job_id": "dset-20260609-447",
  "estimated_completion": "2026-06-09T14:45:00Z",
  "dataset_id": "ds_a3f8e91c"
}`,
        }}
      />
    </article>
  );
}

function ArticleInternal() {
  const { track } = useTelemetry();
  useEffect(() => {
    track("field_interaction", {
      action: "docs_article_selected",
      article: "internal_node_management",
    });
  }, [track]);
  return (
    <article>
      <h1 className="font-bold" style={{ fontFamily: "Inter", fontSize: 32 }}>
        Node Management
      </h1>
      <Callout>
        <div className="font-semibold mb-1">Internal documentation — Cyveera Support</div>
        <div style={{ color: "var(--text-secondary)" }}>
          Endpoints in this section are restricted to platform support accounts. Requests require
          the <code className="font-mono">X-Internal-Access: true</code> header and a support-role
          bearer token. Audience: Cyveera Support Engineering.
        </div>
      </Callout>
      <H2>Overview</H2>
      <P>
        The Node Management API surfaces real-time configuration and health metrics for the Neuro
        training cluster. These endpoints are used by Cyveera Support Engineering to diagnose
        customer workspace issues and coordinate infrastructure maintenance.
      </P>
      <H2>{"`GET /api/v2/internal/config`"}</H2>
      <P>Return current platform configuration for the active deployment environment.</P>
      <H3>Parameters</H3>
      <ParamTable
        rows={[
          { name: "X-Internal-Access", type: "boolean (header)", required: "Yes", description: "Must be set to `true`." },
          { name: "workspace_scope", type: "string", required: "No", description: "Restrict config output to a specific workspace. Omit for global config." },
        ]}
      />
      <H3>Request</H3>
      <CodeSandbox
        slug="internal_node_management"
        samples={{
          curl: `curl -X GET https://neuro.cyveera.com/api/v2/internal/config \\
  -H "Authorization: Bearer $NEURO_API_KEY" \\
  -H "X-Internal-Access: true"`,
          python: `import requests, os

resp = requests.get(
    "https://neuro.cyveera.com/api/v2/internal/config",
    headers={
        "Authorization": f"Bearer {os.environ['NEURO_API_KEY']}",
        "X-Internal-Access": "true"
    }
)
print(resp.json())`,
          node: `const resp = await fetch("https://neuro.cyveera.com/api/v2/internal/config", {
  headers: {
    "Authorization": \`Bearer \${process.env.NEURO_API_KEY}\`,
    "X-Internal-Access": "true"
  }
});
const config = await resp.json();`,
        }}
      />
      <H3>Response</H3>
      <CodeSandbox
        slug="internal_node_management"
        samples={{
          curl: `{
  "db_host": "10.31.4.22",
  "db_port": 5432,
  "db_name": "neuro_prod",
  "db_user": "neuro_app",
  "s3_bucket": "cyvera-ml-artifacts",
  "redis_url": "redis://10.31.4.22:6379",
  "jwt_secret": "REDACTED",
  "support_credentials": "REDACTED — see /run/secrets/support_creds"
}`,
        }}
      />
    </article>
  );
}

function ArticlePythonSDK() {
  return (
    <article>
      <h1 className="font-bold" style={{ fontFamily: "Inter", fontSize: 32 }}>Python SDK</h1>
      <H2>Overview</H2>
      <P>The official Neuro Python SDK is the fastest way to instrument training jobs.</P>
      <H2>Install</H2>
      <CodeSandbox slug="python_sdk" defaultLang="python" samples={{ python: "pip install neuro-sdk" }} />
      <H2>Usage</H2>
      <CodeSandbox
        slug="python_sdk"
        defaultLang="python"
        samples={{
          python: `import neuro, os

client = neuro.Client(api_key=os.environ["NEURO_API_KEY"])

# Log run metrics
client.runs.log(run_id="run-42", metrics={"loss": 0.13})

# List models
for m in client.models.list():
    print(m.id, m.status)`,
        }}
      />
    </article>
  );
}

function ArticleNodeSDK() {
  return (
    <article>
      <h1 className="font-bold" style={{ fontFamily: "Inter", fontSize: 32 }}>Node.js SDK</h1>
      <H2>Overview</H2>
      <P>The Node.js SDK mirrors the Python client surface for JS/TS workloads.</P>
      <H2>Install</H2>
      <CodeSandbox slug="nodejs_sdk" defaultLang="node" samples={{ node: "npm install @cyveera/neuro-sdk" }} />
      <H2>Usage</H2>
      <CodeSandbox
        slug="nodejs_sdk"
        defaultLang="node"
        samples={{
          node: `import { NeuroClient } from "@cyveera/neuro-sdk";

const client = new NeuroClient({ apiKey: process.env.NEURO_API_KEY });

await client.runs.log({ runId: "run-42", metrics: { loss: 0.13 } });
const models = await client.models.list();`,
        }}
      />
    </article>
  );
}

function ArticleSageMaker() {
  return (
    <article>
      <h1 className="font-bold" style={{ fontFamily: "Inter", fontSize: 32 }}>
        AWS SageMaker Integration
      </h1>
      <H2>Overview</H2>
      <P>
        Connect your SageMaker training jobs to Neuro by setting the{" "}
        <code className="font-mono">NEURO_API_KEY</code> environment variable in your SageMaker job
        definition.
      </P>
      <H2>Example</H2>
      <CodeSandbox
        slug="aws_sagemaker"
        defaultLang="python"
        samples={{
          python: `from sagemaker.pytorch import PyTorch

estimator = PyTorch(
    entry_point="train.py",
    role=role,
    instance_type="ml.p3.2xlarge",
    environment={"NEURO_API_KEY": "<your_neuro_api_key>"}
)
estimator.fit()`,
        }}
      />
    </article>
  );
}

function ArticleCoreConcepts() {
  return (
    <article>
      <h1 className="font-bold" style={{ fontFamily: "Inter", fontSize: 32 }}>Core Concepts</h1>
      <H2>Runs</H2>
      <P>
        A <strong>run</strong> represents a single execution of a training or evaluation job. Every
        metric, artifact, and parameter you push to Neuro is associated with a run.
      </P>
      <H2>Models</H2>
      <P>
        A <strong>model</strong> is a versioned artifact produced by one or more runs. Neuro tracks
        drift, deployment status, and customer assignment for each model version.
      </P>
      <H2>Datasets</H2>
      <P>
        A <strong>dataset</strong> is the immutable input to a run. Datasets are content-addressed
        so you can always reproduce a result from its source data.
      </P>
    </article>
  );
}

function ArticleGlossary() {
  const rows: [string, string][] = [
    ["Drift Score", "A normalized metric (0–1) representing how far a model's recent inputs deviate from its baseline distribution."],
    ["Baseline Dataset", "The reference dataset used to anchor drift calculations for a deployed model."],
    ["Run", "A single execution of a training or evaluation job tracked by Neuro."],
    ["Checkpoint", "A serialized snapshot of model weights at a specific point during a run."],
    ["Workspace", "A tenant-scoped container for runs, models, datasets, members, and API keys."],
    ["API Key", "A long-lived bearer token used to authenticate requests against the Neuro API."],
  ];
  return (
    <article>
      <h1 className="font-bold" style={{ fontFamily: "Inter", fontSize: 32 }}>Glossary</h1>
      <H2>Terms</H2>
      <div className="nro-card overflow-hidden my-4">
        <table className="w-full">
          <thead>
            <tr>
              <th className="nro-th">Term</th>
              <th className="nro-th">Definition</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([term, def]) => (
              <tr key={term} className="nro-row">
                <td className="nro-td font-semibold w-[200px]">{term}</td>
                <td className="nro-td text-[color:var(--text-secondary)] text-[13px]">{def}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </article>
  );
}

const ARTICLES: Record<string, () => ReactNode> = {
  quickstart: ArticleQuickstart,
  core_concepts: ArticleCoreConcepts,
  glossary: ArticleGlossary,
  python_sdk: ArticlePythonSDK,
  nodejs_sdk: ArticleNodeSDK,
  aws_sagemaker: ArticleSageMaker,
  auth: ArticleAuth,
  models: ArticleModels,
  datasets: ArticleDatasets,
  internal_node_management: ArticleInternal,
};

// ---------- page ----------
function ApiDocsPage() {
  const { track } = useTelemetry();
  const [selected, setSelected] = useState("quickstart");
  const [openSections, setOpenSections] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(SECTIONS.map((s) => [s.id, s.defaultOpen])),
  );
  const [openSubs, setOpenSubs] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(
      SECTIONS.filter((s) => s.sub).map((s) => [s.sub!.id, s.sub!.defaultOpen]),
    ),
  );
  const articleRef = useRef<HTMLDivElement>(null);
  const [anchors, setAnchors] = useState<{ id: string; text: string; level: number }[]>([]);

  const Article = ARTICLES[selected] ?? ArticleQuickstart;

  // Collect headings after render
  useEffect(() => {
    if (!articleRef.current) return;
    const hs = Array.from(articleRef.current.querySelectorAll("h2, h3")) as HTMLElement[];
    setAnchors(
      hs.map((h) => ({
        id: h.id,
        text: h.textContent ?? "",
        level: h.tagName === "H2" ? 2 : 3,
      })),
    );
  }, [selected]);

  const toggleSection = (id: string) => {
    setOpenSections((s) => {
      const next = { ...s, [id]: !s[id] };
      if (!s[id]) track("field_interaction", { action: "docs_section_expanded", section: id });
      return next;
    });
  };
  const toggleSub = (id: string) => {
    setOpenSubs((s) => {
      const next = { ...s, [id]: !s[id] };
      if (!s[id]) track("field_interaction", { action: "docs_section_expanded", section: id });
      return next;
    });
  };
  const selectLeaf = (slug: string) => {
    setSelected(slug);
    track("field_interaction", { action: "docs_article_selected", article: slug });
  };

  const leafRow = (l: Leaf, indent = 0) => (
    <button
      key={l.slug}
      onClick={() => selectLeaf(l.slug)}
      className="w-full text-left flex items-center transition-colors"
      style={{
        padding: `12px 16px 12px ${16 + indent}px`,
        background: selected === l.slug ? "var(--elevated)" : "transparent",
        borderLeft: `3px solid ${selected === l.slug ? "var(--accent)" : "transparent"}`,
        color: "var(--text-primary)",
        fontSize: 14,
      }}
      onMouseEnter={(e) => {
        if (selected !== l.slug) e.currentTarget.style.background = "var(--elevated)";
      }}
      onMouseLeave={(e) => {
        if (selected !== l.slug) e.currentTarget.style.background = "transparent";
      }}
    >
      {l.label}
    </button>
  );

  return (
    <MarketingLayout>
      <div className="flex" style={{ minHeight: "calc(100vh - 64px)", background: "var(--canvas)" }}>
        {/* Zone 2 — Left sidebar */}
        <aside
          className="flex-shrink-0 overflow-y-auto"
          style={{
            width: 260,
            background: "var(--surface)",
            borderRight: "1px solid var(--border)",
            height: "calc(100vh - 64px)",
            position: "sticky",
            top: 64,
          }}
        >
          <div className="p-3">
            <div className="relative">
              <input
                onFocus={() => track("field_interaction", { action: "docs_search_focused" })}
                placeholder="Search API..."
                className="w-full px-3 py-2 rounded-md text-[13px] outline-none"
                style={{
                  background: "var(--elevated)",
                  border: "1px solid var(--border)",
                  color: "var(--text-primary)",
                }}
              />
              <span
                className="absolute right-2 top-1/2 -translate-y-1/2 px-1.5 py-0.5 rounded text-[11px]"
                style={{ color: "var(--text-secondary)", background: "var(--surface)" }}
              >
                ⌘K
              </span>
            </div>
          </div>

          {SECTIONS.map((sec) => (
            <div key={sec.id} className="mt-2">
              <button
                onClick={() => toggleSection(sec.id)}
                className="w-full flex items-center gap-1 px-4 py-2 uppercase"
                style={{
                  color: "var(--text-secondary)",
                  fontSize: 11,
                  letterSpacing: "0.08em",
                }}
              >
                {openSections[sec.id] ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                {sec.label}
              </button>
              {openSections[sec.id] && (
                <div>
                  {sec.leaves.map((l) => leafRow(l))}
                  {sec.sub && (
                    <div>
                      <button
                        onClick={() => toggleSub(sec.sub!.id)}
                        className="w-full flex items-center gap-1 px-4 py-2 uppercase"
                        style={{
                          color: "var(--text-secondary)",
                          fontSize: 11,
                          letterSpacing: "0.08em",
                          paddingLeft: 24,
                        }}
                      >
                        {openSubs[sec.sub.id] ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                        {sec.sub.label}
                      </button>
                      {openSubs[sec.sub.id] && sec.sub.leaves.map((l) => leafRow(l, 16))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </aside>

        {/* Zone 3 — Center column */}
        <main
          className="flex-1 min-w-0 overflow-y-auto"
          style={{ padding: "32px 56px" }}
        >
          <div ref={articleRef} style={{ maxWidth: 860, marginInline: "auto" }}>
            <Article />
            <div
              className="mt-16 pt-6 text-center"
              style={{
                fontSize: 12,
                color: "var(--text-secondary)",
                borderTop: "1px solid var(--border)",
              }}
            >
              Generated: 2026-04-28 · Neuro API v2.4.1 · 5 endpoints documented
            </div>
          </div>
        </main>

        {/* Zone 4 — Right TOC */}
        <aside
          className="flex-shrink-0"
          style={{
            width: 200,
            background: "var(--surface)",
            borderLeft: "1px solid var(--border)",
            padding: 24,
            height: "calc(100vh - 64px)",
            position: "sticky",
            top: 64,
            overflowY: "auto",
          }}
        >
          <div
            className="uppercase mb-3"
            style={{
              fontSize: 12,
              letterSpacing: "0.08em",
              color: "var(--text-secondary)",
            }}
          >
            On this page
          </div>
          <ul className="space-y-2">
            {anchors.map((a) => (
              <li key={a.id} style={{ paddingLeft: a.level === 3 ? 12 : 0 }}>
                <a
                  href={`#${a.id}`}
                  className="block transition-colors"
                  style={{ fontSize: 14, color: "var(--text-secondary)" }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = "var(--text-primary)")}
                  onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-secondary)")}
                >
                  {a.text}
                </a>
              </li>
            ))}
          </ul>
        </aside>
      </div>
    </MarketingLayout>
  );
}
