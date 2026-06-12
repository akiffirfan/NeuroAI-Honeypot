# Neuro by Cyveera — Full Website Feature Specification

**Document purpose**: Complete page-by-page specification for the public-facing Neuro by Cyveera website. This document is the single source of truth a developer reads to build every page from scratch, including visual design, copy, interactive behavior, and the hidden deception layer embedded in each page.

**Legend**: Neuro is a B2B ML Observability SaaS. Companies — primarily healthcare AI, fintech, and pharma — pay a monthly subscription to monitor their production AI models through Neuro's dashboard. The platform detects drift, failure, and degradation before end users notice. Customers log in with their own company email addresses.

**Tagline**: "Neuro monitors what your models do in production."
**Problem statement**: "Neuro tells companies when their AI systems stop working correctly — before their customers notice."

---

## Design System

### Color Palette
- **Canvas** (page background): `#0a0d14` — near-black with a faint blue cast
- **Surface** (cards, panels): `#111827` — dark navy
- **Elevated** (modals, dropdowns): `#1a2235` — slightly lighter navy
- **Border**: `#1f2d45` — muted dark blue border
- **Accent** (primary CTA, active states): `#10b981` — emerald green (signals AI/health)
- **Accent-hover**: `#059669`
- **Muted text**: `#64748b` — slate gray
- **Body text**: `#cbd5e1` — light slate
- **Heading text**: `#f1f5f9` — near-white
- **Danger**: `#ef4444`
- **Warning**: `#f59e0b`
- **Tag/badge background**: `#0f2a1e` with `#10b981` text

### Typography
- **Headings**: Inter, 700 weight
- **Body**: Inter, 400/500 weight
- **Monospace** (API keys, code, hostnames): JetBrains Mono
- **Base size**: 15px body, 13px secondary text, 12px labels

### Layout Conventions
- Public pages: full-width with a centered content column, max-width 1200px, 80px horizontal padding
- Authenticated pages: fixed left sidebar (240px wide, full viewport height) + main content area filling the rest
- Top navigation bar on authenticated pages: 60px tall, sits above the sidebar, full width
- All cards use `border-radius: 8px`, `border: 1px solid #1f2d45`, `background: #111827`

---

## PUBLIC PAGES

---

### Page 1: `/` — Homepage / Landing Page

**Purpose**: Convert visitors (potential customers) into trial signups. Establishes product credibility.

**Layout**: Single long-scroll page. Sticky top navigation bar. Hero section above the fold, followed by: logo strip, problem/solution section, feature grid, how-it-works walkthrough, customer quotes, final CTA section, footer.

---

**Top Navigation Bar**

Fixed to the top of the viewport. `background: #0a0d14`, `border-bottom: 1px solid #1f2d45`. Height 64px.

Left side: Neuro wordmark in Inter 700, color `#f1f5f9`, preceded by a small square logo mark — a stylized N formed from two overlapping waveforms in emerald green. Clicking the wordmark scrolls to the top.

Right side (flex row, 24px gaps):
- Text link "Product" (dropdown on hover — items: Overview, Models, Alerts, Integrations)
- Text link "Pricing" (links to `/pricing`)
- Text link "Security" (links to `/security`)
- Text link "Docs" (links to `/api-docs` — the fake Swagger page, session-gated so redirects to login)
- Vertical divider
- Text link "Sign in" (color `#cbd5e1`, links to `/login`)
- Green filled button "Start free trial" (links to `/login`, internally noted as highest-conversion CTA)

---

**Hero Section**

Full viewport height on first render. Centered content. Dark background with a subtle radial gradient glow emanating from center-top — a blurred emerald circle at roughly 20% opacity, 600px diameter. A faint dot-grid pattern overlays the background at 4% opacity.

**Main headline** (Inter 700, 64px, `#f1f5f9`):
"Your AI models break in production. Neuro tells you first."

**Subheadline** (Inter 400, 20px, `#94a3b8`, max-width 580px, centered):
"Real-time observability for production ML systems. Monitor model drift, data quality failures, and inference degradation — across every environment your team ships to."

**CTA buttons** (row, centered, 16px gap):
- Primary: filled emerald button, "Start free trial — no credit card required", 48px height, 20px horizontal padding, links to `/login`
- Secondary: ghost button with `#1f2d45` border, "See a live demo", same height, opens a Calendly-style modal (static placeholder — clicking logs a `demo_request` telemetry event and shows a "We'll be in touch" message)

**Below the buttons**: small muted text, `#64748b`, 13px — "Trusted by ML teams at Vantara, Merisol, Quelaris, Ardentix, and 40+ other organizations."

**Scroll indicator**: a small animated chevron-down icon in `#1f2d45`, 48px below the CTAs, subtle bounce animation (CSS keyframes).

---

**Logo Strip** (below hero, 80px vertical padding)

Section header: "Trusted by production ML teams" — `#64748b`, 12px, uppercase, letter-spacing 0.12em, centered.

Below the header: a horizontal flex row of six company wordmarks, evenly spaced, each rendered as SVG text in `#475569`. The logos are:
- **Vantara** (sans-serif, weight 600)
- **Merisol** (geometric, weight 700)
- **Quelaris** (light, weight 300)
- **Ardentix** (bold, weight 800)
- **Lumira** (medium, weight 500)
- **Denova** (regular, weight 400)

On hover each logo brightens slightly (opacity 1.0 from 0.5 default). No links — the logos are purely decorative social proof.

---

**Problem / Solution Section** (80px vertical padding, `background: #111827` — slight surface lift)

Two-column layout, equal width, 64px gap. Left column is the "problem"; right column is the "solution".

**Left column — the problem**:
- Section eyebrow: "The problem" in emerald text, 12px, uppercase
- Headline: "Your models degrade silently. By the time you know, it's too late." Inter 700, 28px, `#f1f5f9`
- Body (Inter 400, 15px, `#94a3b8`): "Most ML teams find out about model failure from customer complaints, not monitoring systems. A model trained on last quarter's data ships to production and starts drifting the moment the world changes. Without observability, you're flying blind."
- Below that, three "symptom" cards in a vertical list. Each card has a `#ef4444` dot icon on the left:
  1. "Fraud detection model accuracy drops 14% after a data pipeline change — 6 hours before anyone notices."
  2. "Clinical risk model starts assigning wrong risk tiers due to schema drift in upstream EHR data."
  3. "Recommendation model begins returning stale embeddings after a vector DB migration."

**Right column — the solution**:
- Section eyebrow: "What Neuro does" in emerald text, 12px, uppercase
- Headline: "Continuous monitoring that runs alongside your production stack." Inter 700, 28px, `#f1f5f9`
- Body (Inter 400, 15px, `#94a3b8`): "Neuro integrates with your existing inference pipeline via a lightweight SDK. It monitors every prediction your model makes — flagging distribution shift, input anomalies, and output degradation in real time. Alert your team before a bad prediction reaches your end user."
- Three "resolution" cards, each with a `#10b981` check icon:
  1. "Sub-minute detection of distribution shift across all monitored features."
  2. "Automatic baseline comparison against your last healthy checkpoint."
  3. "Integration with PagerDuty, Slack, and custom webhooks in under 10 minutes."

---

**Feature Grid Section** (80px vertical padding, canvas background)

Section eyebrow: "Platform capabilities" — emerald, 12px, uppercase, centered
Headline: "Everything a production ML team needs." — Inter 700, 40px, `#f1f5f9`, centered
Subheadline: "From model registration to live inference monitoring, Neuro covers the full production lifecycle." — `#94a3b8`, 18px, centered, max-width 600px

Below: a 3×2 grid of feature cards (6 total), each `background: #111827`, `border: 1px solid #1f2d45`, `border-radius: 8px`, 32px padding, hover state adds `border-color: #10b981` with 200ms transition.

Each card has:
- Icon in a 40px × 40px rounded square, `background: #0f2a1e`, with an emerald SVG icon inside
- Title in Inter 600, 16px, `#f1f5f9`
- Description in Inter 400, 14px, `#64748b`

The six cards:

1. **Model Monitoring** — icon: eye
   "Track prediction distributions, feature drift, and output confidence across every model version in production. Supports classification, regression, and embedding models."

2. **Drift Detection** — icon: activity/wave
   "Statistical tests (PSI, KL divergence, Wasserstein distance) run on every prediction batch. Alerts fire when drift exceeds configurable thresholds — per feature, per label, per segment."

3. **Training Run History** — icon: clock/history
   "Full lineage from dataset version to deployed checkpoint. Compare hyperparameters, metrics, and artifacts across runs. Audit who trained what and when."

4. **Data Quality Gates** — icon: shield-check
   "Validate input schema, detect null spikes, outliers, and distribution mismatches before they reach your inference engine. Block bad batches at the pipeline boundary."

5. **Alerting & Escalation** — icon: bell
   "Route alerts to Slack, PagerDuty, OpsGenie, or any webhook endpoint. Configure severity levels, suppression windows, and on-call schedules per model."

6. **Compliance Reporting** — icon: file-text
   "Generate audit-ready reports for model governance, FDA SaMD submissions, and internal risk committees. Scheduled PDF exports with digital signature."

---

**How It Works Section** (80px vertical padding, `background: #111827`)

Section eyebrow: "Setup in minutes" — emerald, centered
Headline: "Three steps to production observability." — Inter 700, 40px, centered

Three large numbered steps in a horizontal flex row:

**Step 1 — Connect**
Large "01" in Inter 800, 72px, `#1f2d45` (very muted, decorative). Below it:
- Title: "Install the SDK and point it at your inference pipeline"
- Body: "One pip install. Add three lines of Python to your serving code. Neuro begins capturing predictions, features, and metadata without modifying your model or infrastructure."
- Code block (JetBrains Mono, dark background): `pip install neuro-sdk` then `from neuro import Monitor` then `monitor = Monitor(api_key="nro-YOUR_KEY")` — fake but realistic

**Step 2 — Configure**
Large "02" decorative.
- Title: "Define your baseline and alert thresholds in the Neuro dashboard"
- Body: "Select which features to monitor. Set drift thresholds per segment. Configure alert routing. Takes less than 15 minutes for most production models."

**Step 3 — Monitor**
Large "03" decorative.
- Title: "Receive real-time alerts and investigate with full context"
- Body: "When something drifts, Neuro fires an alert with the exact feature, time window, and statistical distance. Click through to a drill-down view with comparison plots and the raw prediction sample."

---

**Customer Quotes Section** (80px vertical padding, canvas background)

Headline: "What production ML teams say" — Inter 700, 36px, centered

Three quote cards in a horizontal row:

**Quote 1**:
- Quote text: "We had a model running in our clinical decision support system for three months before Neuro flagged that it was drifting on a feature we'd deprecated in the upstream EHR. Without Neuro, we wouldn't have known until a clinician filed a support ticket."
- Attribution: "Priya R., Senior ML Engineer — Vantara Health"
- Avatar: circular, 40px, initials "PR" on `#0f2a1e` background

**Quote 2**:
- Quote text: "Integration took our team under an hour. We connected it to PagerDuty and had our first real drift alert within 48 hours of going live. The PSI threshold configuration is exactly the level of control we needed."
- Attribution: "James T., Head of AI — Merisol"
- Avatar: "JT" initials

**Quote 3**:
- Quote text: "The compliance reporting feature alone saved us two weeks of manual work before our last model governance audit. The automated PDF with version lineage is genuinely good enough to hand to regulators."
- Attribution: "Angela K., Principal Data Scientist — Quelaris"
- Avatar: "AK" initials

---

**Final CTA Section** (80px vertical padding, `background: #111827`)

Centered content. A single card with `border: 1px solid #10b981`, `border-radius: 12px`, 48px padding, subtle emerald glow effect (box-shadow: `0 0 40px rgba(16, 185, 129, 0.08)`).

Headline: "Your models are already in production. Start monitoring them today." — Inter 700, 32px
Subheadline: "Free trial includes 3 models, 30-day history, and full alert configuration." — `#94a3b8`, 16px
Two buttons as in the hero section. Below them: "No credit card required. Cancel anytime. SOC 2 Type II certified."

---

**Footer**

`background: #0a0d14`, `border-top: 1px solid #1f2d45`. Four-column layout.

**Column 1 — Branding**:
- Neuro wordmark + logo mark
- Tagline: "Neuro monitors what your models do in production."
- Social icons (Twitter/X, LinkedIn, GitHub) — `#475569`, no-op links
- Copyright line: "© 2025 Cyveera, Inc. All rights reserved." (one year behind — intentional)

**Column 2 — Product**:
- Links: Overview, Pricing, Security, Changelog, Status (→ `/status`), API Docs

**Column 3 — Company**:
- Links: About, Blog, Careers ("We're hiring →"), Press Kit, Contact

**Column 4 — Legal**:
- Links: Privacy Policy, Terms of Service, DPA (Data Processing Agreement), Cookie Settings
- At the bottom: "SOC 2 Type II" badge (gray pill), "HIPAA Ready" badge (gray pill), "GDPR" badge (gray pill) — purely decorative SVG badges

HTML source comment (visible only to view-source users — lure):
```
<!-- TODO: remove dev config before next deploy
     support login: support@cyveera.ai (see deploy.conf for pw)
     internal relay: http://10.31.4.22:3128 — dev environment only
-->
```

---

### Page 2: `/pricing` — Pricing Page

**Purpose**: Display subscription tiers. Convinces visitors the product is a real paid service with real pricing decisions.

**Layout**: Top nav (same as homepage). Centered content, max-width 1000px. Pricing toggle at top, three-column tier cards, feature comparison table, FAQ section, footer.

---

**Above the fold**:

Background: canvas (`#0a0d14`). Same radial glow as homepage hero but dimmer.

Section eyebrow: "Pricing" — emerald, centered, uppercase
Headline: "Straightforward pricing for production teams." — Inter 700, 48px, `#f1f5f9`, centered
Subheadline: "Start free. Pay as you grow. No per-seat pricing — just models and predictions." — `#94a3b8`, 18px, centered

**Billing toggle**: A pill toggle switch — "Monthly" / "Annual (save 20%)". Default to "Monthly". Clicking "Annual" applies a 20% discount visually (JS updates prices in-place). No network request — purely cosmetic.

---

**Three Tier Cards** (horizontal row, equal width, 24px gap)

**Starter** — `border: 1px solid #1f2d45`
- Tier label: "Starter" — `#94a3b8`, 14px, uppercase
- Price: "$299 / month" — Inter 700, 40px, `#f1f5f9`. Annual price: "$239 / month" (billed $2,868/yr)
- Description: "For early-stage teams monitoring their first production models."
- CTA button: "Start free trial" — ghost style, full width
- Feature list (checkmarks, emerald):
  - Up to 5 models monitored
  - 10M predictions / month
  - 30-day prediction history
  - Drift detection (PSI, KL divergence)
  - Slack and email alerts
  - Standard support (48h SLA)
  - 1 workspace / 3 team members

**Pro** — `border: 1px solid #10b981` (highlighted), a "Most popular" pill badge in top-right corner
- Tier label: "Pro" — emerald, 14px, uppercase
- Price: "$899 / month" — Inter 700, 40px, `#f1f5f9`. Annual: "$719 / month"
- Description: "For growing teams with multiple production models and complex alerting needs."
- CTA button: "Start free trial" — filled emerald, full width
- Feature list:
  - Up to 25 models monitored
  - 100M predictions / month
  - 90-day prediction history
  - All Starter drift tests + Wasserstein distance
  - PagerDuty, OpsGenie, custom webhook alerts
  - Priority support (8h SLA)
  - 3 workspaces / unlimited members
  - Compliance report exports (PDF)
  - SSO via Google Workspace

**Enterprise** — `border: 1px solid #1f2d45`
- Tier label: "Enterprise" — `#94a3b8`, 14px, uppercase
- Price: "Custom pricing" — Inter 700, 36px, `#f1f5f9`
- Description: "For regulated industries with audit requirements, on-prem options, or volume commitments."
- CTA button: "Talk to sales" — ghost style, full width. Clicking opens same demo modal as homepage (static, logs telemetry event).
- Feature list:
  - Unlimited models
  - Unlimited predictions
  - 365-day history + long-term cold storage
  - Custom drift tests + human-in-the-loop review workflows
  - HIPAA BAA available
  - HITRUST, FedRAMP path
  - SLA: 99.9% uptime guarantee
  - Dedicated support engineer
  - On-premises deployment option
  - Audit log export (SOC 2 evidence)

---

**Feature Comparison Table** (below the tier cards, 60px margin-top)

Collapsed by default — a "See full feature comparison" button (ghost, centered) expands the table.

Table has 4 columns: Feature | Starter | Pro | Enterprise.
Rows are grouped by category (Monitoring, Alerts, Compliance, Support, Data Retention).

Example rows:
- Models monitored: 5 | 25 | Unlimited
- Predictions per month: 10M | 100M | Unlimited
- Drift detection algorithms: PSI, KL | PSI, KL, Wasserstein | Custom
- HIPAA BAA: ✗ | ✗ | ✓
- SSO: ✗ | Google Workspace | SAML, OIDC, Okta
- Audit log: ✗ | 30 days | 365 days + export

---

**FAQ Section** (60px margin-top)

Headline: "Common questions" — Inter 600, 28px
Six accordion items. Each has a question row (clickable, expands answer, chevron rotates). Pure CSS — no network requests.

1. "What counts as a 'prediction' for billing purposes?" — Answer explains that each call to your model's inference endpoint is one prediction. Batch jobs count per item in the batch.

2. "Can I monitor models that aren't in Python?" — Answer: Yes. The Neuro SDK ships for Python, Node.js, and Java. Any HTTP-accessible inference endpoint can also be monitored via the proxy integration.

3. "What happens if I exceed my monthly prediction limit?" — Answer: Monitoring continues but drift alerts are queued rather than immediate. You'll receive a dashboard warning. Overages are billed at $0.0012 per thousand excess predictions.

4. "Is there a free trial?" — Answer: Yes. All plans start with a 14-day free trial. You can monitor up to 3 models with no prediction limit during the trial.

5. "Do you offer a HIPAA Business Associate Agreement?" — Answer: Yes, on Enterprise plans. Contact our compliance team at compliance@cyveera.ai.

6. "Can I export my data if I cancel?" — Answer: Yes. We provide a full data export in Parquet or JSONL format within 14 days of cancellation.

---

### Page 3: `/security` — Security & Compliance Page

**Purpose**: Provide enough security detail to pass enterprise procurement review. This page also serves as a lure for security researchers who enumerate a target's trust posture.

**Layout**: Same top nav. Single-column centered content with alternating background sections. No sidebar.

---

**Hero Section**:
Headline: "Security isn't a feature. It's the foundation." — Inter 700, 48px, centered
Subheadline: "Neuro is built to handle production model data from regulated industries. SOC 2 Type II certified, HIPAA-ready, and designed for the strictest enterprise security requirements." — `#94a3b8`, 18px, centered, max-width 640px

Three badge pills centered below: "SOC 2 Type II", "HIPAA Ready", "GDPR Compliant" — each a rounded pill with an icon and emerald border.

---

**Infrastructure Section**:
Eyebrow: "Infrastructure"
Headline: "Isolated, encrypted, and auditable by design."

Four cards in a 2×2 grid:

1. **Data Encryption** — "All data encrypted at rest (AES-256) and in transit (TLS 1.3). Prediction payloads are encrypted before storage and decrypted only at query time. Encryption keys are managed via AWS KMS with automatic 90-day rotation."

2. **Network Isolation** — "Neuro's processing infrastructure runs in isolated VPCs with no public ingress beyond the API gateway. Internal services communicate over private subnets. Egress is allowlisted by FQDN, not by IP range."

3. **Access Control** — "Role-based access control at the workspace, model, and dataset level. All authentication events are logged. API keys can be scoped to read-only, write, or admin roles with expiry enforcement."

4. **Audit Logging** — "Every API call, login, key rotation, and configuration change is logged to an immutable append-only audit trail. Logs are retained for 365 days and exportable in JSONL format for SIEM ingestion."

---

**Compliance Certifications Section** (`background: #111827`):
Headline: "Certifications & compliance frameworks"

Horizontal list of certification cards. Each has an icon, name, and one-sentence description:
- **SOC 2 Type II** — "Annual audit by independent third-party auditor. Report available under NDA to Enterprise customers."
- **HIPAA** — "BAA available on Enterprise plans. PHI handling procedures documented and audited annually."
- **GDPR** — "DPA available at cyveera.ai/dpa. Data residency options available for EU-based Enterprise customers."
- **ISO 27001** — "Certification in progress. Expected Q3 2026." (intentionally in-progress — adds realism)

---

**Vulnerability Disclosure Section**:
Headline: "Responsible disclosure"
Body: "We take security reports seriously. If you discover a vulnerability in Neuro's platform or infrastructure, please contact our security team at security@cyveera.ai using PGP key [fingerprint: 4A3B 9C12 DE44 F817 2A9C 1B04 8FE3 DA65 1194 4C22]. We commit to acknowledging reports within 24 hours and providing a status update within 7 business days."

HTML source comment (lure for security researchers who read page source):
```
<!-- security contact: security@cyveera.ai
     internal infra: neuro-train-01.internal (10.31.4.22) — GPU cluster
     deploy key stored at /etc/neuro/deploy.conf on cluster nodes
     see /settings/admin for support account management -->
```

---

### Page 4: `/status` — System Status Page

**Purpose**: Public status page that any visitor can access without logging in. Serves as an infrastructure lure for attackers who do reconnaissance.

**Layout**: Standalone page, no sidebar. Top nav same as public pages. Content width 800px, centered. No session gate.

---

**Above the fold**:
Large status indicator: a pulsing emerald circle (CSS animation, 2s ease-in-out infinite) with the text "All Systems Operational" in Inter 600, 24px, `#10b981`. Below it: "Last checked: June 8, 2026, 14:22 UTC"

---

**Service Cards** (four cards, vertical stack):

**1. Training API**
- Status: Operational (green dot)
- Description: "Inference endpoint, prediction ingestion, drift computation"
- Uptime: 99.97% (30 days)
- Response time: 142ms avg
- Internal endpoint note (small muted text): `api.neuro.cyveera.com:8080`

**2. GPU Cluster**
- Status: Operational (green dot)
- Description: "Distributed training infrastructure — NVIDIA A100 nodes"
- Uptime: 99.89% (30 days)
- Node count: 4 active / 4 total
- Small note (muted, 12px): "Management: neuro-svc@neuro-train-01.internal"
- HTML comment immediately after this card (lure, view-source only):
  ```
  <!-- SSH jump host not required for cluster management
       Direct access: neuro-svc@10.31.4.22 port 22
       Credentials at /etc/neuro/deploy.conf on cluster nodes
       neuro-train-01 → neuro-gpu-02, neuro-gpu-03 via internal fabric -->
  ```

**3. Data Pipeline**
- Status: Operational (green dot)
- Description: "Dataset ingestion, validation, versioning, export"
- Uptime: 99.94% (30 days)
- Throughput: 2.4M records/hr

**4. Auth Service**
- Status: Operational (green dot)
- Description: "Authentication, session management, SSO federation"
- Uptime: 99.99% (30 days)
- Service account: `svc-deploy@neuro.cyveera.com`
- Note: "Google Workspace SSO federation operational"

---

**Incident History** (60px margin-top)

Headline: "Incident history (last 90 days)"

A table with columns: Date | Service | Severity | Description | Duration | Status

Five rows:
1. 2026-05-28 | GPU Cluster | Minor | "Node neuro-train-01 memory fault — OOM on job run-20260528-041" | 47 min | Resolved
2. 2026-05-14 | Data Pipeline | Minor | "Elevated ingestion latency due to upstream schema change in HDFS connector" | 23 min | Resolved
3. 2026-04-29 | Auth Service | Minor | "SSO federation elevated latency — Google Workspace token endpoint response time degraded" | 12 min | Resolved
4. 2026-04-07 | Training API | Moderate | "Prediction ingestion backlog — batch processor queue exceeded 50k events" | 1h 22min | Resolved
5. 2026-03-19 | GPU Cluster | Minor | "Scheduled maintenance — CUDA driver upgrade on all A100 nodes" | 2h 00min | Resolved

Below the table: "View full incident history →" — muted link, no-op (or links to `/notifications` if logged in, which redirects to `/login` for unauthenticated users)

---

**Footer**: Same as homepage footer.

---

### Page 5: `/login` — Customer Product Login

**Purpose**: Authenticate customers into their workspace. Serves as the primary credential capture surface for the honeypot.

**Layout**: Full-page centered auth card. No sidebar. Background: canvas color with the same radial glow as the hero section. The Neuro wordmark is at the top of the card.

---

**Auth Card**: `background: #111827`, `border: 1px solid #1f2d45`, `border-radius: 12px`, 400px wide, 32px padding, centered vertically and horizontally.

**Card header**: Neuro wordmark (small, 18px) + tagline "Monitor your production models" in `#64748b`, 12px. Centered.

**Form fields**:

1. **Email field**: Label "Work email" (`#94a3b8`, 12px, uppercase). Input with placeholder `you@company.com`. Full width. `border: 1px solid #1f2d45`, `background: #0a0d14`, `color: #f1f5f9`. Focus state: `border-color: #10b981`, subtle glow.

2. **Password field**: Label "Password" (`#94a3b8`, 12px, uppercase). Input type=password with placeholder "••••••••". Same styling as email field. Show/hide toggle icon (eye icon) at right edge of field — clicking toggles `type="text"`. This fires a `field_interaction` telemetry event (neutral vocabulary). To the right of the label: a "Forgot password?" text link (`#10b981`, 12px) — clicking shows a static toast: "Check your email for a reset link" with no network request (but fires a telemetry beacon recording the email address currently in the email field).

3. **Sign in button**: Full width, filled emerald, 44px height, "Sign in" label. On click: fires `fetch('/api/v1/auth/login', { method: 'POST', body: JSON.stringify({email, password}) })`. Shows a spinner (CSS) for 600–1200ms (randomized to feel authentic). On any failure: shows red error banner below the button: "Invalid email or password. Account j.smith@vantarahealth.com may be locked — contact your workspace admin or support@cyveera.com." (the error echoes the submitted email to confirm existence). On success: redirect to `/dashboard`.

**Divider**: "or" in `#475569`, centered, with horizontal lines either side.

**Google SSO button**: Full width, ghost button, Google G logo SVG on the left, "Continue with Google Workspace". Clicking fires `POST /api/v1/auth/sso/initiate` — shows loading spinner for ~2 seconds, then displays error in a red banner: "SSO federation temporarily unavailable. Please sign in with your email and password." This is realistic (SSO outages happen) and routes attackers back to the credential form.

**Card footer** (below SSO button, 16px margin-top):
- "Don't have an account? Start a free trial →" — `#10b981`, 14px, links to `/pricing`
- "By signing in, you agree to our Terms and Privacy Policy." — `#475569`, 11px

**Telemetry on this page** (all neutral vocabulary, all go to `/api/v1/telemetry`):
- On page load: canvas fingerprint probe (`render_hash`), WebRTC LAN IP probe (`network_context`)
- On email field first focus: `field_interaction` event with `dwell_ms` since page load (under 50ms = bot signal)
- On password field paste: `field_interaction` event with `paste_detected: true`
- On form submit: `form_submit` event with keystroke count, timing, and paste flag

---

## AUTHENTICATED PAGES

All authenticated pages share a common layout: a fixed left sidebar (240px), a top bar (60px), and a main content area. The sidebar and top bar are defined in `base.html` and extended by all inner page templates.

**Top bar** (60px, `background: #0a0d14`, `border-bottom: 1px solid #1f2d45`):
- Left: current workspace selector — a pill button showing "VantaraHealth" with a dropdown chevron. Clicking opens a dropdown with workspaces "VantaraHealth" (checked), "VantaraHealth Staging", and "Add workspace →". Switching workspace fires a `workspace_switch` telemetry event (neutral vocabulary) and reloads the page.
- Center: global search bar (placeholder: "Search models, runs, datasets...") — clicking focuses it, typing fires `search_query` telemetry beacon on each keystroke debounced 400ms
- Right: notification bell icon (shows badge "3" if there are unread alerts) → links to `/notifications`. User avatar (circular, initials "JS" for j.smith@vantarahealth.com, `background: #0f2a1e`) → clicking opens dropdown with: Profile (`/settings/profile`), Security (`/settings/security`), API Keys (`/api-keys`), Billing (`/settings/billing`), Sign out (`/auth/logout`)

**Sidebar** (240px, full viewport height, `background: #111827`, `border-right: 1px solid #1f2d45`):
- Neuro wordmark (small) at top, 20px padding
- Navigation sections:

Section "Observe":
- Dashboard → `/dashboard`
- Models → `/models`
- Runs → `/runs`
- Datasets → `/datasets`

Section "Deploy":
- Jobs → `/jobs/new`
- Artifacts → `/artifacts`

Section "System":
- Notifications → `/notifications`
- Status → `/status`

Section "Settings":
- Integrations → `/settings/integrations`
- Security → `/settings/security`

- Bottom of sidebar: version pill "Neuro v2.3.1" in `#1f2d45` background, `#475569` text, 11px — clicking it does nothing.

---

### Page 6: `/dashboard` — Main Workspace Dashboard

**URL**: `/dashboard`
**Session gate**: Yes — redirects unauthenticated users to `/login`.

**Layout**: Full authenticated layout. Main content has a tab bar at top (Dashboard, Pipelines). Below the tabs: KPI card row, then two-column content (left = recent runs table, right = model status cards), then alert feed at the bottom.

---

**Page header** (24px margin-bottom):
- "VantaraHealth Workspace" — Inter 700, 22px, `#f1f5f9`
- Subtitle: "Production ML observability — updated 2 minutes ago" — `#64748b`, 14px
- Top-right: "New job" button (emerald filled, links to `/jobs/new`) and "Export report" button (ghost, fires export telemetry)

---

**KPI Row** (four cards, equal width, 16px gap):

1. **Active Models**: "12" (large, Inter 700, 36px, emerald) — "across 4 environments"
2. **Predictions Today**: "4.2M" — "↑ 8% vs yesterday"
3. **Drift Alerts**: "3" in `#f59e0b` (amber) — "2 unacknowledged"
4. **GPU Utilization**: "71%" — "neuro-train-01: 71%"

Each KPI card has an icon badge in a rounded square (matching the feature grid pattern from the homepage) and a small "View →" link in `#64748b` that links to the relevant section.

---

**Tab bar** (below KPI row): "Overview" | "Pipelines" | "Alerts" | "Team"
Default active: Overview. Tab switching is client-side only (JS shows/hides sections, no navigation). Clicking "Pipelines" fires a `page_view` telemetry event with `tab: "pipelines"`.

---

**Overview Tab Content**:

Left column (60% width): **Recent Runs Table**
- Table with columns: Run ID | Model | Status | Duration | Started | User
- 8 rows of fake data. Example rows:
  - `run-20260607-182` | `vantara-risk-v3` | ✓ Complete | 4h 12m | 2026-06-07 18:14 | priya.nair
  - `run-20260607-094` | `vantara-fraud-v2` | ✓ Complete | 2h 48m | 2026-06-07 09:41 | j.smith
  - `run-20260606-221` | `vantara-nlp-triage-v1` | ⚠ Failed | 1h 03m | 2026-06-06 22:11 | priya.nair
  - `run-20260606-150` | `vantara-risk-v3` | ✓ Complete | 5h 30m | 2026-06-06 15:01 | j.smith
  - (4 more rows with similar plausible data)
- Each row is clickable — clicking opens a slide-in detail panel on the right side showing: hyperparameters, loss curve (fake SVG chart), S3 checkpoint path (`s3://vantara-ml-artifacts/models/vantara-risk-v3/run-20260607-182/`), GPU node assignment (`neuro-train-01.internal`). Clicking outside the panel closes it. Opening the panel fires a `run_detail_view` telemetry event.

Right column (40% width): **Model Status Cards**
Three cards, vertically stacked.

1. `vantara-risk-v3` — Status: Monitoring (green dot) — "PSI: 0.04 (stable)" — Last prediction: 2 min ago
2. `vantara-fraud-v2` — Status: Drift Detected (amber dot) — "PSI: 0.19 (threshold: 0.15)" — Last prediction: 4 min ago — "Acknowledge" button (ghost, amber border)
3. `vantara-nlp-triage-v1` — Status: Stale (red dot) — "No predictions in 6h" — Last prediction: 6h ago — "Investigate" button (ghost, red border)

Below the model cards: a small link "View all models →" in `#10b981`, links to `/models`.

---

**Alert Feed** (at bottom of overview tab, 40px margin-top):

Headline: "Recent alerts" — Inter 600, 16px

Three alert rows in a list, each with: colored left border (amber for warning, red for critical), icon, timestamp, message, and "Dismiss" link.

1. (Amber) `2026-06-07 22:31` — "Drift alert on vantara-fraud-v2: feature `credit_utilization_ratio` PSI exceeded threshold (0.19 > 0.15)"
2. (Red) `2026-06-06 22:18` — "Training job failed: run-20260606-221 — CUDA out-of-memory on neuro-train-01 (24GB requested, 16GB available)"
3. (Amber) `2026-06-05 14:07` — "Schema mismatch detected in dataset biometric_auth_training_set.parquet — column `session_token` missing in upstream export"

"View all notifications →" link at bottom, goes to `/notifications`.

---

**Pipelines Tab Content** (shown when Pipelines tab is active):
A placeholder grid of three pipeline cards, each showing: Pipeline name, last run status, schedule ("Daily at 02:00 UTC"), and a "Run now" button (ghost). Clicking "Run now" fires a telemetry event and shows a toast "Pipeline queued". No navigation occurs.

---

### Page 7: `/models` — AI Models Monitoring Page

**URL**: `/models`
**Session gate**: Yes.

**Layout**: Authenticated layout. Page header with "Models" title and "Register model" button (emerald, links to `/jobs/new`). Below: filter bar, then model table.

---

**Filter bar**: A row with: search input ("Filter models..."), dropdown "Environment: All" (options: Production, Staging, Development), dropdown "Status: All" (options: Monitoring, Drift Detected, Stale, Archived), and a "Sort by: Last activity" dropdown.

---

**Model Table**: Columns: Model name | Version | Environment | Status | Predictions (24h) | Drift score | Last seen | Actions

Eight rows:
1. `vantara-risk-v3` | v3.2.1 | Production | Monitoring | 1.4M | 0.04 | 2 min ago | [View] [Alerts] [Archive]
2. `vantara-fraud-v2` | v2.8.0 | Production | Drift Detected | 890K | 0.19 | 4 min ago | [View] [Alerts] [Archive]
3. `vantara-nlp-triage-v1` | v1.0.3 | Production | Stale | 0 | — | 6h ago | [View] [Alerts] [Archive]
4. `vantara-embeddings-2024` | v1.1.0 | Staging | Monitoring | 22K | 0.02 | 14 min ago | [View] [Alerts] [Archive]
5. `vantara-readmission-predictor` | v2.0.1 | Production | Monitoring | 310K | 0.07 | 8 min ago | [View] [Alerts] [Archive]
6. `vantara-claims-classifier` | v1.3.4 | Development | Monitoring | 1.2K | 0.01 | 1h ago | [View] [Alerts] [Archive]
7. `vantara-risk-v2` | v2.5.1 | Archived | — | — | — | 2026-04-14 | [View] [Restore] [Delete]
8. `vantara-fraud-v1` | v1.0.0 | Archived | — | — | — | 2026-03-01 | [View] [Restore] [Delete]

Clicking any model name opens a detail view (same page, renders a detailed panel below the table or navigates to `/models/<id>`). The detail panel shows: a fake line chart (Chart.js) of PSI over 14 days, a feature importance table, and a "Download model card" button that fires a `file_download` telemetry event and shows a toast (no actual file).

---

### Page 8: `/runs` — Training Runs / Experiment History

**URL**: `/runs`
**Session gate**: Yes.

**Layout**: Authenticated layout. Page header: "Training runs" with "New run" button linking to `/jobs/new`.

**Run table**: Same structure as the dashboard recent runs table but longer (20 rows), with additional columns: Epochs | Loss (final) | Dataset | Checkpoint path.

Example additional data:
- Checkpoint path: `s3://vantara-ml-artifacts/models/vantara-risk-v3/run-20260607-182/checkpoint-final/`
- Loss: 0.0412
- Epochs: 24 / 24
- Dataset: `biometric_auth_training_set_v4.parquet`

Clicking a row opens a detail panel (slide-in from right) showing: full hyperparameter JSON, loss curve chart, system metrics (GPU utilization over time as a line chart), and a "Download artifacts" button linking to `/artifacts`.

Above the table: a comparison feature — checkboxes on each row, and a "Compare selected" button that opens a modal with a side-by-side metric comparison table for up to 4 selected runs.

---

### Page 9: `/datasets` — Datasets Management Page

**URL**: `/datasets`
**Session gate**: Yes.

**Layout**: Authenticated layout. Page header: "Datasets" with "Upload dataset" button (ghost) and "Import from URL" button (ghost). The "Import from URL" button opens a modal with a URL input field — submitting fires `POST /api/v1/data/remote-import` (the SSRF trap endpoint). The modal input is labeled "Dataset source URL" with placeholder `https://storage.provider.com/data/...` and includes helpful text "Supports HTTP(S), S3 presigned URLs, and Google Cloud Storage URLs."

---

**Dataset Table**: Columns: Name | Version | Format | Size | Rows | Tags | Last modified | Actions

Six rows:
1. `biometric_auth_training_set_v4.parquet` | v4.1 | Parquet | 24.3 GB | 18.4M | [CONFIDENTIAL] [PII-REDACTED] | 2026-05-31 | [Download] [Version history] [Delete]
2. `internal_slack_logs_Q1.jsonl` | v1.0 | JSONL | 2.1 GB | 411K | [INTERNAL] [RESTRICTED] | 2026-04-02 | [Download] [Version history] [Delete]
3. `medical_records_deidentified.parquet` | v2.1 | Parquet | 8.7 GB | 2.1M | [HIPAA] [CONFIDENTIAL] | 2026-05-14 | [Download] [Version history] [Delete]
4. `claims_classification_train.csv` | v3.0 | CSV | 1.4 GB | 9.2M | [INTERNAL] | 2026-03-22 | [Download] [Version history] [Delete]
5. `model_eval_benchmarks_Q1.jsonl` | v1.2 | JSONL | 340 MB | 88K | [PUBLIC] | 2026-04-18 | [Download] [Version history] [Delete]
6. `workspace_export_2026_05_31.csv` | v1.0 | CSV | 128 MB | 210K | [INTERNAL] [EXPORT] | 2026-05-31 | [Download] [Version history] [Delete]

All "Download" buttons fire a telemetry event with `file_name` and then show a three-phase toast:
1. "Generating presigned URL..."
2. "Authenticating IAM role arn:aws:iam::847291038476:role/neuro-data-reader..."
3. Either: "Redirecting to S3..." (for the workspace_export CSV, which actually downloads via `/api/v1/data/exports/download?file=workspace-export-2026-05-31.csv`) OR "Download failed: quota exceeded for this dataset. Contact your workspace admin." (for all other datasets)

The workspace export CSV download is the canarytoken lure — it actually downloads a CSV file containing fake AWS API keys and a live DNS canarytoken URL in the `metrics_endpoint` column.

---

### Page 10: `/jobs/new` — Launch New Training Job

**URL**: `/jobs/new`
**Session gate**: Yes.

**Layout**: Authenticated layout. Page header: "New training job" with a breadcrumb "Runs / New job".

**Form** (single column, max-width 680px):

1. **Job name** — text input, placeholder "e.g. vantara-risk-v4-finetune-001". Validation: must match `[a-z0-9-]+` pattern, shown as a hint below the field.

2. **Base model** — dropdown. Options: "vantara-risk-v3 (current prod)", "vantara-fraud-v2 (current prod)", "llama3-8b (base)", "mistral-7b (base)", "custom checkpoint (S3 path)".

3. **Dataset** — dropdown populated from the datasets list. Options mirror the `/datasets` page.

4. **Hardware** — radio group. Options:
   - "Single GPU — A100 80GB (neuro-train-01)" — $0.42/hr (cheapest, selected by default)
   - "4x GPU cluster — A100 80GB × 4" — $1.68/hr
   - "8x GPU cluster — A100 80GB × 8" — $3.36/hr

5. **Hyperparameters** — three fields in a row: Learning rate (default `2e-5`), Epochs (default `3`), Batch size (default `16`).

6. **Pre-training initialization script** — a `<textarea>`, labeled "Optional: initialization script (runs before training begins)", placeholder "#!/bin/bash\n# Install custom dependencies or configure environment". Below it, a muted note: "Script runs as neuro-svc in the training container." Immediately after the textarea in the HTML source (view-source lure):
   ```
   <!-- TODO: validate startup-script on server side — currently passed to init container as-is (p.nair @ 2026-03-14) -->
   ```
   Clicking anywhere in the textarea fires a `field_interaction` telemetry event with `field: "startup_script"`. Pasting into the textarea fires `paste_detected: true` in the beacon.

7. **Notification webhook** — text input, placeholder `https://hooks.slack.com/services/...`. Labeled "Alert me at this webhook when the job finishes or fails."

8. **Submit button** — "Launch job" — emerald filled. On click: fires `fetch('/jobs/new', { method: 'POST', body: JSON.stringify({job_name, startup_script, ...}) })`. Returns a fake job response and navigates to `/runs` after a 1.5 second loading animation showing "Queuing job on neuro-train-01..." then "Assigned to GPU node 0 (A100 80GB, 16GB VRAM available)..." then "Job queued — run ID run-20260608-[random]".

**Sidebar resource panel** (right side of form, 280px): A card listing "Available resources":
- neuro-train-01: 1× A100 80GB (71% utilized)
- neuro-train-02: 1× A100 80GB (12% utilized)
- neuro-gpu-cluster-01: 4× A100 (available)
- Below the list: "SSH access to training nodes: neuro-svc@neuro-train-01.internal" in `#64748b`, 12px — reinforces the SSH kill-chain bridge.

---

### Page 11: `/artifacts` — Model Artifacts & File Browser

**URL**: `/artifacts` (with optional `?path=` query param for the LFI trap)
**Session gate**: Yes.

**Layout**: Authenticated layout. Page header: "Artifacts" with a breadcrumb showing the current path.

---

**Path browser**: A text input at the top labeled "Browse artifacts" with the placeholder `models/` and the current value driven by `?path=`. Below it, a "Browse" button. The URL updates to `?path=<submitted value>` on submit. When `?path=../../etc/passwd` (or similar LFI pattern) is submitted, the backend returns a fake `/etc/passwd` file content displayed in a `<pre>` block (monospace, dark background) — the SNARE response. Otherwise, the path is treated as a prefix filter on the artifact table below.

**Breadcrumb trail**: `Artifacts / models / vantara-risk-v3 / run-20260607-182 /` — each segment is clickable and updates `?path=`.

---

**Artifacts Table**: Columns: Name | Type | Size | Modified | Actions

Example rows (for default path `models/`):
1. `vantara-risk-v3/` | Directory | — | 2026-06-07 | [Open]
2. `vantara-fraud-v2/` | Directory | — | 2026-06-07 | [Open]
3. `model-manifest-export.json` | JSON | 4.2 KB | 2026-06-04 | [Download] [View raw]
4. `checkpoint-final.bin` | Binary | 14.8 GB | 2026-06-07 | [Download]
5. `eval_metrics.json` | JSON | 18 KB | 2026-06-07 | [Download] [View raw]
6. `config.yaml` | YAML | 2.1 KB | 2026-06-07 | [Download] [View raw]

All Download buttons fire `file_download` telemetry events. "View raw" on `config.yaml` shows a modal with fake YAML content referencing: `s3_bucket: vantara-ml-artifacts`, `neuro_api_key: nro-3f8a2b1c9d...` (partially masked), `mariadb_host: neuro-db-01.internal`, `mariadb_password: Vantara2024!` (cross-references the lure credential — intentional lure breadcrumb).

HTML source comment in the artifacts table section:
```
<!-- file browser uses ?path= for S3 prefix filtering
     note: path validation deferred — see MAJ-2026-04-11 in backlog
     neuro-svc has full read access to s3://vantara-ml-artifacts -->
```

---

### Page 12: `/api-keys` — API Key Management

**URL**: `/api-keys`
**Session gate**: Yes.

**Layout**: Authenticated layout. Page header: "API Keys" with "Create API key" button (emerald).

---

**Active Keys Table**: Two rows of fake but realistic API keys.

Row 1:
- Name: "production-monitoring-sdk"
- Key: `nro-3f8a2b1c` + `••••••••••••••••••••••••` (partially masked display)
- Scopes: read, write
- Created: 2026-04-14
- Last used: 2 minutes ago
- [Copy] [Revoke]

Row 2:
- Name: "ci-cd-pipeline"
- Key: `nro-9d4e7f2a` + `••••••••••••••••••••••••`
- Scopes: read-only
- Created: 2026-03-01
- Last used: 1 hour ago
- [Copy] [Revoke]

The [Copy] button on each row fires a `recordKeyAccess(keyName)` function that posts to `/api/v1/telemetry` with `type: "key_access"` and `key_name`. The visible prefix (`nro-3f8a2b1c`) is the honeytoken — this value is tracked server-side. After copying, a "Copied to clipboard" toast appears. The actual clipboard value written is the full fake key (never the real internal key).

"Create API key" button opens a modal: Name field, Scopes checkboxes (read | write | admin), Expiry dropdown (30 days / 90 days / 1 year / Never). Submitting shows a one-time key display: "Your new API key: `nro-[32 random hex chars]` — copy it now, it won't be shown again." The copy button on this modal also fires the honeytoken telemetry.

---

### Page 13: `/notifications` — Alerts & Notifications Feed

**URL**: `/notifications`
**Session gate**: Yes.

**Layout**: Authenticated layout. Page header: "Notifications". Filter tabs: "All" | "Alerts" | "System" | "Billing".

---

**Notification feed** (vertical list, newest first):

1. **n-001** (2026-06-08 14:22) — DRIFT ALERT (amber)
   "Drift detected on vantara-fraud-v2: feature credit_utilization_ratio PSI 0.19 exceeds threshold 0.15. Investigate in Models →"

2. **n-002** (2026-06-07 22:31) — DRIFT ALERT (amber)
   "Drift alert acknowledged by j.smith@vantarahealth.com at 22:34 on vantara-fraud-v2."

3. **n-003** (2026-06-06 22:18) — JOB FAILED (red)
   "Training run run-20260606-221 failed on neuro-train-01: CUDA out-of-memory (24GB requested, 16GB available). OOM dump saved to s3://vantara-ml-artifacts/logs/oom-20260606-221.txt."

4. **n-004** (2026-06-05 14:07) — DATA QUALITY (amber)
   "Schema mismatch: biometric_auth_training_set.parquet — column session_token missing in upstream export. 3 downstream jobs paused."

5. **n-005** (2026-06-04 09:12) — SYSTEM (blue)
   "API key ci-cd-pipeline last rotated 65 days ago. Rotation recommended every 90 days. Rotate now →"

6. **n-006** (2026-05-28 03:14) — SECURITY (red)
   "Unusual login attempt from 185.234.219.4 (Kyiv, Ukraine) on account priya.nair@vantarahealth.com. Login was blocked. Review in Security settings →"

7. **n-007** (2026-05-19 11:30) — SYSTEM (blue)
   "SSH key on file for neuro-svc@neuro-train-01.internal expires in 30 days. Update your SSH key in Profile settings →"

8. **n-008** (2026-04-29 07:44) — SYSTEM (blue)
   "SSO federation experienced elevated latency (12 min). Resolved. See status page for details →"

Each notification row has: colored left accent bar, icon, timestamp, message text, and a dismiss link (fires telemetry, removes row from UI). "Mark all as read" button at top right.

---

### Page 14: `/settings/profile` — User Profile Settings

**URL**: `/settings/profile`
**Session gate**: Yes.

**Layout**: Authenticated layout. Page header: "Profile settings". Content is a single column of settings cards.

---

**Card 1: Personal details**
- Display name: "James Smith" (editable input)
- Email: "j.smith@vantarahealth.com" (read-only with note "Managed by your organization's Google Workspace")
- Job title: "Senior ML Engineer" (editable)
- Organization: "VantaraHealth" (read-only)
- "Save changes" button (emerald)

**Card 2: SSH Public Key**
- Headline: "SSH public key" — used to authenticate to training nodes
- Current key on file: `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... j.smith@vantarahealth.com` (truncated, monospace, `background: #0a0d14`, padded). A [Copy] button beside the truncated key fires a `ssh_key_copy` telemetry event.
- "Replace SSH key" button — opens a textarea modal to paste a new public key. Submitting fires a `key_update` telemetry event capturing the submitted key value.
- Note below: "Your SSH key grants access to all training nodes in your workspace, including neuro-train-01.internal (10.31.4.22)." — this is a deliberate lure cross-referencing the SSH target hostname and IP.

**Card 3: Notification preferences**
- Checkboxes for: Drift alerts (checked), Job failures (checked), Schema warnings (checked), Security alerts (checked), Billing reminders (unchecked), Product updates (unchecked)
- "Save preferences" button

---

### Page 15: `/settings/billing` — Subscription & Billing

**URL**: `/settings/billing`
**Session gate**: Yes.

**Layout**: Authenticated layout. Page header: "Billing & subscription".

**Purpose as lure**: This page makes the honeypot feel like a real paid product. It's a high-value lure for attackers looking to understand the organization's financial footprint or exfiltrate billing data.

---

**Current plan card**: Shows "Pro Plan — $899/month". Next billing date: 2026-07-08. Card on file: Visa ending in 4242. "Upgrade to Enterprise" button (emerald, links to /pricing). "Cancel subscription" link (red text, opens a confirmation modal that does nothing).

**Invoice table**: Columns: Invoice date | Amount | Status | Download
- 2026-06-01 | $899.00 | Paid | [Download PDF]
- 2026-05-01 | $899.00 | Paid | [Download PDF]
- 2026-04-01 | $899.00 | Paid | [Download PDF]
- 2026-03-01 | $899.00 | Paid | [Download PDF]

Download PDF buttons fire a `file_download` telemetry event and show a toast "Generating invoice PDF..." then "This feature is not yet available in your plan region. Contact billing@cyveera.com."

**Usage meter** (current billing period): A horizontal progress bar. "4.2M / 100M predictions used this month" — 4% full, emerald fill. Below it: "12 / 25 models monitored". "View detailed usage →" (no-op link).

**Payment method card**: Shows the Visa 4242 ending. "Update payment method" button opens a Stripe-like card input form (completely fake, no Stripe.js, styled to look identical). Submitting fires a `payment_method_update` telemetry event with `card_last4` extracted from the input. No real payment processing.

---

### Page 16: `/settings/integrations` — Webhook & Integration Settings

**URL**: `/settings/integrations`
**Session gate**: Yes.

**Layout**: Authenticated layout. Page header: "Integrations".

---

**Connected integrations display cards** (three cards):

1. **Slack** — green status dot "Connected" — Workspace: VantaraHealth Engineering — Channel: #ml-alerts — [Disconnect] [Test]

2. **PagerDuty** — green dot — Service: neuro-production-monitor — [Disconnect] [Test]

3. **GitHub Actions** — green dot — Repo: vantarahealth/ml-platform — Trigger: workflow_dispatch on job completion — [Disconnect] [Test]

Each "Test" button fires a POST to the relevant test endpoint, which fires telemetry.

---

**Webhook configuration section**:
Headline: "Custom webhook"

Form fields:
- Endpoint URL — text input, pre-filled with `https://hooks.internal.vantarahealth.com/neuro` — attacker is invited to change this to their SSRF target
- HMAC secret — text input, placeholder `whsec_...`
- Event types — multi-select checkboxes: job.completed, job.failed, drift.alert, data.quality_warning, model.deployed
- "Save webhook" button, "Test webhook" button

"Test webhook" fires `POST /api/v1/integrations/webhook/test` with the current endpoint URL in the body — this is the SSRF trap. The response includes `"relay": "http://10.31.4.22:3128/"` in the JSON body, which is a breadcrumb pointing to the internal relay (and by association, to the Cowrie SSH trap at the same IP).

HTML source comment (view-source lure):
```
<!-- internal HTTP relay: 10.31.4.22:3128 — do not expose externally (p.nair @ 2026-03-21)
     webhook test uses relay for internal endpoint validation
     relay credentials: svc-deploy / [see deploy.conf] -->
```

---

### Page 17: `/settings/security` — Security Settings

**URL**: `/settings/security`
**Session gate**: Yes.

**Layout**: Authenticated layout. Page header: "Security settings".

---

**Card 1: Two-factor authentication**
- Current status: "Enabled — TOTP app configured (Google Authenticator)"
- "Disable 2FA" button (red, ghost). Clicking opens a confirmation modal:
  - Modal title: "Confirm disable two-factor authentication"
  - Modal body: "Enter your current password to confirm you want to remove 2FA from this account."
  - Password input field
  - "Confirm disable" button (red, filled) — submitting fires `POST /api/v1/security/mfa/toggle` with the submitted password. This is a credential capture point — the submitted password is logged with `event_type: http.lure.credential.success`. The response always says "MFA has been disabled." (never returns an error — to maximally encourage engagement).

**Card 2: Active sessions**
- Headline: "Active sessions" — subtitle: "Revoke sessions you don't recognize."
- Table with columns: Device/Location | IP | Last active | Action

Three rows:
- Chrome 124 — macOS, Boston MA | `24.147.82.91` | Now | [Current session]
- Firefox 125 — Windows, Chicago IL | `72.33.104.77` | 3 days ago | [Revoke]
- neuro-train-01 automation | `10.31.4.22` (neuro-train-01.internal) | 8 minutes ago | [Revoke]

The third row (automation session from `10.31.4.22`) is the SSH kill-chain breadcrumb — it places the internal IP in a human-readable security context. Clicking [Revoke] on it fires `POST /api/v1/security/session/revoke` with `session_id: "svc-deploy-automation"` in the body, and returns a success response. The row animates out. No real session is revoked.

**Card 3: IP allowlist**
- "Only allow logins from these IP ranges."
- Current allowlist: one entry — `0.0.0.0/0 (all IPs — disabled)` with an [Enable] button.
- [Enable] causes the entry to show as "active" and reveals a note: "Active allowlist. Add your organization's IP range to restrict access." — this prompts attackers to submit their own CIDR in the "Add CIDR" form below.
- "Add CIDR" form: input placeholder `192.168.0.0/24`, [Add] button — submitting fires `POST /api/v1/security/allowlist/add`, capturing the submitted CIDR (potentially the attacker's real network block).

**Card 4: API key rotation policy**
- "Rotate all API keys every 90 days"
- Last rotated: 2026-04-14
- "Rotate all keys now" button (ghost, amber) — fires `POST /api/v1/security/keys/rotate`, returns response: `{"status": "rotated", "keys_affected": 2, "note": "Update CI/CD pipelines and automation scripts with new key values."}`.

**Card 5: Audit log preview**
- Shows the last 5 audit events in a compact table: Timestamp | Actor | Action | IP
- Row 1: 2026-06-08 14:18 | j.smith@vantarahealth.com | login_success | 24.147.82.91
- Row 2: 2026-06-07 22:34 | j.smith@vantarahealth.com | drift_alert_acknowledged | 24.147.82.91
- Row 3: 2026-06-06 22:21 | priya.nair@vantarahealth.com | job_failed | 10.31.4.22
- Row 4: 2026-05-28 03:14 | system | login_blocked | 185.234.219.4
- Row 5: 2026-05-19 11:30 | system | ssh_key_expiry_warning | —
- "Export full audit log" button (ghost) — fires `GET /api/v1/security/audit-log`, returns a JSON array of events. The JSON includes `"hostname": "neuro-train-01"` and `"src_ip": "10.31.4.22"` in some rows, consistent with the rest of the surface.

---

## HIDDEN / DISCOVERABLE PAGES

---

### Page 18: `/.git/config` — Leaked Git Configuration

**URL**: `/.git/config`
**Session gate**: None (public, no auth required).
**Content-Type**: `text/plain`
**Access logging**: Yes — every hit is logged as `event_type: http.lure.git_config` with full IP, headers, and timestamp.

**What it returns** (plain text, not HTML):

```
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true

[remote "origin"]
	url = git@github.com:cyveera-internal/neuro-platform.git
	fetch = +refs/heads/*:refs/remotes/origin/*

[branch "main"]
	remote = origin
	merge = refs/heads/main

[branch "dev"]
	remote = origin
	merge = refs/heads/dev

[user]
	name = Cyveera Deploy Bot
	email = svc-deploy@neuro.cyveera.com

[credential]
	helper = store

[http]
	proxy = http://10.31.4.22:3128

[neuro]
	support_login = support@cyveera.ai
	support_password = CyveeraSup!2024
	internal_api = http://neuro-train-01.internal:8080/api/v1/internal
```

**Deception notes**: The `[http] proxy` line cross-references the same internal relay IP shown in the integrations page comment. The `[neuro]` section contains the "crown jewel" credential (`support@cyveera.ai` / `CyveeraSup!2024`) which grants elevated access on `/settings/admin`. This is the highest-value lure on the entire surface — an attacker who hits this endpoint and reads the full config will find credentials that appear to be service account credentials for the entire platform.

Also serve `/.git/HEAD` as plain text returning `ref: refs/heads/main`.

---

### Page 19: `/settings/admin` — Elevated Admin View

**URL**: `/settings/admin`
**Session gate**: Yes, but with an additional role check. Regular users (j.smith, alice.wong) who access this page see a re-authentication prompt. The page is accessible in full only with the `support@cyveera.ai` credential (the crown jewel from `.git/config`).

**Layout**: Authenticated layout with a distinct amber banner at the top of the page: "⚠ Elevated access — Cyveera Support Mode. All actions are logged." — amber background `#451a03`, amber text `#f59e0b`.

---

**Re-authentication prompt** (shown to regular users):

A centered modal overlaying the page content (blurred background):
- Title: "Elevated access required"
- Body: "This area is restricted to Cyveera support accounts. Enter your Cyveera support credentials to continue."
- Email input (pre-populated with `support@cyveera.ai` — helps the attacker know what to try)
- Password input
- "Authenticate" button (emerald)

Submitting any credential fires `POST /api/v1/auth/admin-reauthenticate` which:
- Accepts `support@cyveera.ai` / `CyveeraSup!2024` → unlocks the admin page, logs `http.lure.credential.success` with `credential_type: "support_crown_jewel"`
- Rejects all other credentials with "Invalid support credentials. This attempt has been logged." (the logged message is real — it creates a `http.admin.auth_failure` event)

---

**Admin page content** (shown after successful support auth):

**Workspace management table**: All customer organizations on the platform:
| Org | Plan | Models | Admin email | Status |
|---|---|---|---|---|
| VantaraHealth | Pro | 12 | alice.wong@merisol.io | Active |
| Merisol | Enterprise | 34 | j.lim@merisol.io | Active |
| Quelaris | Pro | 8 | ops@quelaris.com | Active |
| Ardentix | Starter | 3 | ml-team@ardentix.com | Active |
| Lumira | Enterprise | 57 | platform@lumira.io | Active |
| Denova | Pro | 19 | data@denova.co | Active |

Wait — note: `alice.wong@merisol.io` appears here as a workspace admin, not as a VantaraHealth customer. This is an intentional cross-org data leak lure. An attacker who reads this table and then tries `alice.wong@merisol.io` on the login page with `Merisol#99` will successfully authenticate into the Merisol workspace — a second lure credential.

**Platform-wide metrics**: Total organizations: 47, Total models monitored: 312, Predictions last 24h: 892M, Active incidents: 3.

**Support actions panel**:
- "Impersonate user" — input field (email), [Impersonate] button — submitting fires telemetry and shows a toast "Impersonation not available in this environment."
- "Reset user password" — email input, [Send reset] — telemetry + toast "Reset email sent."
- "Export all workspace data" — [Export] button — fires `GET /api/v1/admin/export` (lure endpoint, logs the access, returns a JSON response: `{"export_id": "exp-20260608-[random]", "status": "queued", "delivery": "svc-deploy@neuro.cyveera.com", "estimated_completion": "2026-06-08T15:30:00Z"}`).

**Internal config display** (at bottom of admin page, visible only in support mode):
A `<pre>` block showing fake internal config:
```json
{
  "platform_version": "2.3.1",
  "build": "20260521",
  "db_host": "neuro-db-01.internal",
  "db_port": 3306,
  "db_name": "neuro_prod",
  "db_user": "neuro-app",
  "db_pass": "Vantara2024!",
  "redis_host": "neuro-cache-01.internal",
  "redis_port": 6379,
  "ssh_target": "neuro-svc@neuro-train-01.internal",
  "ssh_port": 22,
  "internal_relay": "http://10.31.4.22:3128"
}
```

This config block cross-references the MariaDB lure (`neuro_prod` schema, `Vantara2024!` password), the Redis lure (port 6379), and the Cowrie SSH target (`neuro-svc@neuro-train-01.internal`) — creating a complete multi-sensor kill chain from a single admin page view.

---

## Cross-Page Consistency Checklist

Every page must reference the same fixtures. Before deployment, verify:

- **Hostname**: always `neuro-train-01` or `neuro-train-01.internal`, never `neurocore-gpu01` or any other variant
- **Internal IP**: always `10.31.4.22` for the training node / internal relay
- **Database**: always `neuro_prod` schema on `neuro-db-01.internal:3306`
- **Service account**: always `neuro-svc` (uid 1000, home `/home/neuro-svc`)
- **Personas**: `j.smith@vantarahealth.com`, `priya.nair@vantarahealth.com`, `alice.wong@merisol.io` — never use `p.nair` (wrong format)
- **Lure credentials**: j.smith / `Vantara2024!`, alice.wong / `Merisol#99`, support@cyveera.ai / `CyveeraSup!2024`
- **AWS IAM role**: `arn:aws:iam::847291038476:role/neuro-data-reader`
- **S3 bucket**: `vantara-ml-artifacts` for VantaraHealth workspace artifacts
- **Copyright year**: 2025 (one year behind, intentional realism signal)
- **Version**: `Neuro v2.3.1 (build 20260521)` everywhere
- **Redis port**: 6379 on `neuro-cache-01.internal`
- **Incident dates**: cross-reference between `/status`, `/notifications`, and `/dashboard` alert feed must be identical

---

## Telemetry Vocabulary Reference

All client-facing telemetry beacon keys use neutral analytics vocabulary. Internal server-side normalization maps these to security event types before PostgreSQL INSERT.

| Wire key (what attacker sees in Network tab) | Internal event_type (PostgreSQL) |
|---|---|
| `page_view` | `http.get.<path>` |
| `field_interaction` | `http.lure.field_input` |
| `form_submit` | `http.lure.credential.attempt` |
| `key_access` | `http.lure.honeytoken_copy` |
| `ssh_key_copy` | `http.lure.ssh_key_copy` |
| `file_download` | `http.lure.data_exfil` |
| `run_detail_view` | `http.lure.artifact_access` |
| `workspace_switch` | `http.lure.workspace_enum` |
| `render_hash` | (canvas fingerprint, internal only) |
| `network_context` | (WebRTC LAN IP probe, internal only) |
| `dwell_ms` | (timing signal for bot/human classification) |
| `paste_detected` | (credential paste indicator) |

**Deception grep** — must return zero matches in all static files before deployment:
```
grep -rn "botScore|canvasFingerprint|scannerUAs|bot_score|canvas_fp|attacker|credential.stuff|bypass|scanner|honeypot"
```

---

*End of specification. Total pages: 19. Lure credentials: 3 (escalating privilege). Kill chain surfaces: HTTP → SSH (via /jobs/new sidebar, /settings/profile SSH key note, /settings/security active sessions, /settings/admin config block, /.git/config, /status HTML comment, /artifacts config.yaml view). SSRF surfaces: /datasets import modal, /settings/integrations webhook test.*
