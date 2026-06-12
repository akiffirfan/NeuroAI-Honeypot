# Neuro by Cyveera — Frontend Specification (React SPA)

**Product**: Neuro by Cyveera — B2B ML Observability SaaS
**Tagline**: "Your AI models break in production. Neuro tells you first."
**Domain**: neuro.cyveera.com
**Stack**: React SPA compiled with Vite, served from `dist/` via nginx. FastAPI as a pure headless JSON API (no server-side HTML rendering except for two plain-text discovery endpoints). Routing via react-router-dom v6.
**Audience for this document**: The developer and designer building every page from scratch. This document is the single source of truth for visual layout, copy, interactions, data content, collection mechanics, and backend contract. No code — every page is described in sufficient prose to implement without asking questions.

---

## 1. Design System

Apply these tokens consistently across every surface. No ad-hoc hex values.

**Color tokens:**
- `canvas` — `#0a0d14` — page background, the void everything sits on
- `surface` — `#111827` — cards, panels, modals, sidebar background
- `elevated` — `#1a2235` — hover states on cards, open dropdown menus, modal overlays
- `border` — `#1f2d45` — all dividers, card outlines, table row separators, input borders at rest
- `accent` — `#10b981` — all CTAs, active sidebar items, success badges, progress bars, the Neuro brand color
- `danger` — `#ef4444` — error states, red status indicators, destructive action buttons
- `text-primary` — `#f1f5f9` — all headings, table cell primary text, button labels
- `text-secondary` — `#94a3b8` — helper text, timestamps, label text above inputs, table column headers

**Typography:**
- Inter, weight 700 for all headings (page titles, card headers, KPI numbers)
- Inter, weight 400 for all body text, table rows, descriptions
- JetBrains Mono for all code, API keys, IP addresses, hash values, file paths, JSON snippets

**Spacing rhythm**: 4px base unit. Cards use 24px padding. Section gaps are 32px. Form field gaps are 16px.

**Component conventions:**
- Buttons: 8px vertical, 16px horizontal padding. `border-radius: 6px`. Accent-background for primary actions. Transparent with border for secondary.
- Inputs: `border-radius: 6px`. Border `border` color at rest, accent on focus (2px outline, not border replacement). Background `surface`.
- Cards: `border-radius: 10px`. Border `border`. Background `surface`. No drop shadows — flat dark surfaces.
- Status badges: pill shape, 12px font, 4px vertical / 10px horizontal padding. Colors: emerald for healthy, amber `#f59e0b` for degraded, red for down/error, slate for inactive.
- Tables: no outer border. Row hover background `elevated`. Column headers in `text-secondary` uppercase 11px tracking-wide. Cell text `text-primary`.

---

## 2. React Architecture

### 2.1 Three Layout Components

The entire application is divided into three React layout components. Every route is wrapped by exactly one of them. No route uses raw JSX without a layout wrapper.

**`MarketingLayout`**

Wraps all public marketing and informational pages. Renders a fixed top navigation bar (64px height, logo left, center nav links, login/CTA buttons right) and a footer (four-column grid with links). The layout does not render a sidebar. The top nav and footer are described fully in the Public Pages section. Routes wrapped: `/`, `/pricing`, `/docs`, `/status`, `/changelog`, `/login`.

**`AppLayout`**

Wraps all session-gated authenticated pages. On component mount, fires `GET /api/v2/auth/me`. If the response is HTTP 401 or any network error, immediately calls `react-router-dom`'s `navigate("/login?next=" + encodeURIComponent(location.pathname), {replace: true})`. If the response is 200, stores the returned user object in a React context (`WorkspaceDataProvider`) accessible to all child routes. Renders the 240px fixed left sidebar and 60px top bar described in section 2.5. The `WorkspaceDataProvider` exposes: `user` (email, display name, role, ip, user_agent_parsed), `workspace` (name, plan), and a `refetch()` function for post-mutation refreshes. While the `GET /api/v2/auth/me` request is in flight, `AppLayout` renders a full-screen neutral loading state — the `canvas` background color filling the viewport with a small centered spinner in `accent` color. No sidebar, no topbar, no page content is rendered until the auth check resolves. On 401, the redirect to `/login?next=<path>` fires before any authenticated UI is painted. Routes wrapped: all 14 authenticated pages.

**`LegalLayout`**

Wraps pages with a narrow reading column (max-width 800px, centered, 80px top padding). Renders only the Neuro wordmark at the top as a home link. No top nav, no footer, no sidebar. Routes wrapped: `/privacy-policy`, `/terms-of-service`, `/404`.

### 2.2 Routing Matrix

The root `App` component declares all routes using `react-router-dom`'s `<Routes>` and `<Route>` primitives. The wildcard catch-all `<Route path="*">` renders the `NotFoundPage` component inside `MarketingLayout`. There is no 503 catch-all and no `ServiceDegradedPage` component.

| Path | Layout | Component | Access |
|---|---|---|---|
| `/` | MarketingLayout | `HomePage` | Public |
| `/pricing` | MarketingLayout | `PricingPage` | Public |
| `/docs` | MarketingLayout | `ApiDocsPage` | Public |
| `/status` | MarketingLayout | `StatusPage` | Public |
| `/changelog` | MarketingLayout | `ChangelogPage` | Public |
| `/login` | MarketingLayout | `LoginPage` | Public (redirect to /dashboard if session present) |
| `/dashboard` | AppLayout | `DashboardPage` | Authenticated |
| `/runs` | AppLayout | `RunsPage` | Authenticated |
| `/models` | AppLayout | `ModelsPage` | Authenticated |
| `/datasets` | AppLayout | `DatasetsPage` | Authenticated |
| `/artifacts` | AppLayout | `ArtifactsPage` | Authenticated |
| `/jobs` | AppLayout | `JobsPage` | Authenticated |
| `/notifications` | AppLayout | `NotificationsPage` | Authenticated |
| `/team` | AppLayout | `TeamPage` | Authenticated |
| `/api-keys` | AppLayout | `ApiKeysPage` | Authenticated |
| `/settings/profile` | AppLayout | `ProfileSettingsPage` | Authenticated |
| `/settings/billing` | AppLayout | `BillingPage` | Authenticated |
| `/settings/integrations` | AppLayout | `IntegrationsPage` | Authenticated |
| `/settings/security` | AppLayout | `SecuritySettingsPage` | Authenticated |
| `/settings/admin` | AppLayout | `CrossTenantAdminPage` | Authenticated — `cyveera_support` role only |
| `/privacy-policy` | LegalLayout | `PrivacyPolicyPage` | Public |
| `/terms-of-service` | LegalLayout | `TermsOfServicePage` | Public |
| `*` (wildcard) | MarketingLayout | `NotFoundPage` | Public |

### 2.3 Role Gating

`AppLayout` reads the `role` field from the `GET /api/v2/auth/me` response and stores it in `WorkspaceDataProvider`. Route-level role gating is implemented inside each page component, not in the router. Specifically, `CrossTenantAdminPage` checks `user.role === "cyveera_support"` on mount; if false, it calls `navigate("/dashboard", {replace: true})` immediately, without displaying any content. There is no error page, modal, or credential prompt shown. A `customer_user` who navigates to `/settings/admin` sees a redirect to `/dashboard` — nothing else. Role gating is silent.

### 2.4 `useTelemetry` Hook

All client-side telemetry is implemented through a single React hook named `useTelemetry`, located at `src/hooks/useTelemetry.js`. The hook is designed to look like ordinary product analytics infrastructure that any real SaaS frontend would have.

The hook exposes two functions: `track(eventName, properties)` and `identify(properties)`. Internally, `track` constructs a payload and POSTs it to `POST /api/v2/telemetry`. The payload shape is always:

```json
{
  "event": "<eventName>",
  "path": "<window.location.pathname>",
  "<property_key>": "<property_value>",
  "ts": <unix_ms>,
  "sid": "<session_id_extracted_from_nro_session_cookie_if_present>"
}
```

The hook fires automatically on route change (via `useEffect` watching `location.pathname` from `useLocation`) with `event: "page_view"`. On route change, it also runs the canvas fingerprint and WebRTC probe described in section 8.2 and section 8.3, including `render_hash` and `lan_ips` in the page-view beacon payload.

Sensitive field interaction tracking is done by calling `track("field_interaction", {field: "email", ...})` from individual form components — the hook itself does not attach any global event listeners. The paste capture pattern (capture-phase listener on sensitive fields) is implemented in the relevant form components, not in the hook.

No defender-perspective names appear anywhere in the hook or in the payloads it generates. The hook reads like standard product analytics.

### 2.5 Semantic Camouflage Rule

Every React component, hook, context, custom event name, API response field, and JS variable name must be named exactly as a real engineer at a real SaaS company would name it. The following rule is a hard constraint for every file in the project:

If a real Vite/React engineer at Arize.com read any component name, hook name, or prop name in this codebase, none of them would look surprising or suspicious. Names describe the data or user-facing feature they represent, not the defensive purpose they serve.

Examples of this rule applied:

| Describes its defensive purpose (prohibited) | Describes its feature/data (required) |
|---|---|
| `HoneypotTrigger` | `RemoteImportModal` |
| `FakeDataContext` | `WorkspaceDataProvider` |
| `LFIPathBrowser` | `S3ArtifactBrowser` |
| `PivotForceModal` | `ComplianceLockModal` |
| `CanaryDownloadButton` | `InvoiceDownloadButton` |
| `TrapSSRFHandler` | `DatasetImportService` |
| `AttackerSessionTracker` | `useTelemetry` |
| `DeceptionCredentialStore` | `AuthService` |

This rule applies to: component filenames, component display names, prop names, context names, hook names, service module names, utility function names, and event name strings sent over the wire.

### 2.6 Vite Build Configuration

The Vite build must produce deterministic, human-readable output filenames rather than content-hash suffixes. This is achieved by setting `build.rollupOptions.output.entryFileNames`, `chunkFileNames`, and `assetFileNames` to fixed names: `main.js`, `vendor.js`, and `main.css`. A real production app that has not gone through a security-hardened build pipeline often has predictable asset names — content-hash filenames signal a security-aware build process, which is slightly inconsistent with the "internally exposed" cover story.

The `build.sourcemap` option must be set to `false`. Source maps expose the full project directory structure and all component names to anyone who opens DevTools — this would instantly reveal every component name and internal architecture. No source maps in any deployed build.

The `define` block must not inject any string containing defender vocabulary into the compiled bundle — no `__HONEYPOT_MODE__`, no `__CAPTURE_ENABLED__`. Environment variables that reach the client bundle must be limited to the API base URL and the STUN server URL.

### 2.7 Nginx Deployment Configuration

The compiled `dist/` directory is served by nginx with the following configuration. The React SPA requires that all non-file paths are rewritten to `index.html` (client-side routing). The nginx config achieves this with a `try_files $uri $uri/ /index.html` directive in the root location block.

The `.git/` directory path must NOT be served by nginx at any point. There must be no `location /.git/` block with an `alias` directive pointing at a real git repository. Exposing the actual `.git/` directory via nginx alias allows an attacker to reconstruct the full source tree by fetching packed objects. The `/.git/config` and `/.git/HEAD` endpoints are served exclusively by FastAPI as `PlainTextResponse` routes, proxied through nginx to the FastAPI upstream. All other `/.git/*` paths are handled by the React SPA's wildcard catch-all, which renders the `NotFoundPage` component.

The nginx location precedence must be: exact-match locations first (FastAPI upstream for `/api/v2/`, `/.git/config`, `/.git/HEAD`, `/robots.txt`, `/sitemap.xml`, `/.well-known/`), then the SPA catch-all.

HTTP security headers that nginx adds on all responses: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`. No `Strict-Transport-Security` on HTTP-only deployment. These headers match what a SOC 2 shop would configure.

### 2.8 Shared Sidebar and Top Bar (AppLayout Components)

These are rendered by `AppLayout` and appear on every authenticated page.

**Sidebar (240px fixed left, full viewport height):**

Top section (logo area): The Neuro wordmark sits at the top. "Neuro" in white Inter 700 18px, preceded by a small emerald geometric mark (a rounded square with a small neural-network node cluster rendered in 16×16px SVG — three nodes connected by two lines). Below the wordmark, in `text-secondary` 12px: "by Cyveera".

Workspace dropdown: Below the logo, a full-width button (background `elevated`, border `border`, rounded 8px). Left side shows a workspace avatar — a 24px rounded square in emerald with the first letter of the workspace name in white. Right side shows the workspace name in white 14px and a small chevron-down icon. Clicking opens a dropdown listing the current workspace (checked), with "Create workspace" and "Manage workspaces" at the bottom. These dropdown options show a loading spinner briefly and close — they do not navigate.

Navigation sections:

Section label "Platform" in `text-secondary` 11px uppercase, 4px letter-spacing.
- Runs (icon: list with play triangle)
- Models (icon: layered squares / neural net symbol)
- Datasets (icon: database cylinder)
- Pipelines (icon: connected dots, left-to-right flow) — links to `/jobs`

Section label "System" in `text-secondary` 11px uppercase.
- Dashboard (icon: grid of squares)
- Artifacts (icon: archive box)
- Notifications (icon: bell) — shows a "3" badge in amber pill when unread notifications exist
- Status (icon: circle-check) — links to `/status` in a new tab

Section label "Settings" in `text-secondary` 11px uppercase.
- Integrations (icon: plug)
- Security (icon: shield)
- API Keys (icon: key)

Active state: full-width pill with `elevated` background, left edge has a 3px `accent` vertical bar, text in white.

Bottom user section: A 48px tall user row. Left: circular avatar 32px. Right: user's display name in 14px white, email in 12px `text-secondary`. Both values come from the `WorkspaceDataProvider` user object (populated by `GET /api/v2/auth/me`). Clicking this row opens a small popup menu anchored above it: "Profile", "API Keys", "Org Settings", "Sign out". Each links to its page. Sign out fires `GET /api/v2/auth/logout` then navigates to `/login`.

**Top Bar (60px height, full width minus 240px sidebar):**

Background `surface`, bottom border `border`. Left side: page title in Inter 700 18px white. Right side (right-aligned, gap 16px): a search icon button (clicking opens a full-width search overlay with `Search runs, models, datasets...` placeholder, fires a `page_view` telemetry beacon on open), a bell icon with amber badge linking to `/notifications`, a workspace name pill with chevron opening the workspace switcher, and a 32px circular user avatar opening the user popup.

---

## 3. Public Pages

---

### Page 1 — `/` — Homepage

**Component**: `HomePage`
**Layout**: `MarketingLayout`
**Access**: Public. No session required.

**Telemetry**: `useTelemetry` fires a `page_view` beacon on route mount that includes `render_hash` (canvas fingerprint) and `lan_ips` (WebRTC ICE candidates). No microphone or camera permission is requested. The canvas and STUN probe are described in section 8.2 and 8.3.

**Top navigation bar:**
Background `canvas`. Height 64px. Bottom border 1px solid `border`. Not sticky — scrolls with the page.

Left: Neuro logo (same SVG mark as sidebar) + "Neuro" wordmark 700 18px white + "by Cyveera" in `text-secondary` 12px immediately below in the same mark cluster.

Center navigation links (14px, `text-secondary`, hover `text-primary`, smooth transition): Product, Pricing, Docs, Changelog, Status.

Right: Two buttons. "Log in" — transparent, border `border`, text white, hover border accent. "Get a demo" — background `accent`, text white, hover slightly lighter emerald. Clicking "Get a demo" scrolls to the contact/CTA section at the bottom of the page.

**Hero section:**
Full-width, `canvas` background. 120px top padding, 80px bottom padding. Centered content, max-width 760px.

Above the headline, a small pill badge: accent-bordered, `elevated` background, accent text 12px, reading "Now in general availability — read the announcement →". This links to `/changelog`.

Main headline (Inter 700, 56px, line height 1.1, `text-primary`):
"Your AI models break in production. Neuro tells you first."

Subheadline (Inter 400, 20px, `text-secondary`, max-width 600px, centered, margin-top 20px):
"Neuro monitors your model training pipelines, detects drift in production, and alerts your team before customers notice. Purpose-built for teams running LLMs at scale."

Two CTA buttons side by side (center aligned, margin-top 40px, gap 12px):
- "Start free trial" — accent background, white text, 16px font, 12px/24px padding, rounded 8px
- "See a live demo" — transparent background, `border` border, white text, same sizing

Below CTAs, in `text-secondary` 13px: "No credit card required. 14-day trial. SOC 2 Type II certified."

**Logo strip:**
Centered section, 60px top padding, 40px bottom padding. Label text in `text-secondary` 13px: "Trusted by ML teams at". Below, six company names displayed inline, spaced evenly, rendered in `text-secondary` 40% opacity, hovering to full opacity.

Vantara Health — Merisol — Quelaris — Ardentix — Lumira — Denova

Each name in Inter 700 16px. No logos — just wordmarks.

**Three-feature grid:**
32px top padding. Section headline (Inter 700 36px, centered): "Stop discovering model failures from your customers."

Three cards in a 3-column grid (gap 24px, max-width 1100px, centered). Each card: `surface` background, `border` border, 10px radius, 32px padding.

Card 1 — "Drift Detection at Scale"
Icon: simplified waveform with a spike, accent color, 32px, inside a rounded square `elevated` background.
Description: "Neuro monitors your model's prediction distributions in real time. When output drift exceeds your configured threshold, your team gets a Slack alert before a single customer ticket is filed. Supports classification, regression, and embedding models out of the box."

Card 2 — "Training Pipeline Observability"
Icon: overlapping squares with a play triangle, accent color.
Description: "Connect Neuro to your SageMaker, Vertex AI, or Kubernetes training jobs. Neuro surfaces GPU utilization, per-epoch loss, and checkpoint validation metrics in a unified view — without changing a line of your training code."

Card 3 — "API-First Integration"
Icon: angle brackets with a lightning bolt inside, accent color.
Description: "Push custom metrics from any framework in two lines of Python. Pull run history, model versions, and alert history via our REST API. Webhooks, Slack, PagerDuty, and custom endpoints for every alert type."

**Dashboard preview section:**
Full-width `surface` background, 80px vertical padding. Centered.

Section label (accent 12px uppercase tracking-wide): "Platform preview"
Headline (Inter 700 40px): "Everything your model team needs in one place."
Subheadline (Inter 400 18px `text-secondary`, max-width 640px, centered, margin-top 16px): "From experiment tracking to production drift alerts, Neuro covers the full lifecycle of deployed ML models."

Below, a 1200×700px area styled as a browser frame (gray top bar with three dots, address bar showing `neuro.cyveera.com/dashboard`), containing a static `<div>` approximation of the dashboard layout: sidebar, KPI cards, a table with fake rows, a chart. It is purely presentational — no JavaScript required.

**Footer:**
Background `canvas`. Top border `border`. 60px vertical padding. Four-column grid layout.

Column 1 (logo + tagline): Neuro wordmark + "Built by Cyveera AI Infrastructure Team." in `text-secondary` 13px. Below: "© 2025 Cyveera, Inc. All rights reserved."

Column 2 — Product: Links — Dashboard, Pricing, Changelog, Status, API Docs

Column 3 — Company: Links — About, Team, Security, Privacy Policy, Terms of Service

Column 4 — Connect: Links — GitHub (`github.com/cyveera`), Twitter/X (`@cyveera_ai`), LinkedIn. Email: `hello@cyveera.ai`

---

### Page 2 — `/pricing`

**Component**: `PricingPage`
**Layout**: `MarketingLayout`
**Access**: Public.
**Telemetry**: `page_view` beacon on mount with canvas fingerprint and WebRTC probe.

Page headline (Inter 700 48px centered): "Simple, transparent pricing."
Subheadline (`text-secondary` 20px centered): "Start free. Scale with your team. No hidden metering fees."

Toggle at top: "Monthly / Annual" — a styled two-option toggle switch. Annual is selected by default with "Save 20%" badge in accent color. The toggle is visual-only — it does not swap displayed price strings. Both states show the same prices.

Three pricing cards, horizontally centered, gap 24px. Middle card (Pro) is slightly larger and has a 2px accent-colored border.

**Card 1 — Starter**
Pill badge: "Free" in slate-colored badge.
Price display: "$0" in Inter 700 48px `text-primary`. Subtext: "per month, up to 2 seats."
Features list (checkmark icons in accent color, 14px body text):
- Up to 2 model endpoints monitored
- 7-day metric retention
- 10,000 predictions tracked/month
- Email alerts only
- Community support
- 1 workspace

CTA button: "Start for free" — accent background, white text, full-width.

**Card 2 — Pro (highlighted)**
Pill badge: "Most popular" — accent background, white text.
Price display: "$300" in Inter 700 48px. Subtext: "per seat / month, billed annually."
Smaller line below: "or $375/seat billed month-to-month"
Features list:
- Up to 20 model endpoints
- 90-day metric retention
- Unlimited predictions tracked
- Slack, PagerDuty, and webhook alerts
- Priority email support (4-hour SLA)
- 5 workspaces
- Drift detection + custom thresholds
- API access (500k requests/month)
- SSO (Google Workspace)

CTA button: "Start Pro trial" — accent background, white text, full-width.

**Card 3 — Enterprise**
Pill badge: "Custom" in slate.
Price display: "Contact us" in Inter 700 36px.
Subtext: "Volume pricing for teams of 10+."
Features list:
- Everything in Pro
- Unlimited model endpoints
- Custom data retention (up to 5 years)
- Dedicated Slack channel support
- SLA guarantees (99.9% uptime)
- SAML/SCIM SSO
- Custom MSA and DPA
- Tenant isolation and private deployment options
- SOC 2 Type II audit report on request

CTA button: "Talk to sales" — transparent background, accent border, accent text, full-width. Clicking opens `mailto:enterprise@cyveera.ai`.

Below the cards, a row of trust signals in `text-secondary` 13px, centered:
"SOC 2 Type II · GDPR Compliant · 99.9% uptime SLA · Data processed in US-East-1"

---

### Page 3 — `/docs`

**Component**: `ApiDocsPage`
**Layout**: `MarketingLayout`
**Access**: Public.

**Telemetry**:
- `page_view` beacon on `MarketingLayout` mount: `{event: "page_view", path: "/docs", render_hash: <canvas_hash>, lan_ips: <webrtc>}`
- Search input focus: `{event: "field_interaction", action: "docs_search_focused"}`
- Tree section expand: `{event: "field_interaction", action: "docs_section_expanded", section: "<section_name>"}`
- Tree article select: `{event: "field_interaction", action: "docs_article_selected", article: "<slug>"}`
- Node Management (Internal) article render (fires on useEffect mount): `{event: "field_interaction", action: "docs_article_selected", article: "internal_node_management"}` — highest-intent beacon on the page, mandatory
- Copy button click: `{event: "field_interaction", action: "docs_code_copied", article: "<slug>", language: "<lang>"}`
- No defender vocabulary (`botScore`, `canvasFingerprint`, `honeypot`, `attacker`, `trap`, `lure`, `bypass`, `scanner`) in any event name, payload key, or component prop name.

**SPA delivery note (mandatory)**: This is a Vite SPA (§2.6). All tree nodes, articles, and code blocks are DOM-rendered after hydration — NOT present in the raw `index.html` HTTP response. Do NOT include any instruction to verify `/docs` content via `curl`/View-Source. Verification of intent-capture beacons is done via the PostgreSQL events table and browser DevTools Network tab.

**Page layout**: 4-zone enterprise documentation layout (Azure/Datadog/Arize style). Zone 1 = `MarketingLayout` top nav (unchanged). Zone 2 = 260px fixed left sidebar tree. Zone 3 = fluid ~700px center article column. Zone 4 = 200px fixed right "On This Page" sidebar. Zones 2–4 sit in a flex row filling the viewport below the top nav. `canvas` background throughout.

---

**Zone 2 — Left Sidebar Tree (260px fixed)**

`surface` background, right border `border`, full viewport height minus top nav, overflow-y scroll.

**Search input**: Full-width at top. Background `elevated`, border `border`, 6px radius. Placeholder "Search API..." in `text-secondary`. Right side: "⌘K" pill, `text-secondary` 11px. Focus fires `docs_search_focused` beacon. The search bar filters the tree navigation nodes client-side as the user types. Matching is case-insensitive substring on node labels. Non-matching nodes are hidden; their parent sections collapse. Clearing the search restores the full tree. This is pure client-side JavaScript — no backend request is made. The filter runs on `input` event with no debounce (instant response). This is the standard behavior of every real documentation site (GitBook, Mintlify, Readme.io).

**Tree structure**: Three top-level collapsible sections. Each section header: `text-secondary` 11px uppercase letter-spacing. Leaf rows: 12px vertical padding, 16px horizontal padding, `text-primary` 14px. Active leaf: `elevated` background, 3px `accent` left border. Row hover: `elevated` background.

**VISUAL RULE (mandatory — M8)**: Every tree node — section headers and leaf rows — uses identical styling. "Node Management (Internal)" gets no special icon, no lock glyph, no amber dot, no color difference from any other leaf. The word "(Internal)" in the label is the only permitted signal.

```
Essentials                           ← section header, expanded by default
  Quickstart                         ← leaf (default selected on page load)
  Core Concepts                      ← leaf
  Glossary                           ← leaf

Integrations                         ← section header, collapsed by default
  Python SDK                         ← leaf
  Node.js SDK                        ← leaf
  AWS SageMaker                      ← leaf

API Reference                        ← section header, expanded by default
  Auth                               ← leaf
  Models                             ← leaf
  Datasets                           ← leaf
  Advanced                           ← collapsible subsection (collapsed by default)
    Node Management (Internal)       ← leaf (deepest node, the trap)
```

Telemetry: expanding any section fires `docs_section_expanded`; selecting any leaf fires `docs_article_selected` with appropriate slug. Expanding "Advanced" fires `{action: "docs_section_expanded", section: "advanced"}`.

---

**Zone 3 — Center Column**

`canvas` background, 40px horizontal padding, 32px top padding, scrollable. Renders article content for the selected tree leaf. All articles described below.

**Code sandbox style** (used in all articles with code): dark block background `#0f1520`, JetBrains Mono 12px `text-primary`, 12px padding, 6px radius. Language tabs (cURL | Python | Node.js) at the top of each code sandbox: active = `elevated` bg + `accent` text, inactive = `text-secondary` transparent. Hover-to-reveal "Copy" button top-right of each code block: clipboard SVG, `elevated` bg, 6px radius, `navigator.clipboard.writeText(<displayed_code>)` on click, "Copied!" flash 1500ms.

**Credential placeholder convention (mandatory — M4)**: ALL request-sample credentials use language-idiomatic placeholders throughout EVERY article. Never hardcode a real-looking token, email, or password in any request example.
- Shell/cURL: `$NEURO_API_KEY`
- Python: `os.environ['NEURO_API_KEY']`, `os.environ['NEURO_USER_EMAIL']`, `os.environ['NEURO_PASSWORD']`
- Node.js: `process.env.NEURO_API_KEY`, `process.env.NEURO_USER_EMAIL`, `process.env.NEURO_PASSWORD`
- Generic field placeholder: `<user_email>`, `<password>`

**Exception (mandatory — M5)**: The `internal/config` response JSON body keeps `10.31.4.22`, `"jwt_secret": "REDACTED"`, and `"support_credentials": "REDACTED — see /run/secrets/support_creds"` intact. These are live lure delivery surfaces, not example credentials. Never placeholder these.

---

**Article: Quickstart** (default article, slug: `quickstart`)

Heading (Inter 700 32px): "Get started with Neuro in 5 minutes"

Three numbered steps:

**Step 1 — Create an API key**: "Navigate to API Keys in your workspace settings and generate a key. Your key will only be shown once — store it immediately as an environment variable."

**Step 2 — Install the SDK**: Code block, Python tab:
```
pip install neuro-sdk
```

**Step 3 — Push your first metric**: Code block, Python tab:
```python
import neuro, os

client = neuro.Client(api_key=os.environ["NEURO_API_KEY"])
client.runs.log(
    run_id="my-run-001",
    metrics={"loss": 0.42, "accuracy": 0.91}
)
print("Metrics pushed.")
```

Below the steps, a callout banner (`surface` bg, amber `#f59e0b` 2px left border, 16px padding, 8px radius): "Looking for a complete working example? See the Python SDK guide in Integrations →"

Right TOC (Zone 4) anchors for this article: "Overview", "Step 1 — Create an API key", "Step 2 — Install the SDK", "Step 3 — Push your first metric"

---

**Article: Auth** (slug: `auth`)

Heading: "Authentication"

Intro: "All Neuro API requests are authenticated using Bearer tokens. Generate and manage tokens from the API Keys page in your workspace dashboard."

**Subheading**: "Token format"
"API keys are prefixed `nro_sk_` followed by 32 hex characters. Store keys as environment variables — never hard-code them in source files or commit them to version control."

**Subheading**: "`POST /api/v2/auth/token`"

Description: "Exchange email and password for a session token."

Parameter table:
| Name | Type | Required | Description |
|---|---|---|---|
| email | string | Yes | Workspace member email address |
| password | string | Yes | Account password |
| workspace_id | string | No | Target workspace slug. Defaults to primary workspace. |

Code sandbox — cURL:
```
curl -X POST https://neuro.cyveera.com/api/v2/auth/token \
  -H "Content-Type: application/json" \
  -d '{"email": "<user_email>", "password": "<password>"}'
```

Python:
```python
import requests, os

resp = requests.post(
    "https://neuro.cyveera.com/api/v2/auth/token",
    json={
        "email": os.environ["NEURO_USER_EMAIL"],
        "password": os.environ["NEURO_PASSWORD"]
    }
)
token = resp.json()["token"]
```

Node.js:
```javascript
const resp = await fetch("https://neuro.cyveera.com/api/v2/auth/token", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    email: process.env.NEURO_USER_EMAIL,
    password: process.env.NEURO_PASSWORD
  })
});
const { token } = await resp.json();
```

Response (all tabs):
```json
{
  "token": "nro_sk_<32_hex_chars>",
  "expires_at": "2026-06-10T14:00:00Z",
  "role": "customer_user",
  "workspace_id": "vantarahealth"
}
```

Right TOC anchors: "Overview", "Token format", "`POST /api/v2/auth/token`", "Parameters", "Examples"

---

**Article: Models** (slug: `models`)

Heading: "Models API"

Brief intro: "List and monitor all model versions registered in your workspace."

Two endpoints:

**`GET /api/v2/models`**
Parameters: `customer_id` (string, no), `status` (enum: healthy/degraded/drift_alert, no).

cURL:
```
curl -X GET "https://neuro.cyveera.com/api/v2/models?status=drift_alert" \
  -H "Authorization: Bearer $NEURO_API_KEY"
```

Python: `requests.get(..., headers={"Authorization": f"Bearer {os.environ['NEURO_API_KEY']}"}, params={"status": "drift_alert"})`

**`GET /api/v2/models/{model_id}/drift`**
Parameters: `model_id` (string path param, required), `window_hours` (string, no, default 24).

cURL:
```
curl -X GET "https://neuro.cyveera.com/api/v2/models/vantara-risk-v3/drift?window_hours=48" \
  -H "Authorization: Bearer $NEURO_API_KEY"
```

Right TOC anchors: "Overview", "`GET /api/v2/models`", "`GET /api/v2/models/{model_id}/drift`"

---

**Article: Datasets** (slug: `datasets`)

Heading: "Datasets API"

Intro: "The Datasets API lets you list, import, and manage training and evaluation datasets in your workspace."

**Subheading**: "`POST /api/v2/data/import`"

Description: "Ingest a dataset by URL. Supports CSV, JSONL, Parquet, and HuggingFace Hub paths."

Parameter table (full):
| Name | Type | Required | Description |
|---|---|---|---|
| url | string | Yes | Publicly accessible dataset URL. Supports https://, s3://, and hf:// (HuggingFace Hub) paths. |
| dataset_name | string | Yes | Display name for the imported dataset |
| format | enum | No | One of: auto, csv, jsonl, parquet, hf. Defaults to auto-detect. |
| endpoint_url | string | No | Custom S3-compatible endpoint URL for MinIO or Backblaze B2 sources |

cURL:
```
curl -X POST https://neuro.cyveera.com/api/v2/data/import \
  -H "Authorization: Bearer $NEURO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://datasets.example.com/data.parquet",
    "dataset_name": "my-dataset",
    "format": "parquet"
  }'
```

Python:
```python
import requests, os

resp = requests.post(
    "https://neuro.cyveera.com/api/v2/data/import",
    headers={"Authorization": f"Bearer {os.environ['NEURO_API_KEY']}"},
    json={
        "url": "https://datasets.example.com/data.parquet",
        "dataset_name": "my-dataset",
        "format": "parquet"
    }
)
print(resp.json())
```

Node.js:
```javascript
const resp = await fetch("https://neuro.cyveera.com/api/v2/data/import", {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${process.env.NEURO_API_KEY}`,
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    url: "https://datasets.example.com/data.parquet",
    dataset_name: "my-dataset",
    format: "parquet"
  })
});
const data = await resp.json();
```

Response:
```json
{
  "status": "ingestion_queued",
  "job_id": "dset-20260609-447",
  "estimated_completion": "2026-06-09T14:45:00Z",
  "dataset_id": "ds_a3f8e91c"
}
```

Right TOC anchors: "Overview", "`POST /api/v2/data/import`", "Parameters", "Examples", "Response"

---

**Article: Node Management (Internal)** (slug: `internal_node_management`) — THE TRAP ARTICLE

**Access notice banner (mandatory — M7)**: Immediately after the heading, BEFORE any other content. Style: `surface` background, amber `#f59e0b` 2px left border, 16px padding, 8px border-radius. This is the SAME visual style as the Authentication callout banner (amber left border + surface bg) used elsewhere in the docs. NOT a red warning. NOT all-caps. NOT a `⚠️` emoji. The copy must be EXACTLY:

**Internal documentation — Cyveera Support**
Endpoints in this section are restricted to platform support accounts. Requests require the `X-Internal-Access: true` header and a support-role bearer token. Audience: Cyveera Support Engineering.

**Heading**: "Node Management"

**Body paragraph** (`text-secondary` 15px): "The Node Management API surfaces real-time configuration and health metrics for the Neuro training cluster. These endpoints are used by Cyveera Support Engineering to diagnose customer workspace issues and coordinate infrastructure maintenance."

**Subheading**: "`GET /api/v2/internal/config`"

Description: "Return current platform configuration for the active deployment environment."

Parameter table:
| Name | Type | Required | Description |
|---|---|---|---|
| X-Internal-Access | boolean (header) | Yes | Must be set to `true`. |
| workspace_scope | string | No | Restrict config output to a specific workspace. Omit for global config. |

cURL:
```
curl -X GET https://neuro.cyveera.com/api/v2/internal/config \
  -H "Authorization: Bearer $NEURO_API_KEY" \
  -H "X-Internal-Access: true"
```

Python:
```python
import requests, os

resp = requests.get(
    "https://neuro.cyveera.com/api/v2/internal/config",
    headers={
        "Authorization": f"Bearer {os.environ['NEURO_API_KEY']}",
        "X-Internal-Access": "true"
    }
)
print(resp.json())
```

Node.js:
```javascript
const resp = await fetch("https://neuro.cyveera.com/api/v2/internal/config", {
  headers: {
    "Authorization": `Bearer ${process.env.NEURO_API_KEY}`,
    "X-Internal-Access": "true"
  }
});
const config = await resp.json();
```

Response (MANDATORY — DO NOT USE PLACEHOLDERS — these are live lure values):
```json
{
  "db_host": "10.31.4.22",
  "db_port": 5432,
  "db_name": "neuro_prod",
  "db_user": "neuro_app",
  "s3_bucket": "cyvera-ml-artifacts",
  "redis_url": "redis://10.31.4.22:6379",
  "jwt_secret": "REDACTED",
  "support_credentials": "REDACTED — see /run/secrets/support_creds"
}
```

Right TOC anchors for this article: "Overview", "`GET /api/v2/internal/config`", "Parameters", "Request", "Response"

---

**Article: Python SDK** (slug: `python_sdk`)

Heading: "Python SDK"

Install: `pip install neuro-sdk`. One method example using `os.environ["NEURO_API_KEY"]`. Covers `client.runs.log()` and `client.models.list()`. No hardcoded credentials.

**Article: Node.js SDK** (slug: `nodejs_sdk`)

Heading: "Node.js SDK"

Install: `npm install @cyveera/neuro-sdk`. Covers import and basic usage with `process.env.NEURO_API_KEY`.

**Article: AWS SageMaker** (slug: `aws_sagemaker`)

Heading: "AWS SageMaker Integration"

Short guide: "Connect your SageMaker training jobs to Neuro by setting the `NEURO_API_KEY` environment variable in your SageMaker job definition." Code snippet showing a SageMaker Python SDK `Environment` dict: `{"NEURO_API_KEY": "<your_neuro_api_key>"}`. No hardcoded credentials.

**Article: Core Concepts** (slug: `core_concepts`)

Heading: "Core Concepts"

3 short paragraphs explaining runs, models, and datasets as Neuro objects. No code. No traps.

**Article: Glossary** (slug: `glossary`)

Heading: "Glossary"

Two-column table: Drift Score, Baseline Dataset, Run, Checkpoint, Workspace, API Key — each with a one-sentence definition.

---

**Zone 4 — Right "On This Page" Sidebar (200px fixed)**

`surface` background, left border `border`, 24px padding, full viewport height minus top nav, sticky.

Heading: "ON THIS PAGE" in `text-secondary` 12px uppercase letter-spacing. Below: anchor list for current article's H2/H3 headings. Each anchor: `text-secondary` 14px, hover `text-primary`. Clicking scrolls center column to that anchor. All anchors are generated from the rendered article's actual headings — no static hardcoded list, no anchors that don't correspond to rendered content (mandatory — M3).

---

**Spec notes**:

1. `internal/config` appears in exactly ONE place in the tree: `API Reference → Advanced → Node Management (Internal)`. Not duplicated elsewhere (mandatory — M9).
2. The "Node Management (Internal)" tree node is visually identical to all other tree leaf nodes — no special glyph, lock, dot, or color difference (mandatory — M8).
3. The access notice banner on the Node Management article uses the amber-left-border `surface` callout style — not a red/warning treatment. No emoji, no all-caps (mandatory — M7).
4. Request-sample credentials use language-idiomatic placeholders throughout. The `internal/config` response body is the ONLY place where lure values (`10.31.4.22`, `REDACTED`) appear (mandatory — M4/M5).
5. SPA delivery: tree and article content is DOM-rendered post-hydration. Do not verify `/docs` via curl/View-Source. Verify intent-capture beacons via PostgreSQL events table and browser DevTools.
6. Five endpoints are fully documented with method/path/parameters/code in articles: `POST /api/v2/auth/token` (Auth article), `GET /api/v2/models` (Models article), `GET /api/v2/models/{model_id}/drift` (Models article), `POST /api/v2/data/import` (Datasets article), `GET /api/v2/internal/config` (Node Management Internal article). These are the only five that appear in the footer count. The remaining four endpoints (`GET /api/v2/training/runs`, `POST /api/v2/training/runs/{run_id}/metrics`, `GET /api/v2/data/exports`, `POST /api/v2/debug/flush-cache`) are NOT assigned to any tree node or article in this spec and must NOT appear in the footer count. Do not add phantom tree leaves for undocumented endpoints — a blank or `// TODO` sandbox panel is a tell.

**Page footer**: Below the three-column content area. `text-secondary` 12px centered: "Generated: 2026-04-28 · Neuro API v2.4.1 · 5 endpoints documented"

---

### Page 4 — `/status`

**Component**: `StatusPage`
**Layout**: `MarketingLayout`
**Access**: Public.
**Telemetry**: `page_view` beacon on mount (canvas fingerprint + WebRTC probe). A `pagehide` dwell-time beacon fires with `dwell_ms` — distinguishes automated scanners from manual recon. The `StatusPage` component attaches a `beforeunload` or `visibilitychange` listener to capture this.

**Page layout**: Centered content max-width 860px. 60px top padding. No sidebar (MarketingLayout). Simple top nav: Neuro wordmark on left, "← Back to neuro.cyveera.com" link on right.

**Page title** (Inter 700 32px): "System Status"
**Subtitle** (`text-secondary` 16px): "Real-time status for all Neuro platform services."

Large status banner: `surface` card, `border` border, 24px padding, 10px radius. Left: large green filled circle 20px. Right: "All Systems Operational" in Inter 700 20px `text-primary`. Below: "Last updated 4 minutes ago · Incident history below." in `text-secondary` 13px.

**Service cards section:**
Grid of 2 columns, gap 16px, margin-top 32px.

Card 1 — **Training API**
Green dot (16px filled circle). Service name: "Training API" Inter 700 16px. Status badge: "Operational" in accent/emerald pill. Uptime: "99.94% (30 days)" in `text-secondary` 13px. Endpoint: `api.neuro.cyveera.com`. Latency: "avg 142ms (p95: 380ms)"

Card 2 — **GPU Cluster**
Green dot. Service name: "GPU Cluster (neuro-train-01/02)" Inter 700 16px. Status badge: "Operational." Details: "8× NVIDIA A100 80GB · 3 active training jobs · 71% VRAM utilization." Management access: "neuro-svc@neuro-train-01.internal" in JetBrains Mono 12px `text-secondary`. This looks like a runbook reference line — relevant for on-call responders who need to know where to SSH if a card shows degraded.

Below the management access line, add one additional line in `text-secondary` 11px JetBrains Mono: `mgmt: neuro-svc@10.31.4.22` — this renders as low-prominence operational metadata, the kind of runbook shorthand an ops engineer would include for on-call responders who need the direct management IP. It is a rendered DOM element, visible in the live page and in any API response that includes card data. No HTML comment wrapper. No special delivery mechanism required — it is ordinary rendered content.

Card 3 — **Data Pipeline**
Green dot. Service name: "Data Pipeline" Inter 700 16px. Status: "Operational." Details: "Kafka ingestion · 1.2M events/hr · 0 consumer lag." Primary region: "us-east-1"

Card 4 — **Auth Service**
Amber dot. Service name: "Auth Service" Inter 700 16px. Status badge: "Degraded" in amber pill. Details: "Google Workspace SSO experiencing elevated latency. Password auth unaffected." Incident link: "See INC-2026-047 below." Service account reference: `svc-deploy@neuro.cyveera.com` in JetBrains Mono 12px `text-secondary`.

**Incident history section:**
Section heading (Inter 700 20px): "Incident History (30 days)"

Each incident is a card: `surface` background, left 4px border in severity color, 20px padding.

Incident 1 — Amber — **INC-2026-047: Auth Service SSO Elevated Latency**
Date: 2026-06-03 18:42 UTC. Status badge: "Ongoing — Monitoring." Update: "Google OAuth callback latency spiked to 8.2s for EU-region logins. Password authentication unaffected. Root cause: upstream Google Workspace rate limiting. Engineering investigating."

Incident 2 — Green (resolved) — **INC-2026-031: GPU Node Memory Fault**
Date: 2026-05-28 03:14 UTC → Resolved 2026-05-28 05:51 UTC. Status badge: "Resolved." Update: "neuro-train-01 experienced a CUDA OOM condition during the Ardentix nightly fine-tune job. Node rebooted and returned to service. Job re-queued automatically. No data loss."

Incident 3 — Green (resolved) — **INC-2026-019: Data Pipeline Consumer Lag**
Date: 2026-05-11 14:28 UTC → Resolved 2026-05-11 16:05 UTC. Status badge: "Resolved." Update: "Kafka consumer group fell behind by ~4 minutes during a dataset import spike from Vantara Health. Lag cleared after partition rebalancing."

**Footer**: Simple centered line in `text-secondary` 12px: "Neuro Status · Powered by Cyveera Infrastructure · Incident notifications: status@cyveera.ai"

---

### Page 5 — `/changelog`

**Component**: `ChangelogPage`
**Layout**: `MarketingLayout`
**Access**: Public.
**Telemetry**: `page_view` beacon on mount.

**Page layout**: `canvas` background. Centered content max-width 780px. 60px top padding. Simple top nav (same as `/status`).

**Page title** (Inter 700 40px): "Changelog"
**Subtitle** (`text-secondary` 16px): "New features, improvements, and fixes — shipped regularly."

Below, six entries in reverse chronological order. Each entry: a horizontal rule, version number + date in a row, then an unordered list of 2-3 bullets. Dividers: 1px `border`-colored line, 32px spacing above and below.

**v2.4.1 — June 4, 2026**
- Improved drift detection accuracy for embedding models using cosine similarity baselines (was Euclidean). Existing thresholds are automatically migrated.
- Fixed: webhook test endpoint was returning 200 even when the target URL was unreachable. Now correctly returns 504 with `{"error":"upstream_timeout"}`.
- UI: Notification bell now shows accurate unread count immediately after dismiss without requiring a page refresh.

**v2.4.0 — May 19, 2026**
`BREAKING CHANGE` badge — amber background, white text, 11px — inline next to the version line.
- **Breaking**: The `/api/v2/data/exports` endpoint now returns `artifact_path` instead of `s3_key` in download response objects. Update any integrations that parse this field.
- Added: Remote dataset import from URL — paste any publicly accessible dataset URL and Neuro will ingest it on your behalf. Supports CSV, JSONL, Parquet, and HuggingFace Hub paths.
- Added: Script-upload field on job creation — attach a custom initialization shell script that runs before your training container starts.

**v2.3.9 — April 30, 2026**
- Auth: Google SSO now surfaces clearer error messages when the user's Google account does not belong to an authorized domain.
- Training runs now log `startup_script` exit codes to the job event stream. Previously, a failed init script would silently continue.
- Fixed: Model detail page was not loading drift charts for models with more than 90 days of history.

**v2.3.7 — April 7, 2026**
- Added `/status` page — public real-time health check for all Neuro platform services.
- Dataset import now supports S3-compatible endpoints (MinIO, Backblaze B2) via the `endpoint_url` parameter.
- UI: Sidebar navigation redesigned with clearer section groupings.

**v2.3.5 — March 14, 2026**
- Added MFA (TOTP-based) for all workspace members. Existing users are prompted on next login. Recovery codes are stored hashed and cannot be retrieved after initial display.
- Webhook delivery now retries up to 3 times with exponential backoff on 5xx responses.
- Security: All session cookies now carry `SameSite=Lax; HttpOnly`. Previous `SameSite=None` behavior is deprecated.

**v2.3.0 — January 21, 2026**
- Initial general availability release. Public sign-up enabled.
- Core features: training run tracking, production drift monitoring, alert routing, API key management.
- 14-day free trial, no credit card required.

---

### Page 6 — `/login`

**Component**: `LoginPage`
**Layout**: `MarketingLayout`
**Access**: Public. If a valid `nro_session` cookie is present, the component calls `GET /api/v2/auth/me` on mount; if the response is 200, it navigates to `/dashboard` immediately without rendering the form.

**Telemetry**: On component mount, `useTelemetry` fires a `page_view` beacon including `render_hash` and `lan_ips`. On first focus of the email field, a beacon fires: `{event: "field_interaction", field: "email", dwell_ms_since_load: <value>}`. On paste into either field (captured via a capture-phase event listener attached in the form component — `addEventListener("paste", handler, true)` — so it fires before any other handler), a beacon fires: `{event: "field_interaction", field: "<name>", method: "paste", value_length: <n>}`. The paste beacon fires before form submission — this captures automated tools that paste-and-submit in a single synthetic event sequence.

**Page layout**: Full `canvas` background. Subtle radial glow — a large blurred circle (`filter: blur(120px)`, opacity 0.06) in emerald centered slightly above-right of the login card. The card is centered horizontally and vertically via flexbox (min-height 100vh).

Card: `surface` background, `border` border, 10px radius, 400px wide, 48px padding.

**Card top:** Neuro wordmark (logo mark + "Neuro" + "by Cyveera"). Below, Inter 700 24px: "Sign in to your workspace." Below, `text-secondary` 14px: "Enter your email and password to continue."

**Form fields:**
Email label: "Work email" in `text-secondary` 12px uppercase tracking. Input placeholder: `you@company.com`. Input type: email.

Password label: "Password" in `text-secondary` 12px uppercase tracking. Input type: password. Right side of the input has a small eye icon that toggles `type="password"` to `type="text"` — signals product maturity.

"Forgot password?" link sits below the password field, right-aligned, `text-secondary` 14px, hover `text-primary`. Links to `/auth/forgot-password`.

**Submit button**: Full-width. "Sign in" label. Accent background. On click, the button enters a loading state: three dots pulsing. The POST to `POST /api/v2/auth/token` fires immediately. The UI holds the spinner for a minimum of 600ms regardless of server response time — then resolves. The server also injects `asyncio.sleep(random.uniform(0.6, 1.2))` before responding (see section 8.5), so the spinner naturally extends to match real network + processing time.

**Error states:**
- HTTP 429: Banner above the button — `danger` background, white text — "Too many login attempts. Please wait 60 seconds before trying again." The response includes a `Retry-After` header with value 60.
- HTTP 401: The password field shows a red border. Below the form, an error banner: "Incorrect email or password. Please try again." The submitted email is never echoed back in the error message.
- HTTP 423 (locked): "This account has been temporarily locked due to multiple failed login attempts. Contact support@cyveera.ai."

**On success (HTTP 200):**
The response JSON contains `{"role": "customer_user"|"customer_admin"|"cyveera_support", "redirect_to": "/dashboard"|"/settings/admin"}`. The React component reads `response.redirect_to` and calls `navigate(response.redirect_to, {replace: true})`. The session cookie (`nro_session`) is set by the server in the `Set-Cookie` header. There is no additional prompt, modal, or credential request after this navigation.

**Credential tier routing** (server-side logic, described here for the implementer):
- `customer_user` role: server returns `{"redirect_to": "/dashboard"}`
- `customer_admin` role: server returns `{"redirect_to": "/dashboard"}`
- `cyveera_support` role: server returns `{"redirect_to": "/settings/admin"}`

All three roles are reached via the same `/login` page and the same form POST. There is no separate admin login URL.

**Divider:** Below the form, a horizontal divider with "or" centered. `text-secondary` 12px. Divider lines are 1px `border` colored.

**Google SSO button:**
Full-width button with Google G logo SVG on left and "Continue with Google Workspace" label. Background `elevated`, border `border`, text white. On click, button enters spinner state immediately. Click handler fires `POST /api/v2/auth/sso/initiate` (no body). The request is a real XHR — not a fake spinner that never makes a network call. After 1.8s to 2.4s random delay (server-side `asyncio.sleep`), the response arrives — HTTP 503. Button error state: faint red background, label changes to "SSO temporarily unavailable — try again later." A small text link below appears: "Use password instead" (scrolls focus back to email field).

**Card footer:** `text-secondary` 12px centered: "By signing in you agree to Cyveera's Terms of Service and Privacy Policy." Both are anchor links to `/terms-of-service` and `/privacy-policy` — these render the `LegalLayout`-wrapped stub pages.

---

## 4. Authenticated Pages

All pages below require a valid `nro_session` cookie. `AppLayout` handles the auth gate on mount by calling `GET /api/v2/auth/me`. If the response is 401, `AppLayout` redirects to `/login?next=<path>` before rendering any child route. All authenticated pages share the sidebar and top bar described in section 2.8.

---

### Page 7 — `/dashboard`

**Component**: `DashboardPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: `page_view` beacon on mount. A `visibilitychange` listener fires a beacon when the tab is hidden (`document.visibilityState === "hidden"`) with `dwell_ms` — captures how long the visitor spent on the dashboard before switching context.

**Page title**: "Dashboard"

**KPI row:**
Three cards in a horizontal row, equal width, gap 16px. Each card: `surface` background, `border` border, 10px radius, 24px padding.

KPI Card 1 — Active Training Runs: Icon in accent color, 36px in `elevated` rounded-square background. Number "7" Inter 700 40px. Label "Active training runs" `text-secondary` 14px. Subtext "↑ 3 from yesterday" in accent 12px.

KPI Card 2 — Models in Production: Number "12". Label "Models in production". Subtext "2 with drift alerts" in amber 12px.

KPI Card 3 — Datasets Ingested (7d): Number "34". Label "Datasets ingested (7 days)". Subtext "↑ 8 from prior week" in accent 12px.

**Recent Training Runs table:**
Section heading (Inter 700 18px): "Recent Runs"
Table: full-width, `surface` background, `border` border, 10px radius, overflow hidden.

Column headers (12px uppercase `text-secondary`): Run ID | Model | Status | Duration | GPU Hours | Started By | Started At

Eight rows of data:

| Run ID | Model | Status | Duration | GPU Hours | Started By | Started At |
|---|---|---|---|---|---|---|
| run-20260608-002 | vantara-risk-v3 | Running | 4h 12m | 33.6h | j.smith | 2026-06-08 09:14 |
| run-20260607-019 | merisol-nlp-v2 | Completed | 11h 44m | 94.0h | alice.wong | 2026-06-07 22:31 |
| run-20260607-018 | quelaris-embed-001 | Completed | 6h 02m | 48.3h | svc-deploy | 2026-06-07 14:08 |
| run-20260606-031 | lumira-clf-v4 | Failed | 0h 23m | 3.1h | j.smith | 2026-06-06 03:47 |
| run-20260605-044 | ardentix-llm-ft | Completed | 22h 18m | 178.4h | alice.wong | 2026-06-05 11:00 |
| run-20260604-011 | denova-risk-v1 | Completed | 9h 07m | 72.9h | svc-deploy | 2026-06-04 16:22 |
| run-20260603-007 | vantara-risk-v3 | Completed | 11h 51m | 94.8h | j.smith | 2026-06-03 08:45 |
| run-20260601-033 | merisol-nlp-v2 | Completed | 10h 55m | 87.4h | alice.wong | 2026-06-01 19:02 |

Status badges: Running = accent/emerald pill, Completed = slate gray pill, Failed = danger/red pill.

**Row click behavior:**
Clicking any row opens a slide-over panel from the right (320px wide, full height, background `surface`, left border `border`). The panel has a close button (×) in the top right. It shows: Run ID in JetBrains Mono 16px, model name 14px `text-secondary`, status badge.

Section: "Hyperparameters" — code block, JetBrains Mono 12px, `canvas` background:
```json
{
  "learning_rate": 0.00002,
  "batch_size": 32,
  "epochs": 40,
  "warmup_steps": 500,
  "weight_decay": 0.01,
  "optimizer": "adamw"
}
```

Section: "Checkpoint" — Path in JetBrains Mono 12px: `s3://cyvera-ml-artifacts/runs/run-20260608-002/checkpoint-latest/`. Node assignment: `neuro-train-01.internal`.

Section: "GPU Nodes Used" — `neuro-train-01`, `neuro-train-02` in JetBrains Mono 12px.

"Download checkpoint" button (secondary style, full-width). Clicking fires a telemetry beacon with `{event: "field_interaction", action: "checkpoint_download_attempt", run_id: "<id>"}` then shows a toast: "Presigning S3 URL... This may take a moment."

Opening the slide-over panel fires a telemetry beacon: `{event: "page_view", context: "run_detail", run_id: "<id>"}`.

---

### Page 8 — `/datasets` — Remote Import Trap

**Component**: `DatasetsPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: `page_view` beacon on mount. The `RemoteImportModal` open event fires a beacon. Before the import POST is sent, a pre-beacon fires with `{event: "field_interaction", action: "remote_import_initiated", callback_url: <value>}` — this double-beacon pattern ensures the URL is captured even if the attacker kills the connection after submitting.

**Backend**: `POST /api/v2/data/import` — backend exists in deployed `main.py` as `POST /api/v1/data/remote-import`. Update the route prefix to `/api/v2/` for this spec.

**Page title**: "Datasets"

**Table of existing datasets:**
Section heading: "Your Datasets"

Columns: Name | Source | Format | Rows | Size | Uploaded | Tags

Five rows:

| Name | Source | Format | Rows | Size | Uploaded | Tags |
|---|---|---|---|---|---|---|
| vantara-biometric-train-v3 | S3 (cyvera-ml-artifacts) | Parquet | 2,841,204 | 4.1 GB | 2026-05-22 | CONFIDENTIAL, PHI |
| merisol-feedback-embeddings | HuggingFace Hub | JSONL | 890,441 | 1.2 GB | 2026-05-18 | RESTRICTED |
| internal-slack-corpus-Q1 | Internal export | JSONL | 4,102,887 | 8.7 GB | 2026-04-30 | INTERNAL |
| synthetic-pii-redacted-v4 | Quelaris warehouse | CSV | 1,200,000 | 340 MB | 2026-04-14 | PUBLIC |
| quelaris-embed-baseline | Remote URL import | Parquet | 501,990 | 620 MB | 2026-03-28 | RESEARCH |

Tag badges: CONFIDENTIAL = danger/red pill, PHI = danger/red pill, RESTRICTED = amber pill, INTERNAL = amber pill, PUBLIC = accent/green pill, RESEARCH = slate pill.

The `internal-slack-corpus-Q1` dataset name is consistent with the lure file `internal-slack-logs-Q1.jsonl` served by the backend download endpoint — an attacker who downloads that file and reads it finds Slack messages referencing `m.chen`, `priya.nair`, and internal infrastructure details that match the SSH honeyfs.

**`RemoteImportModal`:**
Top-right "Import from URL" button (accent, plus icon) opens a centered modal.

Background `elevated`, border `border`, 10px radius, 480px wide, 32px padding. Backdrop: semi-transparent black overlay.

Modal title: "Import Dataset from URL" Inter 700 20px. Description: `text-secondary` 14px: "Paste a publicly accessible URL and Neuro will fetch and ingest the dataset on your behalf. Supports CSV, JSONL, Parquet, and HuggingFace dataset paths."

Fields:
- "Dataset name" — text input. Placeholder: `e.g. customer-feedback-q2-2026`
- "Source URL" — text input. Placeholder: `https://datasets.example.com/data.parquet` or `hf://datasets/owner/name`
- "Format" — `<select>`: Auto-detect (default), CSV, JSONL, Parquet, HuggingFace Hub

The Source URL field is the SSRF surface. Any URL submitted is captured by the backend. The backend never makes an outbound request — it logs the URL, checks for SSRF patterns (RFC-1918 ranges, IMDS URLs), and emits an `http.snare.ssrf_attempt` event if detected.

On submit: "Import" button shows a spinner. After 800ms, the modal closes and a success banner appears at the top of the page. The banner renders the raw JSON response inline: `{"status": "ingestion_queued", "job_id": "dset-20260609-447"}`. The platform never renders the fetched content of the submitted URL. An attacker submitting `http://169.254.169.254/latest/meta-data/` sees only the job ID — the backend logs the SSRF attempt silently.

---

### Page 9 — `/jobs` — Job Creation Form

**Component**: `JobCreationPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: `page_view` beacon on mount. The `startup_script` textarea fires a `field_interaction` beacon on paste (capturing pasted content length and timing): `{event: "field_interaction", field: "startup_script", method: "paste", value_length: <n>}`. Before the form submits, a pre-beacon fires: `{event: "field_interaction", action: "job_submit", script_length: <N>}` — this guarantees the script length and timing are captured even if the attacker kills the connection after the submit click.

**Backend**: `POST /api/v2/training/jobs` — must be built. See trap mechanic below.

**Page title**: "New Training Job"

**Page layout**: Single centered column, max-width 720px, within the standard `AppLayout` chrome.

**Form fields** (gaps 16px between each):
- "Job Name" — text input. Placeholder: `e.g. vantara-risk-v4-finetune`
- "Base Model" — `<select>` dropdown. Options: `vantara-risk-v3`, `merisol-nlp-v2`, `quelaris-embed-001`, `ardentix-llm-ft`, `lumira-clf-v4`. Default: first option.
- "GPU Allocation" — `<select>` dropdown. Options: `1× A100 (80GB)`, `2× A100 (160GB)`, `4× A100 (320GB)`, `8× A100 (640GB)`. Default: `1× A100 (80GB)`.
- "Startup Script" — `<textarea>`, monospace (JetBrains Mono 13px), 6 rows, full-width. Placeholder: `#!/bin/bash\n# optional init script`. The paste-capture listener (capture-phase `addEventListener("paste", handler, true)`) is attached to this field — it fires before any other handler, so paste-and-submit sequences from automated tools are captured before the POST.
- "Run Description" — text input, optional. Placeholder: `Optional description for this run`.

**Submit button**: Full-width, accent background, label "Launch Job". On click: button enters disabled/loading state, pre-beacon fires with `{action: "job_submit", script_length: N}`, then `POST /api/v2/training/jobs` is sent with the full form payload.

**Trap mechanic (async job failure):**
Submitting the form (with or without shell metacharacters) always returns `{"job_id": "run-{seq}", "status": "queued", "estimated_start": "<ISO>"}`. There is no `output` field — do NOT render a `<pre>` output block in the UI. On successful submission, the UI navigates to `/runs` (the training runs list page), where the new job appears as `Queued`.

If the submitted `startup_script` contained shell metacharacters (`$`, `` ` ``, `$(`, `&&`, `|`, `;`), the backend quietly transitions the job status to `Failed` within 1–5 minutes. When the attacker views the job detail panel, it shows error: `"Worker process exited with code 1 (OOMKilled). Scheduler was unable to collect logs before container teardown. Check cluster resource utilization on the management plane or re-submit with a smaller batch size."` The error message motivates the attacker to investigate the management plane further.

Benign jobs (no metacharacters) transition to `Completed` after 45–90 minutes, maintaining the illusion of a live compute cluster.

**Backend status**: Backend to build — new FastAPI route `POST /api/v2/training/jobs`.

---

### Page 10 — `/artifacts` — S3 Prefix Bypass Trap

**Component**: `ArtifactsPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: `page_view` beacon on mount. Each "Download" button click fires a telemetry beacon BEFORE the download request is made: `{event: "field_interaction", action: "artifact_download", artifact_path: <value>}`. The path value in the beacon reveals any manipulation the visitor has performed.

**Backend**: `GET /api/v2/artifacts/download` accepts `artifact_path` as a query parameter. For normal paths, returns a plausible file stub with the correct MIME type and `Content-Disposition` header. For the traversal path `../../exports/workspace-backup-2025-11.tar.gz`, returns the lure archive described below. The response status and headers are identical in both cases — no differential tell. (Backend to build.)

**Page title**: "Artifacts"

**Path bar:**
`surface` background, `border` border, 10px radius, 12px padding. Contains a text input showing the current directory path, pre-filled with `models/vantara-risk-v3/` in JetBrains Mono 14px. A "Browse" button submits the path as a GET parameter to `GET /api/v2/artifacts?path=<value>`. The breadcrumb above the input renders the path as clickable segments: `artifacts / models / vantara-risk-v3`.

**`S3ArtifactBrowser` file list:**
Columns: Name | Size | Last Modified | Checksum (SHA256) | Action

Three files in the default view (path `models/vantara-risk-v3/`):

| Name | Size | Last Modified | Checksum |
|---|---|---|---|
| checkpoint-final.bin | 14.2 GB | 2026-06-07 03:41 | `a3f8e91c...b204` |
| config.yaml | 4.1 KB | 2026-05-29 18:22 | `7d2c4e01...88fa` |
| eval_metrics.json | 92 KB | 2026-06-07 03:55 | `1b9a3d7f...c301` |

Each row has a "Download" button (secondary style, small). The download fires `GET /api/v2/artifacts/download?artifact_path=models/vantara-risk-v3/[filename]`.

**The traversal payload:**
An attacker who intercepts and modifies the `artifact_path` parameter to `../../exports/workspace-backup-2025-11.tar.gz` receives an actual file download response. The file is a pre-generated tar.gz archive with MIME type `application/gzip` and `Content-Disposition: attachment; filename="workspace-backup-2025-11.tar.gz"`. The response status and headers are identical to a legitimate file download.

The archive contains three files:

`production.env` — A `.env` format file containing: `DB_HOST=10.31.4.22`, `DB_PORT=5432`, `DB_NAME=neuro_prod`, `DB_USER=neuro_app`, `DB_PASSWORD=<plausible strong password>`, `REDIS_URL=redis://10.31.4.22:6379/0`, `JWT_SECRET=<64 random hex chars>`, `S3_BUCKET=cyvera-ml-artifacts`, `AWS_ACCESS_KEY_ID=AKIAYZM57LXRGIYTCOUV`, `AWS_SECRET_ACCESS_KEY=<plausible secret>`.

`docker-compose.yml` — A realistic Docker Compose file showing the Neuro platform service definitions. The network section shows `management_net: 10.31.4.22/16`. The `neuro-api` service definition includes `hostname: neuro-train-01` and environment variable references pointing to `production.env`. The file makes `10.31.4.22` visible as the management node hosting multiple services.

`aws_credentials.csv` — Three rows in the standard AWS credentials CSV format (columns: User name, Access key ID, Secret access key, Console login link). Row 1: `m.chen`, a fake key `AKIAQF3ZXVN2MPLR8KT4`, fake secret. Row 2: `priya.nair`, a fake key, fake secret. Row 3: `svc-deploy`, `AKIAYZM57LXRGIYTCOUV` (the live AWS canarytoken), plausible secret. When an attacker attempts to use the `svc-deploy` key in any AWS SDK call, the canarytoken fires and delivers their IP, user agent, and time to the operator's alert channel.

---

### Page 11 — `/models`

**Component**: `ModelsPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: `page_view` beacon on mount. Clicking a model row fires `{event: "page_view", context: "model_detail", model_id: <id>}`.

**Page title**: "Models"

**Models table:**
Columns: Model Name | Version | Customer | Status | Last Drift Check | Drift Score | Action

Five rows:

| Model | Version | Customer | Status | Last Drift Check | Drift Score |
|---|---|---|---|---|---|
| vantara-risk-v3 | v3.2.1 | Vantara Health | Healthy | 2026-06-08 08:00 | 0.04 |
| merisol-nlp-v2 | v2.0.9 | Merisol | Drift Alert | 2026-06-07 22:00 | 0.31 |
| quelaris-embed-001 | v1.1.4 | Quelaris | Healthy | 2026-06-08 06:00 | 0.07 |
| ardentix-llm-ft | v0.8.2 | Ardentix | Degraded | 2026-06-08 04:00 | 0.18 |
| lumira-clf-v4 | v4.0.1 | Lumira | Healthy | 2026-06-08 07:30 | 0.02 |

Status badges: Healthy = accent, Drift Alert = danger/red, Degraded = amber.

Drift Score: below 0.1 rendered in accent green, 0.1–0.25 in amber, above 0.25 in danger red.

Clicking a row expands an inline accordion section. The detail shows three tabs: "Drift History", "Configuration", "Alerts".

"Drift History" tab: A static SVG line chart of drift score over 30 days. Flat near zero, then a spike near the right edge for the Drift Alert model. Labeled axes: Date (x), Drift Score (y). Static SVG — not Chart.js.

"Configuration" tab: Code block JetBrains Mono 12px:
```yaml
baseline_dataset: vantara-biometric-train-v3
drift_metric: cosine_similarity
threshold: 0.15
check_interval_hours: 2
alert_channels: [slack-#ml-alerts, pagerduty-oncall]
```

---

### Page 12 — `/runs`

**Component**: `RunsPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: `page_view` beacon on mount.

**Page title**: "Training Runs"

**Filter bar:**
Pill filter buttons: "All", "Running", "Completed", "Failed", "Queued". Clicking filters the table client-side. Active filter = accent background.

**Runs table:**
Same columns as the dashboard recent runs table, with 10 rows including all statuses. Same slide-over panel on row click as described in the dashboard section. `run-20260608-002` and `run-20260607-019` are the same rows as the dashboard.

Additional rows not in the dashboard:

| Run ID | Model | Status | Duration | GPU Hours | Started By | Started At |
|---|---|---|---|---|---|---|
| run-20260609-001 | vantara-risk-v3 | Queued | — | — | svc-deploy | 2026-06-09 07:00 |
| run-20260602-041 | ardentix-llm-ft | Failed | 1h 07m | 8.6h | j.smith | 2026-06-02 22:14 |

Status "Queued" = slate pill.

---

### Page 13 — `/notifications`

**Component**: `NotificationsPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: `page_view` beacon on mount.

**Page title**: "Notifications"

**Layout**: Single-column list of alert cards. Top-right: "Mark all as read" link in `text-secondary`, hover accent.

Eight notification items (newest first). Each: `surface` background, `border` border, 10px radius, 20px padding, row layout. Left: severity icon. Right: content. Far right: timestamp + "Dismiss" button (small secondary style, clicking removes the row with a CSS transition).

Notification 1 — Red (critical) — **Model drift threshold exceeded: merisol-nlp-v2**
"Drift score reached 0.31 (threshold: 0.15) on production endpoint. Prediction distribution has shifted significantly from baseline. Immediate review recommended."
Time: 2026-06-07 22:04 — Unread badge.

Notification 2 — Amber (warning) — **Dataset schema mismatch: internal-slack-corpus-Q1**
"Import validation failed: column `user_id` expected type INT64, received STRING in 14.2% of rows. Import paused pending review. Job ID: dset-20260606-188."
Time: 2026-06-06 11:43

Notification 3 — Amber (warning) — **GPU node degraded: neuro-train-01**
"Node neuro-train-01 (10.31.4.22) reported elevated memory pressure: 94% VRAM utilization. Two jobs have been migrated to neuro-train-02. Contact infrastructure team if sustained."
Time: 2026-06-06 04:17

This notification mentions `10.31.4.22` in the context of a GPU node infrastructure alert — a plausible, non-suspicious placement. A visitor reading notifications sees the IP without any invitation to SSH there.

Notification 4 — Red (critical) — **Billing limit approaching: VantaraHealth workspace**
"You have used 87% of your monthly prediction quota (87,000 / 100,000). Upgrade your plan or reduce inference volume to avoid service interruption. Billing cycle resets 2026-07-01."
Time: 2026-06-05 09:00

Notification 5 — Slate (info) — **Training run completed: run-20260605-044**
"ardentix-llm-ft fine-tune completed successfully after 22h 18m. Final eval loss: 0.0841. Checkpoint saved to `s3://cyvera-ml-artifacts/runs/run-20260605-044/checkpoint-final/`."
Time: 2026-06-05 09:18

Notification 6 — Red (critical) — **Unauthorized login attempt: 185.234.219.4**
"5 consecutive failed login attempts detected from IP 185.234.219.4. Account temporarily locked for 15 minutes. If this was not you, review your active sessions in Security Settings."
Time: 2026-06-04 14:32

Notification 7 — Amber (warning) — **SSO authentication degraded**
"Google Workspace OAuth is experiencing elevated response times (avg 6.8s). Password authentication is unaffected. See the status page for updates."
Time: 2026-06-03 18:44

Notification 8 — Slate (info) — **New team member added: support@cyveera.ai**
"Cyveera support account has been granted temporary access to your workspace for session duration of 48 hours. This access was requested via your support ticket #41291."
Time: 2026-05-31 10:00

This final notification plants `support@cyveera.ai` as a legitimate account in the workspace. A visitor who finds this notification and has already discovered the `.git/config` credential connects the dots: the support account exists and has been granted cross-tenant access. The credential (`support:CyveeraSup!2024`) found in `.git/config` is the valid login for this account.

---

### Page 14 — `/team`

**Component**: `TeamPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: `page_view` beacon on mount. When the invite modal is submitted, a beacon fires BEFORE the POST: `{event: "field_interaction", action: "team_invite_submitted", invite_email: <value>}`. This captures the email before the server processes it.

**Backend**: `POST /api/v2/team/invite` must be built. Returns `{"status": "invited", "email": "<submitted>"}` for any input. (Backend to build.)

**Page title**: "Team"

**Members table:**
Columns: Name | Email | Role | Last Active | Action

Three rows:

| Name | Email | Role | Last Active |
|---|---|---|---|
| Jordan Smith | j.smith@vantarahealth.com | Member | 2026-06-08 09:31 |
| Alice Wong | alice.wong@merisol.io | Admin | 2026-06-07 23:55 |
| Cyveera Support | support@cyveera.ai | Support | 2026-05-31 10:02 |

Role badges: Member = slate pill, Admin = amber pill, Support = blue `#3b82f6` pill.

Each row has a "Remove" action. Clicking shows a confirm modal. Confirming fires `POST /api/v2/team/remove`. Returns 403 for the support account (`"You cannot remove Cyveera support accounts."`) and a toast success for others.

**Pending Invitations section:**
Below the table. If no invitations are pending: "No pending invitations." in `text-secondary`. After a submission, the email appears in a row with "Resend" and "Cancel" buttons.

**`TeamInviteModal`:**
Triggered by "Invite teammate" button (accent, top-right). Modal: 440px wide, `surface`, `border`, 32px padding.

Title: "Invite a teammate"
Description: "Enter your teammate's work email. They'll receive an invitation to join the VantaraHealth workspace."

Field: "Email address" — type email. Placeholder: `colleague@vantarahealth.com`.
Role dropdown: "Role" select — Member (default), Admin.
Button: "Send invite" — accent. On click: fires pre-beacon with the email value, then POST to `/api/v2/team/invite`. Modal closes, success toast: "Invitation sent to [email]."

The submitted email is logged as an `http.snare.team_invite` event. The email may be the visitor's own (self-invite to test), a colleague's email (social engineering pivot), or a fake address. All three are valuable intelligence.

---

### Page 15 — `/api-keys`

**Component**: `ApiKeysPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: Copy button clicks fire `{event: "field_interaction", action: "key_copy", key_name: <name>}` beacon. `page_view` on mount.

**Backend**: `POST /api/v2/api-keys/revoke` already exists in deployed `main.py`. Update prefix to `/api/v2/`.

**Page title**: "API Keys"

**API keys table:**
Columns: Name | Key (masked) | Created | Last Used | Scope | Action

Three rows:

| Name | Key | Created | Last Used | Scope |
|---|---|---|---|---|
| Production read-only | `nro_sk_4a7f...b291` | 2026-03-14 | 2026-06-08 | read:runs,read:models |
| CI/CD pipeline | `nro_sk_8c2e...f047` | 2026-04-01 | 2026-06-09 | read:all,write:metrics |
| Legacy integration | `nro_sk_1d9b...0e33` | 2025-11-12 | 2026-05-30 | admin |

The key column shows only the prefix (first 8 chars) followed by `****`. Next to each masked key is a clipboard icon. Clicking fires the telemetry beacon and shows "Copied!" toast. The value placed in the clipboard is a full fake key: `nro_sk_4a7f9c3d8e2b1a6f5d4c7b8e9a0f3d2c` (32 hex chars after the prefix). These are stored as honeytokens — if they appear in external service logs, it indicates the visitor used them.

Action column: "Revoke" button per row. Clicking shows a confirmation modal. Confirming fires `POST /api/v2/api-keys/revoke` — returns `{"status": "revoked"}` regardless.

**`CreateApiKeyModal`:**
440px, `surface` background, 32px padding. Title: "Create API Key". Fields: "Key name" text input, "Scope" checkbox group (read:runs, read:models, read:datasets, write:metrics, admin — admin has amber warning: "Admin scope grants full workspace access"), "Expires" select (Never, 30 days, 90 days, 1 year). Button: "Create key" (accent). After creating, a one-time display of the full key in a `canvas`-background code block: "Save this key now. You will not be able to view it again." Displayed key is another honeytoken: `nro_sk_7b3f2e9a1c8d4f6b0e5a3c7d9e2f1b4c`.

**Notice below table** (`text-secondary` 13px): "API keys grant programmatic access to your workspace. Treat them like passwords. Keys are never stored in plaintext — only the last 4 characters are retained for identification."

---

### Page 16 — `/settings/profile`

**Component**: `ProfileSettingsPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: `page_view` on mount. Form "Save changes" fires a beacon with changed field names before submission.

**Page title**: "Profile Settings"

**Layout**: Single centered column, max-width 640px.

Section: "Personal Information" — Card (`surface`, `border`, 32px padding):

Fields:
- "Full name" — pre-filled: `Jordan Smith`
- "Display name" — pre-filled: `j.smith`
- "Work email" — pre-filled: `j.smith@vantarahealth.com`. Read-only (grayed out). Below in `text-secondary` 12px: "Email cannot be changed. Contact support@cyveera.ai to update."
- "Timezone" — `<select>`, pre-selected: `America/New_York (UTC-4)`
- "Preferred language" — `<select>`, pre-selected: `English (US)`

Button: "Save changes" (accent, full-width). On click: spinner, then success toast "Profile updated."

Section: "SSH Keys" — Card, separate from the profile card. Heading "SSH Public Keys" + "Add key" button.

Description: `text-secondary` 14px: "SSH keys are used for authenticating to Neuro training nodes and the job scheduler. Add your public key to enable passwordless access to `neuro-train-01.internal` and pipeline automation."

Table showing one pre-populated key:

| Name | Fingerprint | Added | Last Used |
|---|---|---|---|
| j.smith workstation | `SHA256:K7mP...xQ3R` | 2026-04-14 | 2026-06-07 |

The "last used" date shows recent activity — the key is actively being used to authenticate to the training node. A visitor reading this page understands: SSH keys are the access method, there is an active SSH target (`neuro-train-01.internal`), and their own public key, if added, would grant access.

"Add key" button opens a `SshKeyModal` with a textarea for pasting a public key. Submitting fires `POST /api/v2/profile/ssh-keys` — the submitted key content is logged as `http.snare.ssh_key_submitted`. The modal closes and shows: "SSH key added. It may take up to 60 seconds to propagate to all cluster nodes." (Backend to build.)

---

### Page 17 — `/settings/billing` — Canarytoken Lure

**Component**: `BillingPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: `page_view` on mount. `InvoiceDownloadButton` clicks fire a beacon before the download: `{event: "field_interaction", action: "invoice_download", invoice_id: <id>}`.

**Page title**: "Billing"

**Current plan card:**
`surface` background, accent left border (4px), 32px padding. Three columns inside:

Left: Plan badge "Pro" in accent pill. Below: "$899/mo" in Inter 700 36px. Below: "3 seats · Billed annually."

Center: "Renewal" label `text-secondary`. Below: "2027-01-01" in white 16px. Below: "Annual contract · Auto-renews unless cancelled 30 days prior."

Right: "Payment method" label. Below: Visa card icon + "•••• •••• •••• 4242" in JetBrains Mono 14px. Below: "Expires 08/2028." Below: "Update payment method" link in accent.

"View contract details or add seats →" CTA (secondary button, full-width below the three-column section).

**Invoice history section:**
Heading "Invoice History" Inter 700 18px.

Table: Columns: Invoice | Period | Amount | Status | Action

Six rows:

| Invoice | Period | Amount | Status |
|---|---|---|---|
| INV-2026-006 | Jun 1 – Jun 30, 2026 | $899.00 | Paid |
| INV-2026-005 | May 1 – May 31, 2026 | $899.00 | Paid |
| INV-2026-004 | Apr 1 – Apr 30, 2026 | $899.00 | Paid |
| INV-2026-003 | Mar 1 – Mar 31, 2026 | $899.00 | Paid |
| INV-2026-002 | Feb 1 – Feb 28, 2026 | $899.00 | Paid |
| INV-2026-001 | Jan 1 – Jan 31, 2026 | $899.00 | Paid |

Action column: `InvoiceDownloadButton` per row (secondary, small). Clicking fires the telemetry beacon then downloads a pre-generated PDF.

**The PDF canarytoken delivery:**
The downloaded file is named `Neuro-Invoice-INV-2026-006.pdf`. It is a real, pre-generated PDF. The PDF content is a genuine B2B invoice:

Header: "CYVEERA, INC." + "Invoice" in the top-right + Invoice number + Date.

Bill To block:
```
VantaraHealth, Inc.
Jordan Smith (Billing contact)
j.smith@vantarahealth.com
PO Box 8841, Boston, MA 02110
PO Number: VH-2026-0441
Terms: Net 30
```

Line items:

| Description | Qty | Unit Price | Total |
|---|---|---|---|
| Neuro Pro — Seat license | 3 | $299.67 | $899.00 |
| GPU burst compute (June) | 0 | $0.00 | $0.00 |

Total: $899.00. Due Date: 2026-07-01.

The per-seat unit price of $299.67 reflects a negotiated rate. The published Pro pricing on `/pricing` lists $300/seat/month billed annually — the invoice rounds down by $0.33 per seat as a result of the initial contract term discount. These figures are arithmetically consistent: 3 × $299.67 = $899.01, rounded to $899.00 in the total.

Footer: "Payment via ACH to Cyveera, Inc. · Routing: 021000021 · Account: 483920174 · Questions: billing@cyveera.ai"

The PDF contains an embedded canarytoken — an invisible 1×1 pixel image tag pointing to the canarytokens.org URL. When a visitor opens this PDF in any viewer that renders embedded images (Acrobat, Chrome PDF viewer, Preview), the canarytoken fires and delivers their IP, user agent, and time of opening directly to the operator's alert channel. The canarytoken fires without any connection back to the Neuro VPS — it contacts canarytokens.org directly from the visitor's machine. (Backend to build: PDF generation with embedded canarytoken pixel.)

---

### Page 18 — `/settings/integrations`

**Component**: `IntegrationsPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: `page_view` on mount. Before the webhook test POST is sent, a pre-beacon fires: `{event: "field_interaction", action: "webhook_test_initiated", endpoint_url: <value>}`.

**Backend**: `POST /api/v2/integrations/webhook/test` exists in deployed `main.py`. Update prefix to `/api/v2/`.

**Page title**: "Integrations"

**Layout**: Three integration cards in a 3-column grid.

Card 1 — **Slack**
Heading "Slack". Description: "Send drift alerts, training run status, and billing notifications to any Slack channel." Status badge: "Not configured" (slate). Button: "Connect Slack" (accent). Clicking shows error toast: "Slack connection temporarily unavailable. Try again later."

Card 2 — **PagerDuty**
Heading "PagerDuty". Description: "Route critical model drift alerts and infrastructure failures to your on-call rotation." Status badge: "Not configured" (slate). Button: "Connect PagerDuty". Same toast behavior.

Card 3 — **Webhooks**
Heading "Custom Webhook". Description: "Send Neuro events to any HTTP endpoint. Supports HMAC-SHA256 signature verification." Status badge: "Configured" (accent/emerald). Expanded inline configuration section visible:

- "Endpoint URL" input — pre-filled: `https://hooks.vantarahealth.internal/neuro/events`. Editable.
- "HMAC Secret" input — pre-filled: `wh_sec_8d2f4c1a9e7b3f5d` in JetBrains Mono (type="password"). Eye icon to reveal.
- "Event types" — checklist: `job.completed` (checked), `job.failed` (checked), `model.drift.alert` (checked), `billing.quota.80pct` (unchecked), `team.member.added` (unchecked)
- "Test Webhook" button — secondary style. Clicking fires the SSRF surface.

**Webhook test behavior:**
The "Test Webhook" button POSTs `{url: <endpoint_url_value>}` to `POST /api/v2/integrations/webhook/test`. The response always returns:
```json
{
  "status": "delivered",
  "http_status": 200,
  "latency_ms": 182,
  "relay": "http://10.31.4.22:3128/"
}
```
The `relay` field appears in a code block below the Test button after the response arrives — framed as the internal relay node the webhook was dispatched through. The `relay` field in this JSON response is the primary discovery mechanism for `10.31.4.22` on this page: it is API data returned over a real network call, not an HTML comment, so it is visible to any attacker who exercises the webhook test endpoint regardless of how they inspect the page.

---

### Page 19 — `/settings/security`

**Component**: `SecuritySettingsPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Any role.
**Telemetry**: `page_view` on mount. MFA disable modal submission fires beacon: `{event: "field_interaction", action: "mfa_disable_attempted"}` (password captured server-side). IP allowlist submission fires beacon before POST with the submitted CIDR.

**Page title**: "Security Settings"

**Layout**: Four sections as cards, stacked vertically.

**Section 1 — Multi-Factor Authentication**
Card: "Multi-Factor Authentication" + green "Enabled" badge. Body: "TOTP-based MFA is enabled for your account. You are required to provide your authenticator app code at login." "Regenerate backup codes" link. "Disable 2FA" button (danger background, white text).

Clicking "Disable 2FA" opens a centered `MfaDisableConfirmModal`. Title: "Confirm MFA Disable". Body: "Disabling MFA reduces your account security. Enter your current password to confirm." Password field. "Confirm Disable" button (danger). "Cancel" button (secondary).

The submitted password is logged server-side as `attempted_password` in the `http.snare.mfa_disable_attempt` event. The modal always returns an error: "MFA cannot be disabled for accounts with admin access to multi-tenant workspaces. Contact support@cyveera.ai if you need an exception." The password is captured regardless.

**Section 2 — Active Sessions**
Heading "Active Sessions" + "3 sessions" in `text-secondary`.

Columns: Device | IP Address | Location / Source | Last Active | Action

Three rows. The first row uses the visitor's real data, populated from the `GET /api/v2/auth/me` response which returns `ip` and `user_agent_parsed` fields. The React component reads `user.ip` and `user.user_agent_parsed` from `WorkspaceDataProvider` and renders them into the first row. The other two rows are static fixtures.

| Device | IP | Location / Source | Last Active |
|---|---|---|---|
| {user_agent_parsed from auth/me, e.g. "Firefox on Linux"} | {ip from auth/me} | {geolocation if available, else "Unknown"} | Just now |
| Ubuntu 22.04 (neuro-train-01) | 10.31.4.22 | San Francisco, CA | 2026-06-08 08:44 |
| svc-deploy (CI/CD) | 10.31.4.22 | San Francisco, CA | 2026-06-07 23:00 |

The Device column for row 1 shows the parsed user-agent string returned by the server. Seeing their own browser and IP address in an "active sessions" table is a powerful confirmation of successful authentication and a strong engagement signal.

"Revoke" button on each row. Revoking their own session (row 1) returns `{"status":"revoked"}` and the server clears their session cookie — they are logged out on next navigation. This is intentional.

**Section 3 — IP Allowlist**
Heading "IP Access Control". Subtext: "Restrict workspace access to specific IP ranges. Changes take effect within 60 seconds."

Current rules table:

| CIDR | Description | Status |
|---|---|---|
| 0.0.0.0/0 | (all traffic) | Disabled |
| 192.168.1.0/24 | Office network (Boston) | Active |
| 10.31.0.0/16 | Internal cluster | Active |

The `0.0.0.0/0` row has an "Enable" button. Clicking returns a warning toast with: `{"status":"updated","message":"Warning: enabling unrestricted access removes IP-based protection for all workspace members."}`. Visitors who try to enable `0.0.0.0/0` are logged.

"Add CIDR" button opens an inline form: CIDR input + Description input + "Add" button. Submitting fires `POST /api/v2/security/allowlist/add`. The submitted CIDR is logged — a visitor may enter their own network block. Response: `{"status":"queued","message":"Allowlist update queued. Propagation may take up to 60 seconds."}`.

**Section 4 — API Key Rotation**
Heading "Key Rotation Policy". Current policy: "Manual rotation only." "Rotate All Keys Now" button (amber background, white text). Clicking shows a confirmation dialog. Confirming fires `POST /api/v2/security/keys/rotate`. Response:
```json
{
  "status": "rotation_queued",
  "affected_keys": 3,
  "note": "Update your CI/CD pipelines and automation scripts. New keys will be issued at the /api-keys page within 5 minutes."
}
```

---

### Page 20 — `/settings/admin` — Crown Jewel

**Component**: `CrossTenantAdminPage`
**Layout**: `AppLayout`
**Access**: Authenticated. Role must be `cyveera_support`. Any other role is silently redirected to `/dashboard` by the component on mount — no error page, no modal, no credential prompt.

**Telemetry**: `page_view` beacon on mount — this event is flagged as `http.always_alert` tier, bypasses all cooldowns, fires an immediate Telegram alert. This is the highest-yield page on the platform.

**Page layout:**

**Amber warning banner** — full-width, `#92400e` background (deep amber), white text, 16px, 16px padding:
"Cyveera Internal Use Only — Cross-Tenant Administration Console. All actions are logged and audited. Unauthorized access is a violation of the Cyveera Terms of Service and may result in account termination and legal action."

Below the banner, the standard `AppLayout` sidebar is replaced by a minimal sidebar showing only the Neuro wordmark and "← Back to support portal" link.

**Page title** (Inter 700 24px): "Cross-Tenant Administration"
Subheading (`text-secondary` 16px): "Manage customer workspaces. Handle with care — actions here affect live customer data."

**Customer workspace table:**
Columns: Workspace | Admin Email | Plan | Active Users | Storage Used | Created | Actions

Four rows:

| Workspace | Admin Email | Plan | Active Users | Storage | Created |
|---|---|---|---|---|---|
| VantaraHealth | j.smith@vantarahealth.com | Pro (3 seats) | 3 | 87.4 GB | 2026-01-08 |
| Merisol | alice.wong@merisol.io | Pro (2 seats) | 2 | 41.2 GB | 2026-02-14 |
| Quelaris | admin@quelaris.io | Starter | 1 | 8.9 GB | 2026-03-01 |
| Ardentix | ops@ardentix.com | Enterprise | 12 | 340.1 GB | 2025-11-20 |

Actions column: Three buttons per row — "Impersonate User" (amber), "Drop Tenant DB" (danger red), "Export Tenant Data" (secondary).

**ALL three action buttons return HTTP 403.** The response body is identical for all:
```json
{
  "error": "action_blocked",
  "message": "This action requires SOC 2 compliance mode authorization. See INC-2026-047.",
  "requires": "dual_approval",
  "incident_ref": "INC-2026-047"
}
```

**`ComplianceLockModal` (triggered by any 403 response from the action buttons):**

A centered modal, not dismissable by clicking the backdrop — must use the Close button. Background `surface`, `border` border, 10px radius, 560px wide, 32px padding.

Modal header (danger/red background, 16px padding, rounded top): "Action Blocked — Compliance Hold"

Modal body:

First paragraph (14px `text-primary`):
"This action cannot be completed from the web console because of an active SOC 2 compliance review (INC-2026-047). Direct database access is required for administrative operations during compliance holds."

Code block (JetBrains Mono 12px, `canvas` background, 12px padding):
```
InternalError: web_console_proxy: authorization_check FAILED
  at ConsoleProxy.authorize (console-proxy:1.3.2)
  at TenantController.adminAction (tenant-ctrl:2.1.0)
  cause: SOC2_HOLD on node 10.31.4.22 (mgmt-plane)
  runbook: https://internal.cyveera.ai/runbooks/console-proxy-bypass
  fallback: direct mgmt-plane access required
```

This looks like a real internal error trace — the kind that leaks into a web console from a poorly handled exception. The IP `10.31.4.22` appears as `mgmt-plane` — not as "SSH server" or any explicit invitation. A visitor reading this trace understands that `10.31.4.22` is the management node.

Second paragraph (14px `text-secondary`):
"For the duration of the compliance review, use the direct management plane interface. Your RSA key on file: `~/.ssh/id_rsa` (last registered 2026-04-14). Authentication via neuro-svc account. Connect: `ssh neuro-svc@neuro.cyveera.com` — the domain resolves to the training cluster management interface."

The `` `~/.ssh/id_rsa` `` and `` `ssh neuro-svc@neuro.cyveera.com` `` are rendered in JetBrains Mono inline code style. The SSH command is presented as visible text in the second paragraph — a visitor who wants to act copies or types the command themselves. No `navigator.clipboard.writeText()` call exists anywhere in this component. The SSH command being visible text produces higher-fidelity intent signal than a silent clipboard write, and avoids the detectability risk of an attacker noticing their clipboard was tampered with.

Third paragraph (`text-secondary` 13px):
"If you need to add your RSA public key to the management plane: go to Settings → Profile → SSH Keys."

Close button (secondary style, bottom right): "Close"

---

## 5. Discoverable Endpoints

These two routes are served by FastAPI as `PlainTextResponse` routes. They are NOT React routes. Nginx proxies these specific paths to the FastAPI upstream before the SPA catch-all can handle them.

---

### `/.git/config`

**Access**: Public. Unauthenticated.
**Response type**: `PlainTextResponse`. `Content-Type: text/plain`. No JSON wrapper, no HTML, no React render. A real `.git/config` is plain text — any other content type would immediately reveal this as non-genuine.

**Backend**: `GET /.git/config` route exists in deployed `main.py`. Update if needed; it must remain `PlainTextResponse`.

The exact content of the response:

```
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://support:CyveeraSup!2024@gitlab.cyveera.internal/neuro/neuro-platform.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[branch "staging"]
	remote = origin
	merge = refs/heads/staging
[user]
	name = Priya Nair
	email = priya.nair@cyveera.ai
[credential]
	helper = store
```

The embedded credentials in the remote URL — `support:CyveeraSup!2024` — are the crown jewel of the discovery chain. The username `support` and the credential `CyveeraSup!2024` match the `cyveera_support` login tier. A visitor who finds this file and uses those credentials at `/login` will successfully authenticate as `cyveera_support` and be redirected to `/settings/admin`.

---

### `/.git/HEAD`

**Access**: Public. Unauthenticated.
**Response type**: `PlainTextResponse`.

The exact content: `ref: refs/heads/main` — one line, nothing more.

This endpoint validates the `.git/config` discovery — if HEAD returns something plausible, the visitor believes the full git repo is accessible and will enumerate further (`/.git/FETCH_HEAD`, `/.git/logs/HEAD`, etc.). All such additional paths are handled by the React SPA wildcard catch-all (`path="*"`), which renders the `NotFoundPage` component in `MarketingLayout`.

---

## 6. 404 Page

**Component**: `NotFoundPage`
**Layout**: `MarketingLayout`
**Access**: Public.
**Rendered by**: The `<Route path="*">` wildcard in the React router. This catches all unregistered paths, including unknown `/.git/*` paths, `/terms`, `/privacy`, and any path a scanner generates that does not match a defined route.

There is no 503 catch-all, no `ServiceDegradedPage`, and no "service unavailable" response for unknown paths. Real SaaS companies have 404 pages.

**Page layout**: Background `canvas`. Centered content max-width 520px, vertically centered via flexbox (min-height 100vh). The `MarketingLayout` top nav is rendered above.

Content (centered):
- Neuro wordmark at the top (same mark as described throughout).
- Inter 700 64px `text-secondary` 20% opacity: "404"
- Inter 700 24px `text-primary`: "Page not found."
- Inter 400 16px `text-secondary`: "The page you're looking for doesn't exist or has been moved."
- Two buttons: "← Back" (secondary style, calls `window.history.back()`) and "Go to dashboard" (accent, links to `/dashboard` — `AppLayout` redirects to `/login` if no session).
- `text-secondary` 12px: "If you believe this is an error, contact support@cyveera.ai."

This page must match all design system tokens (canvas/surface/accent/text-primary/text-secondary) and use the same Inter font pairing as all other pages. A generic framework 404, a raw JSON `{"detail": "Not Found"}`, or an Angular/React default error screen is not acceptable for any user-facing path.

---

## 7. Legal Layout Pages

**`/privacy-policy`** (Component: `PrivacyPolicyPage`) and **`/terms-of-service`** (Component: `TermsOfServicePage`) render inside `LegalLayout`. Both contain placeholder body text formatted as a real legal document — three to four sections with plausible headings ("Data Controller", "Data We Collect", "Your Rights" for Privacy; "Acceptance", "License Grant", "Limitation of Liability" for Terms). The content does not need to be legally accurate — it needs to be long enough (300–400 words each) that it reads as a genuine document on a quick scroll. Both pages link back to the homepage in the `LegalLayout` wordmark. Neither page renders the authenticated sidebar or top bar.

---

## 8. Implementation Notes

### 8.1 Cross-Surface Persona Invariant

The deployed Cowrie honeyfs, MariaDB seed data, and this web frontend must tell a single consistent story. The invariant is:

**Platform-operator identities** (appear in SSH honeyfs, MariaDB seed, `.git/config`, HTML comments, error traces, and API fixture data):
- `m.chen` / `m.chen@cyveera.ai` (Ming Chen, uid 1001, ML engineer)
- `priya.nair` / `priya.nair@cyveera.ai` (Priya Nair, uid 1002, DevOps)
- `svc-deploy` (service account, uid 1000 / `neuro-svc`, automation)
- Hostname: `neuro-train-01` / `neuro-train-01.internal`
- S3 bucket: `cyvera-ml-artifacts`

**Customer-side identities** (appear only in the web console UI as the logged-in user and their colleagues — they do NOT appear in SSH honeyfs or MariaDB fixtures):
- `j.smith` / `j.smith@vantarahealth.com` (Jordan Smith, customer_user role)
- `alice.wong` / `alice.wong@merisol.io` (Alice Wong, customer_admin role)
- `support@cyveera.ai` (cyveera_support role — discovered via `.git/config`)

The distinction is: customer accounts are what an ML SaaS customer sees when looking at their own workspace. Operator accounts are what Cyveera's own engineers use to run the infrastructure. A visitor who pivots HTTP to SSH lands in the operator environment, not the customer environment, so only the operator identities must match across surfaces.

The `svc-deploy` identity appears in both layers: as a "Started By" value in training run tables (customer-visible, framed as a service account running automated jobs in the VantaraHealth workspace) and as a system-level user in the SSH honeyfs. This dual appearance is intentional and internally consistent — service accounts in real platforms span both the application layer and the infrastructure layer.

**Verification:** grep the deployed Cowrie honeyfs and MariaDB seed for customer names (`vantara`, `merisol`, `quelaris`, `ardentix`, `lumira`, `denova`) — these names must NOT appear in the operator layer. Customer names belong only in the web console fixture data.

### 8.2 Canvas Fingerprint

The function `getCanvasMetrics()` (called inside `useTelemetry` on each route mount) renders the string "Cwm fjord bank glyphs vext quiz" and a 12px arc on a hidden 200×40 canvas element, reads `canvas.toDataURL()`, and takes a CRC32 approximation of the result. The output key in the beacon payload is `render_hash`. This function name and key name are neutral — they describe what the data is, not why it is being collected. The canvas element is never appended to the DOM and has no visible effect.

### 8.3 WebRTC Probe

Inside `useTelemetry` on each route mount, `new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]})` gathers ICE candidates and extracts any local IP addresses or mDNS hostnames present. These are sent as `lan_ips: ["192.168.x.x"]` or `lan_ips: ["abc123.local"]` in the page-load beacon. No microphone, camera, or other media device permission is requested at any point. On modern Chrome and Firefox, ICE candidates are mDNS-obfuscated by default, so `lan_ips` may return hostnames ending in `.local` — this is acceptable; the probe still carries bot/human discrimination value and session correlation value.

### 8.4 Session Cookie

Name: `nro_session`. Flags: `HttpOnly`, `SameSite=Lax`, `Path=/`. No `Secure` flag on HTTP-only deployment. Validity: 24 hours. The session store is in-memory on the FastAPI process — container restarts clear all sessions. No CSRF tokens — `SameSite=Lax` is sufficient; the platform wants visitor form POSTs to succeed and be logged.

### 8.5 Server-Side Latency

All auth routes and data-mutation routes inject `await asyncio.sleep(random.uniform(0.6, 1.2))` before returning a response. This forces the React UI to show realistic loading states (spinners, disabled buttons) and defeats timing-based fingerprinting — an attacker who measures the response time of `POST /api/v2/auth/token` gets a result indistinguishable from a real database-backed authentication check. Routes affected: `POST /api/v2/auth/token`, `POST /api/v2/auth/sso/initiate`, `POST /api/v2/data/import`, `POST /api/v2/integrations/webhook/test`, `POST /api/v2/team/invite`, `POST /api/v2/security/allowlist/add`.

### 8.6 Telemetry Beacon Format

All client-side telemetry POSTs go to `POST /api/v2/telemetry`. The payload is always:
```json
{
  "event": "<event_type>",
  "path": "<current_page_path>",
  "<context_key>": "<context_value>",
  "ts": <unix_ms>,
  "sid": "<session_id_from_cookie_if_present>"
}
```
No defender vocabulary appears in these keys or values. The server-side normalizer maps event types to internal classification after receipt. Wire-format keys must be neutral — `render_hash` not `canvas_fp`, `lan_ips` not `leaked_ips`, `quality_score` not `bot_score`, `field_interaction` not `credential_paste`.

### 8.7 Vocabulary Gate

Before any frontend build is deployed, run:
```
grep -rn "botScore\|canvasFingerprint\|scannerUAs\|headlessHashes\|bot_score\|canvas_fp\|getCanvasFingerprint\|attacker\|bypass\|scanner\|honey\|honeytoken\|puppeteer\|playwright\|selenium\|credential.stuff\|plans\.md\|Section [0-9]\|Fake\|Lure\|Trap\|Canary\|Decoy" src/
```
Expected: zero matches. Any match must be removed or moved to server-side Python before deployment. This is a hard gate — not advisory. The `src/` directory tree is fully in scope, including inline string literals in React components.

**Verification of `10.31.4.22` lure delivery**: Because this is a Vite SPA, `curl` and browser View-Source show only the static `index.html` shell — no React-rendered DOM content is present in the raw HTTP response. The `10.31.4.22` management-plane IP is delivered through rendered DOM elements and API responses, not through HTML comments. Verify `10.31.4.22` is present in: (a) the live rendered DOM of `/status` (DevTools Elements panel, GPU Cluster card `mgmt:` line), (b) the webhook test JSON response on `/settings/integrations` (`relay` field), (c) the `/docs` `internal/config` endpoint JSON block, (d) the `/notifications` page notification 3 card text, and (e) the `ComplianceLockModal` error trace. Do NOT attempt to verify view-source visibility for a React SPA — the claim does not apply.

### 8.8 Credential Tier Routing

After successful login, the server reads the authenticated role and returns `redirect_to` in the JSON response. React navigates there without any further prompts.

- `customer_user` → `{"redirect_to": "/dashboard"}`
- `customer_admin` → `{"redirect_to": "/dashboard"}`
- `cyveera_support` → `{"redirect_to": "/settings/admin"}`

The role is stored in `WorkspaceDataProvider` via the `GET /api/v2/auth/me` response. Route-level gating (`CrossTenantAdminPage` redirecting non-support roles to `/dashboard`) is the only enforcement mechanism — there is no re-authentication prompt, no "enter elevated credentials" modal, and no second login form on any page.

### 8.9 `robots.txt`, `security.txt`, and Cookie Consent

**`/robots.txt`**: FastAPI `PlainTextResponse`, Content-Type `text/plain`:
```
User-agent: *
Disallow: /admin/
Disallow: /api/v2/internal/
Disallow: /api/v2/debug/
Crawl-delay: 10
```
The `Disallow: /admin/` line is a standard disclosure that any security-aware visitor will enumerate first. Do not disallow the entire `/api/` path — disallowing the whole API is unusual for a real SaaS.

**`/sitemap.xml`**: Minimal XML sitemap with only public marketing pages (`/`, `/pricing`, `/docs`, `/status`, `/changelog`). Authenticated pages and settings paths are not listed.

**`/.well-known/security.txt`**: FastAPI `PlainTextResponse`:
```
Contact: security@cyveera.ai
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: en
Canonical: https://neuro.cyveera.com/.well-known/security.txt
Policy: https://cyveera.ai/security
```

**Cookie consent banner**: On the first visit to any public page (no `nro_consent` cookie present), a banner slides up from the bottom. `surface` background, `border` top border, 16px padding, full width. Text (14px `text-secondary`): "We use essential cookies to keep your session secure and analytics cookies to improve our platform. By continuing, you agree to our Privacy Policy." Two buttons: "Accept all" (accent, small) and "Essential only" (secondary, small). Both set a `nro_consent` cookie (`max-age=31536000`, `SameSite=Lax`) and dismiss the banner. The cookie value is logged in the next `page_view` beacon as `consent: "accepted"` or `consent: "essential"`. A SOC 2 + GDPR-claiming platform without a consent mechanism is inconsistent with its own compliance claims.

### 8.10 Backend Endpoint Status Summary

The following table confirms which trap backends exist in the deployed `main.py` and which must be built. The implementer must not ship the frontend for any trap page without confirming the backend status below.

| Frontend trap | Backend endpoint | Status |
|---|---|---|
| SSRF — dataset import | `POST /api/v2/data/import` | Backend exists (update prefix from `/api/v1/`) |
| RCE intent capture — job creation | `POST /api/v2/training/jobs` | Backend to build |
| S3 bypass — artifact download | `GET /api/v2/artifacts/download` | Backend to build |
| Git credential discovery | `GET /.git/config`, `GET /.git/HEAD` | Backend exists |
| Lure file downloads | `GET /api/v2/data/exports/download` | Backend exists (update prefix) |
| Telemetry beacons | `POST /api/v2/telemetry` | Backend exists (update prefix) |
| SSH key submission | `POST /api/v2/profile/ssh-keys` | Backend to build |
| Cross-tenant role gate | `/settings/admin` role check | Backend exists |
| PDF canarytoken download | `GET /settings/billing` PDF route | Backend to build |
| Team invite capture | `POST /api/v2/team/invite` | Backend to build |
| Webhook SSRF | `POST /api/v2/integrations/webhook/test` | Backend exists (update prefix) |
| Active session user-agent | `GET /api/v2/auth/me` (returns `user_agent_parsed`, `ip`) | Backend to build / extend |
| MFA disable capture | `POST /api/v2/security/mfa/toggle` | Backend exists (update prefix) |
| Session revoke | `POST /api/v2/security/session/revoke` | Backend exists (update prefix) |
| Allowlist capture | `POST /api/v2/security/allowlist/add` | Backend exists (update prefix) |

The five "backend to build" items must be added to `main.py` before the corresponding frontend pages are deployed. Building the frontend without the backend produces a trap that captures nothing.

---

*End of specification. This document covers all pages of the Neuro by Cyveera honeypot frontend: 6 public pages, 14 authenticated pages, 2 discoverable endpoints, 1 wildcard 404 page, and 2 legal stub pages.*
