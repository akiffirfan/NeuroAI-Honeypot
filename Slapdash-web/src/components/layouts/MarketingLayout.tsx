import { Link } from "@tanstack/react-router";
import { Logo } from "../Logo";
import { useEffect, useState, type ReactNode } from "react";

export function MarketingLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen flex flex-col bg-[color:var(--canvas)]">
      <TopNav />
      <main className="flex-1">{children}</main>
      <Footer />
      <CookieBanner />
    </div>
  );
}

function TopNav() {
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={`sticky top-0 z-40 w-full transition-all ${
        scrolled
          ? "border-b border-[color:var(--border)] bg-[color:var(--canvas)]/80 backdrop-blur-xl"
          : "border-b border-transparent bg-transparent"
      }`}
      style={{ height: 64 }}
    >
      <div className="mx-auto h-full px-6 flex items-center justify-between max-w-[1280px]">
        <Logo />
        <nav className="hidden md:flex items-center gap-1 text-sm">
          {[
            ["Product", "/"],
            ["Pricing", "/pricing"],
            ["Docs", "/docs"],
            ["Changelog", "/changelog"],
            ["Status", "/status"],
          ].map(([label, to]) => (
            <Link
              key={to}
              to={to}
              className="px-3 py-1.5 rounded-md text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)] hover:bg-[color:var(--elevated)]/60 transition-colors"
              activeProps={{ className: "text-white" }}
            >
              {label}
            </Link>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          <Link to="/login" className="nro-btn-secondary text-sm">
            Log in
          </Link>
          <a href="#contact" className="nro-btn-primary text-sm">
            Get a demo
          </a>
        </div>
      </div>
      <div
        aria-hidden
        className="absolute inset-x-0 -bottom-px h-px"
        style={{
          background:
            "linear-gradient(90deg, transparent, color-mix(in oklab, var(--accent) 50%, transparent), transparent)",
          opacity: scrolled ? 1 : 0,
          transition: "opacity .25s ease",
        }}
      />
    </header>
  );
}

function Footer() {
  return (
    <footer
      id="contact"
      className="relative border-t border-[color:var(--border)] bg-[color:var(--canvas)] overflow-hidden"
      style={{ padding: "72px 0 56px" }}
    >
      <div
        aria-hidden
        className="absolute inset-x-0 top-0 h-px"
        style={{
          background:
            "linear-gradient(90deg, transparent, color-mix(in oklab, var(--accent) 60%, transparent), transparent)",
        }}
      />
      <div aria-hidden className="absolute inset-0 nro-grid-bg opacity-[0.08] pointer-events-none" />
      <div className="relative mx-auto max-w-[1280px] px-6">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-10">
          <div className="col-span-2">
            <Logo />
            <p className="mt-4 text-[color:var(--text-secondary)] text-[13px] max-w-[320px] leading-relaxed">
              Production-grade observability for the LLMs your business already
              depends on. Built by the Cyveera AI Infrastructure Team.
            </p>
            <div className="mt-5 flex items-center gap-2">
              <span className="nro-badge nro-badge--accent">
                <span className="w-1.5 h-1.5 rounded-full nro-pulse-dot" style={{ background: "var(--accent)" }} />
                All systems operational
              </span>
              <span className="nro-badge nro-badge--slate">SOC 2 Type II</span>
            </div>
            <p className="mt-5 text-[color:var(--text-secondary)] text-[12px]">
              © 2026 Cyveera, Inc. All rights reserved.
            </p>
          </div>
          <FooterCol
            title="Product"
            links={[
              ["Dashboard", "/dashboard"],
              ["Pricing", "/pricing"],
              ["Changelog", "/changelog"],
              ["Status", "/status"],
              ["API Docs", "/docs"],
            ]}
          />
          <FooterCol
            title="Company"
            links={[
              ["About", "#"],
              ["Team", "#"],
              ["Security", "#"],
              ["Privacy Policy", "/privacy-policy"],
              ["Terms of Service", "/terms-of-service"],
            ]}
          />
          <FooterCol
            title="Connect"
            links={[
              ["GitHub", "https://github.com/cyveera"],
              ["Twitter/X", "https://x.com/cyveera_ai"],
              ["LinkedIn", "#"],
              ["hello@cyveera.ai", "mailto:hello@cyveera.ai"],
            ]}
          />
        </div>
      </div>
    </footer>
  );
}

function FooterCol({
  title,
  links,
}: {
  title: string;
  links: [string, string][];
}) {
  return (
    <div>
      <div className="nro-section-label mb-4">{title}</div>
      <ul className="space-y-2 text-[14px]">
        {links.map(([label, href]) => (
          <li key={label + href}>
            {href.startsWith("/") ? (
              <Link
                to={href}
                className="text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)]"
              >
                {label}
              </Link>
            ) : (
              <a
                href={href}
                className="text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)]"
              >
                {label}
              </a>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function CookieBanner() {
  const [dismissed, setDismissed] = useState(true);
  useEffect(() => {
    if (typeof document === "undefined") return;
    if (!document.cookie.includes("nro_consent=")) setDismissed(false);
  }, []);
  if (dismissed) return null;
  const accept = (kind: "accepted" | "essential") => {
    document.cookie = `nro_consent=${kind}; max-age=31536000; path=/; SameSite=Lax`;
    setDismissed(true);
  };
  return (
    <div
      className="fixed inset-x-0 bottom-0 z-50 border-t border-[color:var(--border)] bg-[color:var(--surface)]/90 backdrop-blur-xl"
      style={{ padding: 16 }}
    >
      <div className="mx-auto max-w-[1280px] flex flex-wrap items-center justify-between gap-4">
        <p className="text-[14px] text-[color:var(--text-secondary)] max-w-[760px]">
          We use essential cookies to keep your session secure and analytics
          cookies to improve our platform. By continuing, you agree to our{" "}
          <Link to="/privacy-policy" className="text-[color:var(--accent)]">
            Privacy Policy
          </Link>
          .
        </p>
        <div className="flex gap-2">
          <button
            onClick={() => accept("essential")}
            className="nro-btn-secondary text-sm"
          >
            Essential only
          </button>
          <button
            onClick={() => accept("accepted")}
            className="nro-btn-primary text-sm"
          >
            Accept all
          </button>
        </div>
      </div>
    </div>
  );
}
