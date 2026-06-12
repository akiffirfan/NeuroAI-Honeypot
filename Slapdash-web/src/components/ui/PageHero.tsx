import type { ReactNode } from "react";

/**
 * Reusable hero treatment for public marketing pages.
 * Grid + accent glow + gradient eyebrow + gradient headline.
 */
export function PageHero({
  eyebrow,
  title,
  description,
  children,
  align = "center",
}: {
  eyebrow?: string;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  align?: "center" | "left";
}) {
  return (
    <section className="relative overflow-hidden border-b border-[color:var(--border)]">
      <div aria-hidden className="absolute inset-0 nro-grid-bg nro-radial-fade opacity-60" />
      <div aria-hidden className="absolute inset-0 nro-accent-glow" />
      <div
        className={`relative mx-auto max-w-[1100px] px-6 ${align === "center" ? "text-center" : ""}`}
        style={{ paddingTop: 96, paddingBottom: 64 }}
      >
        {eyebrow && (
          <div
            className={`inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[color:var(--border)] bg-[color:var(--surface)]/60 backdrop-blur text-[12px] text-[color:var(--text-secondary)] ${align === "center" ? "" : ""}`}
          >
            <span
              className="inline-block w-1.5 h-1.5 rounded-full nro-pulse-dot"
              style={{ background: "var(--accent)" }}
            />
            {eyebrow}
          </div>
        )}
        <h1
          className="font-bold mt-5 nro-text-gradient"
          style={{ fontSize: "clamp(36px, 5.2vw, 60px)", letterSpacing: "-0.025em", lineHeight: 1.05 }}
        >
          {title}
        </h1>
        {description && (
          <p
            className={`mt-5 text-[color:var(--text-secondary)] ${align === "center" ? "mx-auto" : ""}`}
            style={{ fontSize: 19, maxWidth: 720, lineHeight: 1.55 }}
          >
            {description}
          </p>
        )}
        {children && <div className="mt-8">{children}</div>}
      </div>
    </section>
  );
}
