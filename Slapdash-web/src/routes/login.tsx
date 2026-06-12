import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { MarketingLayout } from "@/components/layouts/MarketingLayout";
import { Logo } from "@/components/Logo";
import { Eye, EyeOff } from "lucide-react";
import { useState } from "react";
import { login, initiateSso } from "@/lib/api/auth";
import { isApiError } from "@/lib/api/client";
import { useAuth } from "@/lib/auth.context";

export const Route = createFileRoute("/login")({
  component: LoginPage,
  head: () => ({
    meta: [
      { title: "Sign in — Neuro by Cyveera" },
      { name: "description", content: "Sign in to your Neuro workspace." },
    ],
  }),
});

function LoginPage() {
  const navigate = useNavigate();
  const { refetch } = useAuth();
  const [show, setShow] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ssoLoading, setSsoLoading] = useState(false);
  const [ssoError, setSsoError] = useState(false);
  const [ghLoading, setGhLoading] = useState(false);
  const [ghError, setGhError] = useState(false);

  const onSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const form = new FormData(e.currentTarget);
    const email = form.get("email") as string;
    const password = form.get("password") as string;
    try {
      const result = await login(email, password);
      // Await refetch so AuthProvider has the correct user+role before SPA navigation.
      // This avoids the hard-reload race where the cookie arrives after getMe() fires.
      await refetch();
      navigate({ to: (result.redirect_to || "/dashboard") as "/" });
    } catch (err) {
      setLoading(false);
      if (isApiError(err) && err.status === 429) {
        setError("Too many login attempts. Please wait a moment and try again.");
      } else {
        setError("Email or password is incorrect.");
      }
    }
  };

  const onSso = async () => {
    setSsoLoading(true);
    setSsoError(false);
    try {
      await initiateSso();
    } catch {
      // SSO always returns 503 — fall through to show error state
    }
    setSsoLoading(false);
    setSsoError(true);
  };

  const onGithub = () => {
    setGhLoading(true);
    setGhError(false);
    setTimeout(() => {
      setGhLoading(false);
      setGhError(true);
    }, 1800);
  };

  return (
    <MarketingLayout>
      <div className="relative min-h-[88vh] flex items-center justify-center px-4 overflow-hidden">
        <div aria-hidden className="absolute inset-0 nro-grid-bg nro-radial-fade opacity-40" />
        <div
          aria-hidden
          className="absolute pointer-events-none"
          style={{
            top: "8%",
            right: "18%",
            width: 560,
            height: 560,
            borderRadius: "50%",
            background: "var(--accent)",
            filter: "blur(140px)",
            opacity: 0.09,
          }}
        />
        <div
          aria-hidden
          className="absolute pointer-events-none"
          style={{
            bottom: "10%",
            left: "14%",
            width: 380,
            height: 380,
            borderRadius: "50%",
            background: "var(--info)",
            filter: "blur(140px)",
            opacity: 0.06,
          }}
        />
        <div
          className="nro-card relative z-10 bg-[color:var(--surface)]/85 backdrop-blur-xl"
          style={{ width: 420, padding: 44 }}
        >
          <Logo />
          <div className="mt-7 inline-flex items-center gap-2 px-2.5 py-1 rounded-full border border-[color:var(--border)] bg-[color:var(--elevated)]/60 text-[11px] text-[color:var(--text-secondary)]">
            <span className="w-1.5 h-1.5 rounded-full nro-pulse-dot" style={{ background: "var(--accent)" }} />
            Secure session · TLS 1.3
          </div>
          <h1 className="font-bold mt-3 nro-text-gradient" style={{ fontSize: 26, letterSpacing: "-0.02em" }}>
            Welcome back.
          </h1>
          <p className="mt-1 text-[14px] text-[color:var(--text-secondary)]">
            Sign in to your Neuro workspace to keep going.
          </p>

          <form onSubmit={onSubmit} className="mt-8 space-y-4">
            <div>
              <label className="nro-label">Work email</label>
              <input
                className="nro-input mt-2"
                type="email"
                name="email"
                placeholder="you@company.com"
                required
              />
            </div>
            <div>
              <label className="nro-label">Password</label>
              <div className="relative mt-2">
                <input
                  className="nro-input pr-10"
                  type={show ? "text" : "password"}
                  name="password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShow((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[color:var(--text-secondary)] hover:text-white"
                >
                  {show ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              <div className="text-right mt-2">
                <a
                  href="/auth/forgot-password"
                  className="text-[14px] text-[color:var(--text-secondary)] hover:text-white"
                >
                  Forgot password?
                </a>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="nro-btn-primary w-full mt-2"
            >
              {loading ? "···" : "Sign in"}
            </button>

            {error && (
              <p className="text-sm text-[color:var(--danger)] mt-2">{error}</p>
            )}
          </form>

          <div className="my-6 flex items-center gap-3">
            <div className="flex-1 h-px bg-[color:var(--border)]" />
            <span className="text-[12px] text-[color:var(--text-secondary)]">or</span>
            <div className="flex-1 h-px bg-[color:var(--border)]" />
          </div>

          <div className="space-y-2">
            <button
              onClick={onSso}
              disabled={ssoLoading}
              className="w-full flex items-center justify-center gap-2 rounded-full text-[13px] font-medium transition-colors hover:brightness-110 whitespace-nowrap px-4"
              style={{
                height: 44,
                background: ssoError
                  ? "color-mix(in oklab, var(--danger) 12%, transparent)"
                  : "var(--elevated)",
                border: `1px solid ${ssoError ? "color-mix(in oklab, var(--danger) 40%, transparent)" : "var(--border)"}`,
                color: ssoError ? "var(--danger)" : "var(--text-primary)",
              }}
            >
              <GoogleG />
              <span className="truncate">
                {ssoLoading
                  ? "Connecting…"
                  : ssoError
                  ? "Google temporarily unavailable — try again later."
                  : "Continue with Google Workspace"}
              </span>
            </button>

            <button
              type="button"
              onClick={onGithub}
              disabled={ghLoading}
              className="w-full flex items-center justify-center gap-2 rounded-full text-[13px] font-medium transition-colors hover:brightness-110 whitespace-nowrap px-4"
              style={{
                height: 44,
                background: ghError
                  ? "color-mix(in oklab, var(--danger) 12%, transparent)"
                  : "var(--elevated)",
                border: `1px solid ${ghError ? "color-mix(in oklab, var(--danger) 40%, transparent)" : "var(--border)"}`,
                color: ghError ? "var(--danger)" : "var(--text-primary)",
              }}
            >
              <GithubMark />
              <span className="truncate">
                {ghLoading
                  ? "Connecting…"
                  : ghError
                  ? "GitHub temporarily unavailable — try again later."
                  : "Continue with GitHub"}
              </span>
            </button>
          </div>
          {(ssoError || ghError) && (
            <div className="text-center mt-2">
              <button
                onClick={() => {
                  setSsoError(false);
                  setGhError(false);
                }}
                className="text-[12px] text-[color:var(--text-secondary)] hover:text-white"
              >
                Use password instead
              </button>
            </div>
          )}

          <p className="text-center mt-6 text-[12px] text-[color:var(--text-secondary)]">
            By signing in you agree to Cyveera's{" "}
            <Link to="/terms-of-service" className="text-[color:var(--accent)]">
              Terms of Service
            </Link>{" "}
            and{" "}
            <Link to="/privacy-policy" className="text-[color:var(--accent)]">
              Privacy Policy
            </Link>
            .
          </p>
        </div>
      </div>
    </MarketingLayout>
  );
}

function GoogleG() {
  return (
    <svg width="16" height="16" viewBox="0 0 48 48">
      <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.6 29.3 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.1 7.9 3l5.7-5.7C33.9 6.1 29.2 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z" />
      <path fill="#FF3D00" d="m6.3 14.7 6.6 4.8C14.6 16 19 13 24 13c3.1 0 5.8 1.1 7.9 3l5.7-5.7C33.9 6.1 29.2 4 24 4 16.3 4 9.6 8.3 6.3 14.7z" />
      <path fill="#4CAF50" d="M24 44c5.1 0 9.8-2 13.3-5.2l-6.1-5.2c-2 1.5-4.5 2.4-7.2 2.4-5.2 0-9.6-3.3-11.3-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z" />
      <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.3-2.3 4.2-4.2 5.6l6.1 5.2C40 35.3 44 30.1 44 24c0-1.3-.1-2.4-.4-3.5z" />
    </svg>
  );
}

function GithubMark() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <path d="M12 .5C5.73.5.5 5.73.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56v-2c-3.2.7-3.87-1.37-3.87-1.37-.52-1.33-1.27-1.69-1.27-1.69-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.68 1.24 3.33.95.1-.74.4-1.24.72-1.53-2.55-.29-5.24-1.28-5.24-5.7 0-1.26.45-2.29 1.18-3.1-.12-.29-.51-1.46.11-3.04 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.79 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.58.24 2.75.12 3.04.74.81 1.18 1.84 1.18 3.1 0 4.43-2.69 5.41-5.25 5.69.41.36.78 1.05.78 2.12v3.14c0 .31.21.68.8.56C20.21 21.38 23.5 17.07 23.5 12 23.5 5.73 18.27.5 12 .5z" />
    </svg>
  );
}
