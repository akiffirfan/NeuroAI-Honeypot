import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { useAuth } from "@/lib/auth.context";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toggleMfa, revokeSession, addAllowlistEntry, toggleAllowlist, rotateKeys } from "@/lib/api/mutations";
import { fetchAllowlist } from "@/lib/api/data";
import { isApiError } from "@/lib/api/client";
import { useState } from "react";

export const Route = createFileRoute("/settings/security")({
  component: SecuritySettingsPage,
  head: () => ({ meta: [{ title: "Security Settings — Neuro" }] }),
});

function SecuritySettingsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "cyveera_support";

  return (
    <AppLayout title="Security Settings">
      <AppPageHeader
        title="Security."
        description="Manage MFA, active sessions, IP allowlists, and credential rotation. Every action below is audit-logged."
      />
      <div className="space-y-6">
        {isAdmin ? <AdminMfaCard /> : <MfaCard />}
        <SessionsCard isAdmin={isAdmin} />
        {isAdmin ? <AdminAllowlistCard /> : <AllowlistCard />}
        <RotationCard />
      </div>
    </AppLayout>
  );
}

function MfaCard() {
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const [backupError, setBackupError] = useState(false);
  return (
    <section className="nro-card p-6">
      <div className="flex items-center gap-3">
        <h2 className="font-bold text-[18px]">Multi-Factor Authentication</h2>
        <span className="nro-badge nro-badge--slate">Not Enabled</span>
      </div>
      <p className="mt-3 text-[14px] text-[color:var(--text-secondary)]">
        Your account is not protected by two-factor authentication. Enable MFA
        to require an authenticator app code at every login.
      </p>
      <div className="flex flex-wrap items-center gap-3 mt-4">
        <button
          onClick={() => {
            setBackupError(true);
            setTimeout(() => setBackupError(false), 3500);
          }}
          className="text-[14px] text-[color:var(--accent)] hover:underline bg-transparent border-0 p-0 cursor-pointer"
        >
          Regenerate backup codes
        </button>
        <button
          onClick={() => setOpen(true)}
          className="nro-btn-primary"
        >
          Enable 2FA
        </button>
      </div>
      {backupError && (
        <div
          className="mt-3 p-3 rounded-md text-[13px]"
          style={{
            background: "color-mix(in oklab, var(--danger) 12%, transparent)",
            color: "var(--danger)",
            border: "1px solid color-mix(in oklab, var(--danger) 40%, transparent)",
          }}
        >
          Failed to regenerate backup codes. The backup code service is temporarily unavailable. Please try again later or contact support@cyveera.ai.
        </div>
      )}
      {open && (
        <MfaEnableModal
          onClose={() => setOpen(false)}
          csrf={user?.csrf_token}
        />
      )}
    </section>
  );
}

function MfaEnableModal({
  onClose,
  csrf,
}: {
  onClose: () => void;
  csrf?: string;
}) {
  const mutation = useMutation({ mutationFn: toggleMfa });
  const [errMsg, setErrMsg] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const password = form.get("password") as string;
    setErrMsg(null);
    try {
      await mutation.mutateAsync({ password, _csrf: csrf });
    } catch (err) {
      if (isApiError(err) && err.status === 403) {
        setErrMsg(
          "Unable to enable MFA at this time. Your account may require administrator approval. Contact support@cyveera.ai for assistance.",
        );
      } else if (isApiError(err) && err.status === 401) {
        setErrMsg("Incorrect password. Please try again.");
      } else {
        setErrMsg("An error occurred. Please try again.");
      }
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="nro-card bg-[color:var(--surface)]"
        style={{ width: 480, padding: 32 }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="font-bold text-[20px]">Enable Two-Factor Authentication</h3>
        <p className="mt-2 text-[14px] text-[color:var(--text-secondary)]">
          Enabling MFA adds an extra layer of security to your account. You will
          be required to enter a code from your authenticator app at every login.
          Enter your current password to confirm.
        </p>
        <form onSubmit={handleSubmit} className="mt-4 space-y-4">
          <div>
            <label className="nro-label">Current password</label>
            <input
              name="password"
              className="nro-input mt-2"
              type="password"
              required
            />
          </div>
          {errMsg && (
            <div
              className="text-[13px] p-3 rounded-md"
              style={{
                background: "color-mix(in oklab, var(--danger) 12%, transparent)",
                color: "var(--danger)",
                border: "1px solid color-mix(in oklab, var(--danger) 40%, transparent)",
              }}
            >
              {errMsg}
            </div>
          )}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className="nro-btn-secondary">
              Cancel
            </button>
            <button
              type="submit"
              className="nro-btn-primary"
              disabled={mutation.isPending}
            >
              {mutation.isPending ? "Verifying…" : "Confirm Enable"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

type RevokeTarget = { label: string; sessionId: string; isSelf: boolean };

function SessionsCard({ isAdmin = false }: { isAdmin?: boolean }) {
  const { user } = useAuth();
  const sessionMutation = useMutation({ mutationFn: revokeSession });
  const [target, setTarget] = useState<RevokeTarget | null>(null);
  const [accessDenied, setAccessDenied] = useState(false);

  const displayIp = user?.ip ?? "…";
  const displayUa = user?.user_agent_parsed ?? "…";

  const handleConfirm = async () => {
    if (!target) return;
    if (target.isSelf) {
      try {
        await sessionMutation.mutateAsync({ session_id: "current", _csrf: user?.csrf_token });
      } catch { /* session cleared regardless */ }
      window.location.href = "/login";
    } else {
      setTarget(null);
      setAccessDenied(true);
    }
  };

  return (
    <section className="nro-card p-6">
      <div className="flex items-center justify-between">
        <h2 className="font-bold text-[18px]">Active Sessions</h2>
        <span className="text-[14px] text-[color:var(--text-secondary)]">3 sessions</span>
      </div>

      {accessDenied && (
        <div
          className="mt-4 p-3 rounded-md text-[13px]"
          style={{
            background: "color-mix(in oklab, var(--danger) 12%, transparent)",
            color: "var(--danger)",
            border: "1px solid color-mix(in oklab, var(--danger) 40%, transparent)",
          }}
        >
          Access denied — you do not have permission to revoke service sessions. Contact your workspace administrator.
        </div>
      )}

      <div className="nro-card overflow-hidden mt-4" style={{ background: "var(--canvas)" }}>
        <table className="w-full">
          <thead>
            <tr>
              {["Device", "IP Address", "Location / Source", "Last Active", "Action"].map((h) => (
                <th key={h} className="nro-th">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            <tr className="nro-row">
              <td className="nro-td">{displayUa} <span className="text-[11px] text-[color:var(--accent)] ml-1">● current</span></td>
              <td className="nro-td font-mono text-[13px]">{displayIp}</td>
              <td className="nro-td text-[color:var(--text-secondary)]">Unknown</td>
              <td className="nro-td">Just now</td>
              <td className="nro-td">
                <button
                  onClick={() => setTarget({ label: "your current session", sessionId: "current", isSelf: true })}
                  className="nro-btn-secondary !py-1 !px-3 text-[12px]"
                >
                  Revoke
                </button>
              </td>
            </tr>
            {isAdmin ? (
              <tr className="nro-row">
                <td className="nro-td">
                  Okta Telemetry Sync Agent
                  <span className="ml-2 text-[11px] px-1.5 py-0.5 rounded font-mono" style={{ background: "var(--elevated)", color: "var(--text-secondary)" }}>
                    service
                  </span>
                </td>
                <td className="nro-td font-mono text-[13px]">10.99.0.5</td>
                <td className="nro-td text-[color:var(--text-secondary)]">Cyveera HQ — SSO Fabric</td>
                <td className="nro-td text-[color:var(--text-secondary)]">Active (continuous)</td>
                <td className="nro-td">
                  <button
                    onClick={() => setTarget({ label: "Okta Telemetry Sync Agent", sessionId: "okta-sync-agent", isSelf: false })}
                    className="nro-btn-secondary !py-1 !px-3 text-[12px]"
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ) : (
              <>
                <tr className="nro-row">
                  <td className="nro-td">Ubuntu 22.04 (neuro-train-01)</td>
                  <td className="nro-td font-mono text-[13px]">10.31.4.22</td>
                  <td className="nro-td text-[color:var(--text-secondary)]">San Francisco, CA</td>
                  <td className="nro-td text-[color:var(--text-secondary)]">2026-06-08 08:44</td>
                  <td className="nro-td">
                    <button
                      onClick={() => setTarget({ label: "Ubuntu 22.04 (neuro-train-01)", sessionId: "ubuntu-session", isSelf: false })}
                      className="nro-btn-secondary !py-1 !px-3 text-[12px]"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
                <tr className="nro-row">
                  <td className="nro-td">svc-deploy (CI/CD)</td>
                  <td className="nro-td font-mono text-[13px]">10.31.4.22</td>
                  <td className="nro-td text-[color:var(--text-secondary)]">San Francisco, CA</td>
                  <td className="nro-td text-[color:var(--text-secondary)]">2026-06-07 23:00</td>
                  <td className="nro-td">
                    <button
                      onClick={() => setTarget({ label: "svc-deploy (CI/CD)", sessionId: "svc-deploy-session", isSelf: false })}
                      className="nro-btn-secondary !py-1 !px-3 text-[12px]"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              </>
            )}
          </tbody>
        </table>
      </div>

      {target && (
        <div
          className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
          onClick={() => setTarget(null)}
        >
          <div
            className="nro-card bg-[color:var(--surface)]"
            style={{ width: 420, padding: 32 }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="font-bold text-[18px]">Revoke Session</h3>
            <p className="mt-2 text-[14px] text-[color:var(--text-secondary)]">
              Are you sure you want to revoke <strong className="text-white">{target.label}</strong>?
              {target.isSelf && " You will be signed out immediately."}
            </p>
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={() => setTarget(null)} className="nro-btn-secondary">
                Cancel
              </button>
              <button
                onClick={handleConfirm}
                disabled={sessionMutation.isPending}
                className="nro-btn-danger"
              >
                {sessionMutation.isPending ? "Revoking…" : "Revoke"}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function AllowlistCard() {
  const { user } = useAuth();
  const queryClient = useQueryClient();

  // Load allowlist state from session (persists across page navigation)
  const { data: allowlistState } = useQuery({
    queryKey: ["allowlist"],
    queryFn: fetchAllowlist,
    staleTime: Infinity, // session-backed — only refetch after mutation
  });

  const entries       = allowlistState?.entries  ?? [];
  const controlEnabled = allowlistState?.enabled ?? false;

  // Lockdown modal
  const [showLockdownModal, setShowLockdownModal] = useState(false);

  // Add CIDR form
  const [adding, setAdding] = useState(false);
  const [cidr, setCidr] = useState("");
  const [desc, setDesc] = useState("");

  // Green toast
  const [toast, setToast] = useState<string | null>(null);
  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3500);
  };

  const addMutation = useMutation({
    mutationFn: addAllowlistEntry,
    onSuccess: () => {
      setAdding(false);
      setCidr("");
      setDesc("");
      queryClient.invalidateQueries({ queryKey: ["allowlist"] });
      showToast("CIDR block successfully added to network perimeter routing.");
    },
  });

  const toggleMutation = useMutation({
    mutationFn: toggleAllowlist,
    onSuccess: () => {
      setShowLockdownModal(false);
      queryClient.invalidateQueries({ queryKey: ["allowlist"] });
      showToast("Network access control lists successfully applied globally.");
    },
  });

  return (
    <section className="nro-card p-6">
      {/* Header row with master toggle */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-bold text-[18px]">IP Access Control</h2>
          <p className="mt-1 text-[14px] text-[color:var(--text-secondary)]">
            Restrict workspace access to specific IP ranges. Changes take effect within 60 seconds.
          </p>
        </div>
        <button
          onClick={() => {
            if (!controlEnabled) setShowLockdownModal(true);
          }}
          className="relative flex-shrink-0 ml-6"
          title={controlEnabled ? "Enabled" : "Click to enable"}
          style={{ cursor: controlEnabled ? "default" : "pointer" }}
        >
          <div
            className="w-12 h-6 rounded-full transition-colors duration-200"
            style={{
              background: controlEnabled
                ? "var(--accent)"
                : "var(--elevated)",
              border: "1px solid var(--border)",
            }}
          />
          <div
            className="absolute top-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform duration-200"
            style={{ transform: controlEnabled ? "translateX(26px)" : "translateX(2px)" }}
          />
        </button>
      </div>

      {/* Green toast */}
      {toast && (
        <div
          className="mt-4 p-3 rounded-md text-[13px]"
          style={{
            background: "color-mix(in oklab, var(--accent) 12%, transparent)",
            color: "var(--accent)",
            border: "1px solid color-mix(in oklab, var(--accent) 60%, transparent)",
          }}
        >
          {toast}
        </div>
      )}

      {/* CIDR table */}
      <div className="nro-card overflow-hidden mt-4" style={{ background: "var(--canvas)" }}>
        <table className="w-full">
          <thead>
            <tr>
              {["CIDR Block", "Description", "Status"].map((h) => (
                <th key={h} className="nro-th">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {entries.map((e, i) => (
              <tr key={i} className="nro-row">
                <td className="nro-td font-mono text-[13px]">{e.cidr}</td>
                <td className="nro-td text-[color:var(--text-secondary)]">{e.description}</td>
                <td className="nro-td">
                  <span className={`nro-badge ${e.active ? "nro-badge--accent" : "nro-badge--slate"}`}>
                    {e.active ? "Active" : "Inactive"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Add CIDR row */}
      <button
        onClick={() => setAdding((v) => !v)}
        className="nro-btn-secondary mt-4"
      >
        {adding ? "Cancel" : "Add CIDR"}
      </button>
      {adding && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-3">
          <input
            className="nro-input font-mono"
            placeholder="e.g. 203.0.113.0/24"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
          />
          <input
            className="nro-input"
            placeholder="Description (optional)"
            value={desc}
            onChange={(e) => setDesc(e.target.value)}
          />
          <button
            onClick={() =>
              addMutation.mutate({ cidr, description: desc, _csrf: user?.csrf_token })
            }
            disabled={addMutation.isPending || !cidr.trim()}
            className="nro-btn-primary"
          >
            {addMutation.isPending ? "Adding…" : "Add"}
          </button>
        </div>
      )}

      {/* Lockdown confirmation modal */}
      {showLockdownModal && (
        <div
          className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
          onClick={() => setShowLockdownModal(false)}
        >
          <div
            className="nro-card bg-[color:var(--surface)]"
            style={{ width: 460, padding: 32 }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="font-bold text-[18px]">Confirm Perimeter Lockdown</h3>
            <p className="mt-3 text-[14px] text-[color:var(--text-secondary)] leading-relaxed">
              Enabling IP Access Control will restrict all incoming API and dashboard traffic
              exclusively to the listed CIDR blocks. Incorrect configurations can result in{" "}
              <strong className="text-white">immediate lockout</strong>. Do you want to proceed?
            </p>
            <div
              className="mt-4 p-3 rounded-md text-[13px]"
              style={{
                background: "color-mix(in oklab, var(--amber, #f59e0b) 10%, transparent)",
                border: "1px solid color-mix(in oklab, var(--amber, #f59e0b) 40%, transparent)",
                color: "#f59e0b",
              }}
            >
              ⚠ Ensure your current IP is included in the allowlist before confirming.
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={() => setShowLockdownModal(false)} className="nro-btn-secondary">
                Cancel
              </button>
              <button
                onClick={() => toggleMutation.mutate({ enabled: true, _csrf: user?.csrf_token })}
                disabled={toggleMutation.isPending}
                className="nro-btn-primary"
              >
                {toggleMutation.isPending ? "Applying…" : "Confirm Enable"}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Admin-only card overrides (cyveera_support role)
// ---------------------------------------------------------------------------

function AdminMfaCard() {
  return (
    <section className="nro-card p-6">
      <div className="flex items-center gap-3">
        <h2 className="font-bold text-[18px]">Multi-Factor Authentication</h2>
        <span
          className="px-2 py-0.5 rounded text-[12px] font-medium"
          style={{ background: "var(--elevated)", color: "#64748b", border: "1px solid var(--border)" }}
        >
          SSO Enforced
        </span>
      </div>
      <p className="mt-3 text-[14px] text-[color:var(--text-secondary)] leading-relaxed">
        Enterprise SSO Enforced. Multi-factor authentication, credential rotation, and session
        lifetimes are centrally managed by the Cyveera Okta Identity Engine. Local modifications
        are disabled for internal staff.
      </p>
      <div
        className="mt-4 p-3 rounded-md text-[13px]"
        style={{ background: "var(--elevated)", border: "1px solid var(--border)" }}
      >
        <div className="grid grid-cols-3 gap-4 text-[color:var(--text-secondary)]">
          <div><span className="block text-[11px] uppercase tracking-wide mb-1">Identity Provider</span>Okta (cyveera.okta.com)</div>
          <div><span className="block text-[11px] uppercase tracking-wide mb-1">MFA Policy</span>Adaptive MFA · Mandatory</div>
          <div><span className="block text-[11px] uppercase tracking-wide mb-1">Session Lifetime</span>8h · Idle timeout 30m</div>
        </div>
      </div>
      <div className="flex gap-2 mt-4 opacity-30 pointer-events-none select-none">
        <button className="nro-btn-secondary" disabled>Configure MFA</button>
        <button className="nro-btn-secondary" disabled>Regenerate backup codes</button>
      </div>
    </section>
  );
}

function AdminAllowlistCard() {
  const ADMIN_CIDRS = [
    { cidr: "10.99.0.0/16",    desc: "Cyveera Global Protect VPN (Enforced)" },
    { cidr: "172.16.50.0/24",  desc: "Internal Management Jump Gateways"      },
  ];

  return (
    <section className="nro-card p-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-bold text-[18px]">IP Access Control</h2>
          <p className="mt-1 text-[14px] text-[color:var(--text-secondary)]">
            Management plane access is strictly restricted to authorized Cyveera Zero-Trust VPN
            gateways. Modifications require a Level 3 NetSec approval ticket.
          </p>
        </div>
        {/* Locked toggle — always-on, non-interactive */}
        <div className="relative flex-shrink-0 ml-6 cursor-not-allowed opacity-50" title="Managed by NetSec — read-only">
          <div
            className="w-12 h-6 rounded-full"
            style={{ background: "var(--accent)", border: "1px solid var(--border)" }}
          />
          <div
            className="absolute top-0.5 w-5 h-5 bg-white rounded-full shadow"
            style={{ transform: "translateX(26px)" }}
          />
        </div>
      </div>

      <div className="nro-card overflow-hidden mt-4" style={{ background: "var(--canvas)" }}>
        <table className="w-full">
          <thead>
            <tr>
              {["CIDR Block", "Description", "Status"].map((h) => (
                <th key={h} className="nro-th">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ADMIN_CIDRS.map((row) => (
              <tr key={row.cidr} className="nro-row">
                <td className="nro-td font-mono text-[13px]">{row.cidr}</td>
                <td className="nro-td text-[color:var(--text-secondary)]">{row.desc}</td>
                <td className="nro-td">
                  <span className="nro-badge nro-badge--accent">Enforced</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="mt-3 text-[12px] text-[color:var(--text-secondary)]">
        To request a CIDR amendment, open a NetSec ticket at{" "}
        <span className="font-mono">internal.cyveera.ai/netsec</span> with justification and
        manager sign-off. SLA: 2 business days.
      </p>
    </section>
  );
}

function RotationCard() {
  const { user } = useAuth();
  const rotateMutation = useMutation({ mutationFn: rotateKeys });
  const [rotateMsg, setRotateMsg] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [confirmInput, setConfirmInput] = useState("");

  const handleModalClose = () => {
    setShowModal(false);
    setConfirmInput("");
  };

  const handleConfirm = () => {
    rotateMutation.mutate(
      { _csrf: user?.csrf_token },
      {
        onSuccess: (d) => {
          setRotateMsg(`${d.note} (${d.affected_keys} keys affected)`);
          handleModalClose();
        },
      },
    );
  };

  return (
    <section className="nro-card p-6">
      <h2 className="font-bold text-[18px]">Key Rotation Policy</h2>
      <p className="mt-2 text-[14px] text-[color:var(--text-secondary)]">
        Current policy: Manual rotation only.
      </p>
      {rotateMsg && (
        <p className="mt-3 text-[13px] text-[color:var(--accent)]">{rotateMsg}</p>
      )}
      <button
        onClick={() => setShowModal(true)}
        className="mt-4"
        style={{
          background: "var(--amber)",
          color: "#fff",
          padding: "8px 16px",
          borderRadius: 6,
          fontWeight: 600,
        }}
      >
        Rotate All Keys Now
      </button>

      {showModal && (
        <div
          className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
          onClick={handleModalClose}
        >
          <div
            className="nro-card bg-[color:var(--surface)]"
            style={{ width: 500, padding: 32 }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="font-bold text-[20px]">Confirm Global Key Rotation</h3>
            <p className="mt-3 text-[14px] text-[color:var(--text-secondary)] leading-relaxed">
              You are about to instantly revoke and regenerate all active API keys. This action
              cannot be undone. Any active CI/CD pipelines, automated deployments, or external
              integrations relying on the current keys will immediately fail until they are
              manually updated.
            </p>
            <div className="mt-5">
              <label className="nro-label">
                Type <strong className="text-white font-mono">ROTATE</strong> to confirm
              </label>
              <input
                className="nro-input mt-2"
                type="text"
                placeholder="ROTATE"
                value={confirmInput}
                onChange={(e) => setConfirmInput(e.target.value)}
                autoComplete="off"
              />
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={handleModalClose} className="nro-btn-secondary">
                Cancel
              </button>
              <button
                onClick={handleConfirm}
                disabled={confirmInput !== "ROTATE" || rotateMutation.isPending}
                className="nro-btn-danger"
              >
                {rotateMutation.isPending ? "Rotating…" : "Confirm Revocation"}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
