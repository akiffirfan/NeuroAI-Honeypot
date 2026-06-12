import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { useState, useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/lib/auth.context";
import { updateProfile, submitSshKey } from "@/lib/api/mutations";
import { fetchSshKeys, type SshKey } from "@/lib/api/data";
import { isApiError } from "@/lib/api/client";

export const Route = createFileRoute("/settings/profile")({
  component: ProfileSettingsPage,
  head: () => ({ meta: [{ title: "Profile Settings — Neuro" }] }),
});

function ProfileSettingsPage() {
  const { user, patchUser } = useAuth();
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  // Controlled field state — seeded from auth context once loaded
  const [fullName,     setFullName]     = useState("");
  const [displayName,  setDisplayName]  = useState("");
  const [timezone,     setTimezone]     = useState("America/New_York");
  const [language,     setLanguage]     = useState("English (US)");

  // Seed fields once user data arrives
  useEffect(() => {
    if (!user) return;
    setFullName(user.full_name    ?? "");
    setDisplayName(user.display_name ?? "");
    setTimezone(user.timezone    ?? "America/New_York");
    setLanguage(user.language    ?? "English (US)");
  }, [user?.email]);

  const saveMutation = useMutation({
    mutationFn: updateProfile,
    onSuccess: (data) => {
      patchUser({ full_name: data.full_name, display_name: data.display_name, timezone: data.timezone, language: data.language });
      setToast({ msg: "Profile updated successfully.", ok: true });
      setTimeout(() => setToast(null), 3000);
    },
    onError: (err) => {
      const msg = isApiError(err) ? err.detail : "Failed to save. Please try again.";
      setToast({ msg, ok: false });
      setTimeout(() => setToast(null), 3500);
    },
  });

  const handleSave = () => {
    saveMutation.mutate({
      full_name:    fullName,
      display_name: displayName,
      timezone,
      language,
      _csrf: user?.csrf_token,
    });
  };

  return (
    <AppLayout title="Profile Settings">
      <AppPageHeader
        title="Profile settings."
        description="Your identity within Neuro — name, locale, SSH access. Changes apply across every workspace you belong to."
      />
      <div className="mx-auto" style={{ maxWidth: 640 }}>
        <section className="nro-card p-8">
          <h2 className="font-bold text-[18px] mb-6">Personal Information</h2>

          {toast && (
            <div
              className="mb-4 p-3 rounded-md text-[13px]"
              style={{
                background: toast.ok
                  ? "color-mix(in oklab, var(--accent) 12%, transparent)"
                  : "color-mix(in oklab, var(--danger) 12%, transparent)",
                color: toast.ok ? "var(--accent)" : "var(--danger)",
                border: `1px solid ${toast.ok ? "var(--accent)" : "color-mix(in oklab, var(--danger) 40%, transparent)"}`,
              }}
            >
              {toast.msg}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label className="nro-label">Full name</label>
              <input
                className="nro-input mt-2"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
              />
            </div>
            <div>
              <label className="nro-label">Display name</label>
              <input
                className="nro-input mt-2"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
            </div>
            <div>
              <label className="nro-label">Work email</label>
              <input
                className="nro-input mt-2 opacity-60 cursor-not-allowed"
                value={user?.email ?? ""}
                readOnly
              />
              <p className="mt-1 text-[12px] text-[color:var(--text-secondary)]">
                Email cannot be changed. Contact support@cyveera.ai to update.
              </p>
            </div>
            <div>
              <label className="nro-label">Timezone</label>
              <select
                className="nro-input mt-2"
                value={timezone}
                onChange={(e) => setTimezone(e.target.value)}
              >
                <option value="America/New_York">America/New_York (UTC-4)</option>
                <option value="America/Los_Angeles">America/Los_Angeles (UTC-7)</option>
                <option value="Europe/London">Europe/London (UTC+1)</option>
                <option value="Asia/Tokyo">Asia/Tokyo (UTC+9)</option>
              </select>
            </div>
            <div>
              <label className="nro-label">Preferred language</label>
              <select
                className="nro-input mt-2"
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
              >
                <option value="English (US)">English (US)</option>
                <option value="English (UK)">English (UK)</option>
                <option value="Français">Français</option>
                <option value="Deutsch">Deutsch</option>
              </select>
            </div>
          </div>

          <button
            onClick={handleSave}
            disabled={saveMutation.isPending}
            className="nro-btn-primary w-full mt-6"
          >
            {saveMutation.isPending ? "Saving…" : "Save changes"}
          </button>
        </section>

        <SshKeysSection csrf={user?.csrf_token} displayName={displayName} />
      </div>
    </AppLayout>
  );
}

function SshKeysSection({ csrf, displayName }: { csrf?: string; displayName: string }) {
  const queryClient = useQueryClient();
  const [sshOpen, setSshOpen] = useState(false);

  const { data: keys = [], isLoading } = useQuery({
    queryKey: ["ssh-keys"],
    queryFn: fetchSshKeys,
    staleTime: Infinity,
  });

  // Hardcoded seed key — always shown as the "original" key
  const seedKey: SshKey = {
    name: `${displayName || "j.smith"} workstation`,
    fingerprint: "SHA256:K7mP...xQ3R",
    added_at: "2026-04-14",
    last_used_at: "2026-06-07",
  };

  const allKeys = [seedKey, ...keys];

  return (
    <section className="nro-card p-8 mt-8">
      <div className="flex items-center justify-between">
        <h2 className="font-bold text-[18px]">SSH Public Keys</h2>
        <button onClick={() => setSshOpen(true)} className="nro-btn-secondary">
          Add key
        </button>
      </div>
      <p className="mt-3 text-[14px] text-[color:var(--text-secondary)]">
        SSH keys are used for authenticating to Neuro training nodes and
        the job scheduler. Add your public key to enable passwordless
        access to <span className="font-mono">neuro-train-01.internal</span>{" "}
        and pipeline automation.
      </p>
      <div className="nro-card overflow-hidden mt-5" style={{ background: "var(--canvas)" }}>
        <table className="w-full">
          <thead>
            <tr>
              {["Name", "Fingerprint", "Added", "Last Used"].map((h) => (
                <th key={h} className="nro-th">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={4} className="nro-td text-center text-[color:var(--text-secondary)]">Loading…</td></tr>
            ) : allKeys.map((k, i) => (
              <tr key={i} className="nro-row">
                <td className="nro-td">{k.name}</td>
                <td className="nro-td font-mono text-[12px]">{k.fingerprint}</td>
                <td className="nro-td text-[color:var(--text-secondary)]">{k.added_at ?? "—"}</td>
                <td className="nro-td text-[color:var(--text-secondary)]">{k.last_used_at ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {sshOpen && (
        <SshKeyModal
          onClose={() => setSshOpen(false)}
          csrf={csrf}
          onAdded={() => {
            queryClient.invalidateQueries({ queryKey: ["ssh-keys"] });
            setSshOpen(false);
          }}
        />
      )}
    </section>
  );
}

function SshKeyModal({ onClose, csrf, onAdded }: { onClose: () => void; csrf?: string; onAdded: () => void }) {
  const mutation = useMutation({ mutationFn: submitSshKey });
  const [name, setName] = useState("");
  const [key,  setKey]  = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate({ name, key, _csrf: csrf }, {
      onSuccess: () => {
        setTimeout(() => onAdded(), 1200);
      },
    });
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="nro-card bg-[color:var(--surface)]"
        style={{ width: 520, padding: 32 }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="font-bold text-[20px]">Add SSH Public Key</h3>
        {mutation.isSuccess ? (
          <>
            <p className="mt-4 text-[14px] text-[color:var(--accent)]">
              SSH key added. It may take up to 60 seconds to propagate to all cluster nodes.
            </p>
            <div className="flex justify-end mt-6">
              <button onClick={onAdded} className="nro-btn-primary">Done</button>
            </div>
          </>
        ) : (
          <form onSubmit={handleSubmit} className="mt-4 space-y-4">
            <div>
              <label className="nro-label">Key name</label>
              <input
                className="nro-input mt-2"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. work laptop"
                required
              />
            </div>
            <div>
              <label className="nro-label">Public key</label>
              <textarea
                className="nro-input mt-2 font-mono !text-[12px]"
                rows={5}
                placeholder="ssh-ed25519 AAAA…"
                value={key}
                onChange={(e) => setKey(e.target.value)}
                required
              />
            </div>
            {mutation.isError && (
              <p className="text-[13px] text-[color:var(--danger)]">
                {isApiError(mutation.error) ? mutation.error.detail : "Invalid SSH key format. Supported: ssh-rsa, ssh-ed25519, ssh-ecdsa."}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <button type="button" onClick={onClose} className="nro-btn-secondary">Cancel</button>
              <button disabled={mutation.isPending} className="nro-btn-primary">
                {mutation.isPending ? "Adding…" : "Add key"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
