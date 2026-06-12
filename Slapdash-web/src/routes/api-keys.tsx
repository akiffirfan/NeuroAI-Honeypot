import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchApiKeys, type ApiKey } from "@/lib/api/data";
import { createApiKey, revokeApiKey } from "@/lib/api/mutations";
import { useAuth } from "@/lib/auth.context";
import { isApiError } from "@/lib/api/client";
import { Copy, Plus } from "lucide-react";
import { useState } from "react";

export const Route = createFileRoute("/api-keys")({
  component: ApiKeysPage,
  head: () => ({ meta: [{ title: "API Keys — Neuro" }] }),
});

function ApiKeysPage() {
  const { data: apiKeys = [], isLoading } = useQuery({
    queryKey: ["api-keys"],
    queryFn: fetchApiKeys,
  });
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const [copied, setCopied] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);

  const revokeMutation = useMutation({
    mutationFn: revokeApiKey,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
  });

  const copy = (full: string) => {
    if (typeof navigator !== "undefined") navigator.clipboard?.writeText(full);
    setCopied(full);
    setTimeout(() => setCopied(null), 1500);
  };

  return (
    <AppLayout title="API Keys">
      <AppPageHeader
        title="API keys."
        description="Programmatic access tokens for the Neuro API. Scoped, rotatable, and never stored in plaintext — only the last 4 characters are retained for identification."
        actions={
          <button
            onClick={() => setCreateOpen(true)}
            className="nro-btn-primary text-sm flex items-center gap-1.5"
          >
            <Plus size={14} /> Create API key
          </button>
        }
      />

      {isLoading ? (
        <div className="nro-card p-8 text-center text-[14px] text-[color:var(--text-secondary)]">
          Loading…
        </div>
      ) : (
        <div className="nro-card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr>
                {["Name", "Key", "Created", "Last Used", "Scope", "Action"].map(
                  (h) => (
                    <th key={h} className="nro-th">
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {apiKeys.map((k: ApiKey) => (
                <tr key={k.id ?? k.name} className="nro-row">
                  <td className="nro-td">{k.name}</td>
                  <td className="nro-td">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[13px]">{k.key_masked}</span>
                      <button
                        onClick={() => copy(k.key_full)}
                        className="text-[color:var(--text-secondary)] hover:text-white"
                        aria-label="Copy"
                      >
                        <Copy size={14} />
                      </button>
                      {copied === k.key_full && (
                        <span className="text-[11px] text-[color:var(--accent)]">
                          Copied!
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="nro-td text-[color:var(--text-secondary)]">
                    {k.created_at}
                  </td>
                  <td className="nro-td text-[color:var(--text-secondary)]">
                    {k.last_used_at ?? "Never"}
                  </td>
                  <td className="nro-td font-mono text-[12px]">{k.scope}</td>
                  <td className="nro-td">
                    <button
                      onClick={() =>
                        revokeMutation.mutate({
                          key_id: k.id,
                          _csrf: user?.csrf_token,
                        })
                      }
                      disabled={revokeMutation.isPending}
                      className="nro-btn-secondary !py-1 !px-3 text-[12px]"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="mt-4 text-[13px] text-[color:var(--text-secondary)]">
        API keys grant programmatic access to your workspace. Treat them like
        passwords. Keys are never stored in plaintext — only the last 4
        characters are retained for identification.
      </p>

      {createOpen && (
        <CreateModal
          onClose={() => setCreateOpen(false)}
          csrf={user?.csrf_token}
        />
      )}
    </AppLayout>
  );
}

function CreateModal({
  onClose,
  csrf,
}: {
  onClose: () => void;
  csrf?: string;
}) {
  const queryClient = useQueryClient();
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const mutation = useMutation({
    mutationFn: createApiKey,
    onSuccess: (data) => {
      setCreatedKey(data.key.key_full);
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: (err) => {
      if (isApiError(err)) {
        setCreateError(`Error ${err.status}: ${err.detail}`);
      } else {
        setCreateError("Failed to create key. Please try again.");
      }
    },
  });

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setCreateError(null);
    const form = new FormData(e.currentTarget);
    const name = form.get("key_name") as string;
    const scopes = ["read:runs", "read:models", "read:datasets", "write:metrics", "admin"]
      .filter((s) => form.get(s) === "on")
      .join(",");
    mutation.mutate({ name, scope: scopes || "read:runs", _csrf: csrf });
  };

  const copyKey = () => {
    if (createdKey) navigator.clipboard?.writeText(createdKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
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
        {!createdKey ? (
          <>
            <h3 className="font-bold text-[20px]">Create API Key</h3>
            <form onSubmit={handleSubmit} className="mt-6 space-y-4">
              <div>
                <label className="nro-label">Key name</label>
                <input
                  name="key_name"
                  className="nro-input mt-2"
                  placeholder="e.g. nightly-export"
                  required
                />
              </div>
              <div>
                <label className="nro-label">Scope</label>
                <div className="space-y-1.5 mt-2">
                  {["read:runs", "read:models", "read:datasets", "write:metrics", "admin"].map(
                    (s) => (
                      <label key={s} className="flex items-center gap-2 text-[14px]">
                        <input
                          type="checkbox"
                          name={s}
                          className="accent-[color:var(--accent)]"
                        />
                        <span className="font-mono">{s}</span>
                        {s === "admin" && (
                          <span className="nro-badge nro-badge--amber !text-[10px] ml-1">
                            Admin scope grants full workspace access
                          </span>
                        )}
                      </label>
                    ),
                  )}
                </div>
              </div>
              <div>
                <label className="nro-label">Expires</label>
                <select className="nro-input mt-2">
                  <option>Never</option>
                  <option>30 days</option>
                  <option>90 days</option>
                  <option>1 year</option>
                </select>
              </div>
              {createError && (
                <p className="text-[13px] text-[color:var(--danger)]">{createError}</p>
              )}
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="nro-btn-secondary"
                >
                  Cancel
                </button>
                <button
                  className="nro-btn-primary"
                  disabled={mutation.isPending}
                >
                  {mutation.isPending ? "Creating…" : "Create key"}
                </button>
              </div>
            </form>
          </>
        ) : (
          <>
            <h3 className="font-bold text-[20px]">Save this key now</h3>
            <p className="mt-2 text-[14px] text-[color:var(--text-secondary)]">
              You will not be able to view it again.
            </p>
            <pre
              className="font-mono text-[13px] p-4 mt-4 rounded-md break-all"
              style={{ background: "var(--canvas)" }}
            >
              {createdKey}
            </pre>
            <div className="flex justify-end gap-2 mt-4">
              <button onClick={copyKey} className="nro-btn-secondary">
                {copied ? "Copied!" : "Copy key"}
              </button>
              <button onClick={onClose} className="nro-btn-primary">
                Done
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
