import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { useQuery, useMutation } from "@tanstack/react-query";
import { fetchTeam, type TeamMember } from "@/lib/api/data";
import { inviteTeamMember } from "@/lib/api/mutations";
import { useAuth } from "@/lib/auth.context";
import { isApiError } from "@/lib/api/client";
import { UserPlus } from "lucide-react";
import { useState } from "react";

export const Route = createFileRoute("/team")({
  component: TeamPage,
  head: () => ({ meta: [{ title: "Team — Neuro" }] }),
});

const ROLE_BADGE: Record<string, string> = {
  Member: "nro-badge--slate",
  customer_user: "nro-badge--slate",
  Admin: "nro-badge--amber",
  customer_admin: "nro-badge--amber",
  Support: "nro-badge--info",
  cyveera_support: "nro-badge--info",
};

function formatRole(role: string): string {
  const map: Record<string, string> = {
    customer_user: "Member",
    customer_admin: "Admin",
    cyveera_support: "Support",
  };
  return map[role] ?? role;
}

function TeamPage() {
  const { data: members = [], isLoading } = useQuery({
    queryKey: ["team"],
    queryFn: fetchTeam,
  });
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState<string[]>([]);

  const inviteMutation = useMutation({
    mutationFn: inviteTeamMember,
    onSuccess: (data) => {
      setPending((c) => [...c, data.email]);
      setOpen(false);
    },
  });

  return (
    <AppLayout title="Team">
      <AppPageHeader
        title="Workspace members."
        description="Invite teammates, manage roles, and audit last-active timestamps. SCIM provisioning is available on the Enterprise plan."
        actions={
          <button
            onClick={() => setOpen(true)}
            className="nro-btn-primary text-sm inline-flex items-center gap-1.5"
          >
            <UserPlus size={14} /> Invite teammate
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
                {["Name", "Email", "Role", "Last Active", "Action"].map((h) => (
                  <th key={h} className="nro-th">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {members.map((m: TeamMember) => (
                <tr key={m.email} className="nro-row">
                  <td className="nro-td">{m.display_name}</td>
                  <td className="nro-td font-mono text-[13px]">{m.email}</td>
                  <td className="nro-td">
                    <span
                      className={`nro-badge ${ROLE_BADGE[m.role] ?? "nro-badge--slate"}`}
                    >
                      {formatRole(m.role)}
                    </span>
                  </td>
                  <td className="nro-td text-[color:var(--text-secondary)]">
                    {m.last_active
                      ? m.last_active.replace("T", " ").slice(0, 16)
                      : "—"}
                  </td>
                  <td className="nro-td">
                    <button className="nro-btn-secondary !py-1 !px-3 text-[12px]">
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-8">
        <h3 className="font-bold text-[16px] mb-3">Pending Invitations</h3>
        {pending.length === 0 ? (
          <div className="text-[14px] text-[color:var(--text-secondary)]">
            No pending invitations.
          </div>
        ) : (
          <div className="nro-card overflow-hidden">
            {pending.map((e) => (
              <div
                key={e}
                className="flex items-center justify-between p-4 border-b border-[color:var(--border)] last:border-b-0"
              >
                <div className="font-mono text-[13px]">{e}</div>
                <div className="flex gap-2">
                  <button className="nro-btn-secondary !py-1 !px-3 text-[12px]">
                    Resend
                  </button>
                  <button
                    onClick={() => setPending((c) => c.filter((x) => x !== e))}
                    className="nro-btn-secondary !py-1 !px-3 text-[12px]"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {open && (
        <InviteModal
          onClose={() => setOpen(false)}
          csrf={user?.csrf_token}
          isPending={inviteMutation.isPending}
          onInvite={(email, role) => {
            inviteMutation.mutate({ email, role, _csrf: user?.csrf_token });
          }}
        />
      )}
    </AppLayout>
  );
}

function InviteModal({
  onClose,
  csrf: _csrf,
  isPending,
  onInvite,
}: {
  onClose: () => void;
  csrf?: string;
  isPending: boolean;
  onInvite: (email: string, role: string) => void;
}) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("Member");
  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="nro-card bg-[color:var(--surface)]"
        style={{ width: 440, padding: 32 }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="font-bold text-[20px]">Invite a teammate</h3>
        <p className="mt-2 text-[14px] text-[color:var(--text-secondary)]">
          Enter your teammate's work email. They'll receive an invitation to
          join the VantaraHealth workspace.
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onInvite(email, role);
          }}
          className="mt-6 space-y-4"
        >
          <div>
            <label className="nro-label">Email address</label>
            <input
              className="nro-input mt-2"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="colleague@vantarahealth.com"
            />
          </div>
          <div>
            <label className="nro-label">Role</label>
            <select
              className="nro-input mt-2"
              value={role}
              onChange={(e) => setRole(e.target.value)}
            >
              <option value="Member">Member</option>
              <option value="Admin">Admin</option>
            </select>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="nro-btn-secondary">
              Cancel
            </button>
            <button
              type="submit"
              className="nro-btn-primary"
              disabled={isPending}
            >
              {isPending ? "Sending…" : "Send invite"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
