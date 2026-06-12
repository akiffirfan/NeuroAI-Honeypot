import { Link, useLocation, useRouter } from "@tanstack/react-router";
import { Logo } from "../Logo";
import { useState, useEffect, type ReactNode } from "react";
import {
  LayoutGrid,
  ListChecks,
  Layers,
  Database,
  GitBranch,
  Archive,
  Bell,
  Plug,
  Shield,
  Key,
  ChevronDown,
  ChevronUp,
  Users,
  UserCircle,
} from "lucide-react";
import { useUnreadCount } from "@/lib/notifications.store";
import { useAuth } from "@/lib/auth.context";
import { logout } from "@/lib/api/auth";

// Kept for backward compatibility — settings.security.tsx reads MOCK_USER.ip
// and MOCK_USER.user_agent_parsed. Those are now sourced from the real session
// but the export must remain so the import doesn't break during transition.
export const MOCK_USER = {
  display_name: "Jordan Smith",
  username: "j.smith",
  email: "j.smith@vantarahealth.com",
  role: "customer_user" as
    | "customer_user"
    | "customer_admin"
    | "cyveera_support",
  ip: "…",
  user_agent_parsed: "…",
};

export const MOCK_WORKSPACE = {
  name: "VantaraHealth",
  plan: "Pro",
};

const NAV_PLATFORM = [
  { label: "Runs", to: "/runs", icon: ListChecks },
  { label: "Models", to: "/models", icon: Layers },
  { label: "Datasets", to: "/datasets", icon: Database },
  { label: "Pipelines", to: "/jobs", icon: GitBranch },
];
const NAV_SYSTEM = [
  { label: "Dashboard", to: "/dashboard", icon: LayoutGrid },
  { label: "Artifacts", to: "/artifacts", icon: Archive },
  {
    label: "Notifications",
    to: "/notifications",
    icon: Bell,
  },
];
const NAV_SETTINGS = [
  { label: "Integrations", to: "/settings/integrations", icon: Plug },
  { label: "Security", to: "/settings/security", icon: Shield },
  { label: "API Keys", to: "/api-keys", icon: Key },
];

// Admin-role nav (cyveera_support) — no platform section
const NAV_ADMIN_SYSTEM = [
  { label: "Cross-Tenant Admin", to: "/settings/admin", icon: Users },
  { label: "Notifications",      to: "/notifications",  icon: Bell  },
];
const NAV_ADMIN_SETTINGS = [
  { label: "Security", to: "/settings/security", icon: Shield     },
  { label: "Profile",  to: "/settings/profile",  icon: UserCircle },
];

export function AppLayout({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) {
      router.navigate({ to: "/login" });
    }
  }, [loading, user, router]);

  if (loading) {
    return (
      <div className="flex min-h-screen bg-[color:var(--canvas)] items-center justify-center">
        <div className="text-[color:var(--text-secondary)] text-[14px]">···</div>
      </div>
    );
  }

  if (!user) {
    return null;
  }

  return (
    <div className="flex min-h-screen bg-[color:var(--canvas)]">
      <Sidebar />
      <div
        className="flex-1 flex flex-col relative overflow-x-hidden min-w-0"
        style={{ marginLeft: 240 }}
      >
        <div
          aria-hidden
          className="absolute inset-x-0 top-0 h-[420px] nro-grid-bg opacity-[0.07] pointer-events-none"
        />
        <div
          aria-hidden
          className="absolute pointer-events-none"
          style={{
            top: -80,
            right: -120,
            width: 520,
            height: 360,
            background:
              "radial-gradient(ellipse at center, color-mix(in oklab, var(--accent) 14%, transparent), transparent 70%)",
          }}
        />
        <TopBar title={title} />
        <main className="flex-1 px-8 py-8 relative">{children}</main>
      </div>
    </div>
  );
}

function Sidebar() {
  const unreadCount = useUnreadCount();
  const { user } = useAuth();
  const isAdmin = user?.role === "cyveera_support";

  const navSystem = NAV_SYSTEM.map((item) =>
    item.to === "/notifications"
      ? { ...item, badge: unreadCount || undefined }
      : item,
  );
  const navAdminSystem = NAV_ADMIN_SYSTEM.map((item) =>
    item.to === "/notifications"
      ? { ...item, badge: unreadCount || undefined }
      : item,
  );

  return (
    <aside
      className="fixed left-0 top-0 h-screen border-r border-[color:var(--border)] bg-[color:var(--surface)] flex flex-col"
      style={{ width: 240 }}
    >
      <div className="px-5 pt-5 pb-4">
        <Logo />
      </div>

      <WorkspaceSwitch />

      <nav className="flex-1 overflow-y-auto px-3 py-2 space-y-5">
        {isAdmin ? (
          <>
            <NavSection label="System" items={navAdminSystem} />
            <NavSection label="Settings" items={NAV_ADMIN_SETTINGS} />
          </>
        ) : (
          <>
            <NavSection label="Platform" items={NAV_PLATFORM} />
            <NavSection label="System" items={navSystem} />
            <NavSection label="Settings" items={NAV_SETTINGS} />
          </>
        )}
      </nav>

      <UserMenu />
    </aside>
  );
}

function WorkspaceSwitch() {
  const [open, setOpen] = useState(false);
  const { user } = useAuth();
  const workspaceName = user?.workspace?.name ?? MOCK_WORKSPACE.name;
  return (
    <div className="px-3 pb-3 relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-2 px-2.5 py-2 rounded-lg border border-[color:var(--border)] bg-[color:var(--elevated)] hover:border-[color:var(--accent)]/40 transition-colors"
      >
        <div className="flex items-center gap-2 min-w-0">
          <span
            className="inline-flex items-center justify-center rounded-md text-white text-[12px] font-bold"
            style={{ width: 24, height: 24, background: "var(--accent)" }}
          >
            {workspaceName[0]}
          </span>
          <span className="text-[14px] text-white truncate">{workspaceName}</span>
        </div>
        {open ? (
          <ChevronUp size={14} className="text-[color:var(--text-secondary)]" />
        ) : (
          <ChevronDown
            size={14}
            className="text-[color:var(--text-secondary)]"
          />
        )}
      </button>
      {open && (
        <div className="absolute left-3 right-3 top-full mt-1 z-30 nro-card p-1 bg-[color:var(--elevated)]">
          <div className="px-3 py-2 text-[13px] text-[color:var(--text-primary)] flex items-center justify-between">
            {workspaceName} <span className="text-[color:var(--accent)]">✓</span>
          </div>
          <div className="my-1 h-px bg-[color:var(--border)]" />
          <a
            href="/workspaces/create"
            onClick={() => setOpen(false)}
            className="block w-full text-left px-3 py-2 text-[13px] text-[color:var(--text-secondary)] hover:text-white hover:bg-[color:var(--surface)] rounded"
          >
            Create workspace
          </a>
          <a
            href="/workspaces/manage"
            onClick={() => setOpen(false)}
            className="block w-full text-left px-3 py-2 text-[13px] text-[color:var(--text-secondary)] hover:text-white hover:bg-[color:var(--surface)] rounded"
          >
            Manage workspaces
          </a>
        </div>
      )}
    </div>
  );
}

function NavSection({
  label,
  items,
}: {
  label: string;
  items: {
    label: string;
    to: string;
    icon: any;
    badge?: number;
    external?: boolean;
  }[];
}) {
  return (
    <div>
      <div className="px-3 pb-2 nro-section-label">{label}</div>
      <ul className="space-y-0.5">
        {items.map((item) => (
          <NavItem key={item.to} {...item} />
        ))}
      </ul>
    </div>
  );
}

function NavItem({
  label,
  to,
  icon: Icon,
  badge,
  external,
}: {
  label: string;
  to: string;
  icon: any;
  badge?: number;
  external?: boolean;
}) {
  const loc = useLocation();
  const active = loc.pathname === to;
  const Inner = (
    <span
      className={`relative flex items-center gap-2.5 pl-4 pr-3 py-2 rounded-md text-[14px] transition-colors ${
        active
          ? "bg-[color:var(--elevated)] text-white"
          : "text-[color:var(--text-secondary)] hover:text-white hover:bg-[color:var(--elevated)]/60"
      }`}
    >
      {active && (
        <span
          aria-hidden
          className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-r bg-[color:var(--accent)]"
        />
      )}
      <Icon size={16} className={active ? "text-white" : ""} />
      <span className="flex-1">{label}</span>
      {badge ? (
        <span className="nro-badge nro-badge--amber !py-0 !px-2 !text-[11px]">
          {badge}
        </span>
      ) : null}
    </span>
  );
  if (external)
    return (
      <li>
        <a href={to} target="_blank" rel="noreferrer">
          {Inner}
        </a>
      </li>
    );
  return (
    <li>
      <Link to={to}>{Inner}</Link>
    </li>
  );
}

function UserMenu() {
  const [open, setOpen] = useState(false);
  const router = useRouter();
  const { user } = useAuth();
  const displayName = user?.display_name ?? MOCK_USER.display_name;
  const email = user?.email ?? MOCK_USER.email;

  const handleSignOut = async () => {
    setOpen(false);
    try {
      await logout();
    } catch {
      // session may already be expired — proceed to login
    }
    // Full page navigation clears all React state (auth context, notification cache, query cache)
    // so the next login starts completely fresh without a hard refresh.
    window.location.href = "/login";
  };

  return (
    <div className="border-t border-[color:var(--border)] px-3 py-3 relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-3 px-2 py-1.5 rounded-md hover:bg-[color:var(--elevated)]"
      >
        <span
          className="inline-flex items-center justify-center rounded-full text-white text-[12px] font-bold"
          style={{ width: 32, height: 32, background: "var(--accent)" }}
        >
          {displayName[0]}
        </span>
        <div className="text-left min-w-0">
          <div className="text-[14px] text-white leading-tight truncate">
            {displayName}
          </div>
          <div className="text-[12px] text-[color:var(--text-secondary)] truncate">
            {email}
          </div>
        </div>
      </button>
      {open && (
        <div className="absolute left-3 right-3 bottom-full mb-2 nro-card bg-[color:var(--elevated)] p-1 z-30">
          {[
            ["Profile", "/settings/profile"],
            ["API Keys", "/api-keys"],
            ["Settings", "/settings/security"],
          ].map(([label, to]) => (
            <Link
              key={to}
              to={to}
              onClick={() => setOpen(false)}
              className="block px-3 py-2 text-[13px] text-[color:var(--text-secondary)] hover:text-white rounded"
            >
              {label}
            </Link>
          ))}
          <div className="my-1 h-px bg-[color:var(--border)]" />
          <button
            onClick={handleSignOut}
            className="w-full text-left px-3 py-2 text-[13px] text-[color:var(--text-secondary)] hover:text-white rounded"
          >
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

function TopBar({ title }: { title: string }) {
  const unreadCount = useUnreadCount();
  const { user } = useAuth();
  const workspaceName = user?.workspace?.name ?? MOCK_WORKSPACE.name;
  const displayName = user?.display_name ?? MOCK_USER.display_name;
  return (
    <div
      className="sticky top-0 z-20 flex items-center justify-between px-8 border-b border-[color:var(--border)] bg-[color:var(--surface)]/85 backdrop-blur-xl"
      style={{ height: 60 }}
    >
      <div className="flex items-center gap-3">
        <span
          className="w-1 h-5 rounded-full"
          style={{ background: "var(--accent)" }}
        />
        <h1 className="text-[16px] font-semibold text-white tracking-tight">
          {title}
        </h1>
      </div>
      <div className="flex items-center gap-4">
        <Link
          to="/notifications"
          className="relative text-[color:var(--text-secondary)] hover:text-white"
        >
          <Bell size={18} />
          {unreadCount > 0 && (
            <span
              className="absolute -top-1 -right-1 inline-flex items-center justify-center rounded-full text-[10px] font-bold text-white"
              style={{
                width: 14,
                height: 14,
                background: "var(--amber)",
              }}
            >
              {unreadCount}
            </span>
          )}
        </Link>
        <div className="flex items-center gap-1.5 px-2 py-1 text-[13px] text-white">
          <span
            className="inline-flex items-center justify-center rounded text-white text-[10px] font-bold"
            style={{ width: 18, height: 18, background: "var(--accent)" }}
          >
            {workspaceName[0]}
          </span>
          {workspaceName}
        </div>
        <span
          className="inline-flex items-center justify-center rounded-full text-white text-[12px] font-bold"
          style={{ width: 32, height: 32, background: "var(--accent)" }}
        >
          {displayName[0]}
        </span>
      </div>
    </div>
  );
}
