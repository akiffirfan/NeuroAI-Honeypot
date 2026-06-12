import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "@/lib/api/client";

type Severity = "critical" | "warning" | "info";

export type NotificationItem = {
  id: number;
  sev: Severity;
  title: string;
  body: string;
  time: string;
  unread?: boolean;
};

type ApiNotification = {
  id: number;
  severity: string;
  title: string;
  body: string;
  created_at: string;
  is_read: boolean;
};

function mapApiItem(n: ApiNotification): NotificationItem {
  return {
    id: n.id,
    sev: (n.severity as Severity) || "info",
    title: n.title,
    body: n.body,
    time: n.created_at ? n.created_at.slice(0, 16).replace("T", " ") : "",
    unread: !n.is_read,
  };
}

let globalItems: NotificationItem[] = [];
let globalHistory: NotificationItem[] = [];
let globalLoaded = false;
const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((l) => l());
}

async function loadFromApi() {
  try {
    const data = await apiFetch<{ notifications: ApiNotification[] }>("/notifications");
    const all = (data.notifications || []).map(mapApiItem);
    globalItems = all.filter((n) => n.unread);
    globalHistory = all.filter((n) => !n.unread);
    globalLoaded = true;
    emit();
  } catch {
    globalLoaded = true;
    emit();
  }
}

export function getUnreadCount(): number {
  return globalItems.filter((i) => i.unread).length;
}

export function subscribeNotifications(cb: () => void) {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

export function useNotifications() {
  const [items, setItems] = useState<NotificationItem[]>(globalItems);
  const [history, setHistory] = useState<NotificationItem[]>(globalHistory);

  useEffect(() => {
    const sync = () => {
      setItems([...globalItems]);
      setHistory([...globalHistory]);
    };
    sync();
    const unsub = subscribeNotifications(sync);
    if (!globalLoaded) {
      loadFromApi();
    }
    return () => unsub();
  }, []);

  const markAllRead = useCallback(() => {
    // Optimistic update
    const moved = globalItems.map((i) => ({ ...i, unread: false }));
    globalHistory = [...moved, ...globalHistory];
    globalItems = [];
    emit();
    // Persist to DB
    apiFetch("/notifications/read-all", { method: "PATCH" }).catch(() => {});
  }, []);

  const dismiss = useCallback((id: number) => {
    const found = globalItems.find((i) => i.id === id);
    if (found) {
      // Optimistic update
      globalHistory = [{ ...found, unread: false }, ...globalHistory];
      globalItems = globalItems.filter((i) => i.id !== id);
      emit();
      // Persist to DB
      apiFetch(`/notifications/${id}/read`, { method: "PATCH" }).catch(() => {});
    }
  }, []);

  const clearHistory = useCallback(() => {
    // Optimistic update
    globalHistory = [];
    emit();
    // Persist to DB
    apiFetch("/notifications", { method: "DELETE" }).catch(() => {});
  }, []);

  return {
    items,
    history,
    unreadCount: items.filter((i) => i.unread).length,
    markAllRead,
    dismiss,
    clearHistory,
  };
}

export function useUnreadCount(): number {
  const [count, setCount] = useState(getUnreadCount());

  useEffect(() => {
    const sync = () => setCount(getUnreadCount());
    sync();
    const unsub = subscribeNotifications(sync);
    if (!globalLoaded) {
      loadFromApi();
    }
    return () => unsub();
  }, []);

  return count;
}
