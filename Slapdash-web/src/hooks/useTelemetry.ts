import { useEffect } from "react";
import { beacon } from "@/lib/api/telemetry";
import { useLocation } from "@tanstack/react-router";

export function useTelemetry() {
  const location = useLocation();

  useEffect(() => {
    beacon("page_view", { path: location.pathname });
  }, [location.pathname]);

  return {
    track: (event: string, props?: Record<string, unknown>) =>
      beacon(event, props ?? {}),
    identify: (_props?: Record<string, unknown>) => {},
  };
}

export default useTelemetry;
