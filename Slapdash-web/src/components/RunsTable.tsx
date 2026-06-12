import { useState } from "react";
import { X } from "lucide-react";

// Supports both the legacy mock shape and the API response shape.
export type RunRow = {
  // API shape (canonical)
  run_id?: string;
  model_name?: string;
  status: string;
  duration_min?: number | null;
  gpu_hours?: number | null;
  started_by?: string;
  started_at?: string;
  error_log?: string | null;
  // Legacy mock shape (kept for backward compat during transition)
  id?: string;
  model?: string;
  duration?: string;
  gpu?: string;
  by?: string;
  started?: string;
};

/** Cheap seeded int from a string — deterministic per run_id. */
function seededInt(seed: string, salt: number): number {
  let h = salt * 2654435761;
  for (let i = 0; i < seed.length; i++) h = Math.imul(h ^ seed.charCodeAt(i), 2246822519);
  return (h >>> 0);
}

function deriveHyperparams(runId: string): string {
  const pick = <T,>(arr: T[], salt: number): T => arr[seededInt(runId, salt) % arr.length];

  const lr = pick([1e-5, 2e-5, 3e-5, 5e-5, 8e-5, 1e-4, 2e-4], 1);
  const bs = pick([8, 16, 32, 64, 128], 2);
  const epochs = pick([3, 5, 8, 10, 15, 20, 30, 40], 3);
  const warmup = pick([100, 200, 300, 500, 750, 1000], 4);
  const wd = pick([0.0, 0.001, 0.01, 0.05, 0.1], 5);
  const opt = pick(["adamw", "adam", "adafactor", "sgd"], 6);
  const sched = pick(["cosine", "linear", "constant_with_warmup", "cosine_with_restarts"], 7);
  const grad_acc = pick([1, 2, 4, 8], 8);

  return JSON.stringify({
    learning_rate: lr,
    batch_size: bs,
    epochs,
    warmup_steps: warmup,
    weight_decay: wd,
    optimizer: opt,
    lr_scheduler: sched,
    gradient_accumulation_steps: grad_acc,
  }, null, 2);
}

function formatDuration(min: number | null | undefined): string {
  if (min == null) return "—";
  const h = Math.floor(min / 60);
  const m = min % 60;
  return `${h}h ${String(m).padStart(2, "0")}m`;
}

function adaptRun(r: RunRow) {
  return {
    id: r.run_id ?? r.id ?? "—",
    model: r.model_name ?? r.model ?? "—",
    status: r.status,
    duration: r.duration_min != null ? formatDuration(r.duration_min) : (r.duration ?? "—"),
    gpu: r.gpu_hours != null ? `${r.gpu_hours}h` : (r.gpu ?? "—"),
    by: r.started_by ?? r.by ?? "—",
    started: r.started_at ? r.started_at.replace("T", " ").slice(0, 16) : (r.started ?? "—"),
    error_log: r.error_log ?? null,
    _raw: r,
  };
}

const STATUS_BADGE: Record<string, string> = {
  Running: "nro-badge--success-glow",
  Completed: "nro-badge--slate",
  Failed: "nro-badge--danger-glow",
  Queued: "nro-badge--slate",
};

export function RunsTable({ runs }: { runs: RunRow[] }) {
  const [open, setOpen] = useState<ReturnType<typeof adaptRun> | null>(null);
  const adapted = runs.map(adaptRun);
  return (
    <>
      <div className="nro-card overflow-hidden">
        <table className="w-full">
          <thead className="bg-[color:var(--surface)]">
            <tr>
              {["Run ID", "Model", "Status", "Duration", "GPU Hours", "Started By", "Started At"].map((h) => (
                <th key={h} className="nro-th">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {adapted.map((r) => (
              <tr
                key={r.id}
                onClick={() => setOpen(r)}
                className="nro-row cursor-pointer"
              >
                <td className="nro-td font-mono text-[13px]">{r.id}</td>
                <td className="nro-td font-mono text-[13px]">{r.model}</td>
                <td className="nro-td">
                  <span className={`nro-badge ${STATUS_BADGE[r.status] ?? "nro-badge--slate"}`}>
                    {r.status}
                  </span>
                </td>
                <td className="nro-td">{r.duration}</td>
                <td className="nro-td">{r.gpu}</td>
                <td className="nro-td font-mono text-[13px]">{r.by}</td>
                <td className="nro-td text-[color:var(--text-secondary)]">{r.started}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {open && <RunDetail run={open} onClose={() => setOpen(null)} />}
    </>
  );
}

function RunDetail({
  run,
  onClose,
}: {
  run: ReturnType<typeof adaptRun>;
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 z-40 flex" onClick={onClose}>
      <div className="flex-1 bg-black/40" />
      <aside
        className="h-full overflow-y-auto bg-[color:var(--surface)] border-l border-[color:var(--border)]"
        style={{ width: 380 }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-5 border-b border-[color:var(--border)]">
          <div>
            <div className="font-mono text-[16px] text-white">{run.id}</div>
            <div className="text-[14px] text-[color:var(--text-secondary)] mt-0.5">
              {run.model}
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[color:var(--text-secondary)] hover:text-white"
          >
            <X size={20} />
          </button>
        </div>
        <div className="p-5 space-y-6">
          <span className={`nro-badge ${STATUS_BADGE[run.status] ?? "nro-badge--slate"}`}>
            {run.status}
          </span>

          {run.error_log && (
            <div>
              <div className="nro-label mb-2 text-[color:var(--danger)]">Error Log</div>
              <pre
                className="font-mono text-[12px] p-3 rounded-md overflow-x-auto whitespace-pre-wrap"
                style={{ background: "var(--canvas)", color: "var(--danger)" }}
              >
                {run.error_log}
              </pre>
            </div>
          )}

          <div>
            <div className="nro-label mb-2">Hyperparameters</div>
            <pre
              className="font-mono text-[12px] p-3 rounded-md overflow-x-auto"
              style={{ background: "var(--canvas)" }}
            >
              {deriveHyperparams(run.id ?? run.run_id ?? "")}
            </pre>
          </div>

          <div>
            <div className="nro-label mb-2">Checkpoint</div>
            <div className="font-mono text-[12px] break-all text-[color:var(--text-primary)]">
              s3://cyvera-ml-artifacts/runs/{run.id}/checkpoint-latest/
            </div>
            <div className="mt-2 text-[12px] text-[color:var(--text-secondary)]">
              Node assignment:{" "}
              <span className="font-mono">neuro-train-01.internal</span>
            </div>
          </div>

          <div>
            <div className="nro-label mb-2">GPU Nodes Used</div>
            <div className="font-mono text-[12px] text-[color:var(--text-primary)]">
              neuro-train-01, neuro-train-02
            </div>
          </div>

          <a
            href={`/api/v2/runs/${run.id}/checkpoint`}
            download={`checkpoint-${run.id}-latest.bin`}
            className="nro-btn-secondary w-full text-center block"
          >
            Download checkpoint
          </a>
        </div>
      </aside>
    </div>
  );
}
