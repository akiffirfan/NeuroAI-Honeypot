import { useRef, useState } from "react";

type Props = {
  modelName: string;
  drift: number;
  threshold?: number;
};

function seeded(name: string) {
  let h = 2166136261;
  for (let i = 0; i < name.length; i++) {
    h ^= name.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return () => {
    h ^= h << 13;
    h ^= h >>> 17;
    h ^= h << 5;
    return ((h >>> 0) % 1000) / 1000;
  };
}

export function DriftChart({ modelName, drift, threshold = 0.15 }: Props) {
  const rand = seeded(modelName);
  const days = 30;
  const spike = drift > threshold;

  const drifts: number[] = [];
  for (let i = 0; i < days; i++) {
    const base = Math.min(drift, threshold * 0.6);
    let v = base + (rand() - 0.5) * 0.04;
    if (spike && i >= days - 5) {
      const k = i - (days - 5);
      v = base + k * (drift * 0.18) + rand() * 0.03;
    }
    drifts.push(Math.max(0.005, v));
  }

  const vols: number[] = [];
  for (let i = 0; i < days; i++) vols.push(8 + rand() * 90);

  const W = 720;
  const H = 240;
  const padL = 44;
  const padR = 52;
  const padT = 32;
  const padB = 28;
  const innerW = W - padL - padR;
  const innerH = H - padT - padB;

  const yMax = 0.5;
  const volMax = 100;

  const x = (i: number) => padL + (i / (days - 1)) * innerW;
  const yD = (v: number) => padT + innerH - (Math.min(v, yMax) / yMax) * innerH;
  const yV = (v: number) => padT + innerH - (Math.min(v, volMax) / volMax) * innerH;

  let path = `M ${x(0)} ${yD(drifts[0])}`;
  for (let i = 1; i < days; i++) {
    const xPrev = x(i - 1);
    const xCur = x(i);
    const mid = (xPrev + xCur) / 2;
    path += ` L ${mid} ${yD(drifts[i - 1])} L ${mid} ${yD(drifts[i])} L ${xCur} ${yD(drifts[i])}`;
  }

  const thresholdY = yD(threshold);
  const yTicks = [0, 0.1, 0.2, 0.3, 0.4, 0.5];
  const vTicks = [0, 25, 50, 75, 100];
  const barW = (innerW / days) * 0.7;

  const svgRef = useRef<SVGSVGElement | null>(null);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * W;
    if (px < padL || px > padL + innerW) {
      setHoverIdx(null);
      return;
    }
    const i = Math.round(((px - padL) / innerW) * (days - 1));
    setHoverIdx(Math.max(0, Math.min(days - 1, i)));
  };

  const today = new Date();
  const dateLabel = (i: number) => {
    const d = new Date(today);
    d.setDate(today.getDate() - (days - 1 - i));
    return d.toLocaleDateString("en-US", { month: "short", day: "2-digit" });
  };

  return (
    <div className="w-full">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        className="w-full"
        style={{ height: H }}
        onMouseMove={onMove}
        onMouseLeave={() => setHoverIdx(null)}
      >
        <defs>
          <linearGradient id="dangerZone" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgb(239, 68, 68)" stopOpacity="0.22" />
            <stop offset="100%" stopColor="rgb(245, 158, 11)" stopOpacity="0.04" />
          </linearGradient>
        </defs>

        <rect x={padL} y={padT} width={innerW} height={thresholdY - padT} fill="url(#dangerZone)" />

        {yTicks.map((t) => {
          const yy = yD(t);
          return (
            <g key={`y-${t}`}>
              <line x1={padL} x2={padL + innerW} y1={yy} y2={yy} stroke="rgb(30,41,59)" strokeWidth="1" />
              <text x={padL - 8} y={yy + 3} textAnchor="end" fontSize="10" fill="rgb(100,116,139)" fontFamily="ui-monospace,monospace">
                {t.toFixed(2)}
              </text>
            </g>
          );
        })}

        {vTicks.map((t) => {
          const yy = yV(t);
          return (
            <text key={`v-${t}`} x={padL + innerW + 8} y={yy + 3} fontSize="10" fill="rgb(100,116,139)" fontFamily="ui-monospace,monospace">
              {t}k
            </text>
          );
        })}

        {vols.map(() => null)}

        <line x1={padL} x2={padL + innerW} y1={thresholdY} y2={thresholdY} stroke="rgb(245,158,11)" strokeWidth="1" strokeDasharray="5 4" />
        <text x={padL + innerW - 4} y={thresholdY - 4} textAnchor="end" fontSize="10" fill="rgb(245,158,11)" fontFamily="ui-monospace,monospace">
          threshold {threshold.toFixed(2)}
        </text>

        <path d={path} fill="none" stroke="var(--accent)" strokeWidth="1.75" strokeLinejoin="miter" />

        {drifts.map((v, i) => (
          <circle key={`pt-${i}`} cx={x(i)} cy={yD(v)} r="1.6" fill="var(--accent)" />
        ))}

        {hoverIdx !== null && (() => {
          const cx = x(hoverIdx);
          const cs = drifts[hoverIdx];
          const cv = vols[hoverIdx];
          const tipW = 168;
          const tipH = 52;
          let tx = cx + 8;
          if (tx + tipW > padL + innerW) tx = cx - tipW - 8;
          const ty = padT + 6;
          return (
            <g style={{ pointerEvents: "none" }}>
              <line x1={cx} x2={cx} y1={padT} y2={padT + innerH} stroke="rgb(100,116,139)" strokeWidth="1" strokeDasharray="2 3" />
              <circle cx={cx} cy={yD(cs)} r="3" fill="var(--accent)" stroke="rgb(15,23,42)" strokeWidth="1.5" />
              <rect x={tx} y={ty} width={tipW} height={tipH} rx="4" fill="rgb(2,6,23)" stroke="rgb(51,65,85)" />
              <text x={tx + 8} y={ty + 16} fontSize="10" fill="rgb(148,163,184)" fontFamily="ui-monospace,monospace">
                {dateLabel(hoverIdx)}
              </text>
              <text x={tx + 8} y={ty + 31} fontSize="11" fill="white" fontFamily="ui-monospace,monospace">
                Score: <tspan fill="var(--accent)">{cs.toFixed(2)}</tspan>
              </text>
              <text x={tx + 8} y={ty + 45} fontSize="11" fill="white" fontFamily="ui-monospace,monospace">
                Vol: <tspan fill="rgb(148,163,184)">{cv.toFixed(1)}k</tspan>
              </text>
            </g>
          );
        })()}

        <text x={padL} y={H - 8} fontSize="10" fill="rgb(100,116,139)" fontFamily="ui-monospace,monospace">30 days ago</text>
        <text x={padL + innerW} y={H - 8} textAnchor="end" fontSize="10" fill="rgb(100,116,139)" fontFamily="ui-monospace,monospace">Today</text>
        <text x={padL} y={14} fontSize="10" fill="rgb(148,163,184)" fontFamily="ui-monospace,monospace" letterSpacing="0.12em">DRIFT SCORE</text>
        <text x={padL + innerW} y={14} textAnchor="end" fontSize="10" fill="rgb(148,163,184)" fontFamily="ui-monospace,monospace" letterSpacing="0.12em">INFERENCE VOLUME (k/day)</text>
      </svg>
    </div>
  );
}
