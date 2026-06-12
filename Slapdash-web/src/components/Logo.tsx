import { Link } from "@tanstack/react-router";

export function Logo({
  size = 18,
  showByline = true,
  className = "",
}: {
  size?: number;
  showByline?: boolean;
  className?: string;
}) {
  return (
    <Link to="/" className={`flex items-start gap-2 ${className}`}>
      <span
        aria-hidden
        className="inline-flex items-center justify-center rounded-md"
        style={{
          width: size + 6,
          height: size + 6,
          background:
            "linear-gradient(135deg, var(--accent) 0%, #059669 100%)",
        }}
      >
        <svg
          width={size - 2}
          height={size - 2}
          viewBox="0 0 16 16"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <circle cx="3" cy="4" r="1.6" fill="#fff" />
          <circle cx="13" cy="4" r="1.6" fill="#fff" />
          <circle cx="8" cy="12" r="1.6" fill="#fff" />
          <path
            d="M3 4 L8 12 L13 4"
            stroke="#fff"
            strokeWidth="1.2"
            opacity="0.85"
          />
        </svg>
      </span>
      <span className="flex flex-col leading-none">
        <span
          className="font-bold text-[color:var(--text-primary)]"
          style={{ fontSize: size }}
        >
          Neuro
        </span>
        {showByline && (
          <span className="text-[color:var(--text-secondary)] text-[11px] mt-0.5">
            by Cyveera
          </span>
        )}
      </span>
    </Link>
  );
}
