// Legacy shim — replaced by src/lib/error-capture.ts.
// This file exists only so that any residual import of reportLovableError
// resolves without a TypeScript error during the transition period.
export function reportLovableError(
  error: unknown,
  context: Record<string, unknown> = {},
) {
  if (typeof console !== "undefined") {
    console.error("[neuro-error]", error, context);
  }
}
