/** Theme tokens the Hopper surfaces use, resolved defensively against the real nested shape. */
export interface HopperTheme {
  text: {
    base?: string
    muted?: string
    feedback?: {
      error?: { base?: string }
      warning?: { base?: string }
      success?: { base?: string }
    }
  }
}

export type SemanticToken = "error" | "warning" | "base" | "muted"

/** `theme.text.feedback.error.base` etc., flattened for our surfaces; "" when absent. */
export function resolveToken(theme: HopperTheme | undefined, token: SemanticToken): string {
  if (!theme) return ""
  if (token === "error") return theme.text.feedback?.error?.base ?? ""
  if (token === "warning") return theme.text.feedback?.warning?.base ?? ""
  if (token === "base") return theme.text.base ?? ""
  return theme.text.muted ?? ""
}
