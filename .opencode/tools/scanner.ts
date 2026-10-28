import { tool } from "@opencode-ai/plugin"
import { mkdirSync } from "node:fs"
import { loadScope, assertInScope, checkUrl, ScopeError } from "../lib/scope"

export type ScannerMode = "portscan" | "dirfuzz" | "techscan"

export interface ScannerArgs {
  mode: ScannerMode
  target: string
  extra?: string[]
}

export const COMMON_WORDLIST = `${process.env.HOME ?? "~"}/.cache/hopper/wordlists/common.txt`

export function buildCommand(mode: ScannerMode, target: string, extra: string[] = []): {
  bin: string
  argv: string[]
} {
  switch (mode) {
    case "portscan":
      return { bin: "nmap", argv: ["-sV", "-T4", target, ...extra] }
    case "dirfuzz":
      return { bin: "ffuf", argv: ["-w", COMMON_WORDLIST, "-u", target, ...extra] }
    case "techscan":
      return { bin: "whatweb", argv: [target, ...extra] }
  }
}

async function defaultSpawn(cmd: { bin: string; argv: string[] }): Promise<{ exitCode: number; stdout: string }> {
  const proc = Bun.spawn([cmd.bin, ...cmd.argv], {
    stdout: "pipe",
    stderr: "pipe",
    stdin: "ignore",
  })
  const timer = setTimeout(() => proc.kill(), 300_000)
  const stdout = await new Response(proc.stdout).text()
  const stderr = await new Response(proc.stderr).text()
  const exitCode = await proc.exited
  clearTimeout(timer)
  const combined = (stdout + (stderr ? `\n${stderr}` : "")).slice(0, 128 * 1024)
  return { exitCode, stdout: combined }
}

function scopeTarget(mode: ScannerMode, target: string): string {
  // portscan takes a bare host/CIDR; url-style targets are normalized to hostname
  if (mode === "portscan" && /^[a-z]+:\/\//i.test(target)) {
    return new URL(target).hostname
  }
  return target
}

export async function runScan(
  configDir: string,
  args: ScannerArgs,
  run: (cmd: { bin: string; argv: string[] }) => Promise<{ exitCode: number; stdout: string }> = defaultSpawn,
): Promise<{ command: string; exitCode: number; stdout: string }> {
  const scope = loadScope(configDir) // fail-closed: null scope is rejected below

  if (args.mode === "portscan") {
    assertInScope(scope, scopeTarget("portscan", args.target))
  } else {
    checkUrl(scope, scopeTarget(args.mode, args.target))
  }

  const cmd = buildCommand(args.mode, scopeTarget(args.mode, args.target), args.extra)
  // argv-level scope enforcement: no input-file lists, and every URL token must be in scope
  for (let i = 0; i < cmd.argv.length; i++) {
    const a = cmd.argv[i]!
    if (a === "-iL" || a === "--input-file") {
      throw new ScopeError(`scope guard: input-file lists cannot be scope-verified (${cmd.argv[i + 1] ?? ""})`)
    }
    if (/^https?:\/\//.test(a)) checkUrl(scope, a)
  }
  if (Bun.which(cmd.bin) === null) {
    return {
      command: `${cmd.bin} ${cmd.argv.join(" ")}`,
      exitCode: 127,
      stdout: `${cmd.bin} is not installed. Install it first:\n  brew install ${cmd.bin}\n  # or: apt install ${cmd.bin}`,
    }
  }

  const result = await run(cmd)
  return {
    command: `${cmd.bin} ${cmd.argv.join(" ")}`,
    exitCode: result.exitCode,
    stdout: result.stdout.slice(0, 128 * 1024),
  }
}

export default tool({
  description:
    "Active web/network recon: portscan (nmap service scan), dirfuzz (ffuf directory brute-force with FUZZ placeholder in the target URL), and techscan (whatweb fingerprinting). Targets are checked against the active operation scope — an out-of-scope target or a missing scope refuses the scan (fail-closed). Non-zero exit codes are returned as signal, not errors. Use before drilling with http-request or bash.",
  args: {
    mode: tool.schema.enum(["portscan", "dirfuzz", "techscan"]).describe("Recon mode"),
    target: tool.schema
      .string()
      .describe("Host or CIDR (portscan) or absolute URL (dirfuzz/techscan); must be in scope"),
    extra: tool.schema.array(tool.schema.string()).optional().describe("Extra CLI flags for the wrapped binary"),
  },
  async execute(args, context) {
    const configDir = `${context.worktree ?? context.directory}/.opencode`
    const res = await runScan(configDir, { mode: args.mode, target: args.target, extra: args.extra })
    return [
      `$ ${res.command}`,
      `exit: ${res.exitCode}`,
      "",
      res.stdout || "(no output)",
    ].join("\n")
  },
})

// ensure the wordlist directory exists so first-run ffuf has a stable path
mkdirSync(COMMON_WORDLIST.slice(0, COMMON_WORDLIST.lastIndexOf("/")), { recursive: true })
