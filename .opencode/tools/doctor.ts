import { tool } from "@opencode-ai/plugin"

export const TOOLS = ["nmap", "nuclei", "ffuf", "gobuster", "nikto", "whatweb", "sqlmap", "httpx"]

export interface DoctorReport {
  available: string[]
  missing: string[]
}

export function checkTools(
  names: string[],
  whichFn: (cmd: string) => string | null = (c) => Bun.which(c),
): DoctorReport {
  const available: string[] = []
  const missing: string[] = []
  for (const name of names) {
    if (whichFn(name) !== null) available.push(name)
    else missing.push(name)
  }
  return { available, missing }
}

export default tool({
  description:
    "Run a local environment probe for Hopper. Reports the bun runtime, OS/arch, and which security tools are on PATH (nmap, nuclei, ffuf, gobuster, nikto, whatweb, sqlmap, httpx). Missing tools are listed with install hints but never fail the probe. Takes no arguments. Returns a human-readable markdown report. Use when the operator runs /doctor, reports environment issues, or before promising a scan that depends on a specific binary.",
  args: {},
  async execute() {
    const report = checkTools(TOOLS)
    const lines: string[] = []
    lines.push("# Doctor — environment probe")
    lines.push("")
    lines.push(`- runtime: bun ${Bun.version} on ${process.platform}/${process.arch}`)
    lines.push(`- tools available (${report.available.length}): ${report.available.join(", ") || "none"}`)
    lines.push(`- tools missing (${report.missing.length}): ${report.missing.join(", ") || "none"}`)
    if (report.missing.length > 0) {
      lines.push("")
      lines.push("Install the missing toolbelt (pick what you need):")
      lines.push("")
      lines.push("```bash")
      lines.push(`brew install ${report.missing.join(" ")}`)
      lines.push("# or on Debian/Kali: apt install " + report.missing.join(" "))
      lines.push("```")
      lines.push("")
      lines.push("Missing tools never fail the probe — Hopper degrades and tells the agent what is unavailable.")
    }
    return lines.join("\n")
  },
})
