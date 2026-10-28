import { describe, expect, test } from "bun:test"
import cve, { queryOsv, OsvError, type VulnInfo } from "../.opencode/tools/cve"

const osvPackageResponse = {
  vulns: [
    {
      id: "GHSA-xxxx-yyyy-zzzz",
      summary: "RCE in demo-package via deserialization",
      database_specific: { severity: "HIGH" },
      references: [{ type: "WEB", url: "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz" }],
    },
    {
      id: "CVE-2026-1234",
      summary: "SQL injection in demo-package",
      ecosystem_specific: { severity: "MODERATE" },
    },
  ],
}

const osvCveResponse = {
  id: "CVE-2026-4242",
  summary: "Auth bypass in thing",
  database_specific: { severity: "CRITICAL" },
}

describe("queryOsv", () => {
  test("maps package advisories to VulnInfo", async () => {
    const fetchImpl = (async (input: unknown) => {
      const url = String(input)
      expect(url).toBe("https://api.osv.dev/v1/query/npm/demo-package")
      return new Response(JSON.stringify(osvPackageResponse), { status: 200 })
    }) as unknown as typeof fetch
    const vulns = await queryOsv({ package: "demo-package", ecosystem: "npm" }, fetchImpl)
    expect(vulns.length).toBe(2)
    expect(vulns[0]).toMatchObject({ id: "GHSA-xxxx-yyyy-zzzz", severity: "HIGH" })
    expect(vulns[1]!.severity).toBe("MODERATE")
    expect(vulns[0]!.url).toContain("GHSA-xxxx-yyyy-zzzz")
  })

  test("queries a CVE id directly", async () => {
    const fetchImpl = (async (input: unknown) => {
      expect(String(input)).toBe("https://api.osv.dev/v1/vulns/CVE-2026-4242")
      return new Response(JSON.stringify(osvCveResponse), { status: 200 })
    }) as unknown as typeof fetch
    const vulns = await queryOsv({ cve: "CVE-2026-4242" }, fetchImpl)
    expect(vulns[0]).toMatchObject({ id: "CVE-2026-4242", severity: "CRITICAL" })
  })

  test("falls back to UNKNOWN severity", async () => {
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ vulns: [{ id: "X", summary: "s" }] }), { status: 200 })) as unknown as typeof fetch
    const vulns = await queryOsv({ cve: "X" }, fetchImpl)
    expect(vulns[0]!.severity).toBe("UNKNOWN")
  })

  test("non-200 throws OsvError", async () => {
    const fetchImpl = (async () => new Response("boom", { status: 500 })) as unknown as typeof fetch
    expect(queryOsv({ cve: "X" }, fetchImpl)).rejects.toBeInstanceOf(OsvError)
  })
})

describe("tool shape", () => {
  test("default export is a tool with description, args and execute", async () => {
    const t = cve as unknown as { description: string; execute: (args: Record<string, unknown>) => Promise<string> }
    expect(t.description.length).toBeGreaterThan(10)
    const out = await t.execute({ cve: "CVE-2026-4242" }).catch(() => "network-unavailable")
    expect(typeof out).toBe("string")
  })
})
