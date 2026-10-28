import { Rpc } from "@opencode/plugin/rpc"

/**
 * The typed contract between the Hopper server part (kernel: operation store,
 * findings ledger, scope/opsec state) and every client surface — today the TUI
 * part, tomorrow anything speaking `client.rpc(Hopper)`.
 *
 * Schemas are plain JSON Schema on purpose: no validator dependency, the
 * kernel stays zero-dep.
 */

export interface OperationSummary {
  id: string
  name: string
  target: string
  createdAt: string
}

export interface FindingSummary {
  id: string
  title: string
  severity: string
  status: string
  target: string
  createdAt: string
}

export interface FindingsCounts {
  candidate: number
  observed: number
  verified: number
  reportable: number
  rejected: number
  stale: number
}

export interface OperationStatusResult {
  operation: OperationSummary | null
  opsec: "normal" | "strict"
  findings: FindingsCounts
}

export interface OperationChangedData {
  operationId: string | null
}

export interface FindingChangedData {
  operationId: string
  findingId: string
  status: string
}

/** Best-effort mutation notification the server part forwards as rpc events. */
export type HopperNotify = (
  event: { type: "operation.changed"; data: OperationChangedData } | { type: "finding.changed"; data: FindingChangedData },
) => void

const operationSummarySchema = {
  type: "object",
  properties: {
    id: { type: "string" },
    name: { type: "string" },
    target: { type: "string" },
    createdAt: { type: "string" },
  },
  required: ["id", "name", "target", "createdAt"],
  additionalProperties: false,
} as const

const findingsCountsSchema = {
  type: "object",
  properties: {
    candidate: { type: "number" },
    observed: { type: "number" },
    verified: { type: "number" },
    reportable: { type: "number" },
    rejected: { type: "number" },
    stale: { type: "number" },
  },
  required: ["candidate", "observed", "verified", "reportable", "rejected", "stale"],
  additionalProperties: false,
} as const

export const Hopper = Rpc.define({
  id: "hopper",
  methods: {
    operationStatus: {
      input: { type: "object", properties: {}, additionalProperties: false },
      output: {
        type: "object",
        properties: {
          operation: { anyOf: [operationSummarySchema, { type: "null" }] },
          opsec: { type: "string", enum: ["normal", "strict"] },
          findings: findingsCountsSchema,
        },
        required: ["operation", "opsec", "findings"],
        additionalProperties: false,
      },
    },
    findings: {
      input: {
        type: "object",
        properties: { operationId: { type: "string" } },
        additionalProperties: false,
      },
      output: {
        type: "object",
        properties: {
          items: {
            type: "array",
            items: {
              type: "object",
              properties: {
                id: { type: "string" },
                title: { type: "string" },
                severity: { type: "string" },
                status: { type: "string" },
                target: { type: "string" },
                createdAt: { type: "string" },
              },
              required: ["id", "title", "severity", "status", "target", "createdAt"],
              additionalProperties: false,
            },
          },
        },
        required: ["items"],
        additionalProperties: false,
      },
    },
    createOperation: {
      input: {
        type: "object",
        properties: {
          name: { type: "string" },
          target: { type: "string" },
        },
        required: ["name", "target"],
        additionalProperties: false,
      },
      output: {
        type: "object",
        properties: { operation: operationSummarySchema },
        required: ["operation"],
        additionalProperties: false,
      },
    },
    setOpsec: {
      input: {
        type: "object",
        properties: { level: { type: "string", enum: ["normal", "strict"] } },
        required: ["level"],
        additionalProperties: false,
      },
      output: {
        type: "object",
        properties: { opsec: { type: "string", enum: ["normal", "strict"] } },
        required: ["opsec"],
        additionalProperties: false,
      },
      errors: {
        no_scope: {
          type: "object",
          properties: { message: { type: "string" } },
          required: ["message"],
          additionalProperties: false,
        },
      },
    },
  },
  events: {
    "operation.changed": {
      schema: {
        type: "object",
        properties: { operationId: { anyOf: [{ type: "string" }, { type: "null" }] } },
        required: ["operationId"],
        additionalProperties: false,
      },
    },
    "finding.changed": {
      schema: {
        type: "object",
        properties: {
          operationId: { type: "string" },
          findingId: { type: "string" },
          status: { type: "string" },
        },
        required: ["operationId", "findingId", "status"],
        additionalProperties: false,
      },
    },
  },
})
