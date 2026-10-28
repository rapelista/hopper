/** Shared v2 plugin-context mock capturing registrations (kernel + rpc tests). */
export function makeMockCtx(projectDir: string, permission?: {
  assert: (input: unknown) => Promise<void>
}) {
  const addedTools: Array<{ name: string; description: string; input: unknown; execute: unknown }> = []
  const addedSkills: Array<{ id: string; name: string; description?: string; path: string; content: string }> = []
  const addedCommands: Array<{ name: string; description?: string; execute: (input: any) => Promise<void> }> = []
  const agentUpdates: Array<{ id: string; fn: (agent: any) => void }> = []
  const agentSwitches: unknown[] = []
  const prompts: unknown[] = []
  const toolHooks: Record<string, (event: unknown) => unknown> = {}
  const sessionHooks: Record<string, (event: unknown) => unknown> = {}
  const rpcDefs: unknown[] = []
  const rpcHandlers: Record<string, unknown> = {}
  const rpcEvents: Array<{ name: string; data: unknown }> = []
  const reg = { dispose: async () => {} }
  const editor = {
    list: () => [],
    get: () => undefined,
    add: (t: { name: string; description: string; input: unknown; execute: unknown }) => addedTools.push(t),
    update: () => {},
    remove: () => {},
    namespace: () => {},
  }
  const skillEditor = {
    list: () => [],
    get: () => undefined,
    add: (s: { id: string; name: string; description?: string; path: string; content: string }) => addedSkills.push(s),
    update: () => {},
    remove: () => {},
  }
  const agentEditor = {
    list: () => [],
    get: () => undefined,
    default: () => {},
    update: (id: string, fn: (agent: any) => void) => agentUpdates.push({ id, fn }),
    remove: () => {},
  }
  const commandEditor = {
    add: (c: { name: string; description?: string; execute: (input: any) => Promise<void> }) => addedCommands.push(c),
  }
  const ctx = {
    location: { directory: projectDir, project: { id: "p", directory: projectDir, canonical: projectDir } },
    tool: {
      transform: async (cb: (e: typeof editor) => void) => {
        cb(editor)
        return reg
      },
      hook: async (name: string, cb: (event: unknown) => unknown) => {
        toolHooks[name] = cb
        return reg
      },
      list: async () => [],
    },
    skill: {
      transform: async (cb: (e: typeof skillEditor) => void) => {
        cb(skillEditor)
        return reg
      },
      reload: async () => {},
    },
    agent: {
      transform: async (cb: (e: typeof agentEditor) => void) => {
        cb(agentEditor)
        return reg
      },
      reload: async () => {},
    },
    command: {
      transform: async (cb: (e: typeof commandEditor) => void) => {
        cb(commandEditor)
        return reg
      },
      list: async () => [],
      reload: async () => {},
    },
    session: {
      hook: async (name: string, cb: (event: unknown) => unknown) => {
        sessionHooks[name] = cb
        return reg
      },
      get: async () => ({ agent: "build" }),
      switchAgent: async (input: unknown) => {
        agentSwitches.push(input)
      },
      prompt: async (input: unknown) => {
        prompts.push(input)
        return {}
      },
    },
    rpc: {
      register: async (def: unknown, handlers: Record<string, unknown>) => {
        rpcDefs.push(def)
        Object.assign(rpcHandlers, handlers)
        return {
          events: {
            emit: async (name: string, data: unknown) => {
              rpcEvents.push({ name, data })
            },
          },
          dispose: async () => {},
        }
      },
    },
    ...(permission ? { permission } : {}),
  }
  return {
    ctx,
    addedTools,
    addedSkills,
    addedCommands,
    agentUpdates,
    agentSwitches,
    prompts,
    toolHooks,
    sessionHooks,
    rpcDefs,
    rpcHandlers,
    rpcEvents,
  }
}
