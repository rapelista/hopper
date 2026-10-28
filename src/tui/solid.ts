/**
 * solid-js resolves to the non-reactive server build under bun's node/worker
 * condition (`dist/server.cjs`) — every signal silently stops notifying, which
 * is exactly how a "frozen tab" bug looks. Import the client build explicitly
 * instead. Cross-instance subscriptions are fine even when the host provides
 * its own solid: notification is just observer registration on the signal.
 */
export { createSignal, createRoot, createMemo, For, Show } from "solid-js/dist/solid.js"
