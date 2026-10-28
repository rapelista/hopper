import { Plugin } from "@opencode/plugin/tui"
import { registerStatus, type StatusCtx } from "./tui/status"
import { registerPanel, type PanelCtx } from "./tui/panel"
import { registerCommands, type CommandsCtx } from "./tui/commands"
import { registerNotifications, type NotificationsCtx } from "./tui/notifications"

/**
 * Hopper TUI part — the Hopper UX layer, built the way opencode v2 builds its
 * own features: one focused module per surface, composed here, every
 * subscription and layer cleaned up on unload (hot-reload safe).
 */
export default Plugin.define({
  id: "hopper-tui",
  setup(context) {
    const cleanups: Array<() => void> = []
    // rpc calls must carry the location or the server consults its default registry
    const location = context.location ?? context.data.location.default()

    cleanups.push(
      registerStatus({
        ui: context.ui,
        client: context.client,
        data: context.data,
        storage: context.storage,
        theme: context.theme,
        location,
      } as unknown as StatusCtx).cleanup,
    )

    cleanups.push(
      registerPanel({
        ui: context.ui,
        client: context.client,
        keymap: context.keymap,
        theme: context.theme,
        location,
      } as unknown as PanelCtx).cleanup,
    )

    cleanups.push(
      registerCommands({
        keymap: context.keymap,
        ui: context.ui,
        client: context.client,
        data: context.data,
        session: { prompt: (input: { sessionID: string; text: string }) => context.client.session.prompt(input) },
        location,
      } as unknown as CommandsCtx).cleanup,
    )

    cleanups.push(registerNotifications({ data: context.data, attention: context.attention } as unknown as NotificationsCtx).cleanup)

    return () => {
      for (const cleanup of cleanups) cleanup()
    }
  },
})
