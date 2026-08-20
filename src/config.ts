import type { HydraClientOptions } from "./hydraClient.js";

/**
 * Every entry point (cli.ts, gateCli.ts, incidentCli.ts, webServer.ts)
 * needs the same five HydraDB connection settings, sourced from either
 * CLI flags or environment variables with the same defaults. This was
 * copy-pasted four times before — the same env var names, the same
 * defaults, drifting out of sync would have been a real risk (e.g. one
 * file's default token typo'd differently from another's). Single source
 * of truth now; every entry point calls this instead of re-declaring it.
 */
export function loadHydraConfig(overrides: Partial<HydraClientOptions> = {}): HydraClientOptions {
  return {
    baseUrl: overrides.baseUrl ?? process.env.HYDRA_BASE_URL ?? "http://127.0.0.1:8443",
    token: overrides.token ?? process.env.HYDRA_TOKEN ?? "local-development-token-32-bytes",
    namespace: overrides.namespace ?? process.env.HYDRA_NAMESPACE ?? "default",
    graph: overrides.graph ?? process.env.HYDRA_GRAPH ?? "default",
    cellId: overrides.cellId ?? process.env.HYDRA_CELL ?? "cell-0",
    timeoutMs: overrides.timeoutMs,
  };
}
