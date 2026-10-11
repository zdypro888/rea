import { z } from "zod";
import {
  AnalysisProtocolError,
  AnalysisTimeoutError,
  AnalysisCancelledError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { IdaToolFailure, type IdaMcpConnection } from "./IdaMcpConnection.js";
import { officialIdaQuery } from "./OfficialIdaQuery.js";

export const OFFICIAL_IDA_TOOLS = [
  "open_database",
  "list_databases",
  "close_database",
  "execute_python",
  "reference",
] as const;

/** Explicit official protocol, not a community supervisor impersonation.
 * Only fixed, read-only queries are adapted. Lifecycle calls retain Nexus semantics.
 */
export class OfficialIdaConnection implements IdaMcpConnection {
  readonly official = true;
  constructor(
    private readonly transport: IdaMcpConnection,
    private readonly timeoutMs: number,
  ) {}

  async connect(): Promise<readonly string[]> {
    const tools = await this.transport.connect();
    const missing = OFFICIAL_IDA_TOOLS.filter((t) => !tools.includes(t));
    if (missing.length)
      throw new AnalysisProtocolError(
        `Official IDA MCP is missing tools: ${missing.join(", ")}. Use HexRaysSA/ida-mcp, not ida-pro-mcp.`,
      );
    return tools;
  }

  toolParameters(name: string): readonly string[] | undefined {
    if (name === "decompile")
      return ["addr", "offset", "max_lines", "database"];
    if (name === "analysis_advance") return ["budget_ms", "database"];
    return this.transport.toolParameters?.(name);
  }

  async call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ): Promise<JsonValue> {
    if ((OFFICIAL_IDA_TOOLS as readonly string[]).includes(name))
      return this.transport.call(name, args);
    const database = z.string().min(1).parse(args.database);
    const code = officialIdaQuery(name, args);
    const request = {
      code,
      instance_id: database,
      timeout: this.timeoutMs / 1000,
    };
    // Nexus can report incomplete autoanalysis before query execution.
    // Retry that explicit pre-execution barrier failure once only;
    // never retry user code failures or accept an unanalysed observation.
    const failures: string[] = [];
    const deadline = performance.now() + this.timeoutMs;
    let raw: JsonValue;
    for (;;) {
      if (signal?.aborted) throw new AnalysisCancelledError(name);
      try {
        raw = await this.transport.call("execute_python", request);
        break;
      } catch (cause) {
        if (signal?.aborted) throw new AnalysisCancelledError(name, { cause });
        // Shape/truncation errors remain protocol failures, not engine failures.
        if (!(cause instanceof IdaToolFailure)) throw cause;
        const message = cause.message;
        if (
          failures.length === 0 &&
          cause.upstreamMessage ===
            "Autoanalysis was cancelled before completion" &&
          performance.now() < deadline
        ) {
          failures.push(message);
          request.timeout = Math.max(
            0.001,
            (deadline - performance.now()) / 1000,
          );
          continue;
        }
        const timeout = cause.upstreamMessage.match(
          /^(?:execute|analysis) timed out after (\d+(?:\.\d+)?)s(?:\n|$)/u,
        );
        if (timeout)
          throw new AnalysisTimeoutError(name, Number(timeout[1]) * 1000, {
            cause,
          });
        if (
          /^(?:execute|analysis) was cancelled(?:\n|$)/u.test(
            cause.upstreamMessage,
          )
        )
          throw new AnalysisCancelledError(name, { cause });
        throw new ProviderAdapterError("ida", name, {
          cause,
          userMessage: `Official IDA ${name} failed: ${message}`,
          diagnostics: { reason: message, prior_barrier_failures: failures },
        });
      }
    }
    const execution = z
      .object({
        result: jsonValueSchema,
        stdout: z.string(),
        stderr: z.string(),
      })
      .parse(raw);
    const source = {
      tool: "execute_python",
      arguments: request,
      result: raw,
      ...(failures.length ? { prior_barrier_failures: failures } : {}),
    };
    // Each modern-shaped observation keeps the actual official request/result.
    const annotate = (v: JsonValue): JsonValue => {
      if (v === null || typeof v !== "object" || Array.isArray(v))
        throw new AnalysisProtocolError(
          "Official IDA query omitted an object result.",
        );
      return { ...v, official_source: source };
    };
    return Array.isArray(execution.result)
      ? execution.result.map(annotate)
      : annotate(execution.result);
  }

  serverInfo(): JsonValue {
    return this.transport.serverInfo();
  }
  close(): Promise<void> {
    return this.transport.close();
  }
}
