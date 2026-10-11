import { z } from "zod";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
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
    const raw = await this.transport.call("execute_python", request);
    const execution = z
      .object({
        result: jsonValueSchema,
        stdout: z.string(),
        stderr: z.string(),
      })
      .parse(raw);
    const source = { tool: "execute_python", arguments: request, result: raw };
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
