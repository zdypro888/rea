import { z } from "zod";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisProtocolError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import type { IdaConfiguration } from "./IdaConfiguration.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import { IdaOperationRunner } from "./IdaOperationRunner.js";
import type { IdaOperation } from "./IdaProviderCapabilities.js";
import { modernHealthSchema } from "./IdaProtocolValues.js";
import { sameIdaHostPath } from "./IdaWorkspace.js";

export const idaAnalysisReady = (
  mode: IdaConfiguration["mode"],
  metadata: JsonValue,
): boolean =>
  mode === "attached" ||
  modernHealthSchema.parse(metadata).auto_analysis_ready === true;

interface RecoveryContext {
  operation: IdaOperation;
  options: ExecutionOptions | undefined;
  deadline: number;
  observations: JsonValue[];
}

/** Only advance a bound private worker; queries from unstable analysis are rerun. */
export class IdaAnalysisRecovery {
  constructor(
    private readonly connection: IdaMcpConnection,
    private readonly config: Pick<IdaConfiguration, "mode" | "timeoutMs">,
    private readonly binding: {
      database: string | undefined;
      observe: () => Promise<JsonValue>;
    },
  ) {}

  async run(
    operation: IdaOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions | undefined,
  ) {
    const context: RecoveryContext = {
      operation,
      options,
      deadline: performance.now() + this.config.timeoutMs,
      observations: [],
    };
    let before = await this.ensureReady(await this.binding.observe(), context);
    while (true) {
      this.checkCancellation(context);
      if (
        context.observations.length > 0 &&
        performance.now() >= context.deadline
      )
        throw new AnalysisTimeoutError(operation, this.config.timeoutMs);
      const runner = new IdaOperationRunner(
        this.connection,
        this.config.mode === "attached" ? "legacy" : "modern",
        this.binding.database,
        options?.signal,
      );
      const result = await runner.run(operation, parameters);
      const after = await this.binding.observe();
      this.checkCancellation(context);
      if (idaAnalysisReady(this.config.mode, after))
        return {
          result,
          runner,
          before,
          after,
          recovery: context.observations,
        };
      context.observations.push({
        discarded_observations: jsonValueSchema.parse(runner.raw),
      });
      before = await this.ensureReady(after, context);
    }
  }

  private checkCancellation(context: RecoveryContext): void {
    if (context.options?.signal?.aborted === true)
      throw new AnalysisCancelledError(context.operation);
  }

  private async ensureReady(
    metadata: JsonValue,
    context: RecoveryContext,
  ): Promise<JsonValue> {
    while (!idaAnalysisReady(this.config.mode, metadata)) {
      this.checkCancellation(context);
      if (modernHealthSchema.parse(metadata).auto_analysis_ready === null)
        throw new AnalysisProtocolError(
          "IDA auto-analysis readiness is unknown; it cannot be safely advanced.",
        );
      const parameters = this.connection.toolParameters?.("analysis_advance");
      if (
        this.binding.database === undefined ||
        !parameters?.includes("budget_ms")
      )
        throw new AnalysisCapabilityUnavailableError(
          "ida",
          context.operation,
          "Pending auto-analysis requires the headless analysis_advance tool.",
          {
            userMessage:
              "IDA auto-analysis is incomplete; this backend lacks analysis_advance. Use a compatible headless backend; no result was accepted.",
          },
        );
      const remaining = context.deadline - performance.now();
      if (remaining < 1)
        throw new AnalysisTimeoutError(
          context.operation,
          this.config.timeoutMs,
        );
      const args = {
        database: this.binding.database,
        budget_ms: Math.min(100, Math.floor(remaining)),
      };
      const raw = await this.connection.call(
        "analysis_advance",
        args,
        context.options?.signal,
      );
      const advanced = z
        .object({
          steps: z.number().int().nonnegative(),
          health: modernHealthSchema,
        })
        .parse(raw);
      context.observations.push({
        tool: "analysis_advance",
        arguments: args,
        result: raw,
      });
      // The callback verifies private input digest, database path and image base.
      metadata = await this.binding.observe();
      const observed = modernHealthSchema.parse(metadata);
      if (
        !sameIdaHostPath(advanced.health.input_path, observed.input_path) ||
        advanced.health.idb_path !== observed.idb_path ||
        advanced.health.imagebase !== observed.imagebase
      )
        throw new AnalysisProtocolError(
          "IDA analysis advancement reports a different database identity.",
        );
      this.checkCancellation(context);
      if (advanced.steps === 0 && !idaAnalysisReady(this.config.mode, metadata))
        throw new ProviderAdapterError("ida", context.operation, {
          diagnostics: {
            reason:
              "IDA automatic analysis made no progress; no result was accepted.",
            recovery:
              "Inspect disabled analysis or pending queues in this headless worker.",
          },
        });
    }
    return metadata;
  }
}
