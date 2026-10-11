import { z } from "zod";
import type { JsonValue } from "../domain/jsonValue.js";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import { sameIdaHostPath } from "./IdaWorkspace.js";

const inventorySchema = z.object({
  instances: z.array(
    z.object({
      path: z.string(),
      backend: z.string(),
      status: z.string(),
      instance_id: z.string().nullable(),
      error: z.string().nullable(),
    }),
  ),
});

/** Owns only one Nexus lease to a REA-private input; never requests GUI save/close. */
export class OfficialIdaLifecycle {
  #lease: string | undefined;
  #completed = false;
  #released = false;
  constructor(
    private readonly connection: IdaMcpConnection,
    private readonly inputPath: string,
    private readonly observations: JsonValue[],
  ) {}
  async #inventory() {
    const raw = await this.connection.call("list_databases", {});
    this.observations.push(raw);
    return inventorySchema.parse(raw);
  }
  async open(): Promise<string> {
    const raw = await this.connection.call("open_database", {
      path: this.inputPath,
      set_current: true,
    });
    this.#completed = true;
    this.observations.push(raw);
    const opened = z
      .object({ instance_id: z.string().min(1), backend: z.string() })
      .parse(raw);
    this.#lease = opened.instance_id; // Retain authority before validating backend/inventory.
    if (opened.backend !== "idalib")
      throw new AnalysisProtocolError(
        "Official IDA returned a GUI lease instead of a private idalib worker.",
      );
    const inventory = await this.#inventory();
    const entry = inventory.instances.find(
      (e) => e.instance_id === this.#lease,
    );
    if (
      !entry ||
      entry.backend !== "idalib" ||
      entry.status !== "current" ||
      entry.error !== null ||
      !sameIdaHostPath(entry.path, this.inputPath)
    )
      throw new AnalysisProtocolError(
        "Official IDA did not bind the requested private input lease.",
      );
    return this.#lease;
  }
  async release(): Promise<void> {
    if (this.#lease === undefined) {
      const inventory = await this.#inventory();
      this.#lease =
        inventory.instances.find(
          (e) =>
            sameIdaHostPath(e.path, this.inputPath) && e.instance_id !== null,
        )?.instance_id ?? undefined;
    }
    if (this.#lease !== undefined && !this.#released) {
      const raw = await this.connection.call("close_database", {
        instance_id: this.#lease,
      });
      this.observations.push(raw);
      z.object({ closed: z.literal(true) }).parse(raw);
      this.#released = true;
    }
    const inventory = await this.#inventory();
    if (
      inventory.instances.some(
        (e) =>
          e.instance_id === this.#lease ||
          sameIdaHostPath(e.path, this.inputPath),
      )
    )
      throw new AnalysisProtocolError(
        "Official IDA still advertises the private database after lease release; workspace retained.",
      );
    if (!this.#completed)
      throw new AnalysisProtocolError(
        "Official IDA open did not complete; worker absence cannot prove the pending open has stopped. Workspace retained.",
      );
  }
}
