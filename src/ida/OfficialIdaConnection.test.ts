import { expect, it } from "vitest";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import {
  OfficialIdaConnection,
  OFFICIAL_IDA_TOOLS,
} from "./OfficialIdaConnection.js";
import { officialIdaQuery } from "./OfficialIdaQuery.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { IdaToolFailure } from "./IdaMcpConnection.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import {
  admitsIdaOperation,
  idaCapabilities,
} from "./IdaProviderCapabilities.js";

const fixture = (result: JsonValue) => {
  const calls: { name: string; args: Readonly<Record<string, JsonValue>> }[] =
    [];
  const transport: IdaMcpConnection = {
    connect: async () => OFFICIAL_IDA_TOOLS,
    call: async (name, args) => {
      calls.push({ name, args });
      return result;
    },
    serverInfo: () => ({ name: "ida", version: "20261008.0.1" }),
    close: async () => undefined,
  };
  return {
    calls,
    transport,
    connection: new OfficialIdaConnection(transport, 1000),
  };
};

it("admits and advertises single instructions only for the official backend", () => {
  for (const official of [true, false]) {
    expect(admitsIdaOperation("inspect_native_instruction", official)).toBe(
      official,
    );
    expect(
      idaCapabilities("headless", true, official).find(
        (c) => c.operation === "inspect_native_instruction",
      )?.available,
    ).toBe(official);
  }
});
it("requires the official catalog, not the incompatible community supervisor", async () => {
  const { transport, connection } = fixture(null);
  transport.connect = async () => ["idb_open", "decompile"];
  await expect(connection.connect()).rejects.toThrow("missing tools");
});
it("keeps real Python source, target lease and complete raw execution in Evidence", async () => {
  const raw = {
    result: { addr: "0x123", code: "return 42;" },
    stdout: "",
    stderr: "",
  };
  const { calls, connection } = fixture(raw);
  await connection.connect();
  const result = await connection.call("decompile", {
    database: "lease",
    addr: "0x123",
  });
  expect(calls[0]).toMatchObject({
    name: "execute_python",
    args: { instance_id: "lease", timeout: 1 },
  });
  expect(result).toMatchObject({
    addr: "0x123",
    code: "return 42;",
    official_source: { tool: "execute_python", result: raw },
  });
  expect(connection.toolParameters("decompile")).toContain("offset");
});
it("does not conflate missing/null output or worker errors with successful empty queries", async () => {
  const { connection } = fixture({ result: null, stdout: "", stderr: "" });
  await expect(
    connection.call("server_health", { database: "lease" }),
  ).rejects.toThrow("omitted an object");
  const failed = fixture({ error: "worker failure" });
  await expect(
    failed.connection.call("server_health", { database: "lease" }),
  ).rejects.toThrow();
});
it("never interprets caller symbols as Python and rejects unknown/mutating query names", () => {
  const query = "quote'\\n\"; __import__('os').system('not-a-command')";
  const code = officialIdaQuery("lookup_funcs", { queries: [query] });
  const encoded = code.match(/args = json.loads\((.*)\)/u)?.[1];
  expect(JSON.parse(JSON.parse(encoded ?? "null"))).toEqual({
    queries: [query],
  });
  expect(() => officialIdaQuery("patch", {})).toThrow("Unsupported");
  expect(() => officialIdaQuery("save_database", {})).toThrow("Unsupported");
});
it("retries only an explicit pre-execution analysis barrier once and records it", async () => {
  const { connection, transport } = fixture(null);
  let attempts = 0;
  transport.call = async () => {
    if (++attempts === 1)
      throw new IdaToolFailure("Autoanalysis was cancelled before completion");
    return { result: { status: "ok" }, stdout: "", stderr: "" };
  };
  expect(
    await connection.call("server_health", { database: "lease" }),
  ).toMatchObject({
    status: "ok",
    official_source: {
      prior_barrier_failures: [
        "IDA MCP tool failed: Autoanalysis was cancelled before completion",
      ],
    },
  });
  expect(attempts).toBe(2);
});
it("preserves persistent barrier failures without calling them unreadable output", async () => {
  const { connection, transport } = fixture(null);
  let attempts = 0;
  transport.call = async () => {
    attempts++;
    throw new IdaToolFailure("Autoanalysis was cancelled before completion");
  };
  try {
    await connection.call("server_health", { database: "lease" });
    throw new Error("Expected failure");
  } catch (error) {
    expect(error).toBeInstanceOf(ProviderAdapterError);
    if (!(error instanceof ProviderAdapterError)) throw error;
    expect(projectAnalysisError(error)).toMatchObject({
      code: "execution_failure",
      message: expect.stringContaining(
        "Autoanalysis was cancelled before completion",
      ),
    });
  }
  expect(attempts).toBe(2);
});
it("does not retry the barrier when the caller cancels during the drained request", async () => {
  const { connection, transport } = fixture(null);
  const controller = new AbortController();
  let attempts = 0;
  transport.call = async () => {
    attempts++;
    controller.abort();
    throw new IdaToolFailure("Autoanalysis was cancelled before completion");
  };
  await expect(
    connection.call("server_health", { database: "lease" }, controller.signal),
  ).rejects.toMatchObject({ _tag: "AnalysisCancelledError" });
  expect(attempts).toBe(1);
});
it.each([
  ["execute timed out after 1.00s", "AnalysisTimeoutError"],
  ["execute was cancelled", "AnalysisCancelledError"],
  ["Hex-Rays decompilation failed", "ProviderAdapterError"],
])(
  "does not retry %s and distinguishes it from malformed data",
  async (message, tag) => {
    const { connection, transport } = fixture(null);
    let attempts = 0;
    transport.call = async () => {
      attempts++;
      throw new IdaToolFailure(message);
    };
    await expect(
      connection.call("decompile", { database: "lease", addr: "0x123" }),
    ).rejects.toMatchObject({ _tag: tag });
    expect(attempts).toBe(1);
  },
);
it("generates actual Python newline escapes, not literal backslash+n output", () => {
  const code = officialIdaQuery("decompile", {
    addr: "0x123",
    offset: 0,
    max_lines: 100,
  });
  expect(code).toContain("code = '\\n'.join(");
  expect(code).not.toContain("code = '\\\\n'.join(");
});
it("passes lease release through without inventing unsaved shutdown semantics", async () => {
  const { calls, connection } = fixture({ closed: true });
  expect(
    await connection.call("close_database", { instance_id: "lease" }),
  ).toEqual({ closed: true });
  expect(calls).toEqual([
    { name: "close_database", args: { instance_id: "lease" } },
  ]);
});
