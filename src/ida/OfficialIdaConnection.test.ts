import { describe, expect, it } from "vitest";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import {
  OfficialIdaConnection,
  OFFICIAL_IDA_TOOLS,
} from "./OfficialIdaConnection.js";
import { officialIdaQuery } from "./OfficialIdaQuery.js";
import type { JsonValue } from "../domain/jsonValue.js";

describe("official IDA read-only protocol", () => {
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
  it("passes lease release through without inventing unsaved shutdown semantics", async () => {
    const { calls, connection } = fixture({ closed: true });
    expect(
      await connection.call("close_database", { instance_id: "lease" }),
    ).toEqual({ closed: true });
    expect(calls).toEqual([
      { name: "close_database", args: { instance_id: "lease" } },
    ]);
  });
});
