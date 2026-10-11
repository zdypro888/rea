import { readFile, readdir, rm } from "node:fs/promises";
import { afterEach, expect, it } from "vitest";
import { createIdaTarget } from "../../tests/fixtures/idaMcp.js";
import { IdaSessionClient } from "./IdaSessionClient.js";
import { OFFICIAL_IDA_TOOLS } from "./OfficialIdaConnection.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import type { JsonValue } from "../domain/jsonValue.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});
async function fixture() {
  const { root, target } = await createIdaTarget();
  roots.push(root);
  let input = "",
    active = false,
    closeFails = false,
    backend = "idalib";
  const calls: string[] = [];
  const connection: IdaMcpConnection = {
    official: true,
    connect: async () => OFFICIAL_IDA_TOOLS,
    serverInfo: () => ({ name: "ida", version: "test" }),
    close: async () => {
      calls.push("transport_close");
    },
    call: async (name, args): Promise<JsonValue> => {
      calls.push(name);
      if (name === "open_database") {
        input = String(args.path);
        active = true;
        return { instance_id: "lease", backend };
      }
      if (name === "list_databases")
        return {
          instances: active
            ? [
                {
                  path: input,
                  backend,
                  status: "current",
                  instance_id: "lease",
                  error: null,
                },
              ]
            : [],
        };
      if (name === "server_health")
        return {
          status: "ok",
          input_path: input,
          idb_path: input + ".i64",
          imagebase: "0x1000",
          module: "fixture",
          auto_analysis_ready: true,
        };
      if (name === "close_database") {
        if (closeFails) throw new Error("release failed");
        expect(args).toEqual({ instance_id: "lease" });
        active = false;
        return { closed: true };
      }
      throw new Error("Unmodeled tool " + name);
    },
  };
  const client = new IdaSessionClient(
    {
      backend: "official",
      command: "fixture",
      args: [],
      env: {},
      mode: "headless",
      timeoutMs: 1000,
      workspaceRoot: root,
    },
    target,
    connection,
  );
  return {
    root,
    target,
    client,
    calls,
    input: () => input,
    setCloseFails: (v: boolean) => {
      closeFails = v;
    },
    setBackend: (v: string) => {
      backend = v;
    },
  };
}
it("opens only a verified private copy and releases a real official lease without save calls", async () => {
  const f = await fixture();
  const health = await f.client.execute("health", {});
  if (!health.ok) throw health.error;
  expect(f.input()).not.toBe(f.target.path);
  expect(await readFile(f.input())).toEqual(await readFile(f.target.path));
  const closed = await f.client.close();
  if (!closed.ok) throw closed.error;
  expect(f.calls).toContain("close_database");
  expect(f.calls).not.toContain("save_database");
  expect(f.calls).not.toContain("idb_close");
  expect(
    (await readdir(f.root)).filter((n) => n.startsWith("rea-ida-")),
  ).toEqual([]);
});
it("retains ownership and the private workspace after lease-release failure, then retries safely", async () => {
  const f = await fixture();
  const health = await f.client.execute("health", {});
  if (!health.ok) throw health.error;
  f.setCloseFails(true);
  const failed = await f.client.close();
  expect(failed.ok).toBe(false);
  expect(f.calls).not.toContain("transport_close");
  expect(await readFile(f.input())).toEqual(await readFile(f.target.path));
  f.setCloseFails(false);
  const closed = await f.client.close();
  if (!closed.ok) throw closed.error;
  expect(f.calls.filter((n) => n === "close_database")).toHaveLength(2);
});
it("rejects a GUI backend and releases only the returned lease without analyzing or saving it", async () => {
  const f = await fixture();
  f.setBackend("gui");
  const result = await f.client.execute("health", {});
  expect(result.ok).toBe(false);
  const closed = await f.client.close();
  if (!closed.ok) throw closed.error;
  expect(f.calls).not.toContain("server_health");
  expect(f.calls).not.toContain("save_database");
  expect(f.calls).toContain("close_database");
});
