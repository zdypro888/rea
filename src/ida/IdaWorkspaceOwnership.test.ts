import { chmod, readdir, rm, realpath, symlink } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createIdaTarget,
  RecordingIdaMcp,
} from "../../tests/fixtures/idaMcp.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { IdaSessionClient } from "./IdaSessionClient.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0)) {
    await chmod(root, 0o700);
    await rm(root, { recursive: true, force: true });
  }
});

const clientFor = (root: string, target: BinaryTarget) => {
  const producer = new RecordingIdaMcp(target, "headless");
  const client = new IdaSessionClient(
    {
      command: "fixture",
      args: [],
      env: {},
      mode: "headless",
      timeoutMs: 1000,
      workspaceRoot: root,
    },
    target,
    producer,
  );
  return { client, producer };
};

describe("IDA workspace ownership before input preparation", () => {
  it.skipIf(process.platform === "win32")(
    "binds canonical input paths when the selected workspace parent is a symlink",
    async () => {
      const { root, target } = await createIdaTarget();
      roots.push(root);
      const alias = join(root, "parent-alias");
      await symlink(root, alias, "dir");
      const { client, producer } = clientFor(alias, target);
      try {
        const result = await client.execute("health", {});
        if (!result.ok) throw result.error;
        expect(producer.inputPath).toBe(await realpath(producer.inputPath));
        expect(producer.inputPath).not.toContain("parent-alias");
      } finally {
        await client.close();
      }
      expect(await readdir(root)).toEqual(["parent-alias", "target.elf"]);
    },
  );
  it("retains cleanup ownership when copying the admitted input fails", async () => {
    const { root, target } = await createIdaTarget();
    roots.push(root);
    await rm(target.path);
    const { client, producer } = clientFor(root, target);
    const failed = await client.execute("health", {});
    expect(failed.ok).toBe(false);
    if (!failed.ok)
      expect(failed.error.cause).toMatchObject({ code: "ENOENT" });
    expect(await readdir(root)).toHaveLength(1);
    expect(producer.calls.some(({ name }) => name === "idb_open")).toBe(false);
    expect((await client.close()).ok).toBe(true);
    expect(await readdir(root)).toEqual([]);
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "preserves the input identity failure and retries workspace removal after permission recovery",
    async () => {
      const { root, target } = await createIdaTarget();
      roots.push(root);
      const { client, producer } = clientFor(root, {
        ...target,
        sha256: "a".repeat(64),
      });
      const failed = await client.execute("health", {});
      expect(failed.ok).toBe(false);
      if (!failed.ok) expect(failed.error.message).toContain("target changed");
      const workspace = (await readdir(root)).find((name) =>
        name.startsWith("rea-ida-"),
      );
      expect(workspace).toBeDefined();
      expect(producer.calls.some(({ name }) => name === "idb_open")).toBe(
        false,
      );
      await chmod(root, 0o500);
      try {
        const closed = await client.close();
        expect(closed.ok).toBe(false);
        if (!closed.ok) {
          expect(closed.error.cleanupIncomplete).toBe(true);
          expect(closed.error.cleanupResources).toEqual([
            expect.stringContaining(workspace ?? "missing workspace"),
          ]);
        }
      } finally {
        await chmod(root, 0o700);
      }
      expect((await client.close()).ok).toBe(true);
      expect(await readdir(root)).toEqual(["target.elf"]);
    },
  );
});
