import assert from "node:assert/strict";
import test from "node:test";

import { applyVerifiedSettings } from "../src/settings-transaction.js";

test("persists desired settings only after application and verification", async () => {
  const calls = [];
  const desired = { protectionEnabled: false };
  const previous = { protectionEnabled: true };
  const result = await applyVerifiedSettings({
    desired,
    previous,
    async apply(value) { calls.push(["apply", value]); },
    async verify(value) { calls.push(["verify", value]); return { state: "off" }; },
    async persist(value, verification, rollback) { calls.push(["persist", value, verification, rollback]); },
    async recordFailure(value) { calls.push(["failure", value]); }
  });
  assert.equal(result.rollback, "not_needed");
  assert.deepEqual(calls.map((value) => value[0]), ["apply", "verify", "persist"]);
  assert.equal(calls[2][3], false);
});

test("restores and verifies previous settings when desired verification fails", async () => {
  const calls = [];
  const desired = { protectionEnabled: false };
  const previous = { protectionEnabled: true };
  await assert.rejects(
    applyVerifiedSettings({
      desired,
      previous,
      async apply(value) { calls.push(["apply", value]); },
      async verify(value) {
        calls.push(["verify", value]);
        if (value === desired) throw new Error("desired_failed");
        return { state: "verified" };
      },
      async persist(value, verification, rollback) { calls.push(["persist", value, verification, rollback]); },
      async recordFailure(value) { calls.push(["failure", value]); }
    }),
    /desired_failed/
  );
  assert.deepEqual(calls.map((value) => value[0]), ["apply", "verify", "apply", "verify", "persist", "failure"]);
  assert.equal(calls[4][1], previous);
  assert.equal(calls[4][3], true);
  assert.equal(calls[5][1].rollback, "verified");
});

test("records rollback failure without persisting an unverified state", async () => {
  const calls = [];
  await assert.rejects(
    applyVerifiedSettings({
      desired: { name: "desired" },
      previous: { name: "previous" },
      async apply(value) {
        calls.push(["apply", value]);
        if (value.name === "previous") throw new Error("rollback_failed");
      },
      async verify() { throw new Error("desired_failed"); },
      async persist(...value) { calls.push(["persist", ...value]); },
      async recordFailure(value) { calls.push(["failure", value]); }
    }),
    /desired_failed/
  );
  assert.equal(calls.some((value) => value[0] === "persist"), false);
  assert.equal(calls.at(-1)[1].rollback, "failed");
  assert.match(calls.at(-1)[1].rollbackError.message, /rollback_failed/);
});
