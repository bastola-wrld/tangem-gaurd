import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DATA = fs.mkdtempSync(path.join(os.tmpdir(), "tangem-guard-test-"));
process.env.TANGEM_GUARD_DATA_DIR = DATA;
process.env.TANGEM_GUARD_TIMEOUT_MS = "1500";

const core = await import("../guard-core.js");
const hook = await import("../hook.js");

const TREASURER = "0xAb12c3d4e5f60718293a4b5c6d7e8f90123a9fE3";
const LOOKALIKE = "0xab12" + "9".repeat(32) + "9fe3"; // same first 4 and last 4 as TREASURER
const STRANGER = "0x1111222233334444555566667777888899990000";
const FLAGGED = "0xdead00000000000000000000000000000000beef";

function mockFetch({ goplusDown = false } = {}) {
  return async (url) => {
    const u = String(url);
    const json = (body) => ({ ok: true, status: 200, json: async () => body });
    if (u.includes("gopluslabs")) {
      if (goplusDown) throw new Error("offline");
      if (u.includes("/address_security/")) {
        const flagged = u.toLowerCase().includes(FLAGGED);
        return json({ code: 1, message: "OK", result: { sanctioned: flagged ? "1" : "0", mixer: flagged ? "1" : "0", cybercrime: "0", contract_address: "0", data_source: flagged ? "OFAC" : "" } });
      }
      if (u.includes("/token_security/")) {
        const c = u.split("contract_addresses=")[1];
        return json({ code: 1, result: { [c]: { is_honeypot: "1", token_symbol: "SCAM", sell_tax: "0.9" } } });
      }
    }
    if (u.includes("coingecko")) return json({ "usd-coin": { gbp: 0.78 }, ethereum: { gbp: 2500 } });
    throw new Error(`unexpected url ${u}`);
  };
}

test("lookalike helper really is a lookalike", () => {
  assert.equal(LOOKALIKE.length, 42);
  assert.ok(core.isEvm(LOOKALIKE));
  assert.equal(LOOKALIKE.slice(0, 6).toLowerCase(), TREASURER.slice(0, 6).toLowerCase());
  assert.equal(LOOKALIKE.slice(-4).toLowerCase(), TREASURER.slice(-4).toLowerCase());
});

test("saving contacts", () => {
  core.addContact({ name: "Treasurer", address: TREASURER, network: "polygon-pos", confirmed: true, allowOverwrite: true });
  assert.throws(() => core.addContact({ name: "Treasurer New", address: LOOKALIKE, confirmed: false, addedBy: "agent" }), /address poisoning/);
  assert.throws(() => core.addContact({ name: "Treasurer", address: STRANGER, confirmed: false, addedBy: "agent" }), /confirmed contact/);
  core.addContact({ name: "Sam", address: STRANGER, confirmed: false, addedBy: "agent" });
  assert.equal(core.listContacts().find((c) => c.name === "Sam").confirmed, false);
});

test("saved contact, small USDC payment: ALLOW", async () => {
  const r = await core.evaluate({ address: TREASURER, network: "polygon-pos", token: "usd-coin", amount: "1" }, { fetch: mockFetch(), log: false });
  assert.equal(r.verdict, "ALLOW", JSON.stringify(r.reasons));
  assert.equal(r.contact, "Treasurer");
  assert.equal(r.amount_gbp, 0.78);
});

test("lookalike of a contact: BLOCK", async () => {
  const r = await core.evaluate({ address: LOOKALIKE, network: "polygon-pos", token: "USDC", amount: 1 }, { fetch: mockFetch(), log: false });
  assert.equal(r.verdict, "BLOCK");
  assert.equal(r.lookalike_of.name, "Treasurer");
  assert.match(core.explain(r), /address poisoning/);
});

test("GoPlus flagged address: BLOCK", async () => {
  const r = await core.evaluate({ address: FLAGGED, network: "ethereum", token: "usd-coin", amount: 1 }, { fetch: mockFetch(), log: false });
  assert.equal(r.verdict, "BLOCK");
  assert.match(r.reasons.map((x) => x.text).join(" "), /sanctioned/);
});

test("over the per payment limit: BLOCK", async () => {
  const r = await core.evaluate({ address: TREASURER, network: "polygon-pos", token: "usd-coin", amount: 500 }, { fetch: mockFetch(), log: false });
  assert.equal(r.verdict, "BLOCK");
});

test("unconfirmed contact the AI saved: WARN", async () => {
  const r = await core.evaluate({ address: STRANGER, network: "polygon-pos", token: "usd-coin", amount: 1 }, { fetch: mockFetch(), log: false });
  assert.equal(r.verdict, "WARN");
  assert.match(r.reasons.map((x) => x.text).join(" "), /not confirmed/);
});

test("GoPlus down: WARN, not a silent pass", async () => {
  const r = await core.evaluate({ address: TREASURER, network: "polygon-pos", token: "usd-coin", amount: 1 }, { fetch: mockFetch({ goplusDown: true }), log: false });
  assert.equal(r.verdict, "WARN");
});

test("tool classification", () => {
  assert.equal(hook.classify("mcp__tangem__send_transaction"), "send");
  assert.equal(hook.classify("mcp__tangem__transactions_send_transaction"), "send");
  assert.equal(hook.classify("mcp__tangem__get_tokens"), "read");
  assert.equal(hook.classify("mcp__tangem__get_balances"), "read");
  assert.equal(hook.classify("mcp__tangem__get_transaction_status"), "read");
  assert.equal(hook.classify("mcp__tangem__exchange_quote"), "read");
  assert.equal(hook.classify("mcp__tangem__pairs"), "read");
  assert.equal(hook.classify("mcp__tangem__assets"), "read");
  assert.equal(hook.classify("mcp__tangem__list_transactions"), "read");
  assert.equal(hook.classify("mcp__tangem__exchange"), "swap");
  assert.equal(hook.classify("mcp__tangem__sign_message"), "unknown");
  assert.equal(hook.classify("mcp__tangem-guard__check_recipient"), "other");
  assert.equal(hook.classify("mcp__figma__send_code"), "other");
  assert.equal(hook.classify("mcp__claude_ai_Tangem__send_transaction"), "send");
});

test("real Tangem tool names", () => {
  assert.equal(hook.classify("mcp__tangem__transactions__send_transaction"), "send");
  assert.equal(hook.classify("mcp__tangem__express__exchange_intent_create"), "swap");
  for (const t of ["express__assets", "express__exchange_history", "express__exchange_history_delta", "express__exchange_intent", "express__exchange_quote", "express__pairs", "pay__get_balance", "pay__list_transactions", "transactions__get_balances", "transactions__get_transaction_status", "wallets__get_tokens"]) {
    assert.equal(hook.classify(`mcp__tangem__${t}`), "read", t);
  }
});

test("real Tangem send_transaction input", () => {
  const f = hook.extract({ request: { amount: "1", comment: "pay treasurer", fromAddress: STRANGER, memo: null, networkId: "polygon-pos", sendNotification: true, toAddress: TREASURER, tokenId: "usd-coin" } });
  assert.equal(f.address, TREASURER);
  assert.equal(f.amount, "1");
  assert.equal(f.network, "polygon-pos");
  assert.equal(f.token, "usd-coin");
});

test("real Tangem swap into a honeypot token is blocked", async () => {
  const d = await hook.decide({ tool_name: "mcp__tangem__express__exchange_intent_create", tool_input: { fromAddress: TREASURER, payoutAddress: TREASURER, fromAmount: "1000000", fromAsset: { contractAddress: "0", network: "ethereum", decimals: 18 }, toAsset: { contractAddress: "0x1234567890123456789012345678901234567890", network: "ethereum", decimals: 18 }, provider: "changelly", rateType: "float", sendNotification: true } }, { fetch: mockFetch(), logCalls: false, log: false });
  assert.equal(d.action, "block", d.message);
});

test("field extraction from different input shapes", () => {
  assert.deepEqual(hook.extract({ to_address: TREASURER, amount: "1", network_id: "polygon-pos", token_id: "usd-coin" }), { address: TREASURER, amount: "1", network: "polygon-pos", token: "usd-coin", toToken: null });
  assert.equal(hook.extract({ toAddress: TREASURER, networkId: "base" }).address, TREASURER);
  assert.equal(hook.extract({ transaction: { recipient: TREASURER, value: 2 } }).address, TREASURER);
  assert.equal(hook.extract({ from_address: STRANGER, destination: TREASURER }).address, TREASURER);
  assert.equal(hook.extract({ wallet_address: STRANGER, address: TREASURER }).address, TREASURER);
});

function runHook(event) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [path.join(ROOT, "hook.js")], { env: { ...process.env, TANGEM_GUARD_DATA_DIR: DATA, TANGEM_GUARD_TIMEOUT_MS: "1000" } });
    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => resolve({ code, out, err }));
    p.stdin.end(JSON.stringify({ hook_event_name: "PreToolUse", ...event }));
  });
}

test("hook process: lookalike send is blocked with exit code 2", async () => {
  const r = await runHook({ tool_name: "mcp__tangem__send_transaction", tool_input: { to_address: LOOKALIKE, amount: "1", network_id: "polygon-pos", token_id: "usd-coin" } });
  assert.equal(r.code, 2, r.err);
  assert.match(r.err, /TANGEM GUARD BLOCKED/);
});

test("hook process: read tools pass silently", async () => {
  const r = await runHook({ tool_name: "mcp__tangem__get_balances", tool_input: {} });
  assert.equal(r.code, 0);
  assert.equal(r.out, "");
});

test("hook process: unknown tool asks the user", async () => {
  const r = await runHook({ tool_name: "mcp__tangem__sign_message", tool_input: { message: "hi" } });
  assert.equal(r.code, 0);
  assert.equal(JSON.parse(r.out).hookSpecificOutput.permissionDecision, "ask");
});

test("MCP server: lists tools and blocks a lookalike", async () => {
  const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
  const { StdioClientTransport } = await import("@modelcontextprotocol/sdk/client/stdio.js");
  const transport = new StdioClientTransport({ command: process.execPath, args: [path.join(ROOT, "server.js")], env: { ...process.env, TANGEM_GUARD_DATA_DIR: DATA, TANGEM_GUARD_TIMEOUT_MS: "1000" } });
  const client = new Client({ name: "test", version: "1.0.0" });
  await client.connect(transport);
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name).sort(), ["add_contact", "audit_log", "check_recipient", "check_token", "get_policy", "list_contacts"]);
  const res = await client.callTool({ name: "check_recipient", arguments: { address: LOOKALIKE, network: "polygon-pos", token: "usd-coin", amount: "1" } });
  assert.match(res.content[0].text, /verdict: BLOCK/);
  const add = await client.callTool({ name: "add_contact", arguments: { name: "Treasurer", address: STRANGER } });
  assert.equal(add.isError, true);
  await client.close();
});
