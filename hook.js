#!/usr/bin/env node
// Tangem Guard hook for Claude Code (PreToolUse).
// Claude Code runs this as plain code before every Tangem tool call, so the AI can't skip it
// or be talked out of it. Exit code 2 blocks the call. "ask" makes Claude Code ask you first.

import path from "node:path";
import { pathToFileURL } from "node:url";
import { evaluate, checkToken, explain, logCall, isEvm, looksLikeAddress } from "./guard-core.js";

const RECIPIENT_KEY = /^(to|to_?address|recipient|recipient_?address|destination|destination_?address|dest|dest_?address|address_?to|receiver|receiver_?address|payee|payout_?address|target_?address)$/i;
const AMOUNT_KEY = /^(amount|value|quantity|qty|amount_?decimal|amount_?value|sum)$/i;
const NETWORK_KEY = /^(network|network_?id|chain|chain_?id|blockchain|blockchain_?id)$/i;
const TO_TOKEN_KEY = /^(to_?token|to_?token_?id|to_?contract|to_?contract_?address|to_?asset|to_?asset_?id|destination_?token|dest_?token|buy_?token|output_?token|target_?token|to_?currency)$/i;
const TOKEN_KEY = /^(token|token_?id|token_?symbol|symbol|asset|asset_?id|currency|coin|coin_?id|contract|contract_?address|token_?address|token_?contract|from_?token|from_?token_?id)$/i;
const FROM_KEY = /^(from|from_?address|sender|sender_?address|source_?address|wallet|wallet_?address|wallet_?id|user_?wallet_?id|account|account_?id)$/i;

// Which kind of Tangem tool is this? Reading is always fine; sending and swapping get checked.
export function classify(toolName = "") {
  const low = String(toolName).toLowerCase();
  const match = process.env.TANGEM_GUARD_SERVER_MATCH ? new RegExp(process.env.TANGEM_GUARD_SERVER_MATCH, "i") : /tangem/;
  if (!match.test(low) || low.includes("guard")) return "other";
  const t = low.split("__").pop();
  if (/^exchange_intent$/.test(t) || /quote|pairs|assets|status|balance|providers|estimate|preview|simulat|history|rates?$/.test(t) || /(^|_)(get|list|fetch|read|search|lookup|find)(_|$)/.test(t)) return "read";
  if (/send|transfer|withdraw|payout|(^|_)pay(_|$)/.test(t)) return "send";
  if (/exchange|swap|trade|convert|bridge/.test(t)) return "swap";
  return "unknown";
}

// Pull recipient, amount, network and token out of whatever shape the tool input has.
export function extract(input) {
  const found = { address: null, amount: null, network: null, token: null, toToken: null };
  const loose = [];
  const visit = (obj, depth) => {
    if (!obj || typeof obj !== "object" || depth > 4) return;
    for (const [k, v] of Object.entries(obj)) {
      if (v && typeof v === "object") {
        visit(v, depth + 1);
        continue;
      }
      if (v === null || v === undefined || v === "") continue;
      const s = typeof v === "string" ? v.trim() : v;
      if (found.address === null && RECIPIENT_KEY.test(k) && typeof s === "string") found.address = s;
      else if (found.amount === null && AMOUNT_KEY.test(k)) found.amount = s;
      else if (found.network === null && NETWORK_KEY.test(k)) found.network = String(s);
      else if (found.toToken === null && TO_TOKEN_KEY.test(k)) found.toToken = String(s);
      else if (found.token === null && TOKEN_KEY.test(k)) found.token = String(s);
      else if (typeof s === "string" && looksLikeAddress(s) && !FROM_KEY.test(k)) loose.push({ k, s });
    }
  };
  visit(input, 0);
  if (!found.address) {
    const plain = loose.find((x) => x.k.toLowerCase() === "address");
    const others = loose.filter((x) => x.s !== found.token && x.s !== found.toToken);
    if (plain) found.address = plain.s;
    else if (others.length === 1) found.address = others[0].s;
  }
  return found;
}

const worst = (a, b) => (["ALLOW", "WARN", "BLOCK"].indexOf(a) >= ["ALLOW", "WARN", "BLOCK"].indexOf(b) ? a : b);
const toAction = (v) => (v === "BLOCK" ? "block" : v === "WARN" ? "ask" : "allow");

export async function decide(event, opts = {}) {
  const tool = event?.tool_name || "";
  const input = event?.tool_input || {};
  const kind = classify(tool);
  if (kind === "other") return { action: "allow", kind };
  if (opts.logCalls !== false) logCall({ tool, kind, input });
  if (kind === "read") return { action: "allow", kind };

  const f = extract(input);
  const source = opts.source || "hook";

  if (kind === "send") {
    const r = await evaluate({ address: f.address, network: f.network, token: f.token, amount: f.amount }, { ...opts, source, tool });
    return { action: toAction(r.verdict), kind, verdict: r.verdict, result: r, message: explain(r) };
  }

  if (kind === "swap") {
    let verdict = "ALLOW";
    const parts = [];
    // Tangem express exchange_intent_create: { fromAddress, payoutAddress, fromAsset, toAsset, ... }
    const req = input?.request && typeof input.request === "object" ? input.request : input;
    if (req?.toAsset && typeof req.toAsset === "object") {
      f.toToken = req.toAsset.contractAddress && req.toAsset.contractAddress !== "0" ? String(req.toAsset.contractAddress) : null;
      f.network = req.toAsset.network || f.network;
      f.token = null;
      f.amount = null; // swap amounts are in minor units, so limits are not applied to swaps
      f.address = req.payoutAddress || null;
      if (f.address && req.fromAddress && String(req.fromAddress).trim().toLowerCase() === String(f.address).trim().toLowerCase()) f.address = null; // paying out to your own wallet
    }
    if (f.address) {
      const r = await evaluate({ address: f.address, network: f.network, token: f.token, amount: f.amount }, { ...opts, source, tool });
      verdict = worst(verdict, r.verdict);
      parts.push(explain(r));
    }
    const target = [f.toToken, f.token].find((x) => x && isEvm(x));
    if (target) {
      const t = await checkToken(target, f.network, opts.fetch);
      verdict = worst(verdict, t.verdict);
      parts.push(`Swap token check for ${target}: ${t.verdict}\n${t.reasons.map((x) => `${x.level === "BLOCK" ? "✖" : x.level === "WARN" ? "!" : "✓"} ${x.text}`).join("\n")}`);
    }
    if (!parts.length) parts.push("Swap with no recipient or token contract for Guard to check.");
    return { action: toAction(verdict), kind, verdict, message: parts.join("\n\n") };
  }

  return {
    action: "ask",
    kind,
    verdict: "WARN",
    message: `Tangem Guard does not recognise the Tangem tool "${tool}", so it could not check it. Look very carefully at the review sheet on your phone before you tap.`,
  };
}

async function main() {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  let event;
  try {
    event = JSON.parse(raw || "{}");
  } catch {
    process.exit(0);
  }
  let d;
  try {
    d = await decide(event);
  } catch (e) {
    const kind = classify(event?.tool_name);
    if (kind === "read" || kind === "other") process.exit(0);
    d = { action: "ask", message: `Tangem Guard hit an error (${e?.message}) and could not check this. Check the review sheet on your phone very carefully.` };
  }
  if (d.action === "block") {
    const msg = `TANGEM GUARD BLOCKED THIS PAYMENT.\n\n${d.message}\n\nDo not retry this payment, do not try another tool or a changed address to send it, and tell the user exactly why it was blocked.\n`;
    process.stderr.write(msg, () => process.exit(2));
    return;
  }
  if (d.action === "ask") {
    const out = {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "ask",
        permissionDecisionReason: `Tangem Guard wants you to check this one yourself.\n\n${d.message}`,
      },
    };
    process.stdout.write(JSON.stringify(out), () => process.exit(0));
    return;
  }
  process.exit(0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
