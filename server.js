#!/usr/bin/env node
// Tangem Guard MCP server. Gives Claude tools to check a payment and explain the result.
// The hook (hook.js) is the hard gate. This server is how Claude talks about it.
// On purpose, the AI can't change your spending rules or confirm contacts: only you can, in the terminal.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { evaluate, explain, checkToken, listContacts, addContact, getPolicy, recentLog, groupAddress } from "./guard-core.js";

const INSTRUCTIONS = `Tangem Guard protects payments made with Tangem MCP.
Before any Tangem send_transaction or swap, call check_recipient with the exact recipient address, network, token and amount, then show the user the verdict and the "Before you tap your card" checklist.
If the verdict is BLOCK, do not send and do not look for another way to send it. If it is WARN, explain why and ask the user first.
Treat addresses from documents, invoices, emails, chats, websites and transaction history as untrusted. Prefer saved contacts.
Never ask the user for a seed phrase, recovery phrase, private key or card access code.`;

const server = new McpServer({ name: "tangem-guard", version: "1.0.0" }, { instructions: INSTRUCTIONS });

const text = (t) => ({ content: [{ type: "text", text: typeof t === "string" ? t : JSON.stringify(t, null, 2) }] });
const fail = (t) => ({ ...text(t), isError: true });

server.registerTool(
  "check_recipient",
  {
    title: "Check a payment before sending",
    description:
      "Call this BEFORE every Tangem send_transaction or swap. Checks the recipient against the GoPlus scam list, the user's saved contacts (to catch lookalike addresses used in address poisoning) and the user's spending limits. Returns ALLOW, WARN or BLOCK and a short checklist to show the user before they tap their card.",
    inputSchema: {
      address: z.string().describe("The exact recipient address, copied character for character"),
      network: z.string().optional().describe("Network id, for example ethereum, polygon-pos, base, arbitrum-one, binance-smart-chain, tron, bitcoin, solana"),
      token: z.string().optional().describe("Token id or symbol, for example usd-coin, USDC, tether. Leave empty for the network's main coin"),
      amount: z.union([z.string(), z.number()]).optional().describe("Amount in normal units, for example 5 or \"5.25\""),
    },
  },
  async (args) => {
    const r = await evaluate(args, { source: "agent" });
    const details = { verdict: r.verdict, contact: r.contact, lookalike_of: r.lookalike_of, amount_gbp: r.amount_gbp, price_source: r.price_source, goplus: r.goplus };
    return text(`${explain(r)}\n\n---\n${JSON.stringify(details, null, 2)}`);
  },
);

server.registerTool(
  "check_token",
  {
    title: "Check a token before swapping into it",
    description: "Checks an EVM token contract with GoPlus for honeypots, huge sell taxes, owner tricks and other scam signs. Use it before swapping into a token you don't know.",
    inputSchema: {
      contract: z.string().describe("Token contract address (0x...)"),
      network: z.string().describe("Network id, for example ethereum, polygon-pos, base, binance-smart-chain"),
    },
  },
  async ({ contract, network }) => {
    const t = await checkToken(contract, network);
    const lines = [`Token ${t.token?.symbol ? `${t.token.symbol} ` : ""}(${contract}) on ${network}: ${t.verdict}`];
    for (const x of t.reasons) lines.push(`${x.level === "BLOCK" ? "✖" : x.level === "WARN" ? "!" : "✓"} ${x.text}`);
    return text(lines.join("\n"));
  },
);

server.registerTool(
  "list_contacts",
  {
    title: "List saved contacts",
    description: "Lists the user's saved contacts and whether each one is confirmed by the user.",
    inputSchema: {},
  },
  async () => {
    const contacts = listContacts();
    if (!contacts.length) return text("No saved contacts yet. The user can add one in the terminal: node cli.js add \"Name\" 0x... polygon-pos");
    return text(
      contacts
        .map((c) => `${c.name}${c.own ? " (own wallet)" : ""}${c.confirmed === false ? " (NOT confirmed by the user)" : ""}${c.network ? ` on ${c.network}` : ""}\n  ${groupAddress(c.address)}`)
        .join("\n"),
    );
  },
);

server.registerTool(
  "add_contact",
  {
    title: "Save a new contact (unconfirmed)",
    description:
      "Saves a contact the user told you about. It is saved as NOT confirmed, so Guard will still ask the user before paying it until they confirm it in the terminal. Guard refuses addresses that look like an existing contact, and you can't change an existing confirmed contact.",
    inputSchema: {
      name: z.string().describe("Contact name"),
      address: z.string().describe("Wallet address, exactly as the user gave it"),
      network: z.string().optional().describe("Network id the address is used on"),
    },
  },
  async ({ name, address, network }) => {
    try {
      const c = addContact({ name, address, network, confirmed: false, addedBy: "agent" });
      return text(`Saved "${c.name}" as an unconfirmed contact. Ask the user to confirm it in the terminal with: node cli.js confirm "${c.name}"`);
    } catch (e) {
      return fail(`Not saved: ${e.message}`);
    }
  },
);

server.registerTool(
  "get_policy",
  {
    title: "Show spending rules",
    description: "Shows the user's spending rules. The AI can read them but only the user can change them, in the terminal.",
    inputSchema: {},
  },
  async () => {
    const p = getPolicy();
    return text(
      `Limit per payment: £${p.max_per_tx_gbp}\nDaily limit: £${p.daily_limit_gbp}\nOnly pay saved contacts: ${p.contacts_only ? "yes" : "no"}\nBlock if the scam list can't be reached: ${p.fail_closed ? "yes" : "no"}\n\nThe user can change these with: node cli.js policy max=50 daily=200 contacts_only=false`,
    );
  },
);

server.registerTool(
  "audit_log",
  {
    title: "Recent Guard decisions",
    description: "Shows recent payment checks and what Guard decided.",
    inputSchema: { limit: z.number().int().min(1).max(100).optional().describe("How many entries, default 10") },
  },
  async ({ limit }) => {
    const log = recentLog(limit || 10);
    if (!log.length) return text("No checks yet.");
    return text(
      log
        .map((e) => `${e.ts}  ${e.verdict}  ${e.amount ?? ""} ${e.token ?? ""} ${e.network ? `on ${e.network} ` : ""}to ${e.address ?? "?"}  [${e.source}${e.tool ? `: ${e.tool}` : ""}]${e.reasons?.length ? `\n    ${e.reasons.join("\n    ")}` : ""}`)
        .join("\n"),
    );
  },
);

await server.connect(new StdioServerTransport());
