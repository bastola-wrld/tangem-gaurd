// Tangem Guard core.
// Checks a payment before it can reach your Tangem card:
//   1. GoPlus scam list (free, no key)
//   2. Your saved contacts, to catch lookalike addresses (address poisoning)
//   3. Your spending limits in GBP
// It never sees or asks for keys, seed phrases or card codes.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const DATA_DIR = process.env.TANGEM_GUARD_DATA_DIR || path.join(os.homedir(), ".tangem-guard");
const STATE_FILE = path.join(DATA_DIR, "guard.json");
export const CALLS_LOG = path.join(DATA_DIR, "tangem-calls.jsonl");
const TIMEOUT_MS = Number(process.env.TANGEM_GUARD_TIMEOUT_MS || 8000);
const GOPLUS = "https://api.gopluslabs.io/api/v1";

export const DEFAULT_POLICY = {
  max_per_tx_gbp: 50,
  daily_limit_gbp: 200,
  contacts_only: false,
  fail_closed: false,
};

// ---------------------------------------------------------------- storage

export function loadState() {
  try {
    const s = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    return {
      contacts: Array.isArray(s.contacts) ? s.contacts : [],
      policy: { ...DEFAULT_POLICY, ...(s.policy || {}) },
      log: Array.isArray(s.log) ? s.log : [],
    };
  } catch {
    return { contacts: [], policy: { ...DEFAULT_POLICY }, log: [] };
  }
}

export function saveState(state) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const body = JSON.stringify(state, null, 2);
  const tmp = `${STATE_FILE}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, body);
    fs.renameSync(tmp, STATE_FILE);
  } catch {
    fs.writeFileSync(STATE_FILE, body);
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
  }
}

function update(fn) {
  const s = loadState();
  const out = fn(s);
  saveState(s);
  return out;
}

export function logCall(entry) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.appendFileSync(CALLS_LOG, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n");
  } catch { /* logging must never break a payment check */ }
}

export function recentCalls(limit = 10) {
  try {
    const lines = fs.readFileSync(CALLS_LOG, "utf8").trim().split("\n").filter(Boolean);
    return lines.slice(-limit).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------- addresses

const EVM_RE = /^0x[0-9a-fA-F]{40}$/;
const BECH32_RE = /^(bc1|tb1|ltc1)[02-9ac-hj-np-z]{8,87}$/i;
const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{25,64}$/;
const TON_RE = /^(EQ|UQ|kQ|0Q)[A-Za-z0-9_-]{46}$/;

export function isEvm(a) {
  return typeof a === "string" && EVM_RE.test(a.trim());
}

export function looksLikeAddress(a) {
  if (typeof a !== "string") return false;
  const s = a.trim();
  return EVM_RE.test(s) || BECH32_RE.test(s) || BASE58_RE.test(s) || TON_RE.test(s) || /^addr1[0-9a-z]{50,}$/.test(s);
}

export function normalise(a) {
  const s = String(a ?? "").trim();
  if (EVM_RE.test(s) || BECH32_RE.test(s)) return s.toLowerCase();
  return s;
}

export function sameAddress(a, b) {
  return normalise(a) !== "" && normalise(a) === normalise(b);
}

// Every address of a format starts with the same fixed characters (0x, bc1q, T...).
// Attackers can't choose those, so we compare what comes after them.
function addressBody(a) {
  const s = normalise(a);
  if (EVM_RE.test(s)) return s.slice(2);
  const bech = s.match(/^(bc1|tb1|ltc1)[qp]?/i);
  if (bech) return s.slice(bech[0].length);
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(s)) return s.slice(1); // Tron
  if (/^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/.test(s)) return s.slice(1); // Bitcoin legacy
  if (/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(s)) return s.slice(1); // XRP
  if (TON_RE.test(s)) return s.slice(2);
  if (/^addr1/.test(s)) return s.slice(5);
  return s;
}

function commonPrefix(a, b) {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return i;
}

function commonSuffix(a, b) {
  let i = 0;
  while (i < a.length && i < b.length && a[a.length - 1 - i] === b[b.length - 1 - i]) i++;
  return i;
}

// Address poisoning: scammers make an address with the same start and end as one you use.
// Two random addresses share 3 leading and 3 trailing characters about once in 17 million tries,
// so a match like that is almost certainly on purpose.
export function findLookalike(address, contacts) {
  const target = addressBody(address);
  let best = null;
  for (const c of contacts) {
    if (sameAddress(c.address, address)) continue;
    const other = addressBody(c.address);
    if (!other || other.length !== target.length) continue;
    const prefix = commonPrefix(target, other);
    const suffix = commonSuffix(target, other);
    let level = null;
    if (prefix >= 3 && suffix >= 3) level = "block";
    else if (prefix >= 5 || suffix >= 5) level = "warn";
    if (!level) continue;
    const score = (level === "block" ? 1000 : 0) + prefix + suffix;
    if (!best || score > best.score) best = { name: c.name, address: c.address, prefix, suffix, level, score };
  }
  if (best) delete best.score;
  return best;
}

export function groupAddress(a) {
  const s = String(a ?? "").trim();
  if (EVM_RE.test(s)) return "0x " + s.slice(2).match(/.{1,4}/g).join(" ");
  return s.match(/.{1,4}/g)?.join(" ") || s;
}

export function shortAddress(a) {
  const s = String(a ?? "").trim();
  return s.length <= 14 ? s : `${s.slice(0, 6)}…${s.slice(-4)}`;
}

// ---------------------------------------------------------------- networks and tokens

// Tangem network ids look like CoinGecko platform ids (ethereum, polygon-pos, binance-smart-chain...).
const CHAIN_IDS = {
  ethereum: "1", eth: "1", mainnet: "1",
  "binance-smart-chain": "56", bsc: "56", bnb: "56", "bnb-chain": "56",
  "polygon-pos": "137", polygon: "137", matic: "137",
  "arbitrum-one": "42161", arbitrum: "42161",
  "optimistic-ethereum": "10", optimism: "10",
  base: "8453",
  avalanche: "43114", "avalanche-c-chain": "43114",
  fantom: "250",
  xdai: "100", gnosis: "100",
  zksync: "324", "zksync-era": "324",
  linea: "59144",
  scroll: "534352",
  mantle: "5000",
  blast: "81457",
  cronos: "25",
  "polygon-zkevm": "1101",
  opbnb: "204",
};

export function chainIdFor(network) {
  if (network === undefined || network === null || network === "") return null;
  const k = String(network).trim().toLowerCase();
  return CHAIN_IDS[k] || (/^\d+$/.test(k) ? k : null);
}

function sameNetwork(a, b) {
  const ca = chainIdFor(a);
  const cb = chainIdFor(b);
  if (ca && cb) return ca === cb;
  return String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
}

const SYMBOL_TO_ID = {
  usdc: "usd-coin", usdt: "tether", dai: "dai", eth: "ethereum", weth: "weth",
  btc: "bitcoin", wbtc: "wrapped-bitcoin", pol: "polygon-ecosystem-token", matic: "polygon-ecosystem-token",
  bnb: "binancecoin", sol: "solana", trx: "tron", arb: "arbitrum", op: "optimism",
  avax: "avalanche-2", ton: "the-open-network", xrp: "ripple", doge: "dogecoin",
  ltc: "litecoin", ada: "cardano", usde: "ethena-usde", pyusd: "paypal-usd",
  fdusd: "first-digital-usd", eurc: "euro-coin",
};

const NATIVE_COIN = {
  ethereum: "ethereum", "arbitrum-one": "ethereum", arbitrum: "ethereum",
  "optimistic-ethereum": "ethereum", optimism: "ethereum", base: "ethereum",
  zksync: "ethereum", linea: "ethereum", scroll: "ethereum",
  "polygon-pos": "polygon-ecosystem-token", polygon: "polygon-ecosystem-token",
  "binance-smart-chain": "binancecoin", bsc: "binancecoin",
  avalanche: "avalanche-2", fantom: "fantom", xdai: "xdai", gnosis: "xdai",
  tron: "tron", solana: "solana", bitcoin: "bitcoin", litecoin: "litecoin",
  dogecoin: "dogecoin", ton: "the-open-network", "the-open-network": "the-open-network",
  xrp: "ripple", ripple: "ripple", cardano: "cardano",
};

const STABLE_USD = new Set(["usd-coin", "tether", "dai", "ethena-usde", "paypal-usd", "first-digital-usd", "usds"]);

export function coinIdFor(token, network) {
  const t = token === undefined || token === null ? "" : String(token).trim().toLowerCase();
  if (!t || t === "native") return NATIVE_COIN[String(network ?? "").trim().toLowerCase()] || null;
  if (SYMBOL_TO_ID[t]) return SYMBOL_TO_ID[t];
  if (/-ethereum$/.test(t)) return "ethereum"; // Tangem uses ids like base-ethereum for ETH on L2s
  if (isEvm(t)) return null; // a contract address, priced separately
  if (/^[a-z0-9][a-z0-9-]{1,60}$/.test(t)) return t; // already a CoinGecko style id, which Tangem uses
  return null;
}

async function getJson(url, fetchImpl, headers = { accept: "application/json" }) {
  const res = await fetchImpl(url, { headers, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

const priceCache = new Map();

export async function priceGBP({ coinId, contract, network }, fetchImpl = globalThis.fetch) {
  const key = coinId || `${network}:${contract}`;
  if (priceCache.has(key)) return priceCache.get(key);
  const headers = { accept: "application/json" };
  if (process.env.COINGECKO_API_KEY) headers["x-cg-demo-api-key"] = process.env.COINGECKO_API_KEY;
  let result = null;
  try {
    if (coinId) {
      const j = await getJson(`https://api.coingecko.com/api/v3/simple/price?ids=${encodeURIComponent(coinId)}&vs_currencies=gbp`, fetchImpl, headers);
      const v = j?.[coinId]?.gbp;
      if (typeof v === "number") result = { gbp: v, source: "CoinGecko" };
    } else if (contract && network) {
      const c = contract.toLowerCase();
      const j = await getJson(`https://api.coingecko.com/api/v3/simple/token_price/${encodeURIComponent(network)}?contract_addresses=${c}&vs_currencies=gbp`, fetchImpl, headers);
      const v = j?.[c]?.gbp;
      if (typeof v === "number") result = { gbp: v, source: "CoinGecko" };
    }
  } catch { /* fall back below */ }
  if (!result && coinId && STABLE_USD.has(coinId)) result = { gbp: Number(process.env.GBP_PER_USD || 0.76), source: "approximate stablecoin rate" };
  if (!result && coinId === "euro-coin") result = { gbp: Number(process.env.GBP_PER_EUR || 0.85), source: "approximate stablecoin rate" };
  if (result) priceCache.set(key, result);
  return result;
}

export function parseAmount(v) {
  if (v === undefined || v === null || v === "") return null;
  const n = typeof v === "number" ? v : Number(String(v).replace(/[,\s_]/g, ""));
  return Number.isFinite(n) && n >= 0 ? n : null;
}

const round2 = (n) => Math.round(n * 100) / 100;
const pretty = (flag) => String(flag).replace(/_/g, " ");

// ---------------------------------------------------------------- GoPlus

const ADDRESS_HARD = [
  "sanctioned", "cybercrime", "money_laundering", "phishing_activities", "stealing_attack",
  "blackmail_activities", "financial_crime", "darkweb_transactions", "fake_kyc",
  "malicious_mining_activities", "mixer", "honeypot_related_address", "fake_token", "fake_standard_interface",
];
const ADDRESS_SOFT = ["blacklist_doubt", "gas_abuse", "reinit"];

export async function goplusAddress(address, network, fetchImpl = globalThis.fetch) {
  const chain = chainIdFor(network);
  const url = `${GOPLUS}/address_security/${encodeURIComponent(String(address).trim())}${chain ? `?chain_id=${chain}` : ""}`;
  try {
    const j = await getJson(url, fetchImpl);
    if (j?.code !== 1 || !j.result) return { ok: false, error: j?.message || `GoPlus code ${j?.code}` };
    const r = j.result;
    const hard = ADDRESS_HARD.filter((f) => r[f] === "1");
    if (Number(r.number_of_malicious_contracts_created || 0) > 0) hard.push("created malicious contracts");
    const soft = ADDRESS_SOFT.filter((f) => r[f] === "1");
    return { ok: true, hard, soft, is_contract: r.contract_address === "1", data_source: r.data_source || "" };
  } catch (e) {
    return { ok: false, error: e?.name === "TimeoutError" ? "it timed out" : e?.message || "network error" };
  }
}

const TOKEN_HARD = ["is_honeypot", "cannot_sell_all", "owner_change_balance", "honeypot_with_same_creator", "is_airdrop_scam", "fake_token"];
const TOKEN_SOFT = [
  "hidden_owner", "is_mintable", "transfer_pausable", "is_blacklisted", "is_proxy", "slippage_modifiable",
  "personal_slippage_modifiable", "external_call", "can_take_back_ownership", "selfdestruct", "trading_cooldown",
];

export async function checkToken(contract, network, fetchImpl = globalThis.fetch) {
  const reasons = [];
  let verdict = "ALLOW";
  const flag = (level, text) => {
    reasons.push({ level, text });
    if (RANK[level] > RANK[verdict]) verdict = level;
  };
  const c = String(contract ?? "").trim().toLowerCase();
  const chain = chainIdFor(network);
  if (!isEvm(c)) {
    flag("WARN", "Guard can only check token contracts on EVM networks (0x addresses).");
    return { verdict, reasons, contract: c };
  }
  if (!chain) {
    flag("WARN", `Guard does not know the network "${network}", so it could not check this token.`);
    return { verdict, reasons, contract: c };
  }
  try {
    const j = await getJson(`${GOPLUS}/token_security/${chain}?contract_addresses=${c}`, fetchImpl);
    if (j?.code !== 1) throw new Error(j?.message || `GoPlus code ${j?.code}`);
    const t = j.result?.[c];
    if (!t) {
      flag("WARN", "GoPlus has no data on this token. Be careful with tokens nobody has checked.");
      return { verdict, reasons, contract: c };
    }
    const hard = TOKEN_HARD.filter((k) => t[k] === "1").map(pretty);
    const sellTax = Number(t.sell_tax || 0);
    const buyTax = Number(t.buy_tax || 0);
    if (sellTax >= 0.5) hard.push(`sell tax of ${Math.round(sellTax * 100)}%`);
    const soft = TOKEN_SOFT.filter((k) => t[k] === "1").map(pretty);
    if (t.is_open_source === "0") soft.push("source code not published");
    if (sellTax >= 0.1 && sellTax < 0.5) soft.push(`sell tax of ${Math.round(sellTax * 100)}%`);
    if (buyTax >= 0.1) soft.push(`buy tax of ${Math.round(buyTax * 100)}%`);
    if (hard.length) flag("BLOCK", `GoPlus says this token is dangerous: ${hard.join(", ")}.`);
    if (soft.length) flag("WARN", `GoPlus found risky features: ${soft.join(", ")}.`);
    if (!hard.length && !soft.length) flag("ALLOW", "GoPlus found no problems with this token.");
    if (t.trust_list === "1") flag("ALLOW", "This token is on the GoPlus trust list.");
    return { verdict, reasons, contract: c, token: { name: t.token_name || null, symbol: t.token_symbol || null, holders: t.holder_count || null } };
  } catch (e) {
    flag("WARN", `Could not reach GoPlus (${e?.name === "TimeoutError" ? "it timed out" : e?.message}), so the token was not checked.`);
    return { verdict, reasons, contract: c };
  }
}

// ---------------------------------------------------------------- contacts and policy

export function listContacts() {
  return loadState().contacts;
}

// Contacts saved by the AI are marked unconfirmed, so a tricked AI can't whitelist a scammer.
// Only you can confirm them, change them or delete them, from the terminal (cli.js).
export function addContact({ name, address, network = null, own = false, confirmed = true, addedBy = "you", force = false, allowOverwrite = false }) {
  const cleanName = String(name ?? "").trim();
  const cleanAddress = String(address ?? "").trim();
  if (!cleanName) throw new Error("Give the contact a name.");
  if (!looksLikeAddress(cleanAddress)) throw new Error(`"${cleanAddress}" doesn't look like a wallet address.`);
  return update((s) => {
    const idx = s.contacts.findIndex((c) => c.name.toLowerCase() === cleanName.toLowerCase());
    if (idx >= 0 && !allowOverwrite && s.contacts[idx].confirmed !== false) {
      throw new Error(`A confirmed contact called "${s.contacts[idx].name}" already exists. Only the user can change it, in the terminal.`);
    }
    const others = s.contacts.filter((_, i) => i !== idx);
    const dupe = others.find((c) => sameAddress(c.address, cleanAddress));
    if (dupe) throw new Error(`That address is already saved as "${dupe.name}".`);
    const look = findLookalike(cleanAddress, others);
    if (look && look.level === "block" && !force) {
      throw new Error(`This address looks like your contact "${look.name}" (same first ${look.prefix} and last ${look.suffix} characters) but is different. That is a classic address poisoning trick, so it was not saved.`);
    }
    const entry = { name: cleanName, address: cleanAddress, network: network || null, own: !!own, confirmed: !!confirmed, added_by: addedBy, added_at: new Date().toISOString() };
    if (idx >= 0) s.contacts[idx] = entry;
    else s.contacts.push(entry);
    return entry;
  });
}

export function confirmContact(name) {
  return update((s) => {
    const c = s.contacts.find((x) => x.name.toLowerCase() === String(name ?? "").trim().toLowerCase());
    if (!c) throw new Error(`No contact called "${name}".`);
    c.confirmed = true;
    return c;
  });
}

export function removeContact(name) {
  return update((s) => {
    const before = s.contacts.length;
    s.contacts = s.contacts.filter((x) => x.name.toLowerCase() !== String(name ?? "").trim().toLowerCase());
    if (s.contacts.length === before) throw new Error(`No contact called "${name}".`);
    return true;
  });
}

export function getPolicy() {
  return loadState().policy;
}

export function setPolicy(changes) {
  return update((s) => {
    for (const [k, v] of Object.entries(changes)) {
      if (!(k in DEFAULT_POLICY)) throw new Error(`Unknown policy setting "${k}". Use: ${Object.keys(DEFAULT_POLICY).join(", ")}`);
      if (typeof DEFAULT_POLICY[k] === "boolean") s.policy[k] = v === true || v === "true" || v === "1" || v === "yes";
      else {
        const n = Number(v);
        if (!Number.isFinite(n) || n < 0) throw new Error(`"${k}" must be a number.`);
        s.policy[k] = n;
      }
    }
    return s.policy;
  });
}

export function recentLog(limit = 20) {
  return loadState().log.slice(-limit);
}

function spentTodayGBP(log) {
  const today = new Date().toDateString();
  return log
    .filter((e) => e.source === "hook" && e.verdict !== "BLOCK" && typeof e.amount_gbp === "number" && new Date(e.ts).toDateString() === today)
    .reduce((sum, e) => sum + e.amount_gbp, 0);
}

// ---------------------------------------------------------------- the check

const RANK = { ALLOW: 0, WARN: 1, BLOCK: 2 };

export async function evaluate(input, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  const address = typeof input.address === "string" ? input.address.trim() : input.address ?? null;
  const network = input.network ?? null;
  const token = input.token ?? null;
  const amount = parseAmount(input.amount);
  const state = loadState();
  const policy = state.policy;
  const reasons = [];
  let verdict = "ALLOW";
  const flag = (level, text) => {
    reasons.push({ level, text });
    if (RANK[level] > RANK[verdict]) verdict = level;
  };

  const result = {
    address: address || null, network, token, amount,
    contact: null, own_wallet: false, lookalike_of: null,
    goplus: null, amount_gbp: null, price_source: null,
  };

  if (!address) {
    flag("WARN", "Guard could not find a recipient address in this request, so it could not check it.");
  } else if (!looksLikeAddress(address)) {
    flag("WARN", `"${address}" is not a plain wallet address (it may be a name). Check the real address on the review sheet.`);
  } else {
    const contact = state.contacts.find((c) => sameAddress(c.address, address));
    if (contact) {
      result.contact = contact.name;
      result.own_wallet = !!contact.own;
      flag("ALLOW", contact.own ? `This is one of your own wallets (${contact.name}).` : `Saved contact: ${contact.name}.`);
      if (contact.confirmed === false) {
        flag("WARN", `The AI saved "${contact.name}" and you have not confirmed it yet. If it is right, run: node cli.js confirm "${contact.name}"`);
      }
      if (contact.network && network && !sameNetwork(contact.network, network)) {
        flag("WARN", `${contact.name} is saved for ${contact.network}, but this payment is on ${network}. Sending on the wrong network can lose the money.`);
      }
    } else {
      const look = findLookalike(address, state.contacts);
      if (look) {
        result.lookalike_of = look;
        if (look.level === "block") {
          flag("BLOCK", `This address looks like your contact "${look.name}" (same first ${look.prefix} and last ${look.suffix} characters) but it is a different address. This is how address poisoning scams work.`);
        } else {
          flag("WARN", `This address starts or ends like your contact "${look.name}" but it is a different address.`);
        }
      }
      if (policy.contacts_only) flag("BLOCK", "This address is not in your contacts, and contacts only mode is on.");
      else flag("WARN", "First time recipient: this address is not in your contacts.");
    }

    const gp = await goplusAddress(address, network, fetchImpl);
    result.goplus = gp.ok
      ? { flags: gp.hard, warnings: gp.soft, is_contract: gp.is_contract, data_source: gp.data_source }
      : { error: gp.error };
    if (gp.ok) {
      if (gp.hard.length) flag("BLOCK", `GoPlus security lists this address for: ${gp.hard.map(pretty).join(", ")}${gp.data_source ? ` (source: ${gp.data_source})` : ""}.`);
      if (gp.soft.length) flag("WARN", `GoPlus marks this address as suspicious: ${gp.soft.map(pretty).join(", ")}.`);
      if (!gp.hard.length && !gp.soft.length) flag("ALLOW", "GoPlus has no scam reports for this address.");
      if (gp.is_contract && !result.contact) flag("WARN", "This address is a smart contract, not a normal wallet. Sending tokens to the wrong contract usually loses them.");
    } else {
      flag(policy.fail_closed ? "BLOCK" : "WARN", `Could not reach GoPlus (${gp.error}), so the scam list was not checked.`);
    }
  }

  if (amount !== null && amount > 0) {
    const coinId = coinIdFor(token, network);
    const contract = !coinId && isEvm(String(token ?? "")) ? String(token).trim() : null;
    const price = coinId || contract ? await priceGBP({ coinId, contract, network }, fetchImpl) : null;
    if (price) {
      const gbp = amount * price.gbp;
      result.amount_gbp = round2(gbp);
      result.price_source = price.source;
      if (gbp > policy.max_per_tx_gbp) {
        flag("BLOCK", `This payment is about £${gbp.toFixed(2)}, which is over your £${policy.max_per_tx_gbp} limit per payment.`);
      }
      const spent = spentTodayGBP(state.log);
      if (spent + gbp > policy.daily_limit_gbp) {
        flag("BLOCK", `This would take today's total to about £${(spent + gbp).toFixed(2)}, which is over your £${policy.daily_limit_gbp} daily limit.`);
      }
    } else {
      flag("WARN", "Guard could not price this token, so your spending limits were not checked.");
    }
  }

  result.verdict = verdict;
  result.reasons = reasons;

  if (opts.log !== false) {
    update((s) => {
      s.log.push({
        ts: new Date().toISOString(), source: opts.source || "manual", tool: opts.tool || null,
        address: result.address, network, token, amount, amount_gbp: result.amount_gbp, verdict,
        reasons: reasons.filter((r) => r.level !== "ALLOW").map((r) => r.text),
      });
      if (s.log.length > 500) s.log.splice(0, s.log.length - 500);
    });
  }
  return result;
}

// Plain English summary to show before the card tap.
export function explain(r) {
  const what = r.amount !== null && r.amount !== undefined ? `${r.amount} ${r.token ?? ""}`.trim() : "this payment";
  const gbp = typeof r.amount_gbp === "number" ? ` (about £${r.amount_gbp.toFixed(2)})` : "";
  const who = r.contact
    ? r.contact
    : r.lookalike_of
      ? `an address that only LOOKS like ${r.lookalike_of.name}`
      : "an address that is not in your contacts";
  const lines = [];
  lines.push(`Payment: ${what}${gbp}${r.network ? ` on ${r.network}` : ""}`);
  lines.push(`To: ${who}`);
  if (r.address) lines.push(`Address: ${groupAddress(r.address)}`);
  if (r.lookalike_of) lines.push(`Real ${r.lookalike_of.name}: ${groupAddress(r.lookalike_of.address)}`);
  lines.push("");
  lines.push(`Tangem Guard verdict: ${r.verdict}`);
  for (const x of r.reasons) lines.push(`${x.level === "BLOCK" ? "✖" : x.level === "WARN" ? "!" : "✓"} ${x.text}`);
  lines.push("");
  if (r.verdict === "BLOCK") {
    lines.push("Do not send this. If your phone ever shows this payment, reject it.");
  } else {
    lines.push("Before you tap your card:");
    lines.push(`1. The network on the review sheet says ${r.network ?? "the network you expect"}.`);
    lines.push(`2. The amount is ${what}.`);
    let n = 3;
    if (r.address) lines.push(`${n++}. The whole address matches, including the middle: ${groupAddress(r.address)}`);
    lines.push(`${n}. If anything is different, or someone is rushing you, reject it.`);
  }
  return lines.join("\n");
}
