# Tangem MCP feedback (draft, edit before sending)

From Baburam Bastola, AI and Computing Society, University of Roehampton. Built Tangem Guard at the Encode build night, 26 November 2026.

## What worked well

* Connecting Claude Code to `https://mcp.tangem.org/mcp` was quick, and the sign in worked.
* The tool split (wallets, transactions, express, pay) is clear, and the tool descriptions explain the limits well.
* Keeping signing on the card means the agent can never move money by itself. That made it easy to build on safely.

## What would make it better

1. **Show third party risk notes on the review sheet.** Let an intent carry a short note from a tool like Guard ("unknown address, looks like your contact Treasurer"). The card has no screen, so the phone sheet is the only place a user can check what they sign.
2. **Warn about lookalike and first time recipients in the app itself.** Address poisoning is one of the biggest real losses in crypto, and it targets exactly this copy and paste flow.
3. **Public docs for the tool schemas,** so builders don't have to guess field names.
4. **A testnet or dry run mode** for `send_transaction`, so we can build and demo without real funds.
5. **Clear scopes when connecting:** read only versus can propose payments, plus optional per session limits and a recipient allowlist set in the app.
6. **Say how long an intent stays valid,** and what the push notification shows (amount and recipient, or a generic message).
7. **Mini app docs:** how they run inside the app, how they're reviewed, and whether they can create intents directly.

## Bugs or rough edges I hit

* (add anything you saw tonight)
