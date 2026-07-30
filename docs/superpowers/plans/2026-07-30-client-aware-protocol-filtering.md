# Client-Aware Protocol Filtering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. No test framework exists in this repo; verify via node/python/bash one-liners against the real subscription snapshot in `/tmp/sub_noua.txt` (base64) and `/tmp/sub_surge.txt` (surge).

**Goal:** Make protocol filtering client-aware across all three codebases (gh-pages JS, app.py Python, generate.sh bash) so unsupported protocols (e.g. vless for Surge) are silently dropped, and supported ones (vless for Stash/ClashMac) flow through.

**Architecture:** Add a `CLIENT_PROTOCOLS` matrix as single source of truth. Extend URI parsers to parse vless/vmess/tuic into IR (remove hardcoded scheme rejection). Extend IR converters to emit them. Filter IR by client after parse, before convert. Surge identity path keeps raw lines + line-level protocol filter.

**Tech Stack:** Vanilla JS (browser), Python/Flask, bash+awk.

**Spec:** `docs/superpowers/specs/2026-07-30-client-aware-protocol-filtering-design.md`

## Global Constraints
- Protocol matrix identical across all three: Surge = {anytls,ss,trojan,vmess,hysteria2,tuic,http,https,socks5,socks5-tls,snell,wireguard,ssh,h2,direct}; Stash/ClashMac = {anytls,ss,vmess,vless,trojan,hysteria2,tuic,http,socks5,snell,wireguard,direct}.
- Silent filtering (no user warning). All-filtered -> raise existing "No usable proxy nodes found" error.
- bash must stay dependency-free (no jq/python); use awk/sed/openssl for vmess JSON.
- gh-pages is the live path; ship first.

## File Structure
- Modify: `gh-pages` branch `index.html` (worktree `/var/folders/2h/blgvzhwd66g1qt4zj94xb9vw0000gn/T/opencode/gh-pages-wt/index.html`) — JS
- Modify: `web/app.py` — Python
- Modify: `generate.sh` — bash
- Test fixtures: `/tmp/sub_noua.txt` (base64, has anytls+vless), `/tmp/sub_surge.txt` (surge, anytls only)

---

## Task 1: gh-pages JS — protocol matrix + filter + vless parsing + converters

**Files:** Modify `index.html` (gh-pages worktree)

**Interfaces:**
- Produces: `CLIENT_PROTOCOLS` (map), `filterByClient(nodes, client)`, extended `parseUriNode`/`irToClash`/`irToSurge`/`parseSurgeToIR`, line-filtered `extractSurgeNodes`.

- [ ] 1.1 Add `CLIENT_PROTOCOLS` + `filterByClient` after the IR converter section.
- [ ] 1.2 Rewrite `parseUriNode`: drop scheme rejection; add vless/vmess/tuic branches.
- [ ] 1.3 Extend `irToClash` to emit vless/vmess/tuic.
- [ ] 1.4 Extend `irToSurge` to emit vmess/tuic.
- [ ] 1.5 Extend `parseSurgeToIR` to carry uuid/flow/reality/cipher fields.
- [ ] 1.6 Add line-level client filter in `extractSurgeNodes` (accept client arg).
- [ ] 1.7 Wire `filterByClient` into `doGenerate` (IR array paths) + pass client to surge-string path.
- [ ] 1.8 Verify with node harness: base64->Surge drops vless; base64->Stash keeps vless with reality-opts.

## Task 2: app.py Python — same matrix + filter + parsers + converters

**Files:** Modify `web/app.py`

- [ ] 2.1 Add `CLIENT_PROTOCOLS` + `filter_by_client`.
- [ ] 2.2 Rewrite `parse_uri_node`: drop rejection; add vless/vmess/tuic.
- [ ] 2.3 Extend `ir_to_clash`/`ir_to_surge`.
- [ ] 2.4 Extend `parse_surge_to_ir` for vmess/tuic/vless fields.
- [ ] 2.5 Add line-level filter to `extract_surge_nodes` + wire `filter_by_client` in `gen_surge`/`gen_stash`.
- [ ] 2.6 Verify with python one-liner.

## Task 3: generate.sh bash — same matrix + filter + parsers + converters

**Files:** Modify `generate.sh`

- [ ] 3.1 Add `CLIENT_PROTOCOLS` lookup + `_filter_by_client`.
- [ ] 3.2 Extend `_uri_node_parse` for vless/vmess/tuic (vmess via awk JSON extract).
- [ ] 3.3 Extend `_uri2clash`/`_uri2surge` awk for vless/vmess/tuic.
- [ ] 3.4 Add filter step in `gen_surge`/`gen_stash`; line-level filter for surge identity.
- [ ] 3.5 Verify with bash one-liner.

## Task 4: End-to-end verification + deploy
- [ ] 4.1 Re-run real subscription through patched gh-pages logic (node harness).
- [ ] 4.2 JS syntax check.
- [ ] 4.3 Report; await user OK to commit gh-pages + push.
