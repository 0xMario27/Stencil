# Client-Aware Protocol Filtering — Design Spec

Date: 2026-07-30
Status: Design (pending approval)
Scope: `gh-pages` static page (`index.html`, JS), Docker backend (`web/app.py`, Python), CLI (`generate.sh`, bash) — all three unified.

## 1. Problem

Protocol filtering today is scattered, inconsistent, and **not client-aware**:

| Location | Current behavior | Issue |
|---|---|---|
| JS `parseUriNode` | hardcodes `['anytls','trojan','hysteria','hysteria2']`; drops vmess/vless/tuic | Stash/ClashMac lose vless nodes they actually support |
| Python `parse_uri_node` | `SUPPORTED_SCHEMES = {anytls,trojan,hysteria,hysteria2}` + `ss`; drops vmess/vless/tuic | same |
| bash `_uri_node_parse` | parses any scheme generically (no rejection) | vless leaks through as a generic `password=uuid` node — wrong fields for Stash |
| Surge `[Proxy]` extraction regex (all 3) | allowlist **includes `vless`** | Surge does **not** support vless — produces a broken config |

There is no single source of truth for "which protocols does client X support". The user's case: a base64 subscription containing `anytls://` + `vless://` nodes, generating for Surge → vless must be filtered out.

## 2. Goals & Non-Goals

**Goals**
- One per-client protocol matrix as the single source of truth, identical across all three codebases.
- Silent filtering: nodes whose protocol the target client doesn't support are dropped, no user-facing warning.
- Extend the URI parser + IR converters so `vless`, `vmess`, `tuic` flow through IR — so Stash/ClashMac actually receive them.
- Apply the filter at the IR layer (after parse, before convert) for all non-identity paths.

**Non-Goals**
- No new clients. No UI changes. No subscription-fetch logic changes.
- Not adding `hysteria` v1 / `ssr` / `juicity` etc. beyond the matrix below.
- Not changing the smart-fetcher UA selection.

## 3. Protocol Support Matrix

Single source of truth. `type` values that may appear in IR:

```
Surge:    anytls ss trojan vmess hysteria2 tuic http https socks5 socks5-tls snell wireguard ssh h2 direct
Stash:    anytls ss vmess vless trojan hysteria2 tuic http socks5 snell wireguard direct
ClashMac: anytls ss vmess vless trojan hysteria2 tuic http socks5 snell wireguard direct
```

Rules:
- **Surge** excludes `vless` and `hysteria` (v1; only `hysteria2`).
- **Stash / ClashMac** (Clash.Meta / mihomo core) include `vless`.
- `direct` is always allowed (used by templates).

Each codebase defines this as a constant set/map keyed by client.

## 4. IR (intermediate representation) extensions

Current IR fields (per node):
`type, name, server, port, password, udp, sni, skip_cert_verify, client_fingerprint, peer, network, encrypt_method, obfs, obfs_host, obfs_uri, ws_path, grpc_service_name`

Add fields (only populated by the relevant scheme):

| Field | Used by | Source |
|---|---|---|
| `uuid` | vless, vmess, tuic | vless/vmess identity; tuic uuid |
| `flow` | vless | `flow` param (e.g. `xtls-rprx-vision`) |
| `reality_pbk` | vless | `pbk` param (reality public key) |
| `reality_sid` | vless | `sid` param (reality short id) |
| `security` | vless, vmess | vless `security=reality`; vmess cipher |
| `alter_id` | vmess | vmess `aid` |
| `ws_host` | vless, vmess | ws `Host` header |
| `congestion` | tuic | `congestion` param |
| `udp_relay_mode` | tuic | `udp_relay_mode` param |
| `alpn` | tuic, hysteria2 | `alpn` param |

`password` is reused for tuic password and anytls/trojan/hysteria2/ss auth as today.

## 5. URI parsing (base64 path) — extend parsers

Extend `parseUriNode` (JS), `parse_uri_node` (Python), `_uri_node_parse` (bash) to handle `vless`, `vmess`, `tuic` in addition to the existing `anytls/trojan/hysteria2/ss`. **Remove the hardcoded scheme rejection** — let all schemes parse into IR; the client filter (§7) drops unsupported ones.

### 5.1 vless
`vless://uuid@host:port?type=tcp&security=reality&flow=xtls-rprx-vision&sni=...&fp=chrome&pbk=...&sid=...&insecure=0&host=...&path=...&serviceName=...&headerType=none#name`
- `uuid` → `uuid`
- `type` → `network`
- `security=reality` → `security=reality`, set `tls=true`
- `flow`, `sni`, `fp`, `pbk`, `sid`, `host`(ws Host), `path`(ws path), `serviceName`(grpc) → mapped
- `insecure=1` → `skip_cert_verify`

### 5.2 vmess
`vmess://<base64(json)>` — decode base64, parse JSON:
- `v, ps(name), add(server), port, id(uuid), aid(alter_id), scy(security/cipher), net(network), type(headerType), host(ws Host), path(ws path), tls, sni, alpn`
Map to IR. (If JSON parse fails, skip the node.)

### 5.3 tuic
`tuic://uuid:password@host:port?congestion=bbr&alpn=h3&sni=...&udp_relay_mode=native&insecure=0#name`
- `uuid:password` auth split on first `:`
- params → `congestion`, `alpn`, `sni`, `udp_relay_mode`, `skip_cert_verify`

## 6. Converters — extend irToClash / irToSurge (and bash awk equivalents)

### 6.1 irToClash (for Stash / ClashMac)
- **vless**: `type: vless, uuid: "...", network: <tcp|ws|grpc|h2>, tls: true, flow: <flow>, servername: <sni>, client-fingerprint: <fp>, reality-opts: {public-key: <pbk>, short-id: <sid>}`; add `ws-opts: {path, headers:{Host}}` / `grpc-opts: {grpc-service-name}` when network matches.
- **vmess**: `type: vmess, uuid, alterId, cipher: <security>, network, tls, servername, ws-opts/grpc-opts`.
- **tuic**: `type: tuic, uuid, password, congestion-controller, udp-relay-mode, alpn, sni, skip-cert-verify`.
- existing anytls/trojan/hysteria2/ss unchanged.

### 6.2 irToSurge (for Surge — vless never reaches here, filtered out)
- **vmess**: `Name = vmess, server, port, username=<uuid>, encrypt-method=<security>, [ws=true, ws-path=..., ws-header=Host=... | tls=true]`
- **tuic**: `Name = tuic, server, port, password=<password>, [sni=..., alpn=...]`
- existing anytls/trojan/hysteria2/ss unchanged.

### 6.3 Cross-format notes
- `_clash2surge` (bash awk) and `parse_clash_proxies`→`ir_to_surge` (Python) / `parseClashProxies`→`irToSurge` (JS): extend to read `uuid`/`flow`/`reality-opts`/`cipher`/`alterId` from Clash lines when emitting Surge vmess/tuic. vless Clash lines are dropped for Surge by the filter (not by the converter).

## 7. Filter — single point, silent

`filterByClient(nodes, client)`: return `[n for n in nodes if n.type in CLIENT_PROTOCOLS[client]]`.

Applied:
- **base64 path**: `parseUriList(text)` → **filter** → `irToSurge`/`irToClash`.
- **clash path**: `parseClashProxies(text)` → **filter** → convert.
- **surge→clash path**: `parseSurgeToIR(text)` → **filter** → `irToClash`.
- **surge→surge (identity) path**: raw `[Proxy]` lines are inlined verbatim today (preserves `tfo=true`, `skip-cert-verify=false`, field order). To avoid a fidelity regression, keep raw-line inlining **but** apply a line-level filter using the same matrix: extract the protocol token (word after `= `) from each `[Proxy]` line and drop lines whose protocol ∉ Surge's set. This is the same matrix, just applied to the raw representation.

If filtering removes **all** nodes, raise the existing "No usable proxy nodes found" error.

## 8. Per-codebase change summary

### 8.1 `gh-pages/index.html` (JS) — also applies the prior Surge/base64 fix
- Add `CLIENT_PROTOCOLS` map.
- Remove scheme rejection in `parseUriNode`; add vless/vmess/tuic parsing.
- Extend `irToClash` / `irToSurge` for vless/vmess/tuic.
- Add `filterByClient(nodes, client)`; call it in `doGenerate` before `genSurge`/`genStash` (passing IR arrays — aligns with the prior fix).
- In `extractSurgeNodes`/surge-identity path: add line-level protocol filter for Surge.
- Remove `parseSurgeToIR` scheme limitations (it already parses generically — just ensure it carries `uuid`/`flow` etc. for vmess/tuic lines).

### 8.2 `web/app.py` (Python)
- Add `CLIENT_PROTOCOLS` dict.
- Remove `SUPPORTED_SCHEMES` rejection in `parse_uri_node`; add vless/vmess/tuic.
- Extend `ir_to_clash` / `ir_to_surge`.
- Add `filter_by_client(nodes, client)`; call in `gen_surge`/`gen_stash` after parse, before convert.
- `parse_surge_to_ir`: carry vmess/tuic fields.
- surge-identity path (`extract_surge_nodes` + inline): add line-level filter.

### 8.3 `generate.sh` (bash)
- Add `CLIENT_PROTOCOLS` lookup (case statement or assoc array).
- `_uri_node_parse`: add vless/vmess/tuic field extraction (vless via query params; vmess via `openssl base64 -d` + JSON parse with a small awk/python-free approach or `jq` if available — see open question).
- `_uri2clash` / `_uri2surge` awk: emit vless/vmess/tuic fields.
- Add a `_filter_by_client` step: after producing IR (or clash lines), drop entries whose `type` ∉ client set. For surge-identity, filter raw `[Proxy]` lines by protocol token.
- `_surge2clash` / `_clash2surge` awk: carry vmess/tuic fields.

## 9. Open questions (to resolve in plan)

1. **vmess JSON parsing in bash**: `generate.sh` avoids Python/Ruby. vmess:// is base64(JSON). Options: (a) require `jq` (may not be installed); (b) parse the few needed fields with `grep`/`sed`/`awk`; (c) skip vmess in bash CLI only (document). Recommend (b) — minimal awk extraction of `id, add, port, aid, scy, net, path, host, tls, sni`.
2. **`tfo=true` preservation**: confirm acceptable to keep dropping on cross-format paths (IR has no tfo field); only the surge→surge identity path preserves it. (No change needed if accepted.)

## 10. Testing

- Unit-style checks (node/python/bash one-liners) per codebase:
  - base64 with anytls+vless → Surge: vless dropped, anytls kept.
  - same base64 → Stash: vless kept and emitted as Clash vless with reality-opts.
  - vmess:// → Stash: emitted with uuid/alterId/cipher.
  - tuic:// → Stash and → Surge: emitted correctly (Surge keeps tuic).
  - surge-format subscription → Surge: vless `[Proxy]` lines dropped, anytls lines verbatim.
  - all-nodes-filtered → raises "No usable proxy nodes found".
- Real subscription (the user's URL) end-to-end on gh-pages after deploy.

## 11. Rollout

gh-pages fix (§8.1) is the user's live path; deploy first. app.py + generate.sh follow for consistency. No data migration; templates unchanged.
