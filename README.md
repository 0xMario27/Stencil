# Stencil · Proxy Config Generator

Pull the nodes from an airport subscription and inline them into your own
client template, producing a ready-to-import config. One interactive command,
no proxy-providers / remote includes — the nodes are written directly into the
config so it always works offline of the provider.

Supports **Surge** and **Stash**, and is easy to extend to more clients.

---

## Requirements

`bash`, `curl`, `awk`, `sed`, `openssl` — all preinstalled on macOS / Linux.
No Python / Ruby or other runtime dependencies.

---

## Quick Start

```bash
make config
```

Then follow the four steps:

```
Step 1/4  Choose client      Surge / Stash        (↑/↓ to move, Enter to confirm)
Step 2/4  Choose template    lists templates of the chosen client
Step 3/4  Subscription URL   paste your airport subscription link
Step 4/4  Output file name   press Enter for the default
```

The generated config is written to **`result/`** (your templates are never
modified). Import it into the corresponding client.

> `make help` shows the available commands. Running `make` with no target also
> prints help.

### Menu navigation

In a real terminal the client/template menus support:

- **↑ / ↓** (or `j` / `k`, `w` / `s`) to move the highlight
- **Enter** to confirm
- number keys **1-9** to jump directly

When run non-interactively (piped input), the menus fall back to numbered input.

---

## How it works per client

The node-import mechanism differs by client, handled automatically:

| Client | Template | Ext | What the generator does |
|--------|----------|-----|-------------------------|
| **Surge** | `Surge/` | `.conf` | Fetch subscription → extract `[Proxy]` nodes → inline them into the template's `[Proxy]` → switch `AllServer` from `policy-path` to `include-all-proxies=1` |
| **Stash** | `Stash/` | `.yaml` | Fetch subscription → get nodes → inline into `proxies:` (Flow Mapping) → remove `proxy-providers` → rewrite `use: [SF]` groups into explicit node lists (by each group's `filter`) |

### Stash node sources

The generator gets Stash nodes from whichever format the airport returns,
in this order:

1. **Clash YAML** with a populated `proxies:` section → used directly.
2. **base64 subscription** (the universal `xxx://` URI list) → decoded and
   converted to Clash nodes (currently `anytls://`).
3. Otherwise → reports a client/format mismatch.

### Why inline instead of subscription / provider

- **Surge**: on iOS, importing newer-protocol nodes (e.g. AnyTLS) via
  `policy-path` can show the nodes but fail to connect. Inlining them as native
  `[Proxy]` entries avoids this.
- **Stash**: remote `proxy-providers` can fail in some networks. Inlining the
  nodes into `proxies:` removes the runtime fetch.

> Trade-off: when the airport rotates nodes, just regenerate the config.

---

## Format matching

The User-Agent used to fetch is chosen to match the client (Surge UA for Surge,
a Clash UA for Stash). If the subscription content does not match the selected
client (e.g. a Clash-only link while generating a Surge config), the tool stops
with a clear "subscription does not match the selected client" message. In that
case, use the subscription link/format your airport provides for that client.

---

## Project layout

```
.
├── Makefile          # make config / make help
├── generate.sh       # interactive generator (all clients)
├── README.md
├── Surge/            # Surge templates (*.conf)
│   └── Surge2026.conf
├── Stash/            # Stash templates (*.yaml)
│   └── StashProMax.yaml
└── result/           # generated configs (git-ignored, contains real secrets)
```

---

## Adding things

- **New template**: drop a `.conf` into `Surge/` or a `.yaml` into `Stash/`.
  It appears in the menu automatically.
- **New client**: add a `gen_<client>()` function in `generate.sh` and register
  it in the client list and the dispatch `case`.

---

## Security

Generated configs in `result/` contain real subscription URLs / node
passwords and are git-ignored. Template files contain only placeholders and are
safe to commit.
