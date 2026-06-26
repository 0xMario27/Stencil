# Stencil · Proxy Config Generator

Pull the nodes from an airport subscription and inline them into your own
client template, producing a ready-to-import config.

Supports **Surge** and **Stash**. Three ways to use: CLI, Docker web UI, or static browser page.

---

## Requirements

`bash`, `curl`, `awk`, `sed`, `openssl` — all preinstalled on macOS / Linux.
No Python / Ruby or other runtime dependencies.

---

## Quick Start

### CLI (bash)

```bash
make config
# or: bash generate.sh
```

Four steps: choose client → template → paste subscription URL → output filename.
The generated config is written to `result/` (git-ignored).

### Docker (web UI)

```bash
docker-compose up -d
# open http://localhost:5000
```

### Static Page (GitHub Pages)

Visit `https://0xMario27.github.io/Stencil` — no install, runs in your browser.
A Cloudflare Worker proxies subscription requests to avoid CORS.

> `make help` shows all CLI commands.

---

## How it works per client

The node-import mechanism differs by client, handled automatically:

| Client | Template | Ext | What the generator does |
|--------|----------|-----|-------------------------|
| **Surge** | `Surge/` | `.conf` | Fetch subscription → extract `[Proxy]` nodes → inline into template |
| **Stash** | `Stash/` | `.yaml` | Fetch subscription → get nodes → inline into `proxies:` → remove `proxy-providers` → rewrite `use: [SF]` groups by filter |

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
├── Makefile              # CLI entry point
├── generate.sh           # bash generator (Surge + Stash)
├── README.md
├── docker-compose.yml    # Docker web UI
├── Surge/                # Surge templates (*.conf)
│   └── Surge2026.conf
├── Stash/                # Stash templates (*.yaml)
│   └── StashProMax.yaml
├── web/                  # Flask web app
│   ├── app.py
│   ├── Dockerfile
│   └── templates/index.html
├── _worker.js            # Cloudflare Worker (CORS proxy)
├── wrangler.jsonc
└── index.html            # static SPA (gh-pages branch)
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
