#!/usr/bin/env python3
"""Stencil Config Generator - Web Backend"""

import os
import re
import tempfile
from pathlib import Path

import requests
from flask import Flask, jsonify, render_template, request, send_file

app = Flask(__name__)
_HERE = Path(__file__).resolve().parent
# Auto-detect project root: use parent dir (local dev) or current dir (Docker)
ROOT = _HERE.parent if (_HERE.parent / "Surge").is_dir() else _HERE
UA_SURGE = "Surge iOS/3000 CFNetwork Darwin"
UA_STASH = "ClashforWindows/0.20.39"


# ---------------------------------------------------------------------------
# Template discovery
# ---------------------------------------------------------------------------
def list_templates():
    """Return {client: [filenames]} for Surge/*.conf and Stash/*.yaml."""
    templates = {}
    for client, glob_pat, ext in [
        ("Surge", "Surge/*.conf", ".conf"),
        ("Stash", "Stash/*.yaml", ".yaml"),
        ("ClashMac", "ClashMac/*.yaml", ".yaml"),
    ]:
        files = sorted(
            f.name
            for f in (ROOT / client).glob(f"*{ext}")
            if ".filled." not in f.name
        )
        if files:
            templates[client] = files
    return templates


# ---------------------------------------------------------------------------
# Surge generation
# ---------------------------------------------------------------------------
def extract_surge_nodes(raw_text: str) -> list[str]:
    """Extract Surge-format proxy lines from subscription response."""
    in_proxy = False
    nodes = []
    for line in raw_text.splitlines():
        if line.startswith("[Proxy]"):
            in_proxy = True
            continue
        if in_proxy and line.startswith("["):
            in_proxy = False
            continue
        if not in_proxy:
            continue
        if re.match(
            r"^[^#\s].*=\s*(anytls|ss|ssr|trojan|vmess|vless|hysteria2?|tuic|http|https|socks5(-tls)?|snell|wireguard|direct)(\s*,|\s*$)",
            line,
        ):
            nodes.append(line)
    return nodes


def gen_surge(template_name: str, sub_url: str) -> tuple[bytes, str]:
    """Download subscription, inline nodes, return (content, filename)."""
    tpl_path = ROOT / "Surge" / template_name
    tpl_text = tpl_path.read_text(encoding="utf-8")

    # Fetch subscription
    resp = requests.get(sub_url, headers={"User-Agent": UA_SURGE}, timeout=40)
    resp.raise_for_status()
    nodes = extract_surge_nodes(resp.text)
    if not nodes:
        raise ValueError("No Surge proxy nodes found in subscription")

    # Build output: insert nodes after [Proxy] header, skip old lines
    out_lines = []
    in_proxy = False
    nodes_inlined = False
    for line in tpl_text.splitlines():
        if line.startswith("[Proxy]") and not nodes_inlined:
            out_lines.append(line)
            out_lines.extend(nodes)
            out_lines.append("")
            nodes_inlined = True
            in_proxy = True
            continue
        if in_proxy:
            if line.startswith("["):
                in_proxy = False
                out_lines.append(line)
            # else skip old proxy lines
            continue
        out_lines.append(line)

    output = "\n".join(out_lines).encode("utf-8")
    stem = Path(template_name).stem
    filename = f"{stem}.filled.conf"
    return output, filename


# ---------------------------------------------------------------------------
# Stash generation
# ---------------------------------------------------------------------------
def extract_stash_clash(raw_text: str) -> str:
    """Extract Clash YAML proxies block from subscription response."""
    lines = raw_text.splitlines()
    in_proxies = False
    clash_lines = []
    for line in lines:
        if line.strip() == "proxies:":
            in_proxies = True
            continue
        if in_proxies:
            if re.match(r"^[a-zA-Z]", line):
                break
            clash_lines.append(line)
    return "\n".join(clash_lines)


def gen_stash(template_name: str, sub_url: str) -> tuple[bytes, str]:
    """Download subscription, inline nodes, return (content, filename)."""
    tpl_path = ROOT / "Stash" / template_name
    tpl_text = tpl_path.read_text(encoding="utf-8")

    # 1st attempt: fetch with Clash UA, look for YAML proxies section
    resp = requests.get(sub_url, headers={"User-Agent": UA_STASH}, timeout=40)
    resp.raise_for_status()
    clash = extract_stash_clash(resp.text)

    # 2nd attempt (fallback): fetch with v2rayN UA, base64 decode URI list
    if not clash.strip():
        import base64
        try:
            resp2 = requests.get(sub_url, headers={"User-Agent": "v2rayN/6.45"}, timeout=40)
            resp2.raise_for_status()
            decoded = base64.b64decode(resp2.text).decode("utf-8")
            if "://" in decoded:
                clash = _uri2clash(decoded)
        except Exception:
            pass

    if not clash.strip():
        raise ValueError("No usable proxy nodes found for Stash")

    # Build names array for filter matching
    names = []
    for line in clash.splitlines():
        m = re.search(r'"name"\s*:\s*"([^"]*)"', line)
        if not m:
            m = re.search(r'[{,]\s*name\s*:\s*"?([^",}]+)"?', line)
        if m:
            names.append(m.group(1))

    # Rebuild template
    out_lines = []
    in_pp = False
    proxies_inlined = False
    for line in tpl_text.splitlines():
        if in_pp:
            if re.match(r"^[a-zA-Z]", line):
                in_pp = False
            else:
                continue
        if line.strip() == "proxy-providers:":
            in_pp = True
            continue
        if line.strip() == 'proxies: []' and not proxies_inlined:
            out_lines.append("proxies:")
            out_lines.append(clash.rstrip())
            proxies_inlined = True
            continue
        # Rewrite use:[SF] groups
        if "use: [SF]" in line:
            line = _rewrite_stash_group(line, names)
        out_lines.append(line)

    output = "\n".join(out_lines).encode("utf-8")
    stem = Path(template_name).stem
    filename = f"{stem}.filled.yaml"
    return output, filename


def _uri2clash(text: str) -> str:
    """Convert base64-decoded URI subscription entries to Clash flow format.
    Handles: anytls://password@host:port/?params#name"""
    from urllib.parse import unquote
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("anytls://"):
            continue
        rest = line[len("anytls://"):]
        # Split password and remainder
        if "@" not in rest:
            continue
        password, rest = rest.split("@", 1)
        # Extract name after # (URL-decoded)
        name = ""
        if "#" in rest:
            rest, name = rest.split("#", 1)
            name = unquote(name)
        # Extract query string after ?
        query = ""
        if "?" in rest:
            rest, query = rest.split("?", 1)
        # Extract host:port (strip trailing /)
        host_port = rest.split("/")[0]
        if ":" in host_port:
            host, port = host_port.split(":", 1)
        else:
            host, port = host_port, "443"
        # Parse query params
        sni = fp = ""
        for p in query.split("&"):
            if p.startswith("sni="):
                sni = p[4:]
            elif p.startswith("fp="):
                fp = p[3:]
        if not name:
            name = host
        entry = f'  - {{name: "{name}", type: anytls, server: {host}, port: {port}, password: "{password}", udp: true'
        if sni:
            entry += f", sni: {sni}"
        if fp:
            entry += f", client-fingerprint: {fp}"
        entry += "}"
        result.append(entry)
    return "\n".join(result)


def _rewrite_stash_group(line: str, names: list[str]) -> str:
    """Replace use:[SF] with matching proxy names list."""
    # Extract filter value
    filter_val = ""
    m = re.search(r"filter:\s*'([^']*)'", line)
    if m:
        filter_val = m.group(1)
    else:
        m = re.search(r"filter:\s*([^,\s}]+)", line)
        if m:
            filter_val = m.group(1)

    if filter_val.startswith("^((?!"):
        # Strip negative-lookahead wrapper to get keywords only
        inner = re.sub(r'^\^\(\(\?!', '', filter_val)
        inner = re.sub(r'\)\.\)\*\$$', '', inner)
        pattern = re.compile(inner)
        matched = [n for n in names if not pattern.search(n)]
    elif filter_val:
        pattern = re.compile(filter_val)
        matched = [n for n in names if pattern.search(n)]
    else:
        matched = list(names)

    joined = ", ".join(f'"{n}"' for n in matched)
    line = re.sub(r",\s*use:\s*\[SF\]", "", line)
    line = re.sub(r",\s*filter:\s*'[^']*'", "", line)
    line = re.sub(r",\s*filter:\s*[^,\}]+", "", line)
    line = line.replace("proxies: null", f"proxies: [{joined}]")
    return line


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/templates")
def api_templates():
    return jsonify(list_templates())


@app.route("/api/generate", methods=["POST"])
def api_generate():
    data = request.get_json(silent=True) or {}
    # Also accept form-encoded (for native download via form POST)
    if not data:
        data = request.form.to_dict()
    client = data.get("client")
    template = data.get("template")
    sub_url = data.get("sub_url", "").strip()
    filename = data.get("filename", "").strip() or None

    if not client or not template or not sub_url:
        return jsonify({"error": "Missing client, template, or subscription URL"}), 400

    # Validate template belongs to the selected client
    ext = ".conf" if client == "Surge" else ".yaml"
    if not template.endswith(ext):
        return jsonify({"error": f"Template '{template}' does not match client {client}"}), 400

    try:
        if client == "Surge":
            content, default_name = gen_surge(template, sub_url)
        elif client in ("Stash", "ClashMac"):
            content, default_name = gen_stash(template, sub_url)
        else:
            return jsonify({"error": f"Unknown client: {client}"}), 400

        download_name = filename if filename else default_name
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except requests.RequestException as e:
        return jsonify({"error": f"Subscription download failed: {e}"}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {e}"}), 500

    # Save to temp and send
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{download_name}")
    tmp.write(content)
    tmp.close()
    return send_file(
        tmp.name,
        as_attachment=True,
        download_name=download_name,
        mimetype="application/octet-stream",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
