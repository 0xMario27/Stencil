#!/usr/bin/env python3
"""Stencil Config Generator - Web Backend"""

import os
import re
import tempfile
from pathlib import Path
import base64
from urllib.parse import unquote, parse_qs

import requests
from flask import Flask, jsonify, render_template, request, send_file

app = Flask(__name__)
_HERE = Path(__file__).resolve().parent
# Auto-detect project root: use parent dir (local dev) or current dir (Docker)
ROOT = _HERE.parent if (_HERE.parent / "Surge").is_dir() else _HERE
UA_SURGE = "Surge iOS/3000 CFNetwork Darwin"
UA_STASH = "ClashforWindows/0.20.39"


# ---------------------------------------------------------------------------
# Node IR & Converters (universal pipeline)
# ---------------------------------------------------------------------------
RE_URI_NODE = re.compile(
    r'^(?P<scheme>anytls|trojan|hysteria2?|ss|vmess|vless|tuic)://'
    r'(?P<auth>[^@]+)@'
    r'(?P<host>[^:/?#]+)'
    r'(?::(?P<port>\d+))?'
    r'(?P<path>/[^?#]*)?'
    r'(?:\?(?P<query>[^#]*))?'
    r'(?:#(?P<name>.*))?$'
)

# ── Client-Aware Protocol Matrix ──
CLIENT_PROTOCOLS = {
    "Surge": {"anytls", "ss", "trojan", "vmess", "hysteria2", "tuic", "http", "https", "socks5", "socks5-tls", "snell", "wireguard", "ssh", "h2", "direct"},
    "Stash": {"anytls", "ss", "vmess", "vless", "trojan", "hysteria2", "tuic", "http", "socks5", "snell", "wireguard", "direct"},
    "ClashMac": {"anytls", "ss", "vmess", "vless", "trojan", "hysteria2", "tuic", "http", "socks5", "snell", "wireguard", "direct"},
}

def filter_by_client(nodes, client):
    allowed = CLIENT_PROTOCOLS.get(client)
    if not allowed:
        return nodes
    return [n for n in nodes if n["type"] in allowed]


def parse_uri_node(line: str):
    """Parse a single proxy URI line into an IR dict."""
    line = line.strip()

    # vmess:// is base64(JSON)
    if line.startswith("vmess://"):
        import json as _json
        try:
            b64 = line[len("vmess://"):]
            padded = b64 + '=' * ((4 - len(b64) % 4) % 4)
            j = _json.loads(base64.b64decode(padded).decode("utf-8"))
            node = {
                "type": "vmess", "name": j.get("ps") or j.get("add", ""),
                "server": j.get("add", ""), "port": int(j.get("port", 443)),
                "password": "", "uuid": j.get("id", ""), "udp": True,
                "alter_id": int(j.get("aid", 0)),
                "security": j.get("scy", "auto"), "network": j.get("net", "tcp"),
            }
            if j.get("tls") == "tls":
                node["tls"] = True
                if j.get("sni"):
                    node["sni"] = j["sni"]
            if j.get("host"):
                node["ws_host"] = j["host"]
            if j.get("path"):
                node["ws_path"] = j["path"]
            return node
        except Exception:
            return None

    m = RE_URI_NODE.match(line)
    if not m:
        return None
    scheme = m.group("scheme")
    auth = m.group("auth")
    host = m.group("host")
    port = int(m.group("port") or 443)
    name = unquote(m.group("name") or host)
    query = parse_qs(m.group("query") or "")

    def _q(k, default=None):
        v = query.get(k)
        return v[0] if v else default

    if scheme == "vless":
        node = {
            "type": "vless", "name": name, "server": host, "port": port,
            "password": "", "uuid": auth, "udp": True,
            "network": _q("type", "tcp"),
        }
        sec = _q("security")
        if sec:
            node["security"] = sec
            if sec in ("reality", "tls"):
                node["tls"] = True
        fl = _q("flow")
        if fl: node["flow"] = fl
        pbk = _q("pbk")
        if pbk: node["reality_pbk"] = pbk
        sid = _q("sid")
        if sid: node["reality_sid"] = sid
        sni = _q("sni")
        if sni: node["sni"] = sni
        fp = _q("fp")
        if fp: node["client_fingerprint"] = fp
        if _q("insecure") == "1":
            node["skip_cert_verify"] = True
        wsh = _q("host")
        if wsh: node["ws_host"] = wsh
        wsp = _q("path")
        if wsp: node["ws_path"] = wsp
        gsn = _q("serviceName")
        if gsn: node["grpc_service_name"] = gsn
        return node

    if scheme == "tuic":
        ci = auth.find(":")
        node = {
            "type": "tuic", "name": name, "server": host, "port": port,
            "password": auth[ci+1:] if ci > -1 else "",
            "uuid": auth[:ci] if ci > -1 else auth,
            "udp": True,
        }
        cong = _q("congestion")
        if cong: node["congestion"] = cong
        urm = _q("udp_relay_mode")
        if urm: node["udp_relay_mode"] = urm
        alpn = _q("alpn")
        if alpn: node["alpn"] = alpn
        sni = _q("sni")
        if sni: node["sni"] = sni
        if _q("insecure") == "1":
            node["skip_cert_verify"] = True
        return node

    # anytls, trojan, hysteria2, ss
    node = {
        "type": scheme, "name": name, "server": host, "port": port,
        "password": auth, "udp": True,
    }
    sni = _q("sni")
    if sni: node["sni"] = sni
    fp = _q("fp")
    if fp: node["client_fingerprint"] = fp
    if _q("insecure") == "1" or _q("allowInsecure") == "1":
        node["skip_cert_verify"] = True
    peer = _q("peer")
    if peer: node["peer"] = peer
    typ = _q("type")
    if typ: node["network"] = typ
    return node


def parse_uri_list(text: str):
    """Parse base64-decoded URI list into IR dicts."""
    nodes = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        node = parse_uri_node(line)
        if node:
            nodes.append(node)
    return nodes


def parse_clash_proxies(text: str):
    """Extract Clash YAML proxies section and parse each entry into IR dicts."""
    nodes = []
    in_proxies = False
    for line in text.splitlines():
        if line.strip() == "proxies:":
            in_proxies = True
            continue
        if in_proxies:
            if re.match(r"^[a-zA-Z]", line):
                break
            if re.match(r"^\s*-\s*\{", line):
                node = _parse_clash_line(line)
                if node:
                    nodes.append(node)
    return nodes


def _parse_clash_line(line: str):
    """Parse a single Clash YAML flow-mapping proxy line into an IR dict."""
    def extract(key):
        m = re.search(rf'["\']?{key}["\']?\s*:\s*["\']?([^"\'}},\s]+)["\']?', line)
        return m.group(1) if m else ""

    def extract_bool(key):
        m = re.search(rf'["\']?{key}["\']?\s*:\s*true', line)
        return m is not None

    name = (re.search(r'"name"\s*:\s*"([^"]*)"', line) or
            re.search(r"'name'\s*:\s*'([^']*)'", line) or
            re.search(r'[{,]\s*name\s*:\s*"?([^",}]+)"?', line))
    if not name:
        return None
    name = name.group(1)

    typ = (re.search(r'"type"\s*:\s*"([^"]*)"', line) or
           re.search(r"'type'\s*:\s*'([^']*)'", line) or
           re.search(r'[{,]\s*type\s*:\s*"?([^",}]+)"?', line))
    if not typ:
        return None
    typ = typ.group(1)

    uuid = extract("uuid")
    flow = extract("flow")
    alter_id = extract("alterId")
    cipher = extract("cipher")
    network = extract("network")
    tls = extract_bool("tls")
    servername = extract("servername")
    server = extract("server")
    port = extract("port")
    password = extract("password")
    sni = extract("sni")
    fp = extract("client-fingerprint")

    # reality / ws / grpc opts from the clash line
    rpbk = ""; rsid = ""
    ro = re.search(r'reality-opts\s*:\s*\{[^}]*\}', line)
    if ro:
        rm = re.search(r"public-key\s*:\s*([^ ,}]+)", ro.group())
        if rm: rpbk = rm.group(1)
        sm = re.search(r"short-id\s*:\s*([^ ,}]+)", ro.group())
        if sm: rsid = sm.group(1)
    wp = ""; wh = ""
    wo = re.search(r'ws-opts\s*:\s*\{[^}]*\}', line)
    if wo:
        pm = re.search(r'path\s*:\s*"([^"]*)"', wo.group())
        if pm: wp = pm.group(1)
        hm = re.search(r"Host\s*:\s*([^ ,}]+)", wo.group())
        if hm: wh = hm.group(1)
    gsn = ""
    go = re.search(r'grpc-opts\s*:\s*\{[^}]*\}', line)
    if go:
        gm = re.search(r"grpc-service-name\s*:\s*([^ ,}]+)", go.group())
        if gm: gsn = gm.group(1)

    node = {
        "type": typ,
        "name": name,
        "server": server,
        "port": int(port) if port else 443,
        "password": password,
        "udp": True,
    }
    if uuid: node["uuid"] = uuid
    if flow: node["flow"] = flow
    if alter_id: node["alter_id"] = int(alter_id)
    if cipher: node["security"] = cipher
    if network: node["network"] = network
    if tls: node["tls"] = True
    if servername: node["sni"] = servername
    if rpbk:
        node["reality_pbk"] = rpbk
        node["reality_sid"] = rsid
    if wp:
        node["ws_path"] = wp
        if wh: node["ws_host"] = wh
    if gsn: node["grpc_service_name"] = gsn
    if sni:
        node["sni"] = sni
    if extract_bool("skip-cert-verify"):
        node["skip_cert_verify"] = True
    if fp:
        node["client_fingerprint"] = fp
    peer = extract("peer")
    if peer:
        node["peer"] = peer
    return node


def parse_surge_to_ir(text: str):
    """Parse Surge conf [Proxy] lines into IR dicts."""
    nodes = []
    in_proxy = False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[Proxy]"):
            in_proxy = True
            continue
        if in_proxy and line.startswith("["):
            in_proxy = False
            continue
        if not in_proxy:
            continue
        if "=" not in line:
            continue
        name, rest = line.split("=", 1)
        name = name.strip()
        rest = rest.strip()

        # Handle "direct" (no params)
        if rest == "direct":
            nodes.append({
                "type": "direct",
                "name": name,
                "server": "localhost",
                "port": 0,
                "password": "",
                "udp": False,
            })
            continue

        # Split: protocol, server, port[, key=val, ...]
        parts = [p.strip() for p in rest.split(",")]
        if len(parts) < 2:
            continue
        protocol = parts[0]

        # Skip non-proxy protocol names (Surge General section lines sneak through)
        if protocol in ("system", "server", "1.1.1.1", "8.8.8.8"):
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+", protocol):
            continue

        if len(parts) < 3:
            continue
        server = parts[1]
        port = parts[2]

        node = {
            "type": protocol,
            "name": name,
            "server": server,
            "port": int(port) if port.isdigit() else 0,
            "password": "",
            "udp": True,
        }

        for p in parts[3:]:
            if "=" in p:
                k, v = p.split("=", 1)
                k = k.strip()
                v = v.strip()
                if k == "password":
                    node["password"] = v
                elif k == "username":
                    node["uuid"] = v
                elif k == "encrypt-method":
                    node["security"] = v
                elif k == "congestion-controller":
                    node["congestion"] = v
                elif k == "alpn":
                    node["alpn"] = v
                elif k == "ws-path":
                    node["ws_path"] = v
                elif k == "ws-header" and v.startswith("Host="):
                    node["ws_host"] = v[5:]
                elif k == "sni":
                    node["sni"] = v
                elif k in ("encrypt-method", "method"):
                    node["encrypt_method"] = v
                elif k in ("obfs", "obfs-host", "obfs-uri", "ws-path", "grpc-service-name"):
                    node[k.replace("-", "_")] = v
                elif k == "ws" and v == "true":
                    node["network"] = "ws"
                elif k == "h2" and v == "true":
                    node["network"] = "h2"
                elif k == "tls-hostname":
                    node["sni"] = v
            else:
                k = p.strip()
                if k == "udp-relay=true":
                    node["udp"] = True
                elif k == "skip-cert-verify=true":
                    node["skip_cert_verify"] = True
                elif k == "tfo=true":
                    pass  # TCP Fast Open, not IR-relevant

        nodes.append(node)
    return nodes


def ir_to_surge(nodes):
    """Convert IR node dicts to Surge conf [Proxy] lines."""
    lines = []
    for n in nodes:
        if n["type"] == "vmess":
            parts = [
                f'{n["name"]} = vmess, {n["server"]}, {n["port"]}',
                f'username={n.get("uuid", "")}',
                f'encrypt-method={n.get("security", "auto")}',
            ]
            if n.get("network") == "ws":
                parts.append("ws=true")
                if n.get("ws_path"):
                    parts.append(f'ws-path={n["ws_path"]}')
                if n.get("ws_host"):
                    parts.append(f'ws-header=Host={n["ws_host"]}')
            if n.get("tls") or n.get("sni"):
                parts.append("tls=true")
                if n.get("sni"):
                    parts.append(f'sni={n["sni"]}')
            if n.get("skip_cert_verify"):
                parts.append("skip-cert-verify=true")
            parts.append("tfo=true")
            lines.append(", ".join(parts))
        elif n["type"] == "tuic":
            parts = [
                f'{n["name"]} = tuic, {n["server"]}, {n["port"]}',
                f'password={n.get("password", "")}',
            ]
            if n.get("sni"):
                parts.append(f'sni={n["sni"]}')
            if n.get("alpn"):
                parts.append(f'alpn={n["alpn"]}')
            if n.get("skip_cert_verify"):
                parts.append("skip-cert-verify=true")
            parts.append("udp-relay=true")
            lines.append(", ".join(parts))
        else:
            parts = [f'{n["name"]} = {n["type"]}, {n["server"]}, {n["port"]}']
            if n.get("password"):
                parts.append(f'password={n["password"]}')
            if n.get("udp"):
                parts.append("udp-relay=true")
            if n.get("sni"):
                parts.append(f'sni={n["sni"]}')
            if n.get("skip_cert_verify"):
                parts.append("skip-cert-verify=true")
            if n.get("client_fingerprint"):
                parts.append(f'client-fingerprint={n["client_fingerprint"]}')
            if n.get("peer"):
                parts.append(f'tls-hostname={n["peer"]}')
            lines.append(", ".join(parts))
    return lines


def ir_to_clash(nodes):
    """Convert IR node dicts to Clash YAML proxy lines."""
    entries = []
    for n in nodes:
        typ = n["type"]
        if typ == "vless":
            e = f'  - {{name: "{n["name"]}", type: vless, server: {n["server"]}, port: {n["port"]}, uuid: "{n["uuid"]}", network: {n.get("network", "tcp")}'
            if n.get("tls"):
                e += ', tls: true'
            if n.get("flow"):
                e += f', flow: {n["flow"]}'
            if n.get("sni"):
                e += f', servername: {n["sni"]}'
            if n.get("client_fingerprint"):
                e += f', client-fingerprint: {n["client_fingerprint"]}'
            if n.get("reality_pbk"):
                e += f', reality-opts: {{public-key: {n["reality_pbk"]}, short-id: {n.get("reality_sid", "")}}}'
            if n.get("skip_cert_verify"):
                e += ', skip-cert-verify: true'
            if n.get("ws_path") or n.get("ws_host"):
                e += f', ws-opts: {{path: "{n.get("ws_path", "/")}"'
                if n.get("ws_host"):
                    e += f', headers: {{Host: {n["ws_host"]}}}'
                e += '}'
            e += ', udp: true'
            entries.append(e + "}")
        elif typ == "vmess":
            e = f'  - {{name: "{n["name"]}", type: vmess, server: {n["server"]}, port: {n["port"]}, uuid: "{n.get("uuid", "")}", alterId: {n.get("alter_id", 0)}, cipher: {n.get("security", "auto")}, network: {n.get("network", "tcp")}, udp: true'
            if n.get("tls"):
                e += ', tls: true'
                if n.get("sni"):
                    e += f', servername: {n["sni"]}'
            if n.get("ws_path") or n.get("ws_host"):
                e += f', ws-opts: {{path: "{n.get("ws_path", "/")}"'
                if n.get("ws_host"):
                    e += f', headers: {{Host: {n["ws_host"]}}}'
                e += '}'
            if n.get("skip_cert_verify"):
                e += ', skip-cert-verify: true'
            entries.append(e + "}")
        elif typ == "tuic":
            e = f'  - {{name: "{n["name"]}", type: tuic, server: {n["server"]}, port: {n["port"]}, uuid: "{n.get("uuid", "")}", password: "{n.get("password", "")}", udp: true'
            if n.get("congestion"):
                e += f', congestion-controller: {n["congestion"]}'
            if n.get("udp_relay_mode"):
                e += f', udp-relay-mode: {n["udp_relay_mode"]}'
            if n.get("alpn"):
                e += f', alpn: [{n["alpn"]}]'
            if n.get("sni"):
                e += f', sni: {n["sni"]}'
            if n.get("skip_cert_verify"):
                e += ', skip-cert-verify: true'
            entries.append(e + "}")
        else:
            entry = (
                f'  - {{name: "{n["name"]}", type: {typ}, '
                f'server: {n["server"]}, port: {n["port"]}, '
                f'password: "{n["password"]}", udp: true'
            )
            if n.get("sni"):
                entry += f', sni: {n["sni"]}'
            if n.get("skip_cert_verify"):
                entry += ', skip-cert-verify: true'
            if n.get("client_fingerprint"):
                entry += f', client-fingerprint: {n["client_fingerprint"]}'
            if n.get("peer"):
                entry += f', peer: {n["peer"]}'
            if n.get("network"):
                entry += f', network: {n["network"]}'
            entries.append(entry + "}")
    return "\n".join(entries)


def detect_format(text: str) -> str:
    """Auto-detect subscription response format: surge, clash, base64, or error."""
    if not text or not text.strip():
        return "error"
    if "[Proxy]" in text or "[General]" in text:
        return "surge"
    if re.search(r'^\s*proxies:', text, re.MULTILINE):
        return "clash"
    try:
        decoded = base64.b64decode(text.strip()).decode("utf-8")
        if "://" in decoded:
            return "base64"
    except Exception:
        pass
    return "error"


def _count_nodes(text: str, fmt: str) -> int:
    """Count parseable proxy nodes in a subscription response."""
    if not text or not text.strip():
        return 0
    if fmt == "surge":
        return sum(1 for l in text.splitlines() if re.match(
            r"^[^#\s].*=\s*(anytls|ss|trojan|vmess|vless|hysteria2?|tuic|http|https|socks5(-tls)?|snell|wireguard|ssh|h2|direct)(\s*,|\s*$)", l))
    elif fmt == "clash":
        in_p = False
        count = 0
        for l in text.splitlines():
            if l.strip() == "proxies:":
                in_p = True
                continue
            if in_p:
                if re.match(r"^[a-zA-Z]", l):
                    break
                if re.match(r"^\s*-\s*\{", l):
                    count += 1
        return count
    elif fmt == "base64":
        try:
            decoded = base64.b64decode(text.strip()).decode("utf-8")
            return sum(1 for l in decoded.splitlines() if "://" in l)
        except Exception:
            return 0
    return 0


def fetch_sub(url: str):
    """Fetch subscription with UA fallback. Try all UAs, pick the one with most nodes.
    Default UA breaks ties. Returns (format, raw_text)."""
    ua_configs = [
        ("default", ""),
        ("Surge", "Surge iOS/3000 CFNetwork Darwin"),
        ("Clash", "ClashforWindows/0.20.39"),
        ("v2rayN", "v2rayN/6.45"),
    ]
    best_label = ""; best_fmt = "error"; best_count = 0; best_text = ""

    for label, ua in ua_configs:
        headers = {"User-Agent": ua} if ua else {}
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            fmt = detect_format(resp.text)
            if fmt == "error":
                continue
            count = _count_nodes(resp.text, fmt)
            if count > best_count:
                best_label = label; best_fmt = fmt; best_count = count; best_text = resp.text
            elif count == best_count and count > 0:
                if label == "default" and best_label != "default":
                    best_label = label; best_fmt = fmt; best_count = count; best_text = resp.text
        except Exception:
            continue

    if best_fmt != "error":
        return best_fmt, best_text
    raise ValueError("Failed to fetch subscription with all fallback UAs")



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
def extract_surge_nodes(raw_text: str, client: str = None) -> list[str]:
    """Extract Surge-format proxy lines from subscription response."""
    allowed = CLIENT_PROTOCOLS.get(client) if client else None
    re_proxy = re.compile(
        r"^[^#\s].*=\s*(anytls|ss|trojan|vmess|vless|hysteria2?|tuic|http|https|socks5(-tls)?|snell|wireguard|ssh|h2|direct)(\s*,|\s*$)"
    )
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
        m = re_proxy.match(line)
        if not m:
            continue
        if allowed and m.group(1) not in allowed:
            continue
        nodes.append(line)
    return nodes


def gen_surge(template_name: str, sub_url: str) -> tuple[bytes, str]:
    """Fetch subscription via smart fetcher, convert to Surge, inline nodes."""
    tpl_path = ROOT / "Surge" / template_name
    tpl_text = tpl_path.read_text(encoding="utf-8")

    fmt, raw_text = fetch_sub(sub_url)

    # Convert detected format -> Surge lines
    if fmt == "surge":
        nodes = extract_surge_nodes(raw_text, "Surge")
    elif fmt == "clash":
        ir_nodes = filter_by_client(parse_clash_proxies(raw_text), "Surge")
        nodes = ir_to_surge(ir_nodes)
    elif fmt == "base64":
        decoded = base64.b64decode(raw_text.strip()).decode("utf-8")
        ir_nodes = filter_by_client(parse_uri_list(decoded), "Surge")
        nodes = ir_to_surge(ir_nodes)
    else:
        raise ValueError("No usable proxy nodes found in subscription")

    if not nodes:
        raise ValueError("No usable proxy nodes found in subscription")

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


def gen_stash(client_dir: str, template_name: str, sub_url: str) -> tuple[bytes, str]:
    """Fetch subscription via smart fetcher, convert to Clash YAML, inline nodes."""
    tpl_path = ROOT / client_dir / template_name
    tpl_text = tpl_path.read_text(encoding="utf-8")

    fmt, raw_text = fetch_sub(sub_url)

    # Convert detected format -> Clash YAML lines
    if fmt == "clash":
        ir_nodes = filter_by_client(parse_clash_proxies(raw_text), client_dir)
        clash = ir_to_clash(ir_nodes)
    elif fmt == "base64":
        decoded = base64.b64decode(raw_text.strip()).decode("utf-8")
        ir_nodes = filter_by_client(parse_uri_list(decoded), client_dir)
        clash = ir_to_clash(ir_nodes)
    elif fmt == "surge":
        ir_nodes = filter_by_client(parse_surge_to_ir(raw_text), client_dir)
        clash = ir_to_clash(ir_nodes)
    else:
        raise ValueError("No usable proxy nodes found for Stash")

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
            content, default_name = gen_stash(client, template, sub_url)
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
