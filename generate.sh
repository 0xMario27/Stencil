#!/usr/bin/env bash
# ============================================================
# Stencil · Interactive CLI config generator (multi-client)
# Usage: bash generate.sh   (or make config)
# Flow: pick client → pick template → paste sub URL → name → generate
#
# Per-client strategies:
#   Surge : fetch sub → extract [Proxy] nodes → inline into template → fix AllServer
#   Stash : fetch sub → extract Clash YAML proxies → inline as flow mappings →
#           remove proxy-providers → rewrite use:[SF] groups with filtered names
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

UA="Surge iOS/3000 CFNetwork Darwin"
# Stash uses a Clash UA to fetch Clash-format configs (Stash is Clash-compatible).
# Some providers 500 on "Stash" UA; "ClashforWindows" reliably returns Clash YAML.
UA_STASH="ClashforWindows/0.20.39"
c_t='\033[1;36m'; c_ok='\033[1;32m'; c_w='\033[1;33m'; c_e='\033[1;31m'; c_d='\033[2m'; c_o='\033[0m'

banner() {
  echo -e "${c_t}"
  echo "  ┌────────────────────────────────────────┐"
  echo "  │        Config Generator · CLI          │"
  echo "  └────────────────────────────────────────┘"
  echo -e "${c_o}"
}

# Let the user pick one item from a list; result stored in REPLY_ITEM.
# Real terminal: ↑/↓ (or j/k) to move, Enter to confirm, number for quick jump.
# Non-interactive (pipe/automation): falls back to numbered input.
choose() {
  local prompt="$1"; shift
  local items=("$@") n=${#items[@]} i
  i=1
  for it in "${items[@]}"; do printf "    \033[1;32m%d\033[0m) %s\n" "$i" "$it"; i=$((i+1)); done
  local pick=""
  while :; do
    printf "  %s [1-%d] (default 1): " "$prompt" "$n"
    read -r pick
    [ -z "$pick" ] && pick=1
    if [[ "$pick" =~ ^[0-9]+$ ]] && [ "$pick" -ge 1 ] && [ "$pick" -le "$n" ]; then
      REPLY_ITEM="${items[$((pick-1))]}"; return 0
    fi
    echo -e "  \033[1;31mInvalid choice, try again\033[0m"
  done
}

# ---------- Surge generator ----------
gen_surge() {
  local sub="$1" tpl="Surge/$2" out="result/$3"
  local raw nodes fmt; raw="$(mktemp)"; nodes="$(mktemp)"
  trap 'rm -f "$raw" "$nodes"' RETURN
  echo "  ⏬ Fetching subscription..."
  fmt="$(_fetch_sub "$sub" "$raw")"
  [ "$fmt" = "error" ] && { echo -e "  ${c_e}❌ Download failed (check URL / network)${c_o}"; return 1; }
  echo "  🔍 Detected format: ${c_d}$fmt${c_o}"

  case "$fmt" in
    surge)
      awk '/^\[Proxy\]/{f=1;next} /^\[/{f=0} f' "$raw" \
       | grep -aE '^[^#[:space:]].*=[[:space:]]*(anytls|ss|ssr|trojan|vmess|vless|hysteria2?|tuic|http|https|socks5(-tls)?|snell|wireguard|direct)([[:space:]]*,|[[:space:]]*$)' \
       > "$nodes" || true
      ;;
    clash)
      _clash2surge < "$raw" > "$nodes" || true
      ;;
    base64)
      openssl base64 -d -A -in "$raw" 2>/dev/null | _uri2surge > "$nodes" || true
      ;;
  esac

  local count; count="$(wc -l < "$nodes" | tr -d ' ')"
  [ "$count" -gt 0 ] || { echo -e "  ${c_e}❌ No usable proxy nodes found${c_o}"; return 1; }
  echo -e "  ${c_ok}✅ Extracted $count nodes${c_o}"
  awk -v nodesfile="$nodes" '
    BEGIN { while ((getline l < nodesfile) > 0) nd[++n]=l }
    /^\[Proxy\]$/ { print; for (i=1;i<=n;i++) print nd[i]; print ""; inp=1; next }
    inp==1 { if ($0 ~ /^\[/) inp=0; else next }
    { print }
  ' "$tpl" > "$out"
  echo -e "  ${c_ok}🎉 Done!${c_o} Nodes inlined into [Proxy] ($count)"
}

# Given a proxy-group line, apply its filter against the names[] array
# and produce a rewritten line with proxies: [matchingNames] instead of use:[SF].
# (Relies on the local names array from gen_stash via bash dynamic scoping.)
_stash_group() {
  local line="$1" f inner sel joined x
  # Extract filter value (quoted or unquoted)
  if [[ "$line" == *"filter: '"* ]]; then
    f="${line#*filter: \'}"; f="${f%%\'*}"
  elif [[ "$line" == *"filter: "* ]]; then
    f="${line#*filter: }"; f="${f%%,*}"; f="${f%\}}"
  else
    f=""
  fi
  # Compute matching nodes
  if [[ "$f" == '^((?!'* ]]; then                       # negative: exclude these keywords
    inner="$(printf '%s' "$f" | sed -E 's/^\^\(\(\?!//; s/\)\.\)\*\$$//')"
    sel="$(printf '%s\n' "${names[@]}" | grep -vE "$inner" || true)"
  elif [ -n "$f" ]; then                                # positive: match these keywords
    sel="$(printf '%s\n' "${names[@]}" | grep -E "$f" || true)"
  else
    sel="$(printf '%s\n' "${names[@]}")"
  fi
  joined=""
  while IFS= read -r x; do [ -n "$x" ] && joined="$joined\"$x\", "; done <<< "$sel"
  joined="${joined%, }"
  # Remove use:[SF] & filter:..., then replace proxies: null with the node list
  line="$(echo "$line" | sed "s/, *use: \[SF\]//; s/, *filter: '[^']*'//; s/, *filter: [^,}]*//")"
  line="${line/proxies: null/proxies: [$joined]}"
  printf '%s' "$line"
}

# ---- shared URI node parser ----
# Parses a single URI line into KEY=VALUE IR lines (one node)
# Supported schemes: trojan, anytls, hysteria2
_uri_node_parse() {
  local line="$1" scheme rest auth host port query
  line="${line%$'\r'}"
  scheme="${line%%://*}"; rest="${line#$scheme://}"
  # Extract password (everything before @)
  auth="${rest%%@*}"
  [ "$auth" = "$rest" ] && return 1
  rest="${rest#*@}"
  # Extract fragment name after #
  local name=""
  case "$rest" in *"#"*) name="${rest#*#}"; rest="${rest%%#*}" ;; esac
  # URL-decode name (printf %b handles \xHH)
  name="$(printf '%s' "$name" | sed 's/+/ /g;s/%\([0-9a-fA-F][0-9a-fA-F]\)/\\x\1/g')"
  name="$(printf '%b' "$name")"
  # Extract query string after ?
  query=""
  case "$rest" in *"?"*) query="${rest#*\?}"; rest="${rest%%\?*}" ;; esac
  # Extract host:port (strip trailing /)
  rest="${rest%%/*}"
  host="${rest%%:*}"; port="${rest##*:}"
  [ "$port" = "$host" ] && port="443"
  [ -z "$name" ] && name="$host"

  # Parse query params
  local sni="" fp="" insec="" peer="" ptyp="" IFS='&' p
  for p in $query; do
    case "$p" in
      sni=*) sni="${p#sni=}" ;;
      fp=*) fp="${p#fp=}" ;;
      insecure=*) insec="${p#insecure=}" ;;
      allowInsecure=*) insec="${p#allowInsecure=}" ;;
      peer=*) peer="${p#peer=}" ;;
      type=*) ptyp="${p#type=}" ;;
    esac
  done

  printf 'name=%s\n' "$name"
  printf 'type=%s\n' "$scheme"
  printf 'server=%s\n' "$host"
  printf 'port=%s\n' "$port"
  printf 'password=%s\n' "$auth"
  printf 'udp=%s\n' "true"
  [ -n "$sni" ]  && printf 'sni=%s\n' "$sni"
  [ "$insec" = "1" ] && printf 'skip-cert-verify=%s\n' "true"
  [ -n "$fp" ]   && printf 'client-fingerprint=%s\n' "$fp"
  [ -n "$peer" ] && printf 'peer=%s\n' "$peer"
  [ -n "$ptyp" ] && printf 'network=%s\n' "$ptyp"
  printf '\n'  # blank line terminates node block
}

# ---- URI list -> Clash YAML ----
_uri2clash() {
  local ir tmp
  ir="$(mktemp)"; tmp="$(mktemp)"; trap 'rm -f "$ir" "$tmp"' RETURN
  while IFS= read -r line; do
    _uri_node_parse "$line" >> "$ir" 2>/dev/null || true
  done
  awk 'BEGIN { RS=""; FS="\n" }
  {
    delete v
    for (i=1; i<=NF; i++) { eq=index($i,"="); if(eq>0){v[substr($i,1,eq-1)]=substr($i,eq+1)} }
    if (v["name"] == "") next
    name=v["name"]; typ=v["type"]; host=v["server"]; port=v["port"]; pw=v["password"]
    entry = sprintf("  - {name: \"%s\", type: %s, server: %s, port: %s, password: \"%s\"", name, typ, host, port, pw)
    entry = entry ", udp: true"
    if (v["sni"] != "") entry = entry ", sni: " v["sni"]
    if (v["skip-cert-verify"] == "true") entry = entry ", skip-cert-verify: true"
    if (v["client-fingerprint"] != "") entry = entry ", client-fingerprint: " v["client-fingerprint"]
    if (v["peer"] != "") entry = entry ", peer: " v["peer"]
    if (v["network"] != "") entry = entry ", network: " v["network"]
    entry = entry "}"
    print entry
  }' "$ir"
}

# ---- URI list -> Surge conf lines ----
_uri2surge() {
  local ir
  ir="$(mktemp)"; trap 'rm -f "$ir"' RETURN
  while IFS= read -r line; do
    _uri_node_parse "$line" >> "$ir" 2>/dev/null || true
  done
  awk 'BEGIN { RS=""; FS="\n" }
  {
    delete v
    for (i=1; i<=NF; i++) { eq=index($i,"="); if(eq>0){v[substr($i,1,eq-1)]=substr($i,eq+1)} }
    if (v["name"] == "") next
    # Surge: Name = protocol, server, port, key=val, ...
    printf "%s = %s, %s, %s, password=%s", v["name"], v["type"], v["server"], v["port"], v["password"]
    printf ", udp-relay=true"
    if (v["sni"] != "") printf ", sni=%s", v["sni"]
    if (v["skip-cert-verify"] == "true") printf ", skip-cert-verify=true"
    if (v["client-fingerprint"] != "") printf ", client-fingerprint=%s", v["client-fingerprint"]
    if (v["peer"] != "") printf ", tls-hostname=%s", v["peer"]
    printf "\n"
  }' "$ir"
}

# ---- Clash YAML proxies -> Surge conf lines ----
_clash2surge() {
  awk '
  function getval(str, key,   s) {
    if (match(str, key "[[:space:]]*:[[:space:]]*\047[^\047]*\047")) {
      s = substr(str, RSTART, RLENGTH)
      sub("^" key "[[:space:]]*:[[:space:]]*\047", "", s)
      sub(/\047$/, "", s)
      return s
    }
    if (match(str, key "[[:space:]]*:[[:space:]]*\"[^\"]*\"")) {
      s = substr(str, RSTART, RLENGTH)
      sub("^" key "[[:space:]]*:[[:space:]]*\"", "", s)
      sub(/"$/, "", s)
      return s
    }
    if (match(str, key "[[:space:]]*:[[:space:]]*[^ ,}]+")) {
      s = substr(str, RSTART, RLENGTH)
      sub("^" key "[[:space:]]*:[[:space:]]*", "", s)
      return s
    }
    return ""
  }
  /^[[:space:]]*-[[:space:]]*\{/ {
    name = getval($0, "name")
    typ = getval($0, "type")
    server = getval($0, "server")
    port = getval($0, "port")
    pw = getval($0, "password")
    sni = getval($0, "sni")
    skv = ""
    if ($0 ~ /skip-cert-verify[[:space:]]*:[[:space:]]*true/)
      skv = "true"
    fp = getval($0, "client-fingerprint")
    peer = getval($0, "peer")
    if (name == "" || typ == "" || server == "") next
    printf "%s = %s, %s, %s", name, typ, server, port
    if (pw != "") printf ", password=%s", pw
    printf ", udp-relay=true"
    if (sni != "") printf ", sni=%s", sni
    if (skv == "true") printf ", skip-cert-verify=true"
    if (fp != "") printf ", client-fingerprint=%s", fp
    if (peer != "") printf ", tls-hostname=%s", peer
    printf "\n"
  }'
}

# ---- Clash YAML proxies -> keep as Clash YAML (identity) ----
_clash2clash() {
  awk '/^proxies:/{f=1;next} /^[a-zA-Z]/{f=0} f' \
    | grep -E '^[[:space:]]*-[[:space:]]*\{' \
    | sed -E 's/^[[:space:]]*-[[:space:]]*/  - /' || true
}

# ---- Surge conf [Proxy] lines -> Clash YAML ----
_surge2clash() {
  awk '
  BEGIN { in_proxy = 0 }
  /^\[Proxy\]/ { in_proxy = 1; next }
  /^\[/ { in_proxy = 0; next }
  !in_proxy { next }
  /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
  {
    # Split: Name = rest
    eq = index($0, "=")
    if (eq == 0) next
    name = substr($0, 1, eq - 1); gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
    rest = substr($0, eq + 1); gsub(/^[[:space:]]+|[[:space:]]+$/, "", rest)

    if (rest == "direct") {
      printf "  - {name: \"%s\", type: direct, server: localhost, port: 0, password: \"\", udp: false}\n", name
      next
    }

    # Split rest by ", " into parts
    n = split(rest, parts, /,[[:space:]]*/)
    if (n < 3) next
    typ = parts[1]; server = parts[2]; port = parts[3]

    pw = ""; sni = ""; skv = ""; net = ""; udp = "true"
    for (i = 4; i <= n; i++) {
      p = parts[i]
      if (p == "udp-relay=true") udp = "true"
      else if (p == "skip-cert-verify=true") skv = "true"
      else if (p == "tfo=true") { }  # skip, TCP Fast Open
      else {
        eq2 = index(p, "=")
        if (eq2 > 0) {
          k = substr(p, 1, eq2 - 1); v = substr(p, eq2 + 1)
          if (k == "password") pw = v
          else if (k == "sni") sni = v
          else if (k == "tls-hostname") sni = v
          else if (k == "ws" && v == "true") net = "ws"
          else if (k == "h2" && v == "true") net = "h2"
        }
      }
    }

    entry = sprintf("  - {name: \"%s\", type: %s, server: %s, port: %s", name, typ, server, port)
    if (pw != "") entry = entry sprintf(", password: \"%s\"", pw)
    else entry = entry ", password: \"\""
    entry = entry ", udp: " udp
    if (sni != "") entry = entry ", sni: " sni
    if (skv == "true") entry = entry ", skip-cert-verify: true"
    if (net != "") entry = entry ", network: " net
    entry = entry "}"
    print entry
  }'
}

# ---- Smart fetcher with UA fallback ----
# Tries ALL UAs, counts nodes per response, picks the one with most nodes.
# Default UA gets priority in ties. Returns format string, writes best to output file.

# Helper: count nodes in a file for a given format
_count_nodes() {
  local f="$1" fmt="$2" c=0 decoded
  case "$fmt" in
    surge)
      c="$(awk '/^\[Proxy\]/{f=1;next} /^\[/{f=0} f' "$f" \
        | grep -acE '^[^#[:space:]].*=[[:space:]]*(anytls|ss|ssr|trojan|vmess|vless|hysteria2?|tuic|http|https|socks5(-tls)?|snell|wireguard|direct)([[:space:]]*,|[[:space:]]*$)' 2>/dev/null || echo 0)"
      ;;
    clash)
      c="$(awk '/^proxies:/{f=1;next} /^[a-zA-Z]/{f=0} f' "$f" \
        | grep -cE '^[[:space:]]*-[[:space:]]*\{' 2>/dev/null || echo 0)"
      ;;
    base64)
      decoded="$(openssl base64 -d -A -in "$f" 2>/dev/null || true)"
      c="$(printf '%s\n' "$decoded" | grep -c '://' 2>/dev/null || echo 0)"
      ;;
  esac
  printf '%d' "$c"
}

_fetch_sub() {
  local url="$1" out="$2" best_label="" best_fmt="error" best_count=0 best_file="" label fmt count tmpfile

  # Try all UAs in priority order: default first, then Surge, Clash, v2rayN
  local ua_list=(
    "default||"                     # default UA
    "Surge|Surge iOS/3000 CFNetwork Darwin"
    "Clash|ClashforWindows/0.20.39"
    "v2rayN|v2rayN/6.45"
  )
  local entry_l ua_spec label_l ua_l

  for entry_l in "${ua_list[@]}"; do
    ua_spec="${entry_l#*|}"; label_l="${entry_l%%|*}"; ua_l="${ua_spec#*|}"
    tmpfile="$(mktemp)"

    if [ "$label_l" = "default" ]; then
      curl -fsSL --max-time 30 "$url" -o "$tmpfile" 2>/dev/null || { rm -f "$tmpfile"; continue; }
    else
      curl -fsSL -A "$ua_l" --max-time 30 "$url" -o "$tmpfile" 2>/dev/null || { rm -f "$tmpfile"; continue; }
    fi

    fmt="$(_detect_format "$tmpfile")"
    if [ "$fmt" = "error" ]; then
      rm -f "$tmpfile"; continue
    fi

    count="$(_count_nodes "$tmpfile" "$fmt")"
    count="${count:-0}"

    # Pick best: more nodes wins; default UA breaks ties
    if [ "$count" -gt "$best_count" ]; then
      [ -n "$best_file" ] && rm -f "$best_file"
      best_label="$label_l"; best_fmt="$fmt"; best_count="$count"; best_file="$tmpfile"
    elif [ "$count" -eq "$best_count" ] && [ "$count" -gt 0 ]; then
      # Tie: prefer default UA
      if [ "$label_l" = "default" ] && [ "$best_label" != "default" ]; then
        rm -f "$best_file"
        best_label="$label_l"; best_fmt="$fmt"; best_count="$count"; best_file="$tmpfile"
      else
        rm -f "$tmpfile"
      fi
    else
      rm -f "$tmpfile"
    fi
  done

  if [ -n "$best_file" ] && [ "$best_fmt" != "error" ]; then
    cp "$best_file" "$out"
    rm -f "$best_file"
    echo "$best_fmt"
    return 0
  fi
  echo "error"
  return 1
}

# ---- Format auto-detection ----
# Returns: surge, clash, base64, or error
_detect_format() {
  local f="$1"
  [ ! -s "$f" ] && { echo "error"; return; }

  # Surge config: starts with [General] or has [Proxy] section
  if grep -q '^\[Proxy\]' "$f" 2>/dev/null; then echo "surge"; return; fi
  if grep -q '^\[General\]' "$f" 2>/dev/null; then echo "surge"; return; fi

  # Clash YAML: contains proxies: key
  if grep -q '^proxies:' "$f" 2>/dev/null; then echo "clash"; return; fi

  # Base64: decodes to something with ://
  local decoded
  decoded="$(openssl base64 -d -A -in "$f" 2>/dev/null || true)"
  if printf '%s' "$decoded" | grep -q '://'; then echo "base64"; return; fi

  echo "error"
}

# ---------- Stash generator (inline nodes, no proxy-providers) ----------
gen_stash() {
  local sub="$1" tpl="Stash/$2" out="result/$3"
  local raw fmt clash; raw="$(mktemp)"; trap 'rm -f "$raw"' RETURN
  echo "  ⏬ Fetching subscription..."
  fmt="$(_fetch_sub "$sub" "$raw")"
  [ "$fmt" = "error" ] && { echo -e "  ${c_e}❌ Download failed (check URL / network)${c_o}"; return 1; }
  echo "  🔍 Detected format: ${c_d}$fmt${c_o}"

  case "$fmt" in
    clash)
      clash="$(_clash2clash < "$raw" || true)"
      ;;
    base64)
      local decoded; decoded="$(openssl base64 -d -A -in "$raw" 2>/dev/null || true)"
      if printf '%s' "$decoded" | grep -q '://'; then
        clash="$(printf '%s\n' "$decoded" | _uri2clash || true)"
      fi
      ;;
    surge)
      clash="$(_surge2clash < "$raw" || true)"
      ;;
  esac

  [ -n "$clash" ] || { echo -e "  ${c_e}❌ No usable proxy nodes found${c_o}"; return 1; }
  local count; count="$(printf '%s\n' "$clash" | grep -c '{' || true)"
  echo -e "  ${c_ok}✅ Extracted $count nodes${c_o}"

  # Build names array from Clash entries (used by _stash_group filter logic)
  local -a names=(); local l n
  while IFS= read -r l; do
    [ -z "$l" ] && continue
    n="$(printf '%s' "$l" | sed -nE 's/.*"name"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p')"
    [ -z "$n" ] && n="$(printf '%s' "$l" | sed -nE 's/.*[{,][[:space:]]*name[[:space:]]*:[[:space:]]*"?([^",}]+)"?.*/\1/p')"
    [ -n "$n" ] && names+=("$n")
  done <<< "$clash"

  # Rebuild template line by line: drop proxy-providers, inline proxies, rewrite use:[SF] groups
  : > "$out"
  local in_pp=0 line
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$in_pp" -eq 1 ]; then
      if [[ "$line" =~ ^[a-zA-Z] ]]; then in_pp=0; else continue; fi
    fi
    if [[ "$line" =~ ^proxy-providers: ]]; then in_pp=1; continue; fi
    if [[ "$line" == proxies:*"[]"* ]]; then
      { printf 'proxies:\n'; printf '%s\n' "$clash"; } >> "$out"; continue
    fi
    [[ "$line" == *"use: [SF]"* ]] && line="$(_stash_group "$line")"
    printf '%s\n' "$line" >> "$out"
  done < "$tpl"

  echo -e "  ${c_ok}🎉 Done!${c_o} Nodes inlined into proxies: ($count), proxy-providers removed, use:[SF] groups rewritten"
}

# ============================================================
banner

# ---------- Step 1: Choose client ----------
echo -e "${c_t}Step 1/4  Choose client${c_o}"
clients=()
ls Surge/*.conf  >/dev/null 2>&1 && clients+=("Surge")
ls Stash/*.yaml  >/dev/null 2>&1 && clients+=("Stash")
ls ClashMac/*.yaml >/dev/null 2>&1 && clients+=("ClashMac")
[ "${#clients[@]}" -gt 0 ] || { echo -e "  ${c_e}No client templates found (Surge/*.conf or Stash/*.yaml)${c_o}"; exit 1; }
choose "Choose client" "${clients[@]}"; CLIENT="$REPLY_ITEM"
echo -e "  Selected: ${c_ok}${CLIENT}${c_o}\n"

# ---------- Step 2: Choose template ----------
echo -e "${c_t}Step 2/4  Choose template${c_o}"
case "$CLIENT" in
  Surge) dir="Surge"; ext="conf";;
  Stash) dir="Stash"; ext="yaml";;
  ClashMac) dir="ClashMac"; ext="yaml";;
esac
tpls=()
while IFS= read -r f; do tpls+=("$(basename "$f")"); done < <(ls -1 "$dir"/*."$ext" 2>/dev/null | grep -v '\.filled\.' || true)
[ "${#tpls[@]}" -gt 0 ] || { echo -e "  ${c_e}No .$ext templates found in $dir/${c_o}"; exit 1; }
choose "Choose template" "${tpls[@]}"; TPL="$REPLY_ITEM"
echo -e "  Selected: ${c_ok}${TPL}${c_o}\n"

# ---------- Step 3: Subscription URL ----------
echo -e "${c_t}Step 3/4  Subscription URL${c_o}"
SUB=""
while [ -z "$SUB" ]; do
  printf "  Paste subscription URL: "
  read -r SUB
  SUB="${SUB//\\/}"
  SUB="${SUB#"${SUB%%[![:space:]]*}"}"; SUB="${SUB%"${SUB##*[![:space:]]}"}"
  [ -z "$SUB" ] && echo -e "  ${c_e}Cannot be empty${c_o}"
done
echo

# ---------- Step 4: Output filename ----------
echo -e "${c_t}Step 4/4  Output filename${c_o}"
OUTDIR="result"; mkdir -p "$OUTDIR"
default_out="${TPL%.*}.filled.${ext}"
printf "  Enter filename (Enter for default ${c_d}%s${c_o}): " "$default_out"
read -r OUT
[ -z "$OUT" ] && OUT="$default_out"
[[ "$OUT" == *.$ext ]] || OUT="${OUT}.${ext}"
if [ -e "$OUTDIR/$OUT" ]; then
  printf "  ${c_w}%s exists, overwrite? [y/N]: ${c_o}" "$OUTDIR/$OUT"
  read -r yn; case "$yn" in y|Y) ;; *) echo "Cancelled"; exit 0;; esac
fi
echo

# ---------- Generate ----------
echo -e "${c_t}  Generating...${c_o}"
echo -e "  Client: ${c_d}${CLIENT}${c_o}  Template: ${c_d}${TPL}${c_o}  Output: ${c_d}${OUTDIR}/${OUT}${c_o}\n"
case "$CLIENT" in
  Surge) gen_surge "$SUB" "$TPL" "$OUT";;
  Stash) gen_stash "$SUB" "$TPL" "$OUT";;
  ClashMac) gen_stash "$SUB" "$TPL" "$OUT";;
esac
echo -e "  📄 ${c_ok}$(pwd)/${OUTDIR}/${OUT}${c_o}"
echo -e "  ${c_d}Import into the corresponding client (contains real credentials; do not commit to git)${c_o}"
