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

  # ---- non-interactive: numbered input ----
  if [ ! -t 0 ]; then
    i=1
    for it in "${items[@]}"; do printf "    ${c_ok}%d${c_o}) %s\n" "$i" "$it"; i=$((i+1)); done
    local pick=""
    while :; do
      printf "  %s [1-%d] (default 1): " "$prompt" "$n"
      read -r pick
      [ -z "$pick" ] && pick=1
      if [[ "$pick" =~ ^[0-9]+$ ]] && [ "$pick" -ge 1 ] && [ "$pick" -le "$n" ]; then
        REPLY_ITEM="${items[$((pick-1))]}"; return 0
      fi
      echo -e "  ${c_e}Invalid choice, try again${c_o}"
    done
  fi

  # ---- real terminal: arrow-key selection ----
  local sel=0 key rest first=1
  printf "  ${c_d}%s (↑/↓ to move, Enter to confirm)${c_o}\n" "$prompt"
  printf '\033[?25l'                          # hide cursor
  trap "printf '\033[?25h'" RETURN            # restore cursor on exit
  while :; do
    if [ "$first" -eq 1 ]; then first=0; else printf '\033[%dA' "$n"; fi   # move up N lines
    for i in "${!items[@]}"; do
      printf '\033[2K\r'                       # clear line
      if [ "$i" -eq "$sel" ]; then
        printf "  ${c_ok}❯ %s${c_o}\n" "${items[$i]}"
      else
        printf "    ${c_d}%s${c_o}\n" "${items[$i]}"
      fi
    done
    key=''; IFS= read -rsn1 key || true
    if [ "$key" = $'\033' ]; then              # arrow keys: read [ and A/B/C/D (byte by byte)
      local k2='' k3=''
      IFS= read -rsn1 -t 1 k2 || true        # tolerate macOS built-in bash 3.2
      IFS= read -rsn1 -t 1 k3 || true
      case "$k3" in
        A) sel=$(( (sel - 1 + n) % n )) ;;     # up
        B) sel=$(( (sel + 1) % n )) ;;         # down
      esac
      continue
    fi
    case "$key" in
      k|w) sel=$(( (sel - 1 + n) % n )) ;;
      j|s) sel=$(( (sel + 1) % n )) ;;
      ''|$'\n'|$'\r') break ;;
      [1-9]) if [ "$key" -le "$n" ]; then sel=$((key - 1)); fi ;;
    esac
  done
  printf '\033[?25h'                           # restore cursor
  REPLY_ITEM="${items[$sel]}"
}

# ---------- Surge generator ----------
gen_surge() {
  local sub="$1" tpl="Surge/$2" out="result/$3"
  local raw nodes; raw="$(mktemp)"; nodes="$(mktemp)"
  trap 'rm -f "$raw" "$nodes"' RETURN
  echo "  ⏬ Fetching subscription..."
  curl -fsSL -A "$UA" --max-time 40 "$sub" -o "$raw" \
    || { echo -e "  ${c_e}❌ Download failed (check URL / network)${c_o}"; return 1; }
  awk '/^\[Proxy\]/{f=1;next} /^\[/{f=0} f' "$raw" \
   | grep -aE '^[^#[:space:]].*=[[:space:]]*(anytls|ss|ssr|trojan|vmess|vless|hysteria2?|tuic|http|https|socks5(-tls)?|snell|wireguard|direct)([[:space:]]*,|[[:space:]]*$)' \
   > "$nodes" || true
  local count; count="$(wc -l < "$nodes" | tr -d ' ')"
  [ "$count" -gt 0 ] || { echo -e "  ${c_e}❌ Subscription does not match client Surge (no Surge nodes found)${c_o}"; return 1; }
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
  line="$(printf '%s' "$line" | sed "s/, *use: \[SF\]//; s/, *filter: '[^']*'//; s/, *filter: [^,}]*//")"
  line="${line/proxies: null/proxies: [$joined]}"
  printf '%s' "$line"
}

# URL-decode (%E9.. → UTF-8 bytes)
_urldec() { local s="${1//+/ }"; printf '%b' "${s//%/\\x}"; }
# Extract a query param value from a=b&c=d string
_qval() { printf '%s' "$1" | tr '&' '\n' | sed -n "s/^$2=//p" | head -1; }
# Convert base64 URI subscription entries (xxx:// links) to Clash flow-map format.
# Currently implements: anytls.
_uri2clash() {
  local line rest pass name host port query sni fp insec o
  while IFS= read -r line; do
    line="${line%$'\r'}"                              # strip DOS line-ending \r
    case "$line" in
      anytls://*)
        rest="${line#anytls://}"
        pass="${rest%%@*}"; rest="${rest#*@}"
        name=""; case "$rest" in *"#"*) name="${rest#*#}"; rest="${rest%%#*}";; esac
        query=""; case "$rest" in *"?"*) query="${rest#*\?}";; esac
        rest="${rest%%\?*}"; rest="${rest%%/*}"          # remaining: host:port
        host="${rest%%:*}"; port="${rest##*:}"
        sni="$(_qval "$query" sni)"; fp="$(_qval "$query" fp)"; insec="$(_qval "$query" insecure)"
        if [ -n "$name" ]; then name="$(_urldec "$name")"; else name="$host"; fi
        o="  - {name: \"$name\", type: anytls, server: $host, port: $port, password: \"$pass\", udp: true"
        if [ -n "$sni" ]; then o="$o, sni: $sni"; fi
        if [ -n "$fp" ];  then o="$o, client-fingerprint: $fp"; fi
        if [ "$insec" = "1" ]; then o="$o, skip-cert-verify: true"; fi
        printf '%s}\n' "$o"
        ;;
    esac
  done
}

# ---------- Stash generator (inline nodes, no proxy-providers) ----------
gen_stash() {
  local sub="$1" tpl="Stash/$2" out="result/$3"
  local raw; raw="$(mktemp)"; trap 'rm -f "$raw"' RETURN
  echo "  ⏬ Fetching subscription..."
  curl -fsSL -A "$UA_STASH" --max-time 40 "$sub" -o "$raw" \
    || { echo -e "  ${c_e}❌ Download failed (check URL / network)${c_o}"; return 1; }

  # 1) Extract nodes: try Clash YAML proxies section first
  local clash; clash="$(awk '/^proxies:/{f=1;next} /^[a-zA-Z]/{f=0} f' "$raw" \
    | grep -E '^[[:space:]]*-[[:space:]]*\{' | sed -E 's/^[[:space:]]*-[[:space:]]*/  - /' || true)"
  # Fallback: retry with v2ray UA to get a base64 URI subscription, decode and convert to Clash
  if [ -z "$clash" ]; then
    curl -fsSL -A "v2rayN/6.45" --max-time 40 "$sub" -o "$raw" 2>/dev/null || true
    local decoded; decoded="$(openssl base64 -d -A -in "$raw" 2>/dev/null || true)"
    if printf '%s' "$decoded" | grep -q '://'; then
      clash="$(printf '%s\n' "$decoded" | _uri2clash || true)"
    fi
  fi
  [ -n "$clash" ] || { echo -e "  ${c_e}❌ Subscription does not match client Stash (no usable nodes found)${c_o}"; return 1; }
  local count; count="$(printf '%s\n' "$clash" | grep -c '{' || true)"
  echo -e "  ${c_ok}✅ Extracted $count nodes${c_o}"

  # 2) Build names array from Clash entries (used by _stash_group filter logic)
  local -a names=(); local l n
  while IFS= read -r l; do
    [ -z "$l" ] && continue
    n="$(printf '%s' "$l" | sed -nE 's/.*"name"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p')"
    [ -z "$n" ] && n="$(printf '%s' "$l" | sed -nE 's/.*[{,][[:space:]]*name[[:space:]]*:[[:space:]]*"?([^",}]+)"?.*/\1/p')"
    [ -n "$n" ] && names+=("$n")
  done <<< "$clash"

  # 3) Rebuild template line by line: drop proxy-providers, inline proxies, rewrite use:[SF] groups
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
[ "${#clients[@]}" -gt 0 ] || { echo -e "  ${c_e}No client templates found (Surge/*.conf or Stash/*.yaml)${c_o}"; exit 1; }
choose "Choose client" "${clients[@]}"; CLIENT="$REPLY_ITEM"
echo -e "  Selected: ${c_ok}${CLIENT}${c_o}\n"

# ---------- Step 2: Choose template ----------
echo -e "${c_t}Step 2/4  Choose template${c_o}"
case "$CLIENT" in
  Surge) dir="Surge"; ext="conf";;
  Stash) dir="Stash"; ext="yaml";;
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
esac
echo -e "  📄 ${c_ok}$(pwd)/${OUTDIR}/${OUT}${c_o}"
echo -e "  ${c_d}Import into the corresponding client (contains real credentials; do not commit to git)${c_o}"
