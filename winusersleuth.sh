#!/usr/bin/env bash
# WinUserSleuth v2.7 — Parallel enumeration (impacket + netexec run concurrently)
set -euo pipefail
VERSION="2.7"

print_banner() {
  if command -v figlet >/dev/null 2>&1; then figlet -w 160 "WinUserSleuth"
  else
    cat <<'BANNER'
 __        ___   _   _                 ____                 _ _
 \ \      / / | | | | | ___  _ __ ___ / ___| ___   ___   __| | |
  \ \ /\ / /| | | | | |/ _ \| '__/ _ \ |  _ / _ \ / _ \ / _` | |
   \ V  V / | |_| | | | (_) | | |  __/ |_| | (_) | (_) | (_| | |
    \_/\_/   \___/  |_|\___/|_|  \___|\____|\___/ \___/ \__,_|_|
BANNER
  fi
  echo "🔍 WinUserSleuth v$VERSION — Username Enumerator and Validator"
  echo
}

usage() {
  cat <<USAGE
Usage: $0 -t <TARGET> [-o OUTFILE] [--verbose]
  -t TARGET    Target IP or hostname (required)
  -o OUTFILE   Save final confirmed usernames (default: ./user.txt)
  --verbose    Show debug info for pre-steps
  -h           Help
Example:
  ./winusersleuth.sh -t 10.201.44.39
USAGE
  exit 1
}

TARGET=""; OUTFILE=""; VERBOSE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t) TARGET="$2"; shift 2 ;;
    -o) OUTFILE="$2"; shift 2 ;;
    --verbose) VERBOSE=true; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done
[[ -z "$TARGET" ]] && { echo "❌ Target required"; usage; }
[[ -z "$OUTFILE" ]] && OUTFILE="./user.txt"

TMPDIR="$(mktemp -d /tmp/wus_XXXX)"; trap 'rm -rf "$TMPDIR"' EXIT

print_banner
echo "[*] Target: $TARGET"
echo "[*] Confirmed output file: $OUTFILE"
[[ $VERBOSE == true ]] && echo "[*] Verbose: ON"
echo

run_cmd_verbose() { local cmd="$1" out="$2"; echo "[debug] $cmd"; eval "$cmd" | tee "$out"; }
run_cmd_quiet()   { local cmd="$1" out="$2"; eval "$cmd" >"$out" 2>&1 || true; }

# --- 1) Parallel Enumeration (impacket + netexec) ---
echo "[+] Enumerating Usernames...."

IMPP_OUT="$TMPDIR/impacket.raw"
NET_OUT="$TMPDIR/netexec.raw"

if $VERBOSE; then
  # run in background but print debug header for each
  run_cmd_verbose "impacket-lookupsid guest@$TARGET -no-pass & echo PID \$! >/tmp/imp_pid" "$IMPP_OUT" &
  IMPP_PID=$!
  run_cmd_verbose "netexec smb $TARGET -u guest -p '' --rid-brute & echo PID \$! >/tmp/net_pid" "$NET_OUT" &
  NET_PID=$!
else
  # run quietly in background, capture pids
  impacket-lookupsid "guest@$TARGET" -no-pass >"$IMPP_OUT" 2>&1 &
  IMPP_PID=$!
  netexec smb "$TARGET" -u guest -p '' --rid-brute >"$NET_OUT" 2>&1 &
  NET_PID=$!
fi

# Wait for both to complete
wait $IMPP_PID 2>/dev/null || true
wait $NET_PID 2>/dev/null || true

# If verbose, show both outputs brief header (not raw dump)
if $VERBOSE; then
  echo
  echo "[debug] impacket-lookupsid exit; sample lines:"
  sed -n '1,6p' "$IMPP_OUT" || true
  echo "[debug] netexec exit; sample lines:"
  sed -n '1,6p' "$NET_OUT" || true
  echo
fi

# --- 2) Candidate Extraction & Cleanup ---
RAW="$TMPDIR/users_raw.txt"
: > "$RAW"
grep -hoP '(?<=\\)[A-Za-z0-9._-]{2,30}' "$IMPP_OUT" "$NET_OUT" 2>/dev/null | sort -u > "$RAW" || true

FILTER="$TMPDIR/users_filtered.txt"
NOISE='^(domain|group|policy|pipe|read-only|cloneable|protected|key|ras|allowed|denied|cert|users?|guests?|controllers?|publishers?|enterprise|workgroup|lsarpc|s-|sidtype|lab-dc|dc|ias|srv|svc|server|administrator|guest|krbtgt)$'
: > "$FILTER"
while read -r u; do
  [[ -z "$u" ]] && continue
  [[ "$u" =~ \$ ]] && continue
  echo "$u" | egrep -qi "$NOISE" && continue
  echo "$u" >> "$FILTER"
done < "$RAW"
sort -u "$FILTER" -o "$FILTER" || true

CAND_COUNT=$(wc -l < "$FILTER" | tr -d ' ')
echo "[*] Candidate usernames for Kerbrute: $CAND_COUNT"
[[ $VERBOSE == true ]] && { echo "---- candidate list ----"; cat "$FILTER"; echo "------------------------"; }
(( CAND_COUNT == 0 )) && { echo "❌ No usernames found."; exit 0; }
echo

# --- 3) Domain Detection ---
DOMAIN=$(grep -m1 -oP '([A-Z0-9.-]+)(?=\\Administrator)' "$IMPP_OUT" 2>/dev/null || true)
[[ -z "$DOMAIN" ]] && DOMAIN=$(grep -m1 -oP '([A-Z0-9.-]+)(?=\\)' "$NET_OUT" 2>/dev/null || true)
[[ -z "$DOMAIN" ]] && DOMAIN="WORKGROUP"
echo "[*] Detected domain for Kerbrute: $DOMAIN"
echo

# --- 4) Kerbrute (silent, parse results) ---
KERB_OUT="$TMPDIR/kerbrute.raw"
echo "[+] Running Kerbrute...."
if ! command -v kerbrute >/dev/null 2>&1; then
  echo "❌ kerbrute not found in PATH."; exit 1
fi

# Run kerbrute silently and capture output
kerbrute userenum -d "$DOMAIN" --dc "$TARGET" "$FILTER" > "$KERB_OUT" 2>&1 || true

# --- 5) Parse Kerbrute Output ---
grep -iE 'VALID USERNAME|Valid user|Found valid user|^VALID:|^FOUND:' "$KERB_OUT" 2>/dev/null \
  | sed -E 's/.*(VALID USERNAME|Valid user|Found valid user|VALID:|FOUND:)[:[:space:]]*//Ig' \
  | sed -E 's/@.*$//' | awk 'length($0)>1' | sort -u > "$TMPDIR/valid_users.txt" || true

# --- 6) Show Results and save ---
if [[ -s "$TMPDIR/valid_users.txt" ]]; then
  cp "$TMPDIR/valid_users.txt" "$OUTFILE"
  COUNT=$(wc -l < "$OUTFILE" | tr -d ' ')
  echo
  echo "✅ Kerbrute confirmed usernames:"
  cat "$OUTFILE"
  echo
  echo "→ Total confirmed users: $COUNT"
  echo "→ Saved to: $OUTFILE"
else
  echo
  echo "⚠️  Kerbrute did not confirm any usernames."
  echo "   (Use --verbose to see debug samples.)"
fi

echo
echo "[+] Scan finished."
