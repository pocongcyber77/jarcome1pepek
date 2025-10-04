#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:-shortbf.pcapng}"
IPFILTER="${2:-}"   # optional attacker IP
OUTDIR="shortbf_analysis"
mkdir -p "$OUTDIR"

if ! command -v tshark >/dev/null 2>&1; then
  echo "Error: tshark not found. Install Wireshark/tshark first." >&2
  exit 2
fi

CSV="$OUTDIR/http_posts.csv"
PW_RAW="$OUTDIR/passwords_raw.txt"
USR_RAW="$OUTDIR/usernames_raw.txt"
BODY_FILE="$OUTDIR/post_bodies_extracted.txt"
PW_DECODED="$OUTDIR/passwords_decoded.txt"
USR_DECODED="$OUTDIR/usernames_decoded.txt"
PW_TOP="$OUTDIR/passwords_top.txt"
USR_TOP="$OUTDIR/usernames_top.txt"

: > "$PW_RAW" "$USR_RAW" "$BODY_FILE" "$PW_DECODED" "$USR_DECODED"

echo "[*] Extracting HTTP POST frames to CSV..."
tshark -r "$PCAP" -Y 'http.request.method == "POST"' \
  -T fields -E separator=, -E quote=d -E header=y \
  -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.stream -e http.host -e http.request.uri -e http.file_data \
  > "$CSV"

echo "[*] Rows in CSV: $(wc -l < "$CSV")"

# simple url-decode (bash)
urldecode() {
  local s="$1"
  s="${s//+/ }"
  # convert %XX to \xXX then printf
  s="$(printf '%s' "$s" | sed -E 's/%([0-9A-Fa-f]{2})/\\x\1/g')"
  printf '%b' "$s"
}

echo "[*] Scanning CSV line-by-line (bash loop)..."

# read header and ignore
read -r header < "$CSV" || true

# Process file line by line
# CSV fields are quoted by tshark; to get last field (body) we reverse-cut.
while IFS= read -r line; do
  # optional IP filter
  if [[ -n "$IPFILTER" && ${line,,} != *${IPFILTER,,}* ]]; then
    continue
  fi

  # get last field (http.file_data) robustly:
  # reverse the line, cut up to first comma, then reverse back
  body_rev="$(printf '%s' "$line" | rev | cut -d, -f1)"
  body="$(printf '%s' "$body_rev" | rev)"
  # strip surrounding quotes if any
  body="${body%\"}"
  body="${body#\"}"
  # save the body record for later
  printf '%s\n' "$line|BODY|$body" >> "$BODY_FILE"

  # split the whole line on &, ? and space to find key=val tokens
  # replace '&' and '?' with newline-safe delimiter, then iterate
  # first, replace & and ? with newline char via awk-like approach using printf and tr
  tokens="$(printf '%s' "$line" | tr '&?' '\n\n')"
  while IFS= read -r token; do
    # remove surrounding quotes and spaces
    token="${token%\"}"; token="${token#\"}"
    token="${token## }"; token="${token%% }"
    # only consider strings with '='
    if [[ "$token" == *"="* ]]; then
      key="${token%%=*}"
      val="${token#*=}"
      key_lc="${key,,}"
      # trim val quotes/spaces
      val="${val%\"}"; val="${val#\"}"
      val="${val## }"; val="${val%% }"
      case "$key_lc" in
        username|user|login)
          printf '%s\n' "$val" >> "$USR_RAW"
          ;;
        password|passwd|pwd|pass)
          printf '%s\n' "$val" >> "$PW_RAW"
          ;;
      esac
    fi
  done <<< "$tokens"

done < <(tail -n +2 "$CSV")   # feed lines excluding header

# Also parse bodies saved in BODY_FILE for any key=val that we missed
while IFS= read -r rec; do
  body="${rec#*|BODY|}"
  # skip if empty
  [[ -z "$body" ]] && continue
  # split on &
  IFS='&' read -ra parts <<< "$body"
  for kv in "${parts[@]}"; do
    kv="${kv%\"}"; kv="${kv#\"}"
    if [[ "$kv" == *"="* ]]; then
      k="${kv%%=*}"; v="${kv#*=}"
      kl="${k,,}"
      case "$kl" in
        username|user|login) printf '%s\n' "$v" >> "$USR_RAW" ;;
        password|passwd|pwd|pass) printf '%s\n' "$v" >> "$PW_RAW" ;;
      esac
    fi
  done
done < "$BODY_FILE"

# decode raw candidates
if [[ -s "$PW_RAW" ]]; then
  while IFS= read -r raw; do
    raw="${raw%\"}"; raw="${raw#\"}"
    dec="$(urldecode "$raw" 2>/dev/null || printf '%s' "$raw")"
    dec="$(printf '%s' "$dec" | sed -e 's/^[ \t]*//; s/[ \t]*$//')"
    [[ -n "$dec" ]] && printf '%s\n' "$dec" >> "$PW_DECODED"
  done < "$PW_RAW"
fi

if [[ -s "$USR_RAW" ]]; then
  while IFS= read -r raw; do
    raw="${raw%\"}"; raw="${raw#\"}"
    dec="$(urldecode "$raw" 2>/dev/null || printf '%s' "$raw")"
    dec="$(printf '%s' "$dec" | sed -e 's/^[ \t]*//; s/[ \t]*$//')"
    [[ -n "$dec" ]] && printf '%s\n' "$dec" >> "$USR_DECODED"
  done < "$USR_RAW"
fi

# produce top lists
echo "[*] Top passwords (decoded):"
if [[ -s "$PW_DECODED" ]]; then
  sort "$PW_DECODED" | uniq -c | sort -nr | tee "$PW_TOP"
else
  echo "(no passwords extracted)"
fi

echo "[*] Top usernames (decoded):"
if [[ -s "$USR_DECODED" ]]; then
  sort "$USR_DECODED" | uniq -c | sort -nr | tee "$USR_TOP"
else
  echo "(no usernames extracted)"
fi

# attempts per src ip from CSV (col 3)
echo "[*] Attempts per source IP:"
awk -F',' 'NR>1 { print $3 }' "$CSV" | sort | uniq -c | sort -nr | tee "$OUTDIR/attempts_per_srcip.txt"

# attempts per minute
echo "[*] Attempts per minute:"
if [[ -n "$IPFILTER" ]]; then
  awk -F',' -v ipf="$IPFILTER" 'NR>1 && index($0,ipf)>0 { t=$2; gsub(/\..*/,"",t); print substr(t,1,16) }' "$CSV" | sort | uniq -c | sort -nr | tee "$OUTDIR/attempts_per_minute.txt"
else
  awk -F',' 'NR>1 { t=$2; gsub(/\..*/,"",t); print substr(t,1,16) }' "$CSV" | sort | uniq -c | sort -nr | tee "$OUTDIR/attempts_per_minute.txt"
fi

echo "[*] Done. Files in $OUTDIR:"
ls -l "$OUTDIR"

