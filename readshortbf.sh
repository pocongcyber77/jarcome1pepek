#!/usr/bin/env bash
# reassemble_check.sh
# Reassemble TCP streams and search for FTP USER/PASS/230
PCAP="${1:-shortbf.pcapng}"
if [[ ! -f "$PCAP" ]]; then
  echo "ERROR: pcap '$PCAP' not found"; exit 1
fi
for cmd in tshark awk grep sed sort uniq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command '$cmd' not found: $cmd"; exit 1
  fi
done

echo "[*] Quick check: any TLS/SSL traffic? (if yes, FTPS likely -> cannot extract creds)"
TLS_COUNT=$(tshark -r "$PCAP" -Y "tls or ssl" -T fields -e _ws.col.Protocol 2>/dev/null | wc -l)
echo "TLS/SSL packets: $TLS_COUNT"
if (( TLS_COUNT > 0 )); then
  echo "[!] TLS/SSL packets detected. If FTP is over TLS (FTPS) credentials are encrypted and cannot be extracted from pcap."
fi
echo


mapfile -t STREAMS < <(tshark -r "$PCAP" -Y "tcp.payload" -T fields -e tcp.stream 2>/dev/null | sort -n -u)

if [[ ${#STREAMS[@]} -eq 0 ]]; then
  echo "[!] No tcp.payload streams found. Nothing to reassemble."; exit 0
fi

echo "[*] Found ${#STREAMS[@]} streams with payload. Reassembling each stream and searching for USER/PASS/230 ..."

OUT_STREAMS="streams_found.txt"
OUT_ATT="attempts_streams.csv"
echo "stream|time_epoch|client_ip_port|server_ip_port|user|pass|response" > "$OUT_ATT"
> "$OUT_STREAMS"

for s in "${STREAMS[@]}"; do
  # reassemble ascii for this stream
  # suppress header by cutting after the first blank line; keep the body only (follow,tcp,ascii prints headers)
  data=$(tshark -r "$PCAP" -q -z "follow,tcp,ascii,${s}" 2>/dev/null | sed -n '/^====/,$p' | sed '1d' )
  # if empty skip
  if [[ -z "$data" ]]; then
    continue
  fi
  # quick grep to see if any keyword inside
  if ! echo "$data" | grep -E -i "USER |PASS |^230| 230 " >/dev/null; then
    continue
  fi

  # write the stream id and a small excerpt to streams_found.txt
  echo "=== STREAM $s ===" >> "$OUT_STREAMS"
  echo "$data" | sed -n '1,200p' >> "$OUT_STREAMS"
  echo "" >> "$OUT_STREAMS"

  # Now try to extract USER/PASS pairs and server responses from the reassembled stream text
  # We'll parse line by line: lines starting with 'USER ' or containing 'USER ' -> username
  # lines with 'PASS ' -> password (pair with last seen USER), lines starting with '230' -> success
  last_user=""
  last_client="" # cannot directly know client ip:port from follow output; retrieve mapping below
  while IFS= read -r line; do
    # normalize CRs
    l="$line"
    if echo "$l" | grep -q -i "USER "; then
      # extract first token after USER
      u=$(echo "$l" | sed -n 's/.*[Uu][Ss][Ee][Rr] \+\([^ \t\r\n]*\).*/\1/p' | head -n1)
      last_user="${u:-<unknown>}"
    fi
    if echo "$l" | grep -q -i "PASS "; then
      p=$(echo "$l" | sed -n 's/.*[Pp][Aa][Ss][Ss] \+\([^ \t\r\n]*\).*/\1/p' | head -n1)
      p="${p:-<empty>}"
      # find time & ips/ports for this stream by selecting a packet in this stream that had payload (first occurrence)
      # we query tshark for one packet in this stream that has tcp and get its fields
      pktinfo=$(tshark -r "$PCAP" -Y "tcp.stream==${s} && tcp.payload" -T fields -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport 2>/dev/null | head -n1)
      # fallback empty handling
      if [[ -n "$pktinfo" ]]; then
        time_ep=$(echo "$pktinfo" | awk '{print $1}')
        ipsrc=$(echo "$pktinfo" | awk '{print $2}')
        sport=$(echo "$pktinfo" | awk '{print $3}')
        ipdst=$(echo "$pktinfo" | awk '{print $4}')
        dport=$(echo "$pktinfo" | awk '{print $5}')
        client_ip_port="${ipsrc}:${sport}"
        server_ip_port="${ipdst}:${dport}"
      else
        time_ep=""
        client_ip_port=""
        server_ip_port=""
      fi
      # write attempt; response empty for now
      echo "${s}|${time_ep}|${client_ip_port}|${server_ip_port}|${last_user}|${p}|" >> "$OUT_ATT"
    fi
    if echo "$l" | grep -q -E -i "^230| 230 "; then
      # attach 230 to last attempt created for this stream
      # find last attempt line for this stream in OUT_ATT and append 230
      tmp=$(tail -n 200 "$OUT_ATT" | tac | awk -F'|' -v S="$s" ' $1==S { print NR; exit }' )
      # simpler: we update the last matching record directly with sed: replace last occurrence of "s|...|...|$" adding 230
      # We'll do an in-place sed to replace the last line that starts with "$s|" that has empty response (ends with |)
      if grep -q "^${s}|" "$OUT_ATT"; then
        # replace last occurrence with appended 230
        awk -F'|' -v s="$s" '{
          lines[NR]=$0
        } END{
          for(i=NR;i>=1;i--){
            if(lines[i] ~ "^"s"\\|" && lines[i] ~ "\\|$"){
              lines[i]=lines[i]"230"
              break
            }
          }
          for(j=1;j<=NR;j++) print lines[j]
        }' "$OUT_ATT" > "${OUT_ATT}.tmp" && mv "${OUT_ATT}.tmp" "$OUT_ATT"
      fi
    fi
  done <<< "$data"

done

echo
echo "[*] Reassembly search done."
echo "Streams with matches written to: streams_found.txt (excerpt)."
echo "Parsed attempts written to: $OUT_ATT"
echo

echo "[*] Summary: top source IPs by PASS attempts (best-effort):"
# attempt file columns: stream|time|client|server|user|pass|response
# count by client ip (before colon)
awk -F'|' '{ split($3,a,":"); ip=a[1]; count[ip]++ } END{ for (i in count) print count[i], i }' "$OUT_ATT" | sort -rn | head -n 10

echo
echo "[*] Successful logins found (response contains 230):"
awk -F'|' 'tolower($7) ~ /230/ { print "stream="$1" client="$3" user="$5" pass="$6 }' "$OUT_ATT" || echo "(none)"

echo
echo "If no USER/PASS/230 still found, possibilities:"
echo " - FTP over TLS (FTPS) -> encrypted credentials (looked for TLS/SSL above)."
echo " - Commands split across packets so follow/tcp may still not show plaintext if data never contained ascii patterns."
echo " - Non-standard commands or different encodings (e.g., binary obfuscation)."
echo
echo "Next options I recommend:"
echo " 1) Run this script and paste the top of streams_found.txt (head -n 200) so I can inspect reassembled stream excerpts."
echo " 2) If TLS/SSL > 0 and you expect FTPS, we cannot extract creds from pcap; instead look for client IPs that attempted many TLS connections."
echo " 3) If still empty, try full reassembly export per stream to files and inspect manually:"
echo "    mkdir -p reassembled_streams; for s in \$(tshark -r \"$PCAP\" -Y 'tcp.payload' -T fields -e tcp.stream | sort -n -u); do tshark -r \"$PCAP\" -q -z follow,tcp,ascii,\$s > reassembled_streams/stream_\$s.txt; done"

exit 0
