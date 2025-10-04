#!/usr/bin/env bash
# decode_hid_bash.sh
# Usage: ./decode_hid_bash.sh hid_raw.txt > hid_decoded.txt
# Requires: gawk (GNU awk)

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 hid_raw.txt" >&2
  exit 2
fi
IN="$1"
if [[ ! -s "$IN" ]]; then
  echo "Input file $IN missing or empty" >&2
  exit 3
fi

gawk '
BEGIN {
  IGNORECASE = 1
  SHIFT_MASK = 0x02 + 0x20

  for(i=0;i<26;i++){
    code = 0x04 + i
    map[code] = sprintf("%c", 97 + i)
    shiftmap[code] = sprintf("%c", 65 + i)
  }

  numlist = "1 2 3 4 5 6 7 8 9 0"
  split(numlist, nums, " ")
  for(i=0;i<10;i++){
    code = 0x1e + i
    map[code] = nums[i+1]
  }

  shiftmap[0x1e] = "!"
  shiftmap[0x1f] = "@"
  shiftmap[0x20] = "#"
  shiftmap[0x21] = "$"
  shiftmap[0x22] = "%"
  shiftmap[0x23] = "^"
  shiftmap[0x24] = "&"
  shiftmap[0x25] = "*"
  shiftmap[0x26] = "("
  shiftmap[0x27] = ")"

  map[0x28] = "\n"
  map[0x29] = "<ESC>"
  map[0x2a] = "<BKSP>"
  map[0x2b] = "\t"
  map[0x2c] = " "
  map[0x2d] = "-"
  map[0x2e] = "="
  map[0x2f] = "["
  map[0x30] = "]"
  map[0x31] = "\\"
  map[0x33] = ";"
  map[0x34] = "'"
  map[0x35] = "`"
  map[0x36] = ","
  map[0x37] = "."
  map[0x38] = "/"

  shiftmap[0x2d] = "_"
  shiftmap[0x2e] = "+"
  shiftmap[0x2f] = "{"
  shiftmap[0x30] = "}"
  shiftmap[0x31] = "|"
  shiftmap[0x33] = ":"
  shiftmap[0x34] = "\""
  shiftmap[0x35] = "~"
  shiftmap[0x36] = "<"
  shiftmap[0x37] = ">"
  shiftmap[0x38] = "?"

  DISPLAY="";
}

function parse_hex_field(s, arr,    i, tok, tmp, n) {
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
  gsub(":", " ", s)
  gsub(",", " ", s)
  gsub("\\\\x", " ", s)
  gsub("0x", " ", s)
  n = split(s, parts, /[ \t]+/)
  arr_len = 0
  for(i=1;i<=n;i++){
    tok = parts[i]
    if(tok == "") continue
    if(length(parts[i]) > 2 && match(parts[i], "^[0-9A-Fa-f]+$") && (length(parts[i]) % 2 == 0)) {
      tmp = parts[i]
      for(j=1;j<=length(tmp); j+=2){
        hex = substr(tmp, j, 2)
        arr[++arr_len] = strtonum("0x" hex)
      }
    } else {
      if(match(tok, "^[0-9A-Fa-f]+$")) {
        arr[++arr_len] = strtonum("0x" tok)
      }
    }
  }
  return arr_len
}

{
  frame = $1
  time = $2
  capdata = $0
  sub("^[^\t]*\t","",capdata)
  sub("^[^\t]*\t","",capdata)
  hexstr = capdata

  delete b
  len = parse_hex_field(hexstr, b)
  if(len < 1) next

  mod = b[1]
  seg = ""
  for(i=3;i<=len;i++){
    k = b[i] + 0
    if(k == 0) continue
    if((mod & SHIFT_MASK) != 0) {
      ch = (k in shiftmap) ? shiftmap[k] : ((k in map) ? map[k] : sprintf("<0x%02x>", k))
    } else {
      ch = (k in map) ? map[k] : sprintf("<0x%02x>", k)
    }
    seg = seg ch
  }

  if(length(seg) > 0) {
    print "[" frame "] " time "  -> " seg
    pos = 1
    while(pos <= length(seg)){
      if(substr(seg,pos,1) == "<"){
        tok_end = index(substr(seg,pos), ">")
        if(tok_end > 0){
          token = substr(seg, pos, tok_end)
          if(token == "<BKSP>"){
            if(length(DISPLAY) > 0) DISPLAY = substr(DISPLAY,1,length(DISPLAY)-1)
          }
          pos += tok_end
          continue
        } else {
          DISPLAY = DISPLAY substr(seg,pos,1)
          pos++
        }
      } else {
        c = substr(seg,pos,1)
        if(c == "\n"){
          DISPLAY = DISPLAY "\\n"
        } else {
          DISPLAY = DISPLAY c
        }
        pos++
      }
    }
  }
}

END {
  print "\n--- AGGREGATED TEXT ---\n"
  print DISPLAY
}
' "$IN"
