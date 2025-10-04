#!/usr/bin/env bash
# decode_fix.sh - Simple USB HID keyboard decoder (bash only)

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 hid_raw.txt" >&2
  exit 1
fi
IN="$1"
[[ ! -s "$IN" ]] && { echo "Input '$IN' empty or missing" >&2; exit 1; }

# Keycode maps
letters=( {a..z} )
nums=( "" "" 1 2 3 4 5 6 7 8 9 0 )

map_key() {
  local k=$1 shift=$2
  if ((k>=4 && k<=29)); then
    if [[ $shift -eq 1 ]]; then
      printf "%s" "${letters[k-4]^}"
    else
      printf "%s" "${letters[k-4]}"
    fi
  elif ((k>=30 && k<=39)); then
    local n=${nums[k]}
    if [[ $shift -eq 1 ]]; then
      case $n in
        1) printf "!";;
        2) printf "@";;
        3) printf "#";;
        4) printf "$";;
        5) printf "%%";;
        6) printf "^";;
        7) printf "&";;
        8) printf "*";;
        9) printf "(";;
        0) printf ")";;
      esac
    else
      printf "%s" "$n"
    fi
  else
    case $k in
      40) printf "\n";;
      44) printf " ";;
      42) printf "<BKSP>";;
      *)  printf "<0x%02x>" "$k";;
    esac
  fi
}

AGG=""

while read -r line; do
  [[ -z "$line" ]] && continue
  hexfield="${line##*$'\t'}"
  hexfield="${hexfield//:/}"
  # ambil byte array
  bytes=()
  for ((i=0;i<${#hexfield};i+=2)); do
    bytes+=( "${hexfield:i:2}" )
  done
  [[ ${#bytes[@]} -lt 3 ]] && continue
  mod=$((16#${bytes[0]}))
  shift_pressed=0
  (( (mod & 0x22) != 0 )) && shift_pressed=1
  for ((i=2;i<${#bytes[@]};i++)); do
    b=${bytes[i]}
    [[ "$b" == "00" ]] && continue
    k=$((16#$b))
    ch=$(map_key "$k" "$shift_pressed")
    if [[ "$ch" == "<BKSP>" ]]; then
      [[ -n "$AGG" ]] && AGG="${AGG:0:$((${#AGG}-1))}"
    else
      AGG+="$ch"
    fi
  done
done < "$IN"

echo "--- AGGREGATED TEXT ---"
echo "$AGG"

