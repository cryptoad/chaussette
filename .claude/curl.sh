#!/usr/bin/env bash
set -u

port="${1:-15004}"

targets=(
  # canonical IPv4 loopback / wildcard
  '127.0.0.1'
  '127.0.0.2'
  '127.255.255.255'
  '0.0.0.0'

  # short-dot / legacy numeric IPv4
  '127.1'
  '127.0.1'
  '127'
  '0'

  # decimal dword
  '2130706433'
  '2130706432'

  # hex dword
  '0x7f000001'
  '0x7f000002'
  '0x00000000'
  '0X7F000001'

  # octal dword
  '017700000001'
  '017700000002'
  '000000000000'

  # mixed-base / component encodings
  '0x7f.0.0.1'
  '0x7f.1'
  '0x7f.0x0.0x0.0x1'
  '0177.0.0.1'
  '0177.1'
  '0177.00.00.01'
  '127.00.00.01'
  '127.000.000.001'

  # localhost names
  'localhost'
  'LOCALHOST'
  'localhost.'
  'localhost..'

  # IPv6 / mapped
  '[::1]'
  '[::]'
  '[0:0:0:0:0:0:0:1]'
  '[::ffff:127.0.0.1]'
  '[::ffff:7f00:1]'
  '[::FFFF:127.0.0.1]'

  # userinfo variants
  'foo@127.0.0.1'
  'foo:bar@127.0.0.1'
  'foo@localhost'
  'foo@0.0.0.0'
)

show() {
  printf '\n===== %s =====\n\n' "$1"
}

do_req() {
  local abs="$1"
  local hosthdr="$2"
  local label="$3"

  show "$label"
  curl -sS -i http://example.invalid/ \
    --request-target "$abs" \
    -H "Host: $hosthdr" \
    || echo '[curl error]'
}

for t in "${targets[@]}"; do
  abs="http://$t:$port/"
  host="$t:$port"

  # matching Host header
  do_req "$abs" "$host" "$abs"

  # mismatched Host header
  do_req "$abs" "example.com" "$abs    [Host: example.com]"
done
