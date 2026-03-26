targets=(
'127.0.0.1' '127.0.1' '127.1' '2130706433'
'0x7f000001' '017700000001' '0x7f.0.0.1' '0177.0.0.1' '0x7f.1'
'localhost' '0.0.0.0' '0'
'[::1]' '[0:0:0:0:0:0:0:1]' '[::]'
'[::ffff:127.0.0.1]' '[::ffff:7f00:1]'
)
unset NO_PROXY
unset no_proxy
for t in "${targets[@]}"; do
  curl -sS -i http://example.invalid/ \
    --request-target "http://$t:15004/" \
    -H "Host: $t:15004"
done
