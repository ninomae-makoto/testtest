#!/usr/bin/env bash
# Create a JWT (ES256) with OpenSSL
# - payload/header は「JSON文字列」を受け取る
# - payload には kid を必ず付与（未指定なら空文字）
# Usage:
#   jwt_es256.sh -k ec_private.pem -p '{"sub":"x","exp":111,"iat":111}'
#   jwt_es256.sh -k ec_private.pem -p "$(cat payload.json)"
#   jwt_es256.sh -k ec_private.pem -p '{"sub":"x"}' -H '{"kid":"hdr-key"}'

set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C LANG=C
umask 077

HEADER_JSON_STR=""
PAYLOAD_JSON_STR=""
KEY_FILE=""

while getopts ":H:p:k:" opt; do
  case "$opt" in
    H) HEADER_JSON_STR="$OPTARG" ;;
    p) PAYLOAD_JSON_STR="$OPTARG" ;;
    k) KEY_FILE="$OPTARG" ;;
    *) echo "Usage: $0 -k ec_private.pem -p '<payload json>' [-H '<header json>']" >&2; exit 2 ;;
  esac
done

[[ -n "$PAYLOAD_JSON_STR" && -n "$KEY_FILE" ]] || {
  echo "Usage: $0 -k ec_private.pem -p '<payload json>' [-H '<header json>']" >&2
  exit 2
}

for c in jq openssl xxd awk; do
  command -v "$c" >/dev/null || { echo "missing: $c" >&2; exit 127; }
done

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
minify() { jq -cS .; }  # 安定化（キー順含む）

ensure_p256_key() {
  if ! openssl pkey -in "$KEY_FILE" -pubout -text_pub -noout 2>/dev/null \
      | grep -qE 'NIST CURVE: P-256|secp256r1|prime256v1'; then
    echo "warning: key may not be P-256 (ES256 requires prime256v1/secp256r1)" >&2
  fi
}

build_header_json() {
  if [[ -n "$HEADER_JSON_STR" ]]; then
    printf '%s' "$HEADER_JSON_STR" \
    | jq -c '.' \
    | jq '.alg="ES256" | .typ=(.typ // "JWT")'
  else
    jq -nc '{alg:"ES256",typ:"JWT"}'
  fi
}

# DER(ECDSA) -> JOSE(r||s) base64url
der_to_jose_b64url() {
  local der="$1"
  mapfile -t ints < <(
    openssl asn1parse -inform DER -in "$der" 2>/dev/null \
      | awk '/prim: INTEGER/ { sub(/.*:/,""); print; }' \
      | head -n 2
  )
  local r_hex="${ints[0]:-}" s_hex="${ints[1]:-}"
  [[ -n "$r_hex" && -n "$s_hex" ]] || { echo "failed to parse ECDSA DER" >&2; return 1; }
  while (( ${#r_hex} > 64 )); do r_hex="${r_hex:2}"; done
  while (( ${#s_hex} > 64 )); do s_hex="${s_hex:2}"; done
  while (( ${#r_hex} < 64 )); do r_hex="0${r_hex}"; done
  while (( ${#s_hex} < 64 )); do s_hex="0${s_hex}"; done
  printf '%s' "${r_hex}${s_hex}" | xxd -r -p | b64url
}

ensure_p256_key

# ヘッダ生成（alg/typは上書き、他は任意で持ち込み可）
HEADER_MIN=$(build_header_json | minify)

# ペイロード：受け取った JSON 文字列を検証・最小化し、kid を必ず追加（未指定なら空）
PAYLOAD_MIN=$(printf '%s' "$PAYLOAD_JSON_STR" \
  | jq -c '.' \
  | jq '.kid = (.kid // "")')

H64=$(printf '%s' "$HEADER_MIN"  | b64url)
P64=$(printf '%s' "$PAYLOAD_MIN" | b64url)
INPUT="${H64}.${P64}"

# 署名（DER）
sig_der="$(mktemp)"; trap 'rm -f "$sig_der"' EXIT
printf '%s' "$INPUT" | openssl dgst -sha256 -sign "$KEY_FILE" -out "$sig_der"

# DER -> r||s (64byte) -> base64url
S64=$(der_to_jose_b64url "$sig_der") || exit 1

printf '%s.%s\n' "$INPUT" "$S64"
