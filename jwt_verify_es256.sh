#!/usr/bin/env bash
# Verify a JWT signed with ES256 (ECDSA P-256 + SHA-256) using OpenSSL.
# - Accepts a PEM key (public OR private). If private is given, public is抽出して使用。
# - Converts JOSE signature (r||s raw 64 bytes) to DER before verification.
# Usage:
#   jwt_verify_es256.sh -k ec_pub_or_priv.pem -j "<JWT string>"
#   echo "$JWT" | jwt_verify_es256.sh -k ec_pub_or_priv.pem   # -j省略でstdinからJWT

set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C LANG=C
umask 077

JWT=""
KEY_FILE=""
QUIET=0

while getopts ":k:j:q" opt; do
  case "$opt" in
    k) KEY_FILE="$OPTARG" ;;
    j) JWT="$OPTARG" ;;
    q) QUIET=1 ;;
    *) echo "Usage: $0 -k key.pem [-j <jwt>] [-q]" >&2; exit 2 ;;
  esac
done

[[ -n "$KEY_FILE" ]] || { echo "missing -k <key.pem>" >&2; exit 2; }
if [[ -z "$JWT" ]]; then
  # JWTを標準入力から取得
  read -r JWT || true
fi
[[ -n "$JWT" ]] || { echo "missing JWT (use -j or pipe)" >&2; exit 2; }

for c in openssl jq xxd awk; do
  command -v "$c" >/dev/null || { echo "missing: $c" >&2; exit 127; }
done

# --- helpers ---------------------------------------------------------------

b64url_to_bin() { # $1: base64url string -> stdout: raw bytes
  local s="$1" pad
  s="${s//-/+}"; s="${s//_//}"
  pad=$(( (4 - ${#s} % 4) % 4 ))
  printf '%s' "$s" | awk -v p="$pad" '{ printf "%s", $0; for(i=0;i<p;i++) printf "=" }' \
    | openssl base64 -d -A
}

b64url_to_text() { b64url_to_bin "$1"; } # JSON想定

# JOSE r||s(64bytes) -> DER(ECDSA-Sig-Value)
jose_to_der() { # $1: raw sig file (64 bytes), $2: out der file
  local raw="$1" der="$2"
  local hex r s
  hex="$(xxd -p -c 256 "$raw" | tr -d '\n')"
  if (( ${#hex} != 128 )); then
    echo "invalid JOSE signature length (expect 64 bytes)" >&2
    return 1
  fi
  r="${hex:0:64}"
  s="${hex:64:64}"

  normalize_int() { # hex -> hex (no leading zeros, add 00 if MSB set)
    local h="$1"
    while [[ ${#h} -gt 2 && ${h:0:2} == "00" ]]; do h="${h:2}"; done
    local msb=$((16#${h:0:2}))
    if (( msb >= 0x80 )); then h="00${h}"; fi
    printf '%s' "$h"
  }

  r="$(normalize_int "$r")"
  s="$(normalize_int "$s")"

  local lr=$(( ${#r} / 2 ))
  local ls=$(( ${#s} / 2 ))
  local seq_len=$(( 2 + lr + 2 + ls ))   # 0x02 len r | 0x02 len s, len<128前提
  printf '30%02x02%02x%s02%02x%s' "$seq_len" "$lr" "$r" "$ls" "$s" \
    | xxd -r -p > "$der"
}

# どちらの鍵でもOK（public抽出に失敗したら元をそのまま使う）
PUB_TMP="$(mktemp)"; trap 'rm -f "$PUB_TMP" "$SIG_RAW" "$SIG_DER"' EXIT
if ! openssl pkey -in "$KEY_FILE" -pubout -out "$PUB_TMP" >/dev/null 2>&1; then
  cp -f -- "$KEY_FILE" "$PUB_TMP"
fi

# --- split JWT -------------------------------------------------------------
IFS='.' read -r H64 P64 S64 <<<"$JWT" || true
if [[ -z "$H64" || -z "$P64" || -z "$S64" ]]; then
  echo "invalid JWT format" >&2; exit 2
fi
INPUT="${H64}.${P64}"

# --- decode header/payload for checks --------------------------------------
HDR_JSON="$(b64url_to_text "$H64" | jq -c . 2>/dev/null || true)"
PL_JSON="$(b64url_to_text "$P64" | jq -c . 2>/dev/null || true)"
if [[ -z "$HDR_JSON" || -z "$PL_JSON" ]]; then
  echo "failed to decode header/payload JSON" >&2; exit 1
fi

ALG="$(jq -r '.alg // empty' <<<"$HDR_JSON")"
if [[ "$ALG" != "ES256" ]]; then
  echo "alg is not ES256 (got: ${ALG:-<none>})" >&2; exit 1
fi

# --- rebuild DER signature --------------------------------------------------
SIG_RAW="$(mktemp)"; SIG_DER="$(mktemp)"
b64url_to_bin "$S64" > "$SIG_RAW"
jose_to_der "$SIG_RAW" "$SIG_DER"

# --- verify -----------------------------------------------------------------
if printf '%s' "$INPUT" | openssl dgst -sha256 -verify "$PUB_TMP" -signature "$SIG_DER" >/dev/null 2>&1; then
  (( QUIET == 0 )) && {
    echo "OK: signature valid"
    echo "header:  $(jq -c . <<<"$HDR_JSON")"
    echo "payload: $(jq -c . <<<"$PL_JSON")"
  }
  exit 0
else
  (( QUIET == 0 )) && echo "NG: signature invalid" >&2
  exit 1
fi
