#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# jwt_es256.sh  --  ES256 (ECDSA P-256 + SHA-256) で JWT を署名するスクリプト
# ---------------------------------------------------------------------------
# 目的:
#   * OpenSSL と jq のみで JWT を作成（ヘッダ+ペイロードを Base64URL 化→署名）
#   * 署名は ECDSA P-256（いわゆる ES256）。OpenSSL が返す DER 署名を
#     JOSE 形式（r||s の 64 バイト）に変換して出力します。
#
# 使い方（2通り）:
#   A) ペイロードを自動生成（-p 省略）
#      - 必要な環境変数: FQDN（iss に使用）
#      - 任意の環境変数: EXP_HR（有効期限の時間。未設定は 1 時間）
#        例:
#          FQDN=api.example.com EXP_HR=2 ./jwt_es256.sh -k ec_private.pem
#
#      自動生成されるペイロード:
#        {
#          "iss": $FQDN,
#          "sub": "batch_user",
#          "iat": 現在UTCのUNIX秒,
#          "exp": iat + EXP_HR*3600,
#          "jti": UUID 相当の一意文字列,
#          "kid": ""  （空文字を必ず付与）
#        }
#
#   B) ペイロードを JSON 文字列で直接渡す（-p 使用）
#        ./jwt_es256.sh -k ec_private.pem -p '{"iss":"http://example.com", ...}'
#      ※ この場合も kid が未指定なら空文字を追加します。
#
#   ヘッダの拡張（任意）: -H で JSON 文字列を渡せます（例: kid を載せる）。
#     alg と typ は内部で "ES256" と "JWT" に上書きされます。
#       例: ./jwt_es256.sh -k ec_private.pem -H '{"kid":"header-key"}'
#
# 出力:
#   成功すると 1 行の JWT 文字列（header.payload.signature）を標準出力に出します。
#
# 前提:
#   * 依存コマンド: jq, openssl, awk, （xxd が無い場合は openssl enc -d -hex で代替）
#   * 鍵は P-256（prime256v1/secp256r1）の秘密鍵 PEM。
#
# 注意:
#   * kid は本来ヘッダに置くのが一般的ですが、本スクリプトはリクエストに合わせ
#     ペイロード側にも kid を空文字で必ず付与します（既に存在すれば上書きしません）。
# ---------------------------------------------------------------------------

set -Eeuo pipefail             # 途中失敗や未定義変数を検出して即終了
IFS=$'\n\t'                    # スペースによる意図しない分割を抑止
export LC_ALL=C LANG=C         # ロケール依存の出力揺れを防止
umask 077                      # 作成ファイルを最小権限（秘密鍵等の保護）

# --- オプション解析 ---------------------------------------------------------
HEADER_JSON_STR=""            # -H で渡すヘッダ JSON 文字列（任意）
PAYLOAD_JSON_STR=""           # -p で渡すペイロード JSON 文字列（任意）
KEY_FILE=""                   # -k で渡す P-256 秘密鍵（必須）

while getopts ":H:p:k:" opt; do
  case "$opt" in
    H) HEADER_JSON_STR="$OPTARG" ;;
    p) PAYLOAD_JSON_STR="$OPTARG" ;;
    k) KEY_FILE="$OPTARG" ;;
    *) echo "Usage: $0 -k ec_private.pem [-p '<payload json>'] [-H '<header json>']" >&2; exit 2 ;;
  esac
done

[[ -n "$KEY_FILE" ]] || { echo "missing -k <key.pem>" >&2; exit 2; }

# --- 依存コマンド確認 -------------------------------------------------------
for c in jq openssl awk; do
  command -v "$c" >/dev/null || { echo "missing: $c" >&2; exit 127; }
done
# xxd が無い環境でも動くようフォールバック関数を用意します
command -v xxd >/dev/null || echo "[info] xxd not found: will fall back to 'openssl enc -d -hex'" >&2

# --- 共通ヘルパー -----------------------------------------------------------
# Base64URL エンコード（パディングなし）: stdin -> stdout
b64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# 16進 -> バイナリ: 引数の HEX をバイナリ化して stdout へ（xxd 無ければ openssl 代替）
hex_to_bin() {
  local hex="$1"
  if command -v xxd >/dev/null; then
    printf '%s' "$hex" | xxd -r -p
  else
    printf '%s' "$hex" | openssl enc -d -hex
  fi
}

# JSON を最小化（改行や空白を削除し、キー順も固定して安定化）
minify() { jq -cS .; }

# 鍵が P-256 か簡易チェック（警告のみ）
ensure_p256_key() {
  if ! openssl pkey -in "$KEY_FILE" -pubout -text_pub -noout 2>/dev/null \
      | grep -qE 'NIST CURVE: P-256|secp256r1|prime256v1'; then
    echo "warning: key may not be P-256 (ES256 requires prime256v1/secp256r1)" >&2
  fi
}

# ヘッダ JSON を生成（-H があれば流用しつつ alg/typ を上書き）
build_header_json() {
  if [[ -n "$HEADER_JSON_STR" ]]; then
    printf '%s' "$HEADER_JSON_STR" \
    | jq -c '.' \
    | jq '.alg="ES256" | .typ=(.typ // "JWT")'
  else
    jq -nc '{alg:"ES256",typ:"JWT"}'
  fi
}

# jti を生成（/proc → uuidgen → 乱数 の順にフォールバック）
gen_jti() {
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
  elif command -v uuidgen >/dev/null; then
    uuidgen
  else
    # 簡易な一意ID（厳密な v4 ではないが jti としては十分）
    printf '%s-%s\n' "$(date -u +%s%N)" "$(openssl rand -hex 8)"
  fi
}

# -p 未指定のときに作る自動ペイロード（FQDN 必須 / EXP_HR は整数, 既定=1）
build_auto_payload_json() {
  : "${FQDN:?set FQDN}"                 # iss に使う FQDN が必須
  local iat exp hr jti
  iat="$(date -u +%s)"                  # 現在 UTC の UNIX 秒
  hr="${EXP_HR:-1}"                     # 有効期限（時間）。未設定は 1 時間
  case "$hr" in (*[!0-9]*|'') echo "EXP_HR must be non-negative integer" >&2; exit 2;; esac
  exp="$(( iat + hr * 3600 ))"
  jti="$(gen_jti)"

  # kid は必ず空文字を付与
  jq -nc --arg iss "$FQDN" --arg sub "batch_user" \
         --argjson iat "$iat" --argjson exp "$exp" \
         --arg jti "$jti" --arg kid "" \
         '{iss:$iss, sub:$sub, iat:$iat, exp:$exp, jti:$jti, kid:$kid}'
}

# OpenSSL の ECDSA DER 署名を JOSE 形式（r||s 64B）に変換し、Base64URL で返す
#  * DER は SEQUENCE(INTEGER r, INTEGER s)。
#  * INTEGER は先頭 0x00 が付く場合がある（符号ビット対策）→ 取り除く or 追加調整が必要。
der_to_jose_b64url() {
  local der="$1"
  # asn1parse の出力から r, s を 16進で抽出（コロン区切りを除去）
  mapfile -t ints < <(
    openssl asn1parse -inform DER -in "$der" 2>/dev/null \
      | awk '/prim: INTEGER/ { sub(/.*:/,""); gsub(/:/,""); print; }' \
      | head -n 2
  )
  local r_hex="${ints[0]:-}" s_hex="${ints[1]:-}"
  [[ -n "$r_hex" && -n "$s_hex" ]] || { echo "failed to parse ECDSA DER" >&2; return 1; }

  # 先頭の 00 を削り、全体を 32 バイト（64 桁）に左パディング
  while (( ${#r_hex} > 64 )); do r_hex="${r_hex:2}"; done
  while (( ${#s_hex} > 64 )); do s_hex="${s_hex:2}"; done
  while (( ${#r_hex} < 64 )); do r_hex="0${r_hex}"; done
  while (( ${#s_hex} < 64 )); do s_hex="0${s_hex}"; done

  # r||s をバイナリ化 → Base64URL
  hex_to_bin "${r_hex}${s_hex}" | b64url
}

# --- 署名処理メイン ---------------------------------------------------------
ensure_p256_key

# ヘッダ作成（alg/typ はここで固定）
HEADER_MIN=$(build_header_json | minify)

# ペイロード作成
if [[ -n "$PAYLOAD_JSON_STR" ]]; then
  # 入力 JSON を検証・最小化し、kid 未指定なら空文字を付与
  PAYLOAD_MIN=$(printf '%s' "$PAYLOAD_JSON_STR" \
    | jq -c '.' \
    | jq '.kid = (.kid // "")')
else
  # 自動ペイロード
  PAYLOAD_MIN=$(build_auto_payload_json | minify)
fi

# 署名対象の "header.payload" を Base64URL で構築
H64=$(printf '%s' "$HEADER_MIN"  | b64url)
P64=$(printf '%s' "$PAYLOAD_MIN" | b64url)
INPUT="${H64}.${P64}"

# ECDSA P-256 で署名（OpenSSL は DER を返す）
sig_der="$(mktemp)"; trap 'rm -f "$sig_der"' EXIT
printf '%s' "$INPUT" | openssl dgst -sha256 -sign "$KEY_FILE" -out "$sig_der"

# DER → JOSE r||s(64B) → Base64URL
S64=$(der_to_jose_b64url "$sig_der") || exit 1

# 最終出力: JWT
printf '%s.%s\n' "$INPUT" "$S64"
