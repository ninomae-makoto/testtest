#!/usr/bin/env bash

###############################################################################
# バッチ雛形（コメント付き）
#
# 目的:
#   - bash で安全・堅牢にバッチ処理を実装するためのベース。
#   - 依存コマンドの検証 / ロケール・PATH の固定 / 排他制御 / クリーンアップ /
#     設定(.env)読込 / 署名 + API 呼び出し / リトライ などを網羅。
#
# 前提:
#   - Linux / WSL2 / (互換環境) を想定。
#   - openssl の pkeyutl が RSA-PSS をサポートしていること。
#
# 使い方:
#   1) .env に必須の設定値(API_BASE, PRIVATE_KEY_PATH 等)を記述。
#   2) スクリプトを実行するだけで、排他制御しつつ処理が走ります。
#   3) cron / タスクスケジューラからも呼び出せます。
###############################################################################

# set の安全セット。途中失敗の握りつぶしや未定義変数の参照を防ぎます。
set -Eeuo pipefail

# IFS を改行とタブに限定し、スペースを分割トリガにしない(ファイル名に空白があっても安全)。
IFS=$'\n\t'

# ロケール・PATH を固定。cron 等の貧弱環境でも意図した挙動/コマンドのみを使う。
export LC_ALL=C LANG=C PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin"

# 新規作成ファイルのデフォルト権限を最小化(ファイル 600 / ディレクトリ 700 相当)。
umask 077

#=== 基本定義 ==================================================================
# スクリプト自身のディレクトリ。相対パスを避け、資材同居(.envなど)を読みやすくする。
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# 排他用ロックファイル。環境変数で上書き可能。
# 非特権ユーザで /var/lock が使えない場合は XDG_RUNTIME_DIR などに変更してください。
readonly LOCK_FILE="${LOCK_FILE:-/var/lock/mybatch.lock}"

# 設定ファイルのパス(デフォルトはスクリプト隣の .env)。
readonly ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"

# 必要コマンドの存在チェック関数。見つからなければ 127 で明示失敗。
need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 127; }; }

# 本スクリプトが期待する依存コマンド群。
for c in jq curl openssl base64 flock mktemp date; do need "$c"; done

# ロックファイルのディレクトリを作成(存在しない場合)。
mkdir -p -- "$(dirname -- "$LOCK_FILE")"

# FD 9 でロックファイルを開き、flock で多重起動を阻止。
# -n: 待たずに即時失敗。既に動作中なら 1 で終了(上位でリトライさせやすい)。
exec 9> "$LOCK_FILE"
flock -n 9 || { echo "Already running" >&2; exit 1; }

#=== ログ / 例外トラップ / 一時領域掃除 ========================================
# UTC の ISO 8601 ライクなタイムスタンプ付きでログを吐く簡易関数。
log() { printf '[%(%Y-%m-%dT%H:%M:%SZ)T] %s\n' -1 "$*"; }

# set -E と合わせて、関数内/サブシェルでもエラー時に実行される。
errtrap() { echo "ERROR ${BASH_SOURCE[0]}:${LINENO}: $BASH_COMMAND" >&2; }
trap 'errtrap' ERR

# 一時ディレクトリの削除。EXIT/INT/TERM で確実に掃除する。
tmpdir=""
cleanup() { [[ -n "$tmpdir" ]] && rm -rf -- "$tmpdir"; }
trap 'cleanup' EXIT INT TERM

#=== 設定(.env)の読み込み =======================================================
# .env に記述した変数を export しながら読み込む。例:
#   API_BASE=https://api.example.com
#   PRIVATE_KEY_PATH=/secure/key.pem
if [[ -f "$ENV_FILE" ]]; then set -a; . "$ENV_FILE"; set +a; fi

# 必須設定の存在をチェック(未設定なら即時エラー)。
: "${API_BASE:?set API_BASE}"
: "${PRIVATE_KEY_PATH:?set PRIVATE_KEY_PATH}"

#=== ユーティリティ群 ===========================================================
# 汎用リトライ。指数バックオフ風 + ランダムジッターでスパイク回避。
# 使い方: retry 3 curl ...
retry() { # usage: retry <max> cmd...
  local -i max=$1 n=1; shift
  until "$@"; do (( n >= max )) && return 1
    sleep $(((RANDOM % 200 + 100) * n / 1000))  # 0.1〜0.3s × n のジッター
    ((n++))
  done
}

# RSA-PSS + SHA-256 で署名し、base64(改行なし)で返す。
# stdin: 署名対象バイト列 / stdout: base64 署名
# ※ 署名対象の JSON は別途 jq -cS で正規化してから渡してください。
sign_pss_b64() {
  openssl pkeyutl -sign -inkey "$PRIVATE_KEY_PATH" \
    -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 \
  | base64 -w0
}

# JSON を正規化し、署名ヘッダを付けて POST。失敗は非ゼロで返す。
# usage: post_json /path json-string
post_json() {
  local path="$1" json="$2" norm sig
  norm="$(jq -cS . <<<"$json")"     # 空白やキー順による差分を排除
  sig="$(sign_pss_b64 <<<"$norm")"   # 正規化 JSON に対して署名
  curl --fail-with-body --show-error --silent \
       --retry 5 --retry-all-errors --connect-timeout 5 --max-time 30 \
       -H "Content-Type: application/json" \
       -H "X-Signature: $sig" \
       -H "X-Signature-Alg: RSASSA-PSS-SHA256" \
       --data-binary "$norm" \
       "${API_BASE}${path}"
}

# 例: 処理対象の一覧を取得する API 呼び出し。
fetch_items() {
  curl --fail-with-body --show-error --silent \
       --retry 5 --retry-all-errors --connect-timeout 5 --max-time 20 \
       -H "Accept: application/json" \
       "${API_BASE}/items"
}

#=== 本処理 =====================================================================
main() {
  # 一時作業ディレクトリを作成し、終了時に掃除する。
  tmpdir="$(mktemp -d)"

  # 対象データの取得。失敗時はログを出して終了コード 1。
  local items
  items="$(fetch_items)" || { log "fetch failed"; return 1; }

  # JSON 配列を 1要素=1行の JSON に分解し、安全にループ処理。
  jq -c '.[]' <<<"$items" | while IFS= read -r item; do
    local id status payload resp
    id="$(jq -r '.id' <<<"$item")"
    status="$(jq -r '.status' <<<"$item")"

    # 条件分岐: READY or RETRY のみ処理。それ以外はスキップ。
    [[ "$status" =~ ^(READY|RETRY)$ ]] || { log "skip id=$id status=$status"; continue; }

    # 送信ペイロード作成。署名対象は post_json 内で正規化されます。
    payload="$(jq -n --arg id "$id" --argjson ts "$(date -u +%s)" '{id:$id,ts:$ts}')"

    # POST をリトライ付きで実行。3回失敗したら記録して次へ進む(全体は継続)。
    if ! resp="$(retry 3 post_json "/ingest" "$payload")"; then
      log "post failed id=$id"
      continue
    fi

    # レスポンス検査例: {"result":"ok"} を成功と見なす。
    if [[ "$(jq -r '.result // empty' <<<"$resp")" == "ok" ]]; then
      log "ok id=$id"
    else
      log "ng id=$id resp=$(jq -c . <<<"$resp")"
    fi
  done
}

# エントリポイント。
main "$@"
