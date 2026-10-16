#!/usr/bin/env bash
# Usage: integration_real_comfyui.sh <ComfyUI dir> <python>
set -u
DIR=$(cd "$1" && pwd); PY=$2; HERE=$(cd "$(dirname "$0")/.." && pwd); U=http://127.0.0.1:8199
K=$(mktemp -d); $PY "$HERE/tools/issue_token.py" keygen --out "$K" 2>/dev/null
T=$($PY -c 'import secrets;print(secrets.token_urlsafe(32))')
c(){ curl -s -o /dev/null -w "%{http_code}" "$@"; }
WS="-H Connection:Upgrade -H Upgrade:websocket -H Sec-WebSocket-Version:13 -H Sec-WebSocket-Key:dGhlIHNhbXBsZSBub25jZQ== --max-time 3"
start(){ (cd "$DIR" && env "$@" $PY main.py --cpu --listen 127.0.0.1 --port 8199 >>/tmp/comfy_it.log 2>&1 & echo $! >/tmp/comfy_it.pid)
  for i in $(seq 90); do curl -s -o /dev/null $U/ && break; sleep 1; done; }
stop(){ pkill -f "main.py --cpu --listen 127.0.0.1 --port 8199"; for i in $(seq 20); do curl -s -o /dev/null $U/ || break; sleep 1; done; }
: >/tmp/comfy_it.log

echo "== mode=token =="
start COMFY_AUTH_TOKEN=$T
echo "no token  /system_stats: $(c $U/system_stats)"
echo "wrong     /system_stats: $(c -H 'Authorization: Bearer wrong' $U/system_stats)"
echo "correct   /system_stats: $(c -H "Authorization: Bearer $T" $U/system_stats)"
echo "no token  POST /prompt /view POST /upload/image /: $(c -X POST -d '{}' $U/prompt) $(c "$U/view?filename=x.png") $(c -X POST $U/upload/image) $(c $U/)"
echo "ws ?token=correct (default off): $(c $WS "$U/ws?token=$T")"
echo "ws bearer correct: $(c $WS -H "Authorization: Bearer $T" $U/ws)"
TK=$(curl -s -X POST -H "Authorization: Bearer $T" $U/auth/ws-ticket | $PY -c 'import json,sys;print(json.load(sys.stdin)["ticket"])')
echo "ticket on HTTP /system_stats: $(c "$U/system_stats?ticket=$TK")"
echo "ws ticket 1st: $(c $WS "$U/ws?ticket=$TK")  2nd: $(c $WS "$U/ws?ticket=$TK")"
stop

echo "== mode=jwt (Ed25519) =="
start COMFY_AUTH_PUBKEY_PATH=$K/public.pem COMFY_AUTH_JWT_AUD=comfyui
J(){ $PY "$HERE/tools/issue_token.py" issue --key $K/private.pem --aud comfyui --sub alice --scope generate "$@"; }
J1=$(J)
echo "no token: $(c $U/system_stats)"
echo "valid jwt: $(c -H "Authorization: Bearer $J1" $U/system_stats)  replay: $(c -H "Authorization: Bearer $J1" $U/system_stats)"
echo "ttl 600 (too long): $(c -H "Authorization: Bearer $(J --ttl 600)" $U/system_stats)"
echo "wrong aud: $($PY "$HERE/tools/issue_token.py" issue --key $K/private.pem --aud other --sub a | xargs -I{} curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer {}' $U/system_stats)"
echo "static token sent to jwt mode: $(c -H "Authorization: Bearer $T" $U/system_stats)"
TK=$(curl -s -X POST -H "Authorization: Bearer $(J)" $U/auth/ws-ticket | $PY -c 'import json,sys;print(json.load(sys.stdin)["ticket"])')
echo "ws no auth: $(c $WS $U/ws)  ws ticket 1st: $(c $WS "$U/ws?ticket=$TK")  2nd: $(c $WS "$U/ws?ticket=$TK")"
stop

echo "== GUI login mode =="
GPW=$($PY -c 'import secrets;print(secrets.token_urlsafe(16))')
GH=$(cd "$HERE" && $PY -c "import sys,gui;print(gui.make_hash(sys.argv[1]))" "$GPW")
start COMFY_AUTH_PUBKEY_PATH=$K/public.pem COMFY_AUTH_JWT_AUD=comfyui COMFY_AUTH_GUI=login "COMFY_AUTH_GUI_PASSWORD_HASH=$GH"
JAR=$(mktemp); O="Origin: $U"
echo "browser GET / unauth: $(curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}' -H 'Accept: text/html' $U/)"
echo "GET /auth/login: $(c $U/auth/login)"
echo "login wrong pw: $(c -H "$O" --data-urlencode password=wrong $U/auth/login)"
echo "login bad Origin: $(c -H 'Origin: https://evil.example' --data-urlencode password=$GPW $U/auth/login)"
echo "login ok: $(curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}' -c $JAR -H "$O" --data-urlencode "password=$GPW" --data-urlencode next=/ $U/auth/login)"
echo "cookie flags: $(grep comfy_auth_session $JAR | awk '{print "httponly-line="($1 ~ /HttpOnly/)", secure="$4}')"
echo "GET / (frontend) with cookie: $(c -b $JAR $U/)"
echo "GET /system_stats with cookie: $(c -b $JAR $U/system_stats)"
echo "POST /prompt cookie, no Origin: $(c -b $JAR -X POST -d '{}' $U/prompt)  with Origin: $(c -b $JAR -H "$O" -X POST -H 'Content-Type: application/json' -d '{"prompt":{}}' $U/prompt)"
echo "ws with cookie+Origin: $(c $WS -b $JAR -H "$O" $U/ws)  ws cookie bad Origin: $(c $WS -b $JAR -H 'Origin: https://evil.example' $U/ws)"
echo "logout: $(c -b $JAR -H "$O" -X POST $U/auth/logout)"
echo "after logout: / -> $(c -b $JAR -H 'Accept: text/html' $U/)  /system_stats -> $(c -b $JAR $U/system_stats)"
stop

echo "== GUI deny mode =="
start COMFY_AUTH_PUBKEY_PATH=$K/public.pem COMFY_AUTH_JWT_AUD=comfyui COMFY_AUTH_GUI=deny
echo "/ with valid JWT: $(c -H "Authorization: Bearer $(J)" $U/)  /system_stats with JWT: $(c -H "Authorization: Bearer $(J)" $U/system_stats)  /auth/login: $(c $U/auth/login)"
stop

echo "== GUI login without hash (fail closed) =="
start COMFY_AUTH_PUBKEY_PATH=$K/public.pem COMFY_AUTH_JWT_AUD=comfyui COMFY_AUTH_GUI=login
echo "/auth/login: $(c $U/auth/login)  /system_stats JWT: $(c -H "Authorization: Bearer $(J)" $U/system_stats)"
stop

echo "== invalid integer env (must fail closed, not skip the node) =="
start COMFY_AUTH_TOKEN=$T COMFY_AUTH_MAX_TTL=abc
echo "/system_stats correct token: $(c -H "Authorization: Bearer $T" $U/system_stats)"
stop

echo "== no config (fail closed) =="
start
echo "/system_stats: $(c -H "Authorization: Bearer $T" $U/system_stats)"
stop

echo "secrets leaked in log? token:$(grep -c -- "$T" /tmp/comfy_it.log) jwt:$(grep -c -- "$J1" /tmp/comfy_it.log) ticket:$( [ -n "$TK" ] && grep -c -- "$TK" /tmp/comfy_it.log) gui-pw:$(grep -c -- "$GPW" /tmp/comfy_it.log) cookie:$(grep -c -- "$(awk '/comfy_auth_session/{print $7}' $JAR)" /tmp/comfy_it.log)"
grep -E "auth-guard\] (enabled|config error)" /tmp/comfy_it.log
rm -rf "$K" "$JAR"
