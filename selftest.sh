#!/bin/zsh
# Self-test for miner_check.py: fake the Oct 2026 XMRig pattern, harmlessly.
# - copies /usr/bin/yes to a temp folder as "xmrig" and runs 2 copies (~2 cores)
#   with miner-like arguments; output goes to /dev/null
# - writes a fake KeepAlive plist with a base64 payload into the same temp
#   folder; it is only read by the scanner, never loaded into launchd
# The trap stops the fake processes and removes only the folder made here.
set -u
here=${0:A:h}
work=$(mktemp -d "${TMPDIR:-/private/tmp}/minercheck-selftest.XXXXXX")
pids=()
cleanup() { (( ${#pids} )) && kill $pids 2>/dev/null; rm -rf -- "$work"; }
trap cleanup EXIT INT TERM

cp /usr/bin/yes "$work/xmrig"
# A copied Apple platform binary is SIGKILLed outside /usr/bin; ad-hoc sign it.
codesign -f -s - "$work/xmrig" 2>/dev/null
for i in 1 2; do
  "$work/xmrig" -o pool.hashvault.sh:443 --donate-level 1 >/dev/null &
  pids+=($!)
done

mkdir "$work/plists"
payload=$(print -n "$work/xmrig -o pool.hashvault.sh:443" | base64)
payload="$payload$(printf 'A%.0s' {1..120})"
cat > "$work/plists/com.fake.update.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.fake.update</string>
  <key>ProgramArguments</key><array>
    <string>/bin/bash</string><string>-c</string>
    <string>echo $payload | base64 -d | bash</string>
  </array>
  <key>KeepAlive</key><true/>
</dict></plist>
EOF

sleep 4   # let ps %cpu catch up
python3 -I "$here/miner_check.py" --plist-dir "$work/plists" --days 0 > "$work/out.txt"
rc=$?
grep -A1 -E '^\[(HIGH|MED )\]' "$work/out.txt"
echo "scanner exit=$rc (expect 2)"
ok=1
for want in "process  pid" "launchd  .*com.fake.update" "files    .*xmrig"; do
  if grep -qE "^\[HIGH\] $want" "$work/out.txt"; then echo "  caught: $want"
  else echo "  MISSED: $want"; ok=0; fi
done
[[ $rc == 2 && $ok == 1 ]] && echo "SELFTEST PASS" || { echo "SELFTEST FAIL"; exit 1; }
