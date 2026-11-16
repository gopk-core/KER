#!/bin/sh
# Dracut pre-mount hook. Same fail-closed policy as the initramfs-tools script.
[ -f /etc/ker/state.json ] || exit 0
export PATH="/bin:/sbin:/usr/bin:/usr/sbin"
export PYTHONPATH="/usr/lib/ker${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p /run/ker
rc=0
json=$(python3 /usr/lib/ker/ker-boot-check 2>/run/ker/boot-check.err) || rc=$?
[ -n "$json" ] || json='{"allow":false,"block":true,"reason":"CHECKER_FAILED","mode":"unknown"}'
printf '%s\n' "$json" > /run/ker/boot-status.json
printf '%s\n' "KER boot hook: $json" > /dev/console 2>/dev/null || true
block=$(printf '%s\n' "$json" | python3 -c 'import json,sys; print("yes" if json.load(sys.stdin).get("block") else "no")' 2>/dev/null || echo yes)
if [ "$block" = "yes" ]; then
  printf 'KER: boot authorization failed; refusing to continue to the real root\n' > /dev/console
  poweroff -f 2>/dev/null || reboot -f 2>/dev/null || while :; do sleep 60; done
fi
exit 0
