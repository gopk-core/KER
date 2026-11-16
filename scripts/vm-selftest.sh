#!/bin/bash
# Runs as PID 1 inside the KER qemu guest. Never run on the production host.
set -uo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PYTHONPATH="/usr/lib/ker${PYTHONPATH:+:$PYTHONPATH}"
export KER_IN_VM=1
export LANG=C

mount_fs() {
  mkdir -p /proc /sys /dev /dev/pts /run /tmp /sys/fs/bpf /sys/kernel/security
  mount -t proc proc /proc 2>/dev/null || true
  mount -t sysfs sys /sys 2>/dev/null || true
  mount -t devtmpfs dev /dev 2>/dev/null || true
  mkdir -p /dev/pts
  mount -t devpts devpts /dev/pts 2>/dev/null || true
  mount -t tmpfs tmpfs /run 2>/dev/null || true
  # If the hook already put files in /run from the previous tmpfs, they are gone
  # after switch_root unless copied onto the real root's /run. Prefer the copy
  # the initrd placed at /run/ker/boot-status.json on the real root: if /run was
  # just remounted as tmpfs we may have wiped it — recover from /root/run or a
  # pre-switch copy under /run/ker on the rootfs if that directory existed.
  mount -t tmpfs tmpfs /tmp 2>/dev/null || true
  mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
  mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
  for m in ext4 jbd2 mbcache crc32c vfat nls_cp437 nls_iso8859-1; do
    modprobe "$m" 2>/dev/null || true
  done
}

mount_fs
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true
ip link set lo up 2>/dev/null || true
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

PHASE=phase1
if grep -qw 'ker.selftest=phase2' /proc/cmdline 2>/dev/null; then
  PHASE=phase2
fi
# Recover hook status copied onto the real root before switch_root.
if [ -f /run/ker/boot-status.json ] || [ -f /root/ker-boot-status.json ]; then
  PHASE=phase2
fi

RESULT_MNT=/mnt/ker-result
mkdir -p "$RESULT_MNT" /var/log/ker
for i in $(seq 1 40); do
  [ -b /dev/vdd ] && break
  sleep 0.25
done
if [ -b /dev/vdd ]; then
  if ! mount -o rw /dev/vdd "$RESULT_MNT" 2>/dev/null; then
    mkfs.ext4 -F -L KERRESULT /dev/vdd >/dev/null 2>&1 || true
    mount -o rw /dev/vdd "$RESULT_MNT" || true
  fi
fi
if ! mountpoint -q "$RESULT_MNT"; then
  RESULT_MNT=/tmp/ker-result
  mkdir -p "$RESULT_MNT"
fi
export RESULT="$RESULT_MNT/result.json"
export LOG="$RESULT_MNT/selftest.log"
touch "$LOG"
if [ -w /dev/console ]; then
  exec > >(tee -a "$LOG" >/dev/console) 2>&1
else
  exec >>"$LOG" 2>&1
fi
echo "KER VM selftest starting $(date -Is) phase=$PHASE"
echo "kernel=$(uname -r) virt=$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)"
ls -l /dev/vd* /usr/sbin/ker /usr/lib/ker/ker-probe /usr/lib/ker/bpf/ker.bpf.o || true

_finish() {
  local rc="$1"
  sync
  sleep 1
  reboot -f 2>/dev/null || poweroff -f 2>/dev/null || echo b > /proc/sysrq-trigger
  sleep 5
  exit "$rc"
}

fail() {
  echo "FAIL: $*"
  python3 - "$RESULT" "$*" "$PHASE" << 'PY'
import json, sys, time
path, err, phase = sys.argv[1], sys.argv[2], sys.argv[3]
open(path, "w").write(json.dumps({
    "ok": False, "error": err, "phase": phase,
    "finished": time.strftime("%Y-%m-%dT%H:%M:%S%z")
}, indent=2) + "\n")
PY
  sync
  _finish 1
}

if [ "$PHASE" = "phase2" ]; then
  # Early-boot hook already ran. Confirm it verified boot.pem, then uninstall.
  STATUS=""
  for cand in /run/ker/boot-status.json /root/ker-boot-status.json "$RESULT_MNT/boot-hook.json"; do
    if [ -f "$cand" ]; then
      STATUS=$cand
      echo "found boot hook status: $cand"
      cat "$cand"
      break
    fi
  done
  [ -n "$STATUS" ] || fail "phase2 missing boot hook status"
  python3 - "$STATUS" << 'PY' || fail "boot hook did not verify in enforcement"
import json, sys
d = json.load(open(sys.argv[1]))
if not d.get("verified"):
    raise SystemExit("boot hook did not verify: " + json.dumps(d))
if d.get("block"):
    raise SystemExit("boot hook blocked unexpectedly: " + json.dumps(d))
if not d.get("allow"):
    raise SystemExit("boot hook did not allow: " + json.dumps(d))
print("early boot hook ok", d.get("reason"), d.get("mode"))
PY

  ker --language zh-CN --version || fail "ker --version failed in phase2"
  ker --language zh-CN uninstall --yes || fail "uninstall failed"
  python3 - "$RESULT" "$RESULT_MNT/phase1.json" "$STATUS" << 'PY'
import json, os, subprocess, sys, time
from pathlib import Path
result, phase1_path, status_path = sys.argv[1], sys.argv[2], sys.argv[3]
ver = subprocess.check_output(["ker", "--version"], text=True).strip()
phase1 = {}
if Path(phase1_path).is_file():
    phase1 = json.loads(Path(phase1_path).read_text())
hook = json.loads(Path(status_path).read_text())
out = dict(phase1)
out.update({
    "ok": True,
    "version": ver,
    "uninstalled": not Path("/etc/ker/state.json").exists(),
    "early_boot_hook": hook,
    "phase2": True,
    "finished": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
})
if not hook.get("verified") or hook.get("block"):
    out["ok"] = False
    out["error"] = "early boot hook result not acceptable"
if not out.get("uninstalled"):
    out["ok"] = False
    out["error"] = "uninstall left state.json in place"
Path(result).write_text(json.dumps(out, indent=2) + "\n")
print(out)
PY
  echo OK
  _finish 0
fi

# ---------------- phase 1 ----------------
for dev in /dev/vdb /dev/vdc /dev/vdd /dev/vde; do
  for i in $(seq 1 40); do
    [ -b "$dev" ] && break
    sleep 0.25
  done
  [ -b "$dev" ] || fail "missing block device $dev"
done

command -v ker >/dev/null || fail "ker not installed"
ker --language zh-CN --version || fail "ker --language zh-CN --version failed"

MEDIA_JSON='[{"path":"/dev/vdb","kind":"disk","keys":["root.pem","boot.pem","write.pem","read.pem","run.pem"],"role":"root"},{"path":"/dev/vdc","kind":"disk","keys":["admin.pem"],"role":"admin"},{"path":"/dev/vde","kind":"disk","keys":["ssh.pem"],"role":"keys"}]'
ker --language zh-CN init --yes --assume-replug --permissions write,read,run,boot,ssh --media-json "$MEDIA_JSON" \
  || fail "init failed"
ker --language zh-CN test-media --assume-replug || fail "test-media failed"
ker --language zh-CN status || fail "status failed"
ker --language zh-CN console --admin-dev /dev/vdc status || fail "console status failed"

# --- boot hook (in-guest policy + shipped checker) ---
python3 - << 'PY' || fail "boot hook in-guest tests failed"
import json, subprocess, sys
from pathlib import Path
from ker.hooks import authorize
from ker.state import state, save_state

d = authorize("boot", scan=True)
print("boot test-mode", json.dumps(d))
assert d["allow"] and not d["block"] and d["verified"] and d["mode"] == "test"

# checker CLI
r = subprocess.run(["/usr/lib/ker/ker-boot-check"], capture_output=True, text=True)
print("ker-boot-check rc", r.returncode, r.stdout)
assert r.returncode == 0, r.stderr
cli = json.loads(r.stdout)
assert cli["verified"] and cli["allow"]

# enforce without loading extra state into maps here (maps tested later)
st = state()
st["mode"] = "enforce"
st["kernel_enforcement"] = True
save_state(st)
d = authorize("boot", scan=True)
print("boot enforce-present", json.dumps(d))
assert d["allow"] and d["verified"] and not d["block"]

# deny: hide all media paths
st = state()
backup = list(st["media"])
st["media"] = []
save_state(st)
d = authorize("boot", scan=False)
print("boot enforce-missing", json.dumps(d))
assert d["block"] and not d["allow"] and not d["verified"]
r = subprocess.run(["/usr/lib/ker/ker-boot-check", "--no-scan"], capture_output=True, text=True)
assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)

st = state()
st["media"] = backup
st["mode"] = "test"
st["kernel_enforcement"] = False
save_state(st)
print("boot hook in-guest ok")
PY

# --- SSH hook: install, key login allow/deny, PAM account path ---
if [ -x /usr/lib/ker/install-hooks ]; then
  /usr/lib/ker/install-hooks || fail "install-hooks failed"
fi
if ! command -v sshd >/dev/null; then
  fail "openssh-server is not in the guest; vm-test.sh should install it into the rootfs"
fi
mkdir -p /root/.ssh /run
chmod 700 /root/.ssh
if [ ! -f /root/.ssh/id_ed25519 ]; then
  ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519 >/dev/null
fi
cat /root/.ssh/id_ed25519.pub > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
ssh-keygen -A >/dev/null 2>&1 || true
# Keep UsePAM yes so both key and password paths hit the account hook.
if [ -f /etc/ssh/sshd_config ]; then
  sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
  sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sed -i 's/^#\\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
  grep -q '^ListenAddress 127.0.0.1' /etc/ssh/sshd_config || echo 'ListenAddress 127.0.0.1' >> /etc/ssh/sshd_config
fi
echo 'root:ker-ssh-pass' | chpasswd
mkdir -p /run/sshd
/usr/sbin/sshd -o PidFile=/run/sshd.pid || fail "sshd failed to start"
sleep 0.5

ssh_cmd() {
  ssh -i /root/.ssh/id_ed25519 \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o GlobalKnownHostsFile=/dev/null \
    -o PreferredAuthentications=publickey \
    -o PasswordAuthentication=no \
    -o ConnectTimeout=5 \
    root@127.0.0.1 "$@"
}

ssh_cmd true || fail "SSH key login failed in test mode with media present"

# PAM account path (password + account): hook inactive/test should allow
/usr/lib/ker/ker-pam-probe --service sshd --user root --password 'ker-ssh-pass' \
  || fail "PAM sshd path failed in test mode"

# Turn on enforcement (state only first for hook tests; BPF comes later)
python3 - << 'PY' || fail "SSH enforce allow/deny failed"
import json, os, shutil, subprocess, sys, time
from pathlib import Path
from ker.hooks import authorize
from ker.state import state, save_state

st = state()
st["mode"] = "enforce"
st["kernel_enforcement"] = True
save_state(st)
d = authorize("ssh", scan=True)
print("ssh enforce-present", json.dumps(d))
assert d["allow"] and d["verified"] and not d["block"], d
r = subprocess.run(
    ["ssh", "-i", "/root/.ssh/id_ed25519",
     "-o", "StrictHostKeyChecking=no",
     "-o", "UserKnownHostsFile=/dev/null",
     "-o", "GlobalKnownHostsFile=/dev/null",
     "-o", "PreferredAuthentications=publickey",
     "-o", "PasswordAuthentication=no",
     "-o", "ConnectTimeout=5",
     "root@127.0.0.1", "true"]
)
print("ssh key login with media rc", r.returncode)
if r.returncode != 0:
    sys.exit("expected SSH allow with media")

# PAM account should also allow
r = subprocess.run(["/usr/lib/ker/ker-pam-probe", "--service", "sshd", "--user", "root",
                    "--password", "ker-ssh-pass"])
if r.returncode != 0:
    sys.exit(f"PAM allow failed rc={r.returncode}")

# Wipe ssh media, deny path, then restore
subprocess.check_call(["dd", "if=/dev/vde", "of=/tmp/ssh-media.bak", "bs=1M", "status=none"])
subprocess.run(["wipefs", "-a", "/dev/vde"], check=False, capture_output=True)
subprocess.run(["dd", "if=/dev/zero", "of=/dev/vde", "bs=1M", "count=8", "status=none"], check=False)
d = authorize("ssh", scan=True)
print("ssh enforce-missing", json.dumps(d))
assert d["block"] and not d["allow"], d
r = subprocess.run(
    ["ssh", "-i", "/root/.ssh/id_ed25519",
     "-o", "StrictHostKeyChecking=no",
     "-o", "UserKnownHostsFile=/dev/null",
     "-o", "GlobalKnownHostsFile=/dev/null",
     "-o", "PreferredAuthentications=publickey",
     "-o", "PasswordAuthentication=no",
     "-o", "ConnectTimeout=5",
     "root@127.0.0.1", "true"]
)
print("ssh key login without media rc", r.returncode)
if r.returncode == 0:
    sys.exit("expected SSH deny without media")
r = subprocess.run(["/usr/lib/ker/ker-pam-probe", "--service", "sshd", "--user", "root",
                    "--password", "ker-ssh-pass"])
print("PAM deny rc", r.returncode)
if r.returncode == 0:
    sys.exit("expected PAM deny without ssh media")

subprocess.check_call(["dd", "if=/tmp/ssh-media.bak", "of=/dev/vde", "bs=1M", "status=none"])
d = authorize("ssh", scan=True)
print("ssh restored", json.dumps(d))
assert d["allow"] and d["verified"], d

# back to test mode for the remaining 0.3 flow (cluster / later enforce toggle)
st = state()
st["mode"] = "test"
st["kernel_enforcement"] = False
save_state(st)
print("ssh hook ok")
PY

# stop sshd so it does not interfere later
if [ -f /run/sshd.pid ]; then
  kill "$(cat /run/sshd.pid)" 2>/dev/null || true
fi

ker --language zh-CN token --host 127.0.0.1 --port 4170 --name child-vm > /tmp/token || fail "token failed"
ker --language zh-CN serve --host 127.0.0.1 --port 4170 &
SERVE_PID=$!
sleep 0.5
kill -0 "$SERVE_PID" 2>/dev/null || fail "master serve died"

export KER_PREFIX=/tmp/ker-child
mkdir -p "$KER_PREFIX"
if ! ker --language zh-CN addnet --master 127.0.0.1:4170 --token "$(cat /tmp/token)" --yes --name child-vm; then
  unset KER_PREFIX
  kill "$SERVE_PID" 2>/dev/null || true
  fail "addnet join failed"
fi
python3 - << 'PY' || { unset KER_PREFIX; fail "child poll failed"; }
from ker.cluster import child_poll
from ker.state import state
r = child_poll()
st = state()
assert st.get("role") == "child", st
print("child poll ok", r)
PY
unset KER_PREFIX

ker --language zh-CN enforce --set enforce --yes || fail "enforce enable failed"
if ! /usr/lib/ker/ker-probe; then
  fail "ker-probe denied while media present"
fi
python3 - << 'PY' || fail "media_ok flip / probe failed"
import subprocess, sys
from ker.enforce import update_maps
from ker.state import state
st = state()
perms = st.get("permissions") or []
update_maps(enforcement=True, media_ok=False, permissions=perms)
r = subprocess.run(["/usr/lib/ker/ker-probe"])
print("probe rc with media_ok=0:", r.returncode)
if r.returncode == 0:
    sys.exit("probe unexpectedly allowed")
update_maps(enforcement=True, media_ok=True, permissions=perms)
r = subprocess.run(["/usr/lib/ker/ker-probe"])
if r.returncode != 0:
    sys.exit("probe denied after restore")
print("enforcement probe ok")
PY
ker --language zh-CN enforce --set test --yes || fail "enforce disable failed"

ker --language zh-CN console --admin-dev /dev/vdc rotate --assume-replug || fail "rotate failed"
ker --language zh-CN test-media --assume-replug || fail "test-media after rotate failed"

# Leave the guest in enforcement so the next qemu boot's initramfs hook is fail-closed.
ker --language zh-CN enforce --set enforce --yes || fail "re-enable enforce before hook boot failed"

python3 - "$RESULT_MNT/phase1.json" << 'PY'
import json, os, subprocess, sys, time
from pathlib import Path
ver = subprocess.check_output(["ker", "--version"], text=True).strip()
out = {
    "ok": True,
    "phase1": True,
    "version": ver,
    "hooks": {"boot_in_guest": True, "ssh": True},
    "need_early_boot": True,
    "finished_phase1": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
}
Path(sys.argv[1]).write_text(json.dumps(out, indent=2) + "\n")
# also a placeholder result until phase2 finishes
Path(os.environ["RESULT"]).write_text(json.dumps({**out, "ok": False, "error": "waiting for early-boot hook phase"}, indent=2) + "\n")
print(out)
PY
kill "$SERVE_PID" 2>/dev/null || true
echo PHASE1_OK
_finish 0
