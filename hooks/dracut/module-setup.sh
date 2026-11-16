#!/bin/bash
# Dracut module setup for KER boot authorization. Ships as
# /usr/lib/dracut/modules.d/90ker-boot/module-setup.sh
check() { return 0; }
depends() { echo systemd; return 0; }
installkernel() {
  instmods ext4 vfat nls_cp437 nls_iso8859-1 usb_storage uas virtio_blk virtio_pci isofs
}
install() {
  inst_multiple python3 gpgv openssl mount umount poweroff reboot || true
  inst /usr/lib/ker/ker-boot-check /usr/lib/ker/ker-boot-check
  [[ -d /usr/lib/ker/ker ]] && inst_dir /usr/lib/ker/ker && cp -a /usr/lib/ker/ker "${initdir}/usr/lib/ker/"
  pyver=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)
  if [[ -n "$pyver" && -d /usr/lib/python$pyver ]]; then
    mkdir -p "${initdir}/usr/lib/python$pyver"
    cp -a /usr/lib/python$pyver/. "${initdir}/usr/lib/python$pyver/" 2>/dev/null || true
  fi
  for d in /usr/lib/python3/dist-packages /usr/lib/python3/site-packages /usr/lib64/python3/site-packages; do
    if [[ -d "$d" ]]; then
      mkdir -p "${initdir}${d}"
      for pkg in cryptography cffi; do
        [[ -e "$d/$pkg" ]] && cp -a "$d/$pkg" "${initdir}${d}/"
      done
      find "$d" -maxdepth 1 -name '_cffi_backend*.so' | while read -r p; do cp -a "$p" "${initdir}${d}/"; done
    fi
  done
  if [[ -d /etc/ker ]]; then
    mkdir -p "${initdir}/etc/ker"
    [[ -f /etc/ker/state.json ]] && inst /etc/ker/state.json /etc/ker/state.json
    [[ -f /etc/ker/config.json ]] && inst /etc/ker/config.json /etc/ker/config.json
    [[ -d /etc/ker/trust ]] && mkdir -p "${initdir}/etc/ker/trust" && cp -a /etc/ker/trust/. "${initdir}/etc/ker/trust/"
    if [[ -f /etc/ker/state.json ]] && python3 -c 'import json,sys; st=json.load(open("/etc/ker/state.json")); sys.exit(0 if "boot" in (st.get("permissions") or []) else 1)'; then
      echo required > "${initdir}/etc/ker/boot-required"
    else
      echo optional > "${initdir}/etc/ker/boot-required"
    fi
  fi
  inst_hook pre-mount 90 "$moddir/ker-boot.sh"
}
