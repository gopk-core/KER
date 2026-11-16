#!/bin/sh
set -e
# Dedicated interpreter name so LSM allowlisting does not have to
# permit a generic python3 comm (any user script). Created here because
# the packaged tree cannot hard-link the target system's python at build time.
if [ -x /usr/bin/python3 ]; then
  py=$(readlink -f /usr/bin/python3 2>/dev/null || echo /usr/bin/python3)
  if [ -x "$py" ]; then
    mkdir -p /usr/lib/ker
    ln -f "$py" /usr/lib/ker/ker-python 2>/dev/null || cp -a "$py" /usr/lib/ker/ker-python
    chmod 755 /usr/lib/ker/ker-python 2>/dev/null || true
  fi
fi
# Take over previous install; enable hooks on the target. Never auto-enables BPF.
if [ -x /usr/sbin/ker ] && [ -x /usr/lib/ker/ker-python ]; then
  PYTHONPATH=/usr/lib/ker /usr/sbin/ker upgrade --migrate --from-package || true
fi
if [ -x /usr/lib/ker/install-hooks ]; then
  /usr/lib/ker/install-hooks --from-package || true
fi
exit 0
