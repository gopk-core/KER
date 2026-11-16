#!/bin/sh
set -e
echo "KER package removed; keys and state in /etc/ker and /var/lib/ker were left untouched." >&2
echo "For a full wipe, run 'ker uninstall' before removing the package, or remove those directories yourself." >&2
exit 0
