#!/usr/bin/env bash
# Run the e2e suite in the running FreeBSD VM (ci/freebsd-vm.sh env applies)
# against the installed daemon. The suite comes from the port's extracted
# source (WRKSRC), never the working tree: the tree's cases may assert
# behavior the pinned release predates, while WRKSRC's suite matches the
# installed binary by construction. ALLOW_UNSUPPORTED_SYSTEM: the publish VMs
# run EOL OPNsense bases the pinned ports tree otherwise refuses.
set -euo pipefail

HERE="$(dirname "$0")"

"$HERE"/freebsd-vm.sh run 'pkg install -y python3'
"$HERE"/freebsd-vm.sh run 'cd $(make -C /usr/ports/net/netflector ALLOW_UNSUPPORTED_SYSTEM=yes -V WRKSRC) && python3 e2e/run.py --backend native --binary /usr/local/bin/netflector'
