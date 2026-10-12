#!/bin/sh
# Copy the working tree's port into the VM's ports tree and register it in
# net/Makefile's SUBDIR list and its account in UIDs and GIDs: those entries are
# deliverables of the ports-tree submission, portlint checks the list entry, and
# the framework refuses USERS without the ids.
set -eu

# scp -r copies INTO an existing directory, so the day net/netflector lands upstream the
# push would nest ours at net/netflector/netflector and every make would build the tree's
# port instead: green, and testing nothing of the change.
ci/freebsd-vm.sh run 'rm -rf /usr/ports/net/netflector'
ci/freebsd-vm.sh push dist/freebsd/net/netflector /usr/ports/net/netflector
ci/freebsd-vm.sh run 'cd /usr/ports/net && awk "/^ *SUBDIR \+= / && !ins && \$3 > \"netflector\" { print \"    SUBDIR += netflector\"; ins = 1 } { print } END { if (!ins) print \"    SUBDIR += netflector\" }" Makefile > Makefile.new && mv Makefile.new Makefile && grep -n "SUBDIR += netflector" Makefile'

# 678 was free in both files on 2026-10-12, away from where new ports were taking ids;
# the ports committer may assign another.
id=678
add_id() {
    ci/freebsd-vm.sh run "cd /usr/ports && if ! grep -q '^netflector:' $1; then awk -F: -v line='$2' '\$0 == \"# free: $id\" { print line; ins = 1; next } !/^#/ && !ins && \$3 > $id { print line; ins = 1 } { print }' $1 > $1.new && mv $1.new $1; fi && grep -n '^netflector:' $1"
}
add_id UIDs "netflector:*:$id:$id::0:0:Netflector Daemon:/nonexistent:/usr/sbin/nologin"
add_id GIDs "netflector:*:$id:"
