#!/bin/sh
# Copy the working tree's port into the VM's ports tree and register it in
# net/Makefile's SUBDIR list: the list entry is a deliverable of the ports-tree
# submission, and portlint checks it.
set -eu

# scp -r nests into an existing directory; see ci/freebsd-port-package.sh.
ci/freebsd-vm.sh run 'rm -rf /usr/ports/net/netflector'
ci/freebsd-vm.sh push dist/freebsd/net/netflector /usr/ports/net/netflector
ci/freebsd-vm.sh run 'cd /usr/ports/net && awk "/^ *SUBDIR \+= / && !ins && \$3 > \"netflector\" { print \"    SUBDIR += netflector\"; ins = 1 } { print } END { if (!ins) print \"    SUBDIR += netflector\" }" Makefile > Makefile.new && mv Makefile.new Makefile && grep -n "SUBDIR += netflector" Makefile'
