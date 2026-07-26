#!/bin/sh
set -eu

# Cut a plugin release. From a clean main in sync with origin/main, this confirms the plugin version,
# waits for CI (ci.yml) to pass on HEAD, then tags os-v<version> (from PLUGIN_VERSION in the plugin
# Makefile) and pushes it. Pushing the tag triggers .github/workflows/publish-plugin.yml, which
# re-checks CI and the tag against PLUGIN_VERSION, packages the plugin for each supported FreeBSD
# major (and the daemon for all ABIs when the version the port pins is not yet published), signs the
# trees, gates on real OPNsense, and pushes to netflector/pkg. Requires the gh CLI (authenticated)
# for the CI check.

cd "$(dirname "$0")"
. ./release-lib.sh

version=$(sed -n 's/^PLUGIN_VERSION=[[:space:]]*//p' dist/opnsense/net/netflector/Makefile)
if [ -z "$version" ]; then
    echo "Could not read PLUGIN_VERSION from dist/opnsense/net/netflector/Makefile." >&2
    exit 1
fi
tag="os-v${version}"

ensure_releasable
ensure_tag_absent "$tag" "bump PLUGIN_VERSION in the plugin Makefile first"
wait_for_ci
confirm_and_push_tag "$tag"

echo "Pushed ${tag}. The publish workflow takes over from here -- it packages the plugin (and the"
echo "daemon if the pinned version is unpublished), signs, gates on OPNsense, and publishes:"
echo "  https://github.com/${slug}/actions/workflows/publish-plugin.yml"
