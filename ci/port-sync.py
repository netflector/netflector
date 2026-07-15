#!/usr/bin/env python3
"""Keep the FreeBSD port's crate list and hashes in sync with Cargo.lock.

The port pins every byte it builds from: the release tarball and all 20 crates, each with a SHA256 in
distinfo. Those hashes have to match the lockfile of the release the port claims to build, or the port
either fails to build (a crate it never heard of) or builds something other than what we released.

Two things make this cheap. Cargo.lock already carries the SHA256 of every .crate file, so the crate
hashes can be checked with no network and no FreeBSD box. And the port builds a TAG, not the working
tree, so the lockfile to compare against is the one at that tag: main's Cargo.toml is bumped to the next
patch the moment a release is cut, and comparing against main would fail forever after.

  ci/port-sync.py --check              verify the port against the tag it declares
  ci/port-sync.py --update 0.13.0      point the port at v0.13.0 and regenerate the hashes
"""

import argparse
import hashlib
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

PORT = Path(__file__).resolve().parent.parent / 'dist' / 'freebsd' / 'net' / 'netflector'
MAKEFILE = PORT / 'Makefile'
DISTINFO = PORT / 'distinfo'

GH_ACCOUNT = 'netflector'
GH_PROJECT = 'netflector'
CRATE_URL = 'https://crates.io/api/v1/crates/{name}/{version}/download'
TARBALL_URL = 'https://codeload.github.com/{acct}/{proj}/tar.gz/v{version}'

# One [[package]] block: a crate has a source and a checksum, the root package has neither.
PACKAGE = re.compile(
    r'\[\[package\]\]\n'
    r'name = "(?P<name>[^"]+)"\n'
    r'version = "(?P<version>[^"]+)"\n'
    r'source = "[^"]*"\n'
    r'checksum = "(?P<checksum>[0-9a-f]+)"'
)

# The whole CARGO_CRATES assignment: the first crate sits on the assignment line, the rest on
# backslash-continued lines. Matching the block as a unit, rather than any indented line that happens to
# look like a crate, keeps this from quietly scraping some other continued variable.
CARGO_CRATES = re.compile(r'^CARGO_CRATES=\t(?P<block>(?:.*\\\n)*.*)$', re.M)


def distversion():
    text = MAKEFILE.read_text()
    match = re.search(r'^DISTVERSION=\t(.+)$', text, re.M)
    if not match:
        sys.exit('port Makefile has no DISTVERSION')
    return match.group(1).strip()


def latest_release():
    """The highest v* tag on the remote."""
    listing = subprocess.run(
        ['git', 'ls-remote', '--tags', '--refs', '--sort=-v:refname', 'origin', 'v*'],
        capture_output=True, text=True, check=True,
    ).stdout.split('\n')

    tags = [line.split('refs/tags/')[1] for line in listing if 'refs/tags/' in line]
    if not tags:
        sys.exit('origin has no v* tags: nothing is released, so there is no version to build')
    tag = tags[0]

    # git show needs the tag object here, and it may never have been fetched.
    subprocess.run(['git', 'fetch', '--quiet', 'origin', 'tag', tag], check=True)
    return tag.lstrip('v')


def lockfile_at(tag):
    """Cargo.lock as it was at the release the port builds, not as it is now."""
    try:
        return subprocess.run(
            ['git', 'show', f'{tag}:Cargo.lock'],
            capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError:
        sys.exit(f'no tag {tag}: the port declares a version that was never released')


def crates_from(lock):
    """[(name, version, sha256)], in the order the ports framework lists them."""
    found = [(m['name'], m['version'], m['checksum']) for m in PACKAGE.finditer(lock)]
    return sorted(found, key=lambda c: f'{c[0]}-{c[1]}')


def listed_crates(makefile):
    """The name-version strings the port's CARGO_CRATES declares."""
    match = CARGO_CRATES.search(makefile)
    if not match:
        return []
    return match.group('block').replace('\\', ' ').split()


def fetch(url):
    with urllib.request.urlopen(url) as response:
        return response.read()


def tarball_name(version):
    return f'{GH_ACCOUNT}-{GH_PROJECT}-v{version}_GH0.tar.gz'


def render_crates(crates):
    """The CARGO_CRATES assignment. No trailing newline: it replaces a $-anchored match."""
    lines = [f'{name}-{version}' for name, version, _ in crates]
    body = ' \\\n\t\t'.join(lines)
    return f'CARGO_CRATES=\t{body}'


def render_distinfo(crates, sizes, tarball_sha, tarball_size, version):
    out = [f'TIMESTAMP = {int(time.time())}\n']
    for name, ver, sha in crates:
        crate = f'rust/crates/{name}-{ver}.crate'
        out.append(f'SHA256 ({crate}) = {sha}\n')
        out.append(f'SIZE ({crate}) = {sizes[f"{name}-{ver}"]}\n')
    tar = tarball_name(version)
    out.append(f'SHA256 ({tar}) = {tarball_sha}\n')
    out.append(f'SIZE ({tar}) = {tarball_size}\n')
    return ''.join(out)


def check():
    version = distversion()
    crates = crates_from(lockfile_at(f'v{version}'))
    makefile = MAKEFILE.read_text()
    distinfo = DISTINFO.read_text()
    problems = []

    listed = set(listed_crates(makefile))
    expected = {f'{n}-{v}' for n, v, _ in crates}
    if listed != expected:
        problems.append(
            f'CARGO_CRATES does not match Cargo.lock at v{version}\n'
            f'    only in the port:   {sorted(listed - expected)}\n'
            f'    only in Cargo.lock: {sorted(expected - listed)}'
        )

    tarball = tarball_name(version)
    fetched = {f'rust/crates/{n}-{v}.crate' for n, v, _ in crates} | {tarball}

    hashes = dict(re.findall(r'^SHA256 \((.+?)\) = ([0-9a-f]+)$', distinfo, re.M))
    sizes = set(re.findall(r'^SIZE \((.+?)\) = \d+$', distinfo, re.M))

    stale = (set(hashes) | sizes) - fetched
    if stale:
        problems.append(
            f'distinfo pins files the port does not fetch: {sorted(stale)}'
        )

    for name in sorted(fetched):
        if name not in hashes:
            problems.append(f'distinfo has no SHA256 for {name}')
        if name not in sizes:
            problems.append(f'distinfo has no SIZE for {name}')

    # The tarball's hash cannot be checked here: it is not in Cargo.lock, and GitHub generates that
    # archive server-side. The freebsd-port-build job verifies it (and every SIZE) by fetching for real.
    for name, ver, sha in crates:
        crate = f'rust/crates/{name}-{ver}.crate'
        if crate in hashes and hashes[crate] != sha:
            problems.append(f'{name}-{ver}: distinfo says {hashes[crate]}, Cargo.lock says {sha}')

    if problems:
        print('port is out of sync with Cargo.lock:\n', file=sys.stderr)
        for problem in problems:
            print(f'  {problem}', file=sys.stderr)
        print(f'\nrun: ci/port-sync.py --update {version}', file=sys.stderr)
        return 1

    print(f'port matches Cargo.lock at v{version}: {len(crates)} crates, hashes agree')
    return 0


def update(version):
    crates = crates_from(lockfile_at(f'v{version}'))

    # Download each crate to measure it. The hash is already known from Cargo.lock, so verify rather
    # than trust: if crates.io ever served different bytes under the same name and version, that is the
    # supply-chain attack this file exists to stop, and it should fail here rather than be recorded.
    sizes = {}
    for name, ver, sha in crates:
        blob = fetch(CRATE_URL.format(name=name, version=ver))
        got = hashlib.sha256(blob).hexdigest()
        if got != sha:
            sys.exit(f'{name}-{ver}: crates.io served {got}, Cargo.lock says {sha}')
        sizes[f'{name}-{ver}'] = len(blob)
        print(f'  {name}-{ver}: {len(blob)} bytes, hash ok')

    tarball = fetch(TARBALL_URL.format(acct=GH_ACCOUNT, proj=GH_PROJECT, version=version))
    tarball_sha = hashlib.sha256(tarball).hexdigest()
    print(f'  {tarball_name(version)}: {len(tarball)} bytes')

    makefile = MAKEFILE.read_text()
    makefile = re.sub(r'^DISTVERSION=\t.+$', f'DISTVERSION=\t{version}', makefile, flags=re.M)
    makefile = re.sub(r'^CARGO_CRATES=\t(?:.*\\\n)*.*$', render_crates(crates), makefile, flags=re.M)
    MAKEFILE.write_text(makefile)
    DISTINFO.write_text(render_distinfo(crates, sizes, tarball_sha, len(tarball), version))
    print(f'port now builds v{version}')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true')
    group.add_argument('--update', metavar='VERSION', nargs='?', const='', default=None,
                       help='version to build; defaults to the newest release')
    args = parser.parse_args()

    if args.check:
        return check()

    version = args.update or latest_release()
    if not args.update:
        print(f'newest release is v{version}')
    return update(version)


if __name__ == '__main__':
    sys.exit(main())
