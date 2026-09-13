#!/usr/bin/env python3
"""Render checked-in workflow matrices and query the shared platform catalog.

Static generated blocks keep every job visible in GitHub's workflow UI, without
an extra discovery job or dynamically changing required checks. --check compares
all blocks; --write refreshes them after a policy change. Requires Python 3.11+.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "ci/platforms.toml"
BLOCK = re.compile(
    r"^(?P<indent> *)# BEGIN platforms: (?P<view>[a-z_-]+)\n"
    r".*?^(?P=indent)# END platforms\n",
    re.MULTILINE | re.DOTALL,
)
# Every consumer must retain its marker: accidentally deleting a whole block is
# an error too, even though there would be nothing left for the regex to compare.
CONSUMERS = {
    "ci.yml": [
        "package-pins",
        "freebsd-ci",
        "freebsd-ci",
        "freebsd-majors",
        "docker-native",
        "linux-test",
        "miri",
        "test",
        "lint",
    ],
    "ci-port.yml": ["freebsd-port", "freebsd-majors"],
    "ci-opnsense.yml": ["package-pins", "opnsense"],
    "build-daemon-pkgs.yml": ["freebsd-package"],
    "publish-plugin.yml": ["opnsense"],
    "pkg-deploy.yml": ["opnsense"],
    "release.yml": ["release", "images"],
}


def catalog() -> dict:
    with CATALOG.open("rb") as source:
        data = tomllib.load(source)
    majors = data["freebsd_majors"]
    served = {series["major"] for series in data["opnsense"]}
    if not majors or len(majors) != len(set(majors)):
        raise ValueError("FreeBSD majors must be nonempty and unique")
    if data["freebsd_static_baseline"] != min(majors) or not served <= set(majors):
        raise ValueError(
            "static baseline must be oldest major; all OPNsense majors must be tested"
        )
    for key, field in (("linux", "arch"), ("freebsd", "name"), ("opnsense", "series")):
        rows = data[key]
        if not rows or len({row[field] for row in rows}) != len(rows):
            raise ValueError(f"{key}: empty or duplicate {field}")
    expected = {f"freebsd{major}.env" for major in majors}
    expected |= {f"freebsd{major}-opnsense.env" for major in served}
    actual = {path.name for path in (ROOT / "ci").glob("freebsd*.env")}
    if expected != actual:
        raise ValueError(
            f"pin files do not match catalog: missing={expected - actual}, stale={actual - expected}"
        )
    return data


def views(data: dict) -> dict:
    linux = data["linux"]
    freebsd = data["freebsd"]
    macos = data["macos"]
    native = [row for row in linux if not row.get("emulated", False)]
    linux_test = [
        dict(name=f"linux-{row['arch']}-glibc", runner=row["runner"], triple="")
        for row in native
    ]
    for row in linux:
        target = dict(
            name=f"linux-{row['arch']}-musl", runner=row["runner"], triple=row["triple"]
        )
        if row.get("emulated"):
            target["emulated"] = True
        linux_test.append(target)
    opnsense = [
        dict(
            opnsense=row["series"],
            os=row["major"],
            plugins_branch=f"stable/{row['series']}",
            abi=f"FreeBSD:{row['major']}:amd64",
        )
        for row in data["opnsense"]
    ]
    shipped = [row["triple"] for row in linux + freebsd + macos]
    baseline = data["freebsd_static_baseline"]
    releases = [
        dict(variant=f"linux-{row['arch']}", runner=row["runner"], target=row["triple"])
        for row in linux
    ]
    releases.extend(
        dict(variant=f"macos-{row['arch']}", runner=row["runner"], target=row["triple"])
        for row in macos
    )
    releases.extend(
        dict(
            variant=f"freebsd-{row['name']}",
            runner="ubuntu-24.04",
            target=row["triple"],
            freebsd_arch=row["name"],
            freebsd_baseline=baseline,
        )
        for row in freebsd
    )
    return {
        "package-pins": [
            f"ci/freebsd{major}-opnsense.env"
            for major in sorted({row["major"] for row in data["opnsense"]})
        ],
        "freebsd-ci": dict(
            os=data["freebsd_majors"],
            arch=[dict(**row, baseline=baseline) for row in freebsd],
        ),
        "freebsd-port": dict(os=data["freebsd_majors"], arch=freebsd),
        "freebsd-package": dict(
            os=sorted({row["major"] for row in data["opnsense"]}), arch=freebsd
        ),
        "freebsd-majors": dict(os=data["freebsd_majors"]),
        "docker-native": dict(
            arch=[dict(name=row["arch"], runner=row["runner"]) for row in native]
        ),
        "linux-test": dict(target=linux_test),
        "test": dict(
            target=linux_test
            + [dict(name=f"macos-{row['arch']}", runner=row["runner"], triple="") for row in macos]
        ),
        "lint": dict(target=shipped),
        "miri": dict(target=[row["gnu"] for row in native] + shipped),
        "opnsense": dict(include=opnsense),
        "release": dict(include=releases),
        "images": dict(
            include=[
                dict(arch=row["arch"], runner=row["runner"], platform=row["platform"])
                for row in linux
            ]
        ),
    }


def render(name: str, indent: str, matrices: dict) -> str:
    lines = [f"{indent}# BEGIN platforms: {name}"]
    matrix = matrices[name]
    if isinstance(matrix, list):
        lines.extend(f"{indent}- {json.dumps(value)}" for value in matrix)
    else:
        for key, values in matrix.items():
            lines.append(f"{indent}{key}:")
            lines.extend(f"{indent}  - {json.dumps(value)}" for value in values)
    lines.append(f"{indent}# END platforms")
    return "\n".join(lines) + "\n"


def sync(data: dict, write: bool) -> int:
    matrices = views(data)
    changed = []
    for filename, expected in CONSUMERS.items():
        path = ROOT / ".github/workflows" / filename
        original = path.read_text()
        found = [match["view"] for match in BLOCK.finditer(original)]
        if found != expected:
            raise ValueError(
                f"{filename}: expected catalog blocks {expected}, got {found}"
            )
        updated = BLOCK.sub(
            lambda match: render(match["view"], match["indent"], matrices), original
        )
        if updated != original:
            changed.append(filename)
            if write:
                path.write_text(updated)
    if changed:
        print(
            f"{'updated' if write else 'stale matrices (run python3 ci/platforms.py --write)'}: {', '.join(changed)}"
        )
    else:
        print("platform catalog, pins, and workflow matrices agree")
    return int(bool(changed) and not write)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--check", action="store_true")
    operation.add_argument("--write", action="store_true")
    operation.add_argument("--abis", action="store_true")
    operation.add_argument("--abi-arches", action="store_true")
    operation.add_argument("--freebsd", choices=("amd64", "arm64"), metavar="ARCH")
    parser.add_argument("--field", choices=("triple", "packages", "kvm"))
    args = parser.parse_args()
    data = catalog()
    if args.abis:
        for major in sorted({row["major"] for row in data["opnsense"]}):
            for row in data["freebsd"]:
                print(f"FreeBSD:{major}:{row['abi']}")
    elif args.abi_arches:
        print(" ".join(row["abi"] for row in data["freebsd"]))
    elif args.freebsd:
        if not args.field:
            parser.error("--freebsd requires --field")
        row = next(row for row in data["freebsd"] if row["name"] == args.freebsd)
        value = row[args.field]
        print(str(value).lower() if isinstance(value, bool) else value)
    else:
        return sync(data, args.write)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError) as error:
        sys.exit(f"platform catalog: {error}")
