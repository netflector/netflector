# netflector

Reflects link-local service traffic between two network interfaces. Useful when devices that need to
talk to each other sit on different L2 segments that don't forward each other's broadcasts or
multicasts. The classic case: a router with a wired LAN on one side and a Wi-Fi or IoT VLAN on the
other, where a phone on Wi-Fi can't discover or cast to a TV on the LAN.

It reflects four link-local protocols and layers an optional DIAL proxy on top of SSDP:

- **Wake-on-LAN**: magic packets sent on one interface are re-emitted on another, so a sender can
  wake a host on a different segment.
- **multicast DNS (mDNS)**: service-discovery traffic is relayed between the two interfaces, so
  clients on one segment can discover responders on the other.
- **SSDP (UPnP/DLNA)**: discovery traffic is relayed both ways, so a caster on one segment can find
  renderers (TVs, media servers) on the other.
- **DIAL proxy** *(optional, builds on SSDP)*: a "cast to TV" device's REST API lives on its own
  segment, often unreachable from the client's (and some TVs refuse off-subnet clients); the proxy
  bridges that gap so a client on the other segment can launch apps on it. Enabled with
  `dial = true` on an SSDP entry; see [DIAL](#dial).
- **WS-Discovery (WSD)**: SOAP-over-UDP discovery is relayed both ways, so a client on one segment can
  discover ONVIF cameras or Windows devices (printers, scanners) on the other.

Each named entry bridges one `source_if` → `target_if` interface pair and enables one or more of the
four reflected protocols, in any mix; the DIAL proxy then layers onto SSDP.

## Contents

- [Platform support](#platform-support)
- [Run](#run): [privileges](#runtime-privileges), [Docker](#run-in-docker), [MikroTik](#on-mikrotik-routeros), [FreeBSD/OPNsense packages](#install-on-freebsd-and-opnsense)
- [Configuration](#configuration): [env vars](#environment-variables), [`macs`](#the-macs-field), [`address_family`](#address_family), [per-protocol behavior](#per-protocol-behavior), [DIAL](#dial), [duplicate detection](#duplicate-detection)
- [Diagnostics](#diagnostics)
- [Developing](#developing)
- [License](#license)

## Platform support

netflector runs on **Linux, macOS, and FreeBSD**.

**Docker**: a multi-arch image is published to `ghcr.io/netflector/netflector` for `linux/amd64`,
`linux/arm64`, `linux/arm/v7`, and `linux/arm/v5`; Docker pulls the variant matching the host. The
32-bit ARM variants reach low-end embedded routers and SBCs, down to soft-float ARMv5, handy for the
router that bridges the two segments.

**FreeBSD** isn't a Docker target (Docker shares the host's Linux kernel), so each release also ships
a standalone static binary for `amd64` and `arm64`, cross-built against the FreeBSD 14 base
pinned in `ci/freebsd14.env` and running on that release or newer.

## Run

```sh
netflector [--check-config] [--] [config.toml]
```

Configuration comes from a TOML file, from environment variables, or from both. With a path argument
the file is read and merged with any `NETFLECTOR_*` environment variables; with **no argument** the
configuration comes entirely from the environment (see [Environment variables](#environment-variables)).
The process logs to stderr with UTC timestamps, shuts down cleanly on `SIGINT` / `SIGTERM`, and on
`SIGUSR1` dumps the per-interface [packet counters](#diagnostics) and a memory report to the log on
demand (regardless of `counters_interval_secs`). Warnings whose cause can recur per packet (a failing
send, an oversized frame) are logged at most once per minute; occurrences inside the window are
counted and reported by the next logged warning as `(N suppressed)`; the counters carry the exact
volumes.

| Option | |
| --- | --- |
| `--check-config` | Load and validate the configuration, print a summary, exit. |
| `-V`, `--version` | Print the version and exit. |
| `-h`, `--help` | Print the usage and exit. |
| `--` | End of options. Needed only for a config file whose name begins with a dash. |

`--check-config` parses and validates only. It opens no interface, so it needs no privileges and runs
on a machine where the configured interfaces do not exist (useful for validating a generated config on
a build host), but for the same reason it cannot tell you that an interface is missing:

```sh
$ netflector --check-config /usr/local/etc/netflector.toml
config ok: 1 reflector
```

### Runtime privileges

netflector opens one L2 packet-capture socket per interface: it both observes incoming packets and
re-injects reflected ones through that same socket (the sender doesn't bind a port, so no port
privileges are involved). mDNS, SSDP, and WSD additionally join their multicast group(s) on it, which
needs no privilege beyond opening the socket. That capture socket drives the requirements below.

#### Linux

Capture and injection use `AF_PACKET`; the DIAL proxy's TCP connect pins its interface with
`SO_BINDTODEVICE`. Both require `CAP_NET_RAW`. Either run as root or grant the capability once:

```sh
sudo setcap cap_net_raw=eip /path/to/netflector
```

#### macOS

Capture and injection use BPF (`/dev/bpf*`); the DIAL proxy's connect uses `IP_BOUND_IF`, which needs
no extra privilege. BPF devices are owned by `root:wheel` with mode `0600` on a default install, so out
of the box netflector must run as root. To run unprivileged, install Wireshark's `ChmodBPF` helper.
It creates an `access_bpf` group, adds the current user to it, and re-applies the right permissions to
`/dev/bpf*` on every boot:

```sh
open "/Applications/Wireshark.app/Contents/Resources/Extras/Install ChmodBPF.pkg"
```

Log out and back in after installing for the group membership to take effect.

#### FreeBSD

Capture and injection use BPF (`/dev/bpf*`), like macOS. FreeBSD has no `IP_BOUND_IF`, so the DIAL
proxy's connect pins its interface by binding the source address; no port privileges are needed. BPF
devices are root-only by default, so out of the box netflector must run as root. To run
unprivileged, grant a group read/write on `/dev/bpf*` with a devfs ruleset (`/etc/devfs.rules` +
`devfs_system_ruleset` in `/etc/rc.conf`) and add the user to that group.

### Run in Docker

Prebuilt multi-arch images are published to `ghcr.io/netflector/netflector`, tagged `latest` and per
release version, for `linux/amd64`, `linux/arm64`, `linux/arm/v7`, and `linux/arm/v5`; Docker pulls the
variant matching the host. The image is a single static binary on `scratch`: no shell, no package
manager. Its entrypoint is netflector with no default argument, so it configures itself from
`NETFLECTOR_*` [environment variables](#environment-variables); pass a config file path to use a file
instead.

Because netflector captures at L2 on each interface, the container must be **on the real segments it
bridges**, not on a default NAT bridge network (which would hide that traffic from it). On a Linux host,
`--network host` is the simplest way. Configure it with `-e` variables:

```sh
docker run --rm \
    --network host \
    -e NETFLECTOR_TV_SOURCE_IF=eth0 \
    -e NETFLECTOR_TV_TARGET_IF=eth1 \
    -e NETFLECTOR_TV_MDNS=true \
    ghcr.io/netflector/netflector:latest
```

`CAP_NET_RAW` is required (see [Runtime privileges](#runtime-privileges)) and is in Docker's default
capability set, so the command above works as-is. For least privilege, drop everything else and grant
just that one:

```sh
docker run --rm \
    --network host \
    --cap-drop ALL --cap-add NET_RAW \
    -e NETFLECTOR_TV_SOURCE_IF=eth0 \
    -e NETFLECTOR_TV_TARGET_IF=eth1 \
    -e NETFLECTOR_TV_MDNS=true \
    ghcr.io/netflector/netflector:latest
```

To use a config file instead of (or alongside) the environment, mount it and pass its path as the
argument. This form also shows running it as a service, `-d` with a restart policy:

```sh
docker run -d --name netflector --restart unless-stopped \
    --network host \
    --cap-drop ALL --cap-add NET_RAW \
    -v /path/to/config.toml:/etc/netflector/config.toml:ro \
    ghcr.io/netflector/netflector:latest /etc/netflector/config.toml
```

#### On MikroTik RouterOS

The `arm64`, `arm/v7`, and `arm/v5` variants let netflector run on the router itself through the
RouterOS *Container* feature, bridging two of the router's VLANs without a separate host. Since it has
to see both segments, give the container **two `veth` interfaces, one bridged into each VLAN**, and name
them as the entry's `source_if` / `target_if`. Two veths on one container needs RouterOS 7.20 or newer:

```toml
[reflectors.livingroom-tv]
source_if = "veth-lan"   # veth bridged into the LAN VLAN
target_if = "veth-iot"   # veth bridged into the IoT VLAN
macs      = ["B0:37:95:C5:60:BE"] # optional; scope to specific device(s) (omit for the whole VLAN)
wol       = true         # enable Wake-on-LAN, disabled by default
mdns      = true         # enable mDNS, disabled by default
ssdp      = true         # enable SSDP, disabled by default
dial      = true         # enable the DIAL proxy, disabled by default
wsd       = true         # enable WS-Discovery, disabled by default
```

On RouterOS, setting the container's environment variables is usually easier than mounting a file: the
entry above becomes `NETFLECTOR_TV_NAME=livingroom-tv`, `NETFLECTOR_TV_SOURCE_IF=veth-lan`,
`NETFLECTOR_TV_TARGET_IF=veth-iot`, `NETFLECTOR_TV_MACS=B0:37:95:C5:60:BE`,
`NETFLECTOR_TV_WOL=true`, and so on. The tag names the entry unless `NAME` overrides it, so without
that first variable the reflector is called `tv` (see
[Environment variables](#environment-variables)). To use the file instead, mount it to
`/etc/netflector/config.toml` and set that path as the container's command argument. For the RouterOS
side (enabling container mode, creating the `veth`s, and attaching each to its VLAN), see MikroTik's
[Container documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container).

### Install on FreeBSD and OPNsense

Signed packages for FreeBSD 14 and 15 (amd64 and aarch64) are served from a
[package repository](https://github.com/netflector/pkg) that tracks the OPNsense releases upstream
supports, currently 26.1 and 26.7. Each package is built on its target's FreeBSD base, so plain
FreeBSD works too, from that base up (14.3+ and 15.1+). Two fetches enable it; the catalogue is
signed, and pkg verifies it against the public key on every update:

```sh
mkdir -p /usr/local/etc/pkg/keys /usr/local/etc/pkg/repos
fetch -o /usr/local/etc/pkg/keys/netflector-pkg.pub https://netflector.github.io/pkg/netflector-pkg.pub
fetch -o /usr/local/etc/pkg/repos/netflector.conf https://netflector.github.io/pkg/netflector.conf
```

On plain FreeBSD, install `netflector` (man pages and the rc service included), write
`/usr/local/etc/netflector.toml` (netflector.toml(5) documents it), and start:

```sh
pkg install netflector
sysrc netflector_enable=YES
service netflector start
```

On a CARP failover pair, `netflector_carp_vhid` confines the service to the MASTER node so the
backup does not reflect a second copy of everything; netflector(8) has the details.

On OPNsense, install the plugin instead. It pulls in the daemon and owns the configuration and the
service from its GUI page under Services > Netflector:

```sh
pkg install os-netflector
```

## Configuration

`config.toml` contains optional top-level settings plus at least one reflector entry. Entries are tables
under `reflectors`, keyed by name (`[reflectors.<name>]`, the name being the label used in logs), each
describing one `source_if` → `target_if` bridge that enables one or more of the protocols. The
top-level settings are `log_level`, `debug_memory_interval_secs`, and `counters_interval_secs` (the
summaries the latter enables are described under [Diagnostics](#diagnostics)):

```toml
log_level = "info"                 # optional; one of off | error | warn | info | debug | trace (default: info)
                                   # release builds compile trace out, where it behaves as debug
debug_memory_interval_secs = 0     # optional; seconds between memory diagnostic reports; 0 disables (default 0)
                                   # reports peak RSS everywhere, current RSS on Linux only
counters_interval_secs = 0         # optional; seconds between per-interface packet-counter summaries; 0 disables (default 0)

[reflectors.tv]
source_if = "en0"                # required; interface to listen on (must differ from target_if)
target_if = "lo0"                # required; interface to emit reflected traffic on
macs      = ["B0:37:95:C5:60:BE"] # optional; device(s) to scope to (see below). Omit for a whole network.
wol       = true                 # optional; enable Wake-on-LAN reflection (default false)
mdns      = true                 # optional; enable mDNS reflection (default false)
ssdp      = true                 # optional; enable SSDP reflection (default false)
dial      = true                 # optional; enable the DIAL app proxy (requires ssdp; IPv4-only; default false)
wsd       = true                 # optional; enable WS-Discovery reflection (default false)
wol_ports = [7, 9]               # optional; WoL UDP ports (default [7, 9]); only valid when wol = true
address_family = "default"       # optional; default | dual | ipv4 | ipv6 (default "default")
```

An entry must enable at least one protocol and expands into one reflector per enabled protocol, all
sharing the entry's interfaces, MAC selection, and `address_family`. The same shape serves one or a few
specific devices (set `macs`) or a whole network (omit it). No IP addresses ever appear in the config.
`dial` is not a separate reflector; it augments the entry's SSDP reflector with the DIAL application
proxy (so it requires `ssdp`; see [DIAL](#dial)).

### Environment variables

Every setting can also come from the environment, which is convenient for containers. A file argument is
then optional; with none, the environment is the whole configuration. Variables are named
`NETFLECTOR_<TAG>_<PARAM>`:

- `<TAG>` ties one entry's parameters together: any alphanumeric string (`1`, `2`, `TV`, …). It also
  becomes the entry's name (and thus its log label) unless a `NAME` parameter overrides it.
- `<PARAM>` is `NAME` or any field from the entry table above (`SOURCE_IF`, `TARGET_IF`, `MACS`,
  `WOL`, `MDNS`, `SSDP`, `WSD`, `DIAL`, `WOL_PORTS`, `ADDRESS_FAMILY`), case-insensitive.

The globals are `NETFLECTOR_LOG_LEVEL`, `NETFLECTOR_DEBUG_MEMORY_INTERVAL_SECS`, and
`NETFLECTOR_COUNTERS_INTERVAL_SECS`, so `LOG`, `DEBUG`, and `COUNTERS` are reserved tags. Booleans are
`true`/`false` or `1`/`0`; `WOL_PORTS`
and `MACS` are comma-separated (`7,9` / `B0:...,C4:...`). The `[reflectors.tv]` entry above looks like
this in the environment:

```sh
NETFLECTOR_LOG_LEVEL=info
NETFLECTOR_TV_SOURCE_IF=en0
NETFLECTOR_TV_TARGET_IF=lo0
NETFLECTOR_TV_MACS=B0:37:95:C5:60:BE
NETFLECTOR_TV_WOL=true
NETFLECTOR_TV_MDNS=true
NETFLECTOR_TV_SSDP=true
NETFLECTOR_TV_DIAL=true
NETFLECTOR_TV_WSD=true
```

When a file and environment variables are both given they are merged: each contributes entries to one
combined configuration, and each global variable (`NETFLECTOR_LOG_LEVEL`,
`NETFLECTOR_DEBUG_MEMORY_INTERVAL_SECS`, `NETFLECTOR_COUNTERS_INTERVAL_SECS`) overrides its file
counterpart. The
[duplicate detection](#duplicate-detection) below applies across both
sources. An unknown `<PARAM>`, a non-alphanumeric or reserved tag, and a tag with no parameter are all
rejected at startup.

### The `macs` field

`macs` is an optional list naming the device(s) an entry is scoped to. One field covers WoL, mDNS,
SSDP, and WSD because a device's NIC MAC is both the target of its Wake-on-LAN magic packet and the L2
source of its mDNS/SSDP/WSD advertisements. A single device is just a one-entry list
(`macs = ["B0:37:95:C5:60:BE"]`); list several to scope one entry to a set of devices
(`macs = ["B0:37:95:C5:60:BE", "C4:9D:8F:11:22:33"]`). Below, "the allow-set" means the configured
devices:

- **WoL** re-emits only magic packets whose payload targets a device in the allow-set.
- **mDNS / SSDP / WSD** relay, in the target→source direction, only frames whose L2 source MAC is in the
  allow-set (exposing just those devices); the source→target direction is never MAC-filtered. For SSDP
  and WSD the same filter scopes the proxied unicast replies: only the allow-set's responses are
  carried back to a searcher. Because the filter reads the frame's L2 source, these protocols refuse
  `macs` at startup when the target link carries no MAC addresses (a BSD `DLT_NULL` link such as a
  loopback or an L3 tunnel) - it could never match. WoL is unaffected: it matches the MAC inside the
  magic packet's payload.

Omit `macs` for a network-level entry: WoL proxies every valid magic packet, and mDNS/SSDP/WSD relay
every device's traffic rather than a chosen set (only the message kinds the corresponding direction
allows, per the table below).

### `address_family`

`"default"` attempts both IPv4 and IPv6, requires IPv4, and treats IPv6 as best-effort; `"dual"`
requires both; `"ipv4"` / `"ipv6"` use only one. It applies to every protocol the entry enables. A
**required** family that can't be initialized for an entry fails startup; a best-effort one that can't
(IPv6 under `"default"`) is skipped and the entry keeps running on the family it has.

mDNS, SSDP, and WSD are bidirectional, so a handled family must have a source address on **both**
interfaces (the target re-emits relayed queries/searches, the source re-emits relayed
responses/advertisements).
The condition is re-checked at runtime (see
[Reacting to address changes](#reacting-to-address-changes) below): a family is torn down if either
interface loses its address and brought back up once both can send it again.

### Reacting to address changes

netflector watches the kernel for interface address and lifecycle changes (a `NETLINK_ROUTE`
socket on Linux, a `PF_ROUTE` socket on the BSDs) and adapts at runtime, without a restart. mDNS,
SSDP, and WSD bring a family up (joining its multicast group(s)) once that family becomes
reflectable (a source address for it is present on **both** interfaces), and tear it down when either
interface loses the address; the family resumes automatically when the address returns. Capture
registrations stay installed throughout; what changes is the group membership and whether the egress
can source the family. WoL has no group to join and instead checks reachability per packet.
Either way, a best-effort IPv6 family that had no address at startup begins reflecting as soon as one
appears. Gaining a family logs at `info`; losing a *required* family logs at `error`, an optional one at
`info`. The monitor is best-effort: if it cannot start, netflector logs a warning and runs without
address refresh.

It also survives an interface being destroyed and recreated (a fresh kernel identity, e.g. a PPPoE
reconnect or a bridge/VLAN rebuild). Lifecycle events (backed by a periodic reconcile, so recovery
never depends on one notification surviving) detect that the name's kernel identity moved; the
captures are then re-bound in place, addresses re-resolved, and multicast groups re-joined on the new
interface, while its DIAL proxies are evicted to re-mint on the next advertisement. While the
interface is absent its reflection parks (sends drop quietly, as on an address loss) and resumes when
the name returns (`interface <name>: returned as ifindex B`, or `recreated (ifindex A -> B)` when the
replacement appeared within one event batch). On macOS the route socket
has no lifecycle messages and can drop notifications silently, so detection there may fall back to
the periodic reconcile (up to ~30 s).

### Per-protocol behavior

| Protocol | Port(s) | Group / destination | Relay direction |
|---|---|---|---|
| WoL | `wol_ports` (default 7, 9) | `255.255.255.255` (v4) / `ff02::1` (v6) | magic packets source → target |
| mDNS | 5353 | `224.0.0.251` / `ff02::fb` | queries source→target, responses target→source |
| SSDP | 1900 | `239.255.255.250` / `ff02::c` + `ff05::c` | M-SEARCH source→target, NOTIFY target→source |
| DIAL | 1900 + ephemeral TCP | (uses SSDP discovery) | terminating HTTP reverse proxy (IPv4 only) |
| WSD | 3702 | `239.255.255.250` / `ff02::c` | Probe/Resolve source→target, Hello/Bye target→source |

WoL matching requires the magic-packet sequence (six `0xFF` bytes followed by the target MAC repeated 16
times) at the start of the UDP payload; trailing bytes such as a SecureOn password are ignored when
matching and forwarded as-is. mDNS responses include unsolicited announcements (so they flow
target→source too); mDNS/SSDP/WSD datagrams are re-emitted verbatim to the same group (mDNS at hop
limit 255, SSDP at 2, WSD at 1).
A site-local SSDP group (`ff05::c`) is sourced from a routable address when the interface has one. With
only a link-local address it is sourced from that, which still reaches the attached segment but will
not cross a router.

mDNS is relayed as pure multicast. A querier that asks for a unicast answer (the QU bit, or a query
from an ephemeral source port) is answered off the group, and that answer is not relayed; SSDP and WSD
instead proxy each searcher's unicast reply.

Messages that advertise only link-local addresses (`169.254.0.0/16`, `fe80::/10`) are dropped rather
than relayed: an mDNS response whose A/AAAA records are all link-local, an SSDP advertisement or
search reply whose `LOCATION` names one, a WSD message whose `XAddrs` all name one. Such an address
is valid only on the link it came from, so the relayed message would advertise endpoints the other
segment can never reach. One routable address among them lets the message through. A `LOCATION` the
DIAL proxy rewrote is exempt: it names netflector's own listener on the egress interface, reachable
from that link even when the interface's address is itself link-local. Suppressed messages count as
`dropped` and log at debug level.

netflector reads untagged Ethernet frames carrying IPv4 or IPv6 UDP. VLAN-tagged frames and IPv6
extension headers are not parsed, so configure the VLAN as its own interface (`vlan10`, `em0.10`) and
name that as the entry's `source_if` / `target_if` rather than the trunk.

For SSDP, multicast reflection delivers **passive** discovery: devices' periodic `NOTIFY ssdp:alive`
advertisements reach the source segment so clients see them. **Active** discovery works end to end as
well: a client's `M-SEARCH` is relayed to the target segment from a reserved ephemeral port, and the
device's unicast `HTTP/1.1 200 OK` reply to that port is proxied back across to the original searcher.
The proxy is always on whenever `ssdp` is enabled; it keeps one short-lived session per in-flight
search (expiring shortly after the search's `MX` window) and needs no configuration. Reaching a
device's `LOCATION` URL and driving an app launch across segments is the job of the optional DIAL proxy
below.

WSD (WS-Discovery) works the same way but on port 3702 with SOAP messages instead of HTTPU: `Hello` /
`Bye` announcements are relayed target→source, and a client's `Probe` / `Resolve` is relayed
source→target with the device's unicast `ProbeMatches` / `ResolveMatches` proxied back through a
per-searcher session, the same machinery as SSDP's `M-SEARCH`, with no DIAL layer. It shares SSDP's
IPv4 group but uses only the link-local IPv6 scope (`ff02::c`), and covers ONVIF NVR↔camera and Windows
device/printer discovery across segments.

### DIAL

DIAL (DIscovery And Launch, the protocol behind "cast to TV" for YouTube, Netflix, etc.) lets a phone
or laptop find a smart TV and launch an app on it. The catch: the device's description and REST
endpoints live at its address on the other segment, which the client often cannot reach, and some
devices refuse off-subnet clients outright (the DIAL spec doesn't require that, but Chromecast and
some Samsung TVs do it). Either way a client on a different segment discovers the device but cannot
drive it. Setting `dial = true` on an SSDP entry makes netflector bridge that gap.

It is a **terminating HTTP reverse proxy**. When a DIAL `LOCATION` (in a relayed `NOTIFY` or `M-SEARCH`
`200 OK`) crosses target→source, netflector mints a pair of per-device ephemeral TCP listeners on
`source_if`'s address, one for the device's description and one for its REST endpoints, and rewrites
the `LOCATION` authority to point at the description listener. A source-side client then connects to
netflector, which opens an upstream connection to the device **bound to `target_if`'s address**, so the
device sees an on-subnet client and serves it. Along the way it rewrites the four authority-bearing
headers (`LOCATION`, the description's `Application-URL`, request `Host`, and response `Location`) from
the device's authority to a netflector authority and back; HTTP bodies stream through untouched.
App launch (`POST`) and stop (`DELETE`) work end to end.

`dial = true` requires `ssdp` and is **IPv4-only** (the DIAL spec ties the device authority to an IPv4
address); an `ipv6`-only entry with `dial = true` is rejected at startup. It is the only DIAL knob;
every cap and timeout is a fixed constant. The proxy degrades benignly: a `LOCATION`/`Application-URL`
netflector can't rewrite (an `https` URL, a hostname instead of an IPv4 literal, a listener cap/bind
failure) is forwarded unchanged and logged, leaving on-subnet discovery unaffected.

### Duplicate detection

Entry names must be unique across the file and the environment: a name that appears twice (including the
same name from both sources) is rejected at startup. Beyond that, two entries that enable the same
protocol are rejected as a duplicate of that protocol only when they could reflect the same packet
twice: same `source_if`, same `target_if`, overlapping MAC selection, overlapping address-family
handling, and, for WoL, at least one shared port. MAC selection overlaps when the entries' allow-sets
share at least one device, or when either omits its MAC filter (any device). Address-family handling overlaps when both can
handle the same IP version: an `ipv4`-only and an `ipv6`-only entry never overlap, while `default`/`dual`
overlap with either. Entries that differ in interface, MAC, address family (or WoL ports), or that
enable *different* protocols, coexist.

## Diagnostics

With `counters_interval_secs` set (and on `SIGUSR1`), one summary line per interface reports its
non-zero counters:

```
counters eth0: recoveries=1; mDNS query reflected=42 skipped=10; SSDP search reflected=5 dropped=1; filtered=2; oversized=3
```

Per message type: `reflected` (re-emitted on the other interface), `skipped` (right protocol, wrong
direction for this leg - normal, this is the loop prevention working), `dropped` (should have been
reflected but was not: a send error, a resource cap, or the link-local suppression) and `stalled`
(the egress had no source address of the packet's family yet). Interface-wide: `filtered`
(unrecognized traffic on the group), `oversized` (received frames too large to forward) and
`recoveries` (the interface was destroyed and recreated, and its capture re-bound). `netflector(8)`
carries the full definitions.

## Developing

[DEVELOP.md](DEVELOP.md) covers building from source, the test suites, the platform-gated code, and
what CI runs. [RELEASE.md](RELEASE.md) covers the release and packaging process.

## License

Copyright 2026 Sergii Bogomolov.

Licensed under the BSD 2-Clause License. See [LICENSE](LICENSE).
