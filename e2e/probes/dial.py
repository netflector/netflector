"""DIAL device and client protocol fixtures."""

from __future__ import annotations

import argparse
import http.server
import socket
import struct
import sys
import threading
import time

from probes.sockets import bind_reporting_conflict, join_group

DIAL_SERVICE_TYPE = "urn:dial-multiscreen-org:service:dial:1"


def _own_address(interface: str, family: int) -> str:
    # This container's address on the interface facing netflector -- the address netflector's
    # egress-pinned upstream connect() lands on, and the host we advertise in LOCATION / Application-URL.
    # A dummy connect + getsockname resolves it without parsing `ip addr`. The DIAL device is single-homed
    # (target network only), so the route -- and hence the source address -- is unambiguous.
    fam = socket.AF_INET6 if family == 6 else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as probe:
        if family == 6:
            probe.connect(("ff02::1", 9, 0, socket.if_nametoindex(interface)))
        else:
            # FreeBSD 15 refuses a broadcast connect (ENETUNREACH, SO_BROADCAST or not), so pin the
            # interface like the v6 branch and connect to the multicast group instead; that needs no
            # route at all (the vnet-jail case) and works the same on Linux.
            mreqn = struct.pack(
                "@4s4si", socket.inet_aton("0.0.0.0"), b"\x00\x00\x00\x00",
                socket.if_nametoindex(interface),
            )
            probe.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
            probe.connect(("239.255.255.250", 9))
        return probe.getsockname()[0]


def dial_device(args: argparse.Namespace) -> int:
    # Emulate a DIAL device: answer the proxied M-SEARCH with a 200 OK whose LOCATION points at our own
    # (target-side) HTTP description endpoint, and serve the description + REST endpoints over TCP. We
    # record the peer address of every accepted HTTP connection: with the device single-homed on the
    # target network, the only client that can reach these endpoints is netflector's upstream connect,
    # so the recorded peer must be netflector's target_if address (run.py asserts this).
    own = _own_address(args.interface, args.family)
    peers: set[str] = set()
    host_errors: list[str] = []
    state_lock = threading.Lock()

    def note(peer_ip: str, host, expected: str) -> None:
        # Record the upstream peer (must be netflector's target_if address) and verify the request's Host
        # was rewritten to this device's own authority -- the device must never see netflector's authority.
        with state_lock:
            peers.add(peer_ip)
            if host != expected:
                host_errors.append(f"got {host!r}, expected {expected!r}")

    # A relative-only body, so the proxy never has to rewrite a body byte; every rewritable URL is a header.
    desc_body = (
        '<?xml version="1.0"?>\r\n'
        "<root><device><friendlyName>e2e-dial</friendlyName>"
        "<X_DIALEX_AppsListURL>/apps</X_DIALEX_AppsListURL></device></root>\r\n"
    ).encode()

    class DescHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # noqa: ANN002 - silence the default stderr access log
            pass

        def do_GET(self):  # noqa: N802 - stdlib handler name
            note(self.client_address[0], self.headers.get("Host"), f"{own}:{desc_port}")
            # Application-URL is an absolute header on the REST port: the proxy must rewrite it.
            self.send_response(200)
            self.send_header("Content-Type", "text/xml; charset=utf-8")
            self.send_header("Application-URL", f"http://{own}:{rest_port}/apps")
            self.send_header("Content-Length", str(len(desc_body)))
            self.end_headers()
            self.wfile.write(desc_body)

    class RestHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # noqa: ANN002
            pass

        def _drain_body(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length:
                self.rfile.read(length)

        def _chunked(self, status, body, extra=None):
            # Chunked, like the captured LG TV REST stream: the proxy forwards chunk data verbatim and
            # only parses chunk-size lines to find the terminating 0-chunk.
            self.send_response(status)
            self.send_header("Content-Type", "text/xml; charset=utf-8")
            self.send_header("Transfer-Encoding", "chunked")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if body:
                self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")

        def do_GET(self):  # noqa: N802
            note(self.client_address[0], self.headers.get("Host"), f"{own}:{rest_port}")
            self._drain_body()
            self._chunked(200, b"<service><state>stopped</state></service>")

        def do_POST(self):  # noqa: N802 - app launch
            note(self.client_address[0], self.headers.get("Host"), f"{own}:{rest_port}")
            self._drain_body()
            # 201 Created with an ABSOLUTE Location on the REST port -- the proxy rewrites this header too.
            self._chunked(201, b"", {"Location": f"http://{own}:{rest_port}{self.path}/run"})

        def do_DELETE(self):  # noqa: N802 - app stop
            note(self.client_address[0], self.headers.get("Host"), f"{own}:{rest_port}")
            self._drain_body()
            self._chunked(200, b"")

    # Bind the HTTP servers on ephemeral ports (the description port is "dynamic" by design). In
    # --unreachable mode no server is started: the advertised port is one we bind-then-close, so
    # netflector's upstream connect is refused -- exercising the connect-failure path.
    bind_host = "::" if args.family == 6 else "0.0.0.0"
    if args.unreachable:
        with socket.socket(socket.AF_INET6 if args.family == 6 else socket.AF_INET, socket.SOCK_STREAM) as dead:
            dead.bind((bind_host, 0))
            desc_port = dead.getsockname()[1]
        rest_port = desc_port  # unused: nothing is served in this mode
    else:
        server_cls = http.server.ThreadingHTTPServer
        if args.family == 6:
            server_cls = type("V6Server", (http.server.ThreadingHTTPServer,), {"address_family": socket.AF_INET6})
        desc_server = server_cls((bind_host, 0), DescHandler)
        rest_server = server_cls((bind_host, 0), RestHandler)
        desc_port = desc_server.server_address[1]
        rest_port = rest_server.server_address[1]
        threading.Thread(target=desc_server.serve_forever, daemon=True).start()
        threading.Thread(target=rest_server.serve_forever, daemon=True).start()

    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    udp_bind = "::" if family == socket.AF_INET6 else "0.0.0.0"
    location = f"http://{own}:{desc_port}/dd.xml"
    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((udp_bind, args.port))
        join_group(sock, family, args.join_group, args.interface)
        print(f"dial-device ready: desc {own}:{desc_port} rest {own}:{rest_port} ssdp :{args.port}", flush=True)

        if args.notify:
            # Passive discovery: advertise an unsolicited NOTIFY ssdp:alive periodically (as real devices
            # do), so the later-listening client catches one; netflector relays each and rewrites LOCATION.
            notify = (
                "NOTIFY * HTTP/1.1\r\n"
                f"HOST: {args.join_group}:{args.port}\r\n"
                "CACHE-CONTROL: max-age=1800\r\n"
                f"LOCATION: {location}\r\n"
                f"NT: {DIAL_SERVICE_TYPE}\r\n"
                "NTS: ssdp:alive\r\n"
                f"USN: uuid:e2e-dial::{DIAL_SERVICE_TYPE}\r\n\r\n"
            ).encode()
            if family == socket.AF_INET6:
                scope = socket.if_nametoindex(args.interface)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, scope)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 2)
                dest = (args.join_group, args.port, 0, scope)
            else:
                ifindex = socket.if_nametoindex(args.interface)
                mreqn = struct.pack("@4s4si", b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", ifindex)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                dest = (args.join_group, args.port)
            print(f"dial-device advertising NOTIFY (LOCATION {location}) to {args.join_group}:{args.port}", flush=True)
            deadline = time.monotonic() + args.serve_seconds
            while time.monotonic() < deadline:
                sock.sendto(notify, dest)
                time.sleep(0.5)
        else:
            # Active discovery: answer the one proxied M-SEARCH with a 200 OK carrying our LOCATION.
            ok = (
                "HTTP/1.1 200 OK\r\n"
                "CACHE-CONTROL: max-age=1800\r\n"
                f"ST: {DIAL_SERVICE_TYPE}\r\n"
                f"USN: uuid:e2e-dial::{DIAL_SERVICE_TYPE}\r\n"
                f"LOCATION: {location}\r\n\r\n"
            ).encode()
            sock.settimeout(args.timeout)
            try:
                payload, peer = sock.recvfrom(4096)
            except TimeoutError:
                print(f"dial-device: no M-SEARCH for {args.timeout:.3f}s", file=sys.stderr, flush=True)
                return 1
            print(f"dial-device received {len(payload)} bytes from {peer[0]}:{peer[1]}", flush=True)
            sock.sendto(ok, peer)
            print(f"dial-device replied 200 OK (LOCATION {location}) to {peer[0]}:{peer[1]}", flush=True)
            time.sleep(args.serve_seconds)  # keep the HTTP endpoints up for the client's GET/POST/DELETE

    print(f"dial-device upstream peers seen: {sorted(peers)}", flush=True)
    if host_errors:
        print(f"dial-device request Host NOT rewritten to this device: {host_errors}", file=sys.stderr, flush=True)
        return 1
    print("dial-device request Host rewritten to this device on every request", flush=True)
    return 0


def _http_request(host, port, method, path, family, body=b""):
    fam = socket.AF_INET6 if family == 6 else socket.AF_INET
    with socket.socket(fam, socket.SOCK_STREAM) as sock:
        sock.settimeout(8.0)
        sock.connect((host, port) if family == 4 else (host, port, 0, 0))
        req = (f"{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        sock.sendall(req)
        # Read the full header block first.
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        if b"\r\n\r\n" not in buf:
            raise ConnectionError("no complete HTTP response (upstream aborted)")
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split(" ")[1])
        headers = {}
        for line in lines[1:]:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
        # Read the body per its framing rather than waiting for the connection close: netflector
        # defers the client-side close to its eviction timer, so an EOF-driven read would block on that.
        if headers.get("transfer-encoding", "").lower() == "chunked":
            while not rest.endswith(b"0\r\n\r\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                rest += chunk
        elif "content-length" in headers:
            need = int(headers["content-length"])
            while len(rest) < need:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                rest += chunk
    return status, headers, rest


def _authority(url: str) -> str:
    # Strip scheme + path: http://host:port/p -> host:port (IPv6 literals keep their brackets).
    return url.split("://", 1)[1].split("/", 1)[0]


def _dial_discover(args):
    # Return the (netflector-rewritten) SSDP response carrying the device LOCATION, or None on timeout. Active
    # discovery sends an M-SEARCH and reads the unicast 200 OK; passive discovery joins the group and waits
    # for the relayed NOTIFY ssdp:alive.
    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    udp_bind = "::" if family == socket.AF_INET6 else "0.0.0.0"
    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if args.passive:
            sock.bind((udp_bind, args.port))                       # bind 1900 + join the group to hear NOTIFYs
            join_group(sock, family, args.address, args.interface)
            print(f"dial-client listening for a DIAL NOTIFY on {args.address}:{args.port}", flush=True)
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                sock.settimeout(max(0.1, deadline - time.monotonic()))
                try:
                    payload, peer = sock.recvfrom(4096)
                except TimeoutError:
                    break
                text = payload.decode("latin-1")
                if text.upper().startswith("NOTIFY") and DIAL_SERVICE_TYPE in text \
                        and any(ln.lower().startswith("location:") for ln in text.split("\r\n")):
                    print(f"dial-client received NOTIFY from {peer[0]}:{peer[1]}:\n{text}", flush=True)
                    return text
            print(f"dial-client: no DIAL NOTIFY for {args.timeout:.3f}s", file=sys.stderr, flush=True)
            return None
        # Active discovery: send the M-SEARCH from a bound source port, await the proxied unicast 200 OK.
        bind_reporting_conflict(sock, udp_bind, args.source_port)
        if family == socket.AF_INET6:
            scope = socket.if_nametoindex(args.interface)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, scope)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            dest = (args.address, args.port, 0, scope)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            ifindex = socket.if_nametoindex(args.interface)
            mreqn = struct.pack("@4s4si", b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", ifindex)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
            dest = (args.address, args.port)
        sock.sendto(args.payload_hex, dest)
        print(f"dial-client sent M-SEARCH to {args.address}:{args.port}", flush=True)
        sock.settimeout(args.timeout)
        try:
            payload, peer = sock.recvfrom(4096)
        except TimeoutError:
            print(f"dial-client: no 200 OK for {args.timeout:.3f}s", file=sys.stderr, flush=True)
            return None
        text = payload.decode("latin-1")
        print(f"dial-client received 200 OK from {peer[0]}:{peer[1]}:\n{text}", flush=True)
        return text


def dial_client(args: argparse.Namespace) -> int:
    # Run the full DIAL flow through netflector and assert each rewritable authority was rewritten to
    # netflector's source-side address (and never leaks the device's true target-side address). The
    # device is unreachable from this (source) network except via netflector, so a missing rewrite
    # makes the HTTP step connect to an unroutable address and fail.
    refl = args.netflector_authority  # netflector's source_if address (host only; LOCATION ports are dynamic)
    device = args.device_authority    # the device's TRUE target-side host, asserted absent from rewrites

    text = _dial_discover(args)
    if text is None:
        return 1
    location = next((ln.split(":", 1)[1].strip() for ln in text.split("\r\n")
                     if ln.lower().startswith("location:")), None)
    if location is None:
        print("dial-client: 200 OK had no LOCATION", file=sys.stderr, flush=True)
        return 1
    loc_host = _authority(location).rsplit(":", 1)[0]
    if loc_host != refl:
        print(f"dial-client: LOCATION host {loc_host!r} is not the netflector authority {refl!r} "
              f"(rewrite missing); full LOCATION {location!r}", file=sys.stderr, flush=True)
        return 1
    if device in _authority(location):
        print(f"dial-client: LOCATION still names the device {device!r}: {location!r}", file=sys.stderr, flush=True)
        return 1
    desc_host, _, desc_port_s = _authority(location).rpartition(":")
    desc_port = int(desc_port_s)
    desc_path = "/" + location.split("://", 1)[1].split("/", 1)[1]
    print(f"dial-client: LOCATION rewritten to netflector authority {desc_host}:{desc_port}", flush=True)

    if args.expect_fetch_failure:
        # The LOCATION was rewritten (the listener was minted), but the device's upstream is dead, so the
        # proxied fetch must fail -- and fail PROMPTLY. netflector must FIN the client when the upstream
        # connect is refused, not leave it hanging until the eviction timer (~5s). A 2s budget cleanly
        # separates the prompt close from that stall.
        start = time.monotonic()
        try:
            _http_request(desc_host, desc_port, "GET", desc_path, args.family)
        except Exception as exc:  # noqa: BLE001 - any failure (refused / reset / EOF / timeout) is the point
            elapsed = time.monotonic() - start
            if elapsed > 2.0:
                print(f"dial-client: fetch failed but only after {elapsed:.1f}s (> 2s) -- netflector did "
                      f"not close the client promptly on upstream failure", file=sys.stderr, flush=True)
                return 1
            print(f"dial-client: description fetch failed promptly after {elapsed:.1f}s "
                  f"({type(exc).__name__}: {exc}) -- upstream unreachable, client closed promptly", flush=True)
            return 0
        print("dial-client: description fetch unexpectedly SUCCEEDED (upstream should be unreachable)",
              file=sys.stderr, flush=True)
        return 1

    status, headers, _ = _http_request(desc_host, desc_port, "GET", desc_path, args.family)
    if status != 200:
        print(f"dial-client: GET description -> {status}", file=sys.stderr, flush=True)
        return 1
    app_url = headers.get("application-url")
    if app_url is None:
        print("dial-client: description had no Application-URL", file=sys.stderr, flush=True)
        return 1
    app_host = _authority(app_url).rsplit(":", 1)[0]
    if app_host != refl or device in _authority(app_url):
        print(f"dial-client: Application-URL {app_url!r} not rewritten to netflector authority {refl!r}",
              file=sys.stderr, flush=True)
        return 1
    rest_host, _, rest_port_s = _authority(app_url).rpartition(":")
    rest_port = int(rest_port_s)
    apps_path = "/" + app_url.split("://", 1)[1].split("/", 1)[1]
    print(f"dial-client: Application-URL rewritten to {rest_host}:{rest_port}", flush=True)

    status, headers, _ = _http_request(rest_host, rest_port, "POST", f"{apps_path}/YouTube", args.family,
                                       body=b"pairingCode=e2e")
    if status != 201:
        print(f"dial-client: launch POST -> {status} (expected 201)", file=sys.stderr, flush=True)
        return 1
    run_loc = headers.get("location")
    if run_loc is None:
        print("dial-client: 201 had no LOCATION", file=sys.stderr, flush=True)
        return 1
    run_host = _authority(run_loc).rsplit(":", 1)[0]
    if run_host != refl or device in _authority(run_loc):
        print(f"dial-client: 201 LOCATION {run_loc!r} not rewritten to netflector authority {refl!r}",
              file=sys.stderr, flush=True)
        return 1
    print(f"dial-client: 201 LOCATION rewritten to {_authority(run_loc)}", flush=True)

    run_path = "/" + run_loc.split("://", 1)[1].split("/", 1)[1]
    status, _, _ = _http_request(rest_host, rest_port, "DELETE", run_path, args.family)
    if status not in (200, 204):
        print(f"dial-client: stop DELETE -> {status}", file=sys.stderr, flush=True)
        return 1
    print("dial-client: stop DELETE ok", flush=True)
    print("dial-client: all rewrites confirmed (LOCATION, Application-URL, 201 Location)", flush=True)
    return 0
