from __future__ import annotations

import sys
import time

from cases.models import AnswerCase, RoundTripCase, SearchRecreateCase

from fixtures import SEARCHER_SOURCE_PORT
from harness.environment import Environment
from harness.settings import (
    NETFLECTOR_IFNAMES,
    NETFLECTOR_SOURCE_IFNAME,
    RECEIVER_IFNAME,
)


class RoundTripRunner:
    # The SSDP M-SEARCH round trip: a searcher on the source segment sends an M-SEARCH;
    # netflector relays it to the group on the target from a reserved port; a responder (device)
    # on the target unicasts a 200 OK back to that reserved port; netflector proxies the reply
    # to the searcher. The negative case (expect_reply=False) starts no responder and asserts the
    # searcher hears nothing -- netflector must not fabricate a reply.
    def __init__(
        self, env: Environment, case: RoundTripCase | SearchRecreateCase
    ) -> None:
        self.env = env
        self.rt = case
        self.searcher_seg, self.responder_seg = (
            ("source", "target")
            if case.direction == "forward"
            else ("target", "source")
        )

    def start_responder(self) -> None:
        ifname = self.env.backend.helper_ifname(RECEIVER_IFNAME)
        if self.rt.responder_unicast:
            listen = [
                "--bind-address",
                self.env.backend.helper_address(self.responder_seg, self.rt.family),
            ]
        else:
            listen = ["--join-group", self.rt.group, "--interface", ifname]
        self.env.backend.start_probe(
            "responder",
            self.responder_seg,
            ifname,
            [
                "respond",
                "--port",
                str(self.rt.port),
                "--timeout",
                str(self.rt.timeout_seconds),
                "--family",
                str(self.rt.family),
                *listen,
                "--reply-hex",
                self.rt.reply_hex,
            ],
            pin_address=self.rt.responder_unicast,
        )
        self.env.wait_for_log("responder", "responder ready", "responder")

    def run_searcher(self) -> None:
        expectation = (
            ["--expect-payload-hex", self.rt.reply_hex]
            if self.rt.expect_reply
            else ["--expect-none"]
        )
        ifname = self.env.backend.helper_ifname(NETFLECTOR_IFNAMES[self.searcher_seg])
        self.env.backend.start_probe(
            "searcher",
            self.searcher_seg,
            ifname,
            [
                "search",
                "--source-port",
                str(SEARCHER_SOURCE_PORT),
                "--port",
                str(self.rt.port),
                "--address",
                self.rt.group,
                "--interface",
                ifname,
                "--family",
                str(self.rt.family),
                "--payload-hex",
                self.rt.probe_hex,
                "--timeout",
                str(self.rt.timeout_seconds),
                *expectation,
            ],
        )

    def wait_for_searcher(self) -> None:
        exit_code = self.env.backend.wait("searcher")
        out, err = self.env.backend.logs("searcher")
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)
        if exit_code != 0:
            raise RuntimeError(f"searcher failed with exit code {exit_code}")

    def run(self) -> None:
        if self.rt.expect_reply:
            self.start_responder()  # must be listening before the search goes out
        self.run_searcher()
        self.wait_for_searcher()
        # The per-searcher session must be torn down once it expires (SSDP: MX 2 + 2s grace ~= 4s;
        # WSD: a fixed 5s window): the deadline timer sweeps it, drops its port reservation, and
        # unregisters its response capture -- logged by netflector. wait_for_log raises if it
        # never fires.
        self.env.wait_for_log("netflector", self.rt.evict_log, "session eviction")
        print(f"{self.rt.name}: session evicted after expiry", flush=True)
        print(f"PASS {self.rt.name}", flush=True)
        if self.env.args.show_netflector_logs:
            time.sleep(0.5)
            self.env.print_netflector_logs()


class AnswerRunner:
    # See AnswerCase. The receiver sits on the sender's segment, unlike a TestCase's, and skips
    # the sender's own query, which the group hands it too.
    def __init__(self, env: Environment, case: AnswerCase) -> None:
        self.env = env
        self.answer = case
        self.sender_segment, self.receiver_segment = "source", "target"

    def run(self) -> None:
        ifname = self.env.backend.helper_ifname(RECEIVER_IFNAME)
        # Pinned: with peers on the source too, the answer comes to it as a unicast copy.
        self.env.backend.start_probe(
            "receiver",
            self.sender_segment,
            ifname,
            [
                "receive",
                "--port",
                str(self.answer.port),
                "--timeout",
                str(self.answer.timeout_seconds),
                "--family",
                str(self.answer.family),
                "--join-group",
                self.answer.group,
                "--interface",
                ifname,
                "--expect-payload-hex",
                self.answer.answer_hex,
                "--ignore-payload-hex",
                self.answer.query_hex,
            ],
            pin_address=True,
        )
        self.env.wait_for_log("receiver", "receiver ready", "receiver")
        self.env.backend.start_probe(
            "responder",
            self.receiver_segment,
            ifname,
            [
                "respond",
                "--port",
                str(self.answer.port),
                "--timeout",
                str(self.answer.timeout_seconds),
                "--family",
                str(self.answer.family),
                "--bind-address",
                self.env.backend.helper_address(
                    self.receiver_segment, self.answer.family
                ),
                "--reply-hex",
                self.answer.answer_hex,
            ],
            pin_address=True,
        )
        self.env.wait_for_log("responder", "responder ready", "responder")
        sender_ifname = self.env.backend.helper_ifname(NETFLECTOR_SOURCE_IFNAME)
        self.env.backend.start_probe(
            "sender",
            self.sender_segment,
            sender_ifname,
            [
                "send",
                "--payload-hex",
                self.answer.query_hex,
                "--port",
                str(self.answer.port),
                "--address",
                self.answer.group,
                "--interface",
                sender_ifname,
            ],
            detach=False,
        )
        self.env.wait_for_result()
        print(f"PASS {self.answer.name}", flush=True)
        if self.env.args.show_netflector_logs:
            time.sleep(0.5)
            self.env.print_netflector_logs()


class SearchRecreateRunner(RoundTripRunner):
    # Reuses the discovery probe operations with an explicit environment, but opens a session,
    # recreates one interface, and re-searches. A target recreation drops the session (asserted via
    # the cleared-sessions log). A source recreation must never clear sessions, but whether the
    # retransmit REUSES the baseline session is wall-clock luck: the window is MX + grace, MX is
    # spec-capped at 5, and a slow lane (TCG) can legitimately let it lapse mid-recreation. So the
    # source branch asserts a second reflected search (reused or fresh, both prove the ingress rebound
    # and re-joined) plus the absence of the target-change clearing line. The source retransmit is
    # fire-and-forget -- a reused session routes the reply to the baseline container's MAC, so no
    # round trip is expected; the target retransmit expects the 200 OK (its fresh session carries the
    # retransmit's own MAC). The responder is restarted only for the target.

    def _search(self, role: str, *, no_wait: bool = False) -> None:
        # One M-SEARCH; with no_wait, send and exit (any reply is routed elsewhere), else assert the
        # 200 OK proxies back.
        expectation = (
            ["--no-wait"] if no_wait else ["--expect-payload-hex", self.rt.reply_hex]
        )
        ifname = self.env.backend.helper_ifname(NETFLECTOR_SOURCE_IFNAME)
        self.env.backend.start_probe(
            role,
            "source",
            ifname,
            [
                "search",
                "--source-port",
                str(SEARCHER_SOURCE_PORT),
                "--port",
                str(self.rt.port),
                "--address",
                self.rt.group,
                "--interface",
                ifname,
                "--family",
                str(self.rt.family),
                "--payload-hex",
                self.rt.probe_hex,
                "--timeout",
                str(self.rt.timeout_seconds),
                *expectation,
            ],
        )
        exit_code = self.env.backend.wait(role)
        out, err = self.env.backend.logs(role)
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)
        if exit_code != 0:
            raise RuntimeError(f"{role} failed with exit code {exit_code}")

    def _recreate(self) -> None:
        # With the decoy, occupy the freed index before recreating so the interface returns on a
        # different one (the changed-index path); without it, FreeBSD reuses the index (the same-index
        # path). Both must behave the same, so both variants run.
        interface = self.rt.interface
        ifname = NETFLECTOR_IFNAMES[interface]
        self.env.backend.delete_interface(interface)
        self.env.wait_for_log(
            "netflector", f"interface {ifname} is gone", f"{interface} deletion"
        )
        if self.rt.decoy:
            self.env.backend.add_decoy_interface()
        self.env.backend.recreate_interface(interface)
        self.env.wait_for_log(
            "netflector",
            f"interface {ifname}: returned as ifindex",
            f"{interface} recreation",
        )
        if self.rt.decoy:
            self.env.backend.remove_decoy_interface()

    def run(self) -> None:

        # First search: opens a session (its reservation + response registration are on the target).
        self.start_responder()
        self._search("searcher-baseline")
        print(f"{self.rt.name}: baseline round trip before the recreation", flush=True)

        # Destroy + recreate one interface. Target: the reservation + response registration die with it,
        # so the dispatcher drops the session; a fresh searcher re-opens and round-trips. Source:
        # nothing session-side lives there, so the session lives out its MX + grace window untouched --
        # which a fast lane carries across the recreation and a slow one may not.
        self._recreate()

        if self.rt.interface == "target":
            # A fresh responder answers the retransmit's fresh session (the baseline's exited, and on the
            # native fabrics the target's wire died with it).
            self.env.backend.remove("responder")
            self.start_responder()
            self._search("searcher-retransmit")
            self.env.wait_for_log(
                "netflector",
                "cleared all sessions after the target interface changed",
                "session cleared",
            )
            print(
                f"{self.rt.name}: session cleared, round trip resumed after the target recreation",
                flush=True,
            )
        else:
            # Fire-and-forget: the retransmit must be reflected again, proving the source ingress
            # rebound and re-joined its group. Both reflect lines contain this marker, and the
            # baseline contributed one, so a count of two accepts reuse and fresh alike.
            self._search("searcher-retransmit", no_wait=True)
            self.env.wait_for_log(
                "netflector", "SSDP search from", "post-recreation reflection", count=2
            )
            out, err = self.env.backend.logs("netflector")
            if (
                "cleared all sessions after the target interface changed"
                in f"{out}{err}"
            ):
                raise RuntimeError(
                    "a source recreation cleared sessions; only a target change may"
                )
            mode = (
                "session reused"
                if "re-reflected SSDP search" in f"{out}{err}"
                else "fresh session, the MX window lapsed"
            )
            print(
                f"{self.rt.name}: search reflected after the source recreation ({mode}); "
                "sessions never cleared",
                flush=True,
            )
        print(f"PASS {self.rt.name}", flush=True)
        if self.env.args.show_netflector_logs:
            time.sleep(0.5)
            self.env.print_netflector_logs()
