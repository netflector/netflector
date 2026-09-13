"""Aggregate the protocol case catalogs in stable CLI order."""

from __future__ import annotations

from cases.dial import DIAL_ADDRESS_CHANGE_CASES, DIAL_CASES, DIAL_RECREATE_CASES
from cases.discovery import ANSWER_CASES, ROUNDTRIP_CASES, SEARCH_RECREATE_CASES
from cases.lifecycle import ADDRESS_CHANGE_CASES, RECREATE_CASES
from cases.mdns import MDNS_CASES
from cases.models import (
    AddressChangeCase,
    AnswerCase,
    DialAddressChangeCase,
    DialCase,
    DialRecreateCase,
    RecreateCase,
    RoundTripCase,
    SearchRecreateCase,
    TestCase,
)
from cases.ssdp import SSDP_CASES
from cases.udp import PEERS_CASES, RELAY_CASES
from cases.wol import TEST_CASES
from cases.wsd import WSD_CASES

ALL_CASES: list[
    TestCase
    | RoundTripCase
    | SearchRecreateCase
    | DialCase
    | DialAddressChangeCase
    | AddressChangeCase
    | RecreateCase
    | DialRecreateCase
    | AnswerCase
] = [
    *TEST_CASES,
    *MDNS_CASES,
    *SSDP_CASES,
    *WSD_CASES,
    *RELAY_CASES,
    *PEERS_CASES,
    *ROUNDTRIP_CASES,
    *ANSWER_CASES,
    *SEARCH_RECREATE_CASES,
    *DIAL_CASES,
    *DIAL_ADDRESS_CHANGE_CASES,
    *ADDRESS_CHANGE_CASES,
    *RECREATE_CASES,
    *DIAL_RECREATE_CASES,
]
