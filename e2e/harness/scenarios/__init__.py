"""Select scenario behavior from the case type."""

from __future__ import annotations

from typing import Protocol

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

from harness.environment import Environment
from harness.scenarios.datagram import DatagramScenario
from harness.scenarios.dial import (
    DialAddressChangeRunner,
    DialRecreateRunner,
    DialRunner,
)
from harness.scenarios.discovery import (
    AnswerRunner,
    RoundTripRunner,
    SearchRecreateRunner,
)
from harness.scenarios.lifecycle import AddressChangeRunner, RecreateRunner


class Scenario(Protocol):
    def run(self) -> None: ...


def make_runner(
    env: Environment,
    case: TestCase
    | RoundTripCase
    | SearchRecreateCase
    | DialCase
    | DialAddressChangeCase
    | AddressChangeCase
    | RecreateCase
    | DialRecreateCase
    | AnswerCase,
) -> Scenario:
    if isinstance(case, AnswerCase):
        return AnswerRunner(env, case)
    if isinstance(case, SearchRecreateCase):
        return SearchRecreateRunner(env, case)
    if isinstance(case, RoundTripCase):
        return RoundTripRunner(env, case)
    if isinstance(case, DialRecreateCase):
        return DialRecreateRunner(env, case)
    if isinstance(case, DialAddressChangeCase):
        return DialAddressChangeRunner(env, case)
    if isinstance(case, DialCase):
        return DialRunner(env, case)
    if isinstance(case, RecreateCase):
        return RecreateRunner(env, case)
    if isinstance(case, AddressChangeCase):
        return AddressChangeRunner(env, case)
    return DatagramScenario(env, case)
