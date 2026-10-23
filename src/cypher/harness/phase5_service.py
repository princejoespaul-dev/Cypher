"""Convenience facade aggregating the Phase 5 service modules."""
from __future__ import annotations

from cypher.harness.fixverify import FixVerificationService
from cypher.harness.phase5_ports import Phase5Repository, PureAdjudicator, ReplayRunner
from cypher.harness.readjudicate import ReadjudicationService
from cypher.harness.suites import RegressionSuiteService
from cypher.harness.findings import FindingsService
from cypher.harness.phase5_ports import Clock, Rng, SystemClock, SystemRng


class Phase5Services:
    def __init__(self, repository: Phase5Repository, replay_runner: ReplayRunner, adjudicator: PureAdjudicator,
                 *, clock: Clock | None = None, rng: Rng | None = None) -> None:
        self.repository = repository
        effective_clock = clock or SystemClock()
        effective_rng = rng or SystemRng()
        self.fix_verification = FixVerificationService(repository, clock=effective_clock, rng=effective_rng)
        self.regression_suites = RegressionSuiteService(repository, replay_runner, clock=effective_clock, rng=effective_rng)
        self.readjudication = ReadjudicationService(repository, adjudicator, clock=effective_clock, rng=effective_rng)
        self.findings = FindingsService(repository)
