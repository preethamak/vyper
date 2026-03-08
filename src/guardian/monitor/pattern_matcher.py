"""Anomaly detection engine.

Implements five rule-based anomaly detectors that compare live
transaction records against a stored ``BaselineProfile``:

  1. Gas spike detection
  2. Failed transaction clustering
  3. Rapid balance drain
  4. Unusual call patterns
  5. Reentrancy indicator detection

All logic is pure Python — no platform-specific code.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from guardian.models import AlertSeverity, BaselineProfile, MonitorAlert, TransactionRecord
from guardian.utils.logger import get_logger

log = get_logger("monitor.pattern_matcher")


def _alert_id() -> str:
    return uuid.uuid4().hex[:12]


class PatternMatcher:
    """Compare live transactions against a baseline profile and emit alerts.

    Args:
        baseline: A previously computed ``BaselineProfile``.
        gas_spike_factor: Multiplier above (mean + stdev) to flag gas spikes.
        failed_cluster_window_secs: Window (seconds) for clustering failures.
        failed_cluster_threshold: Min failures in the window to alert.
        drain_threshold_wei: Value drain threshold (in wei) within the window.
        drain_window_secs: Window for rapid-drain detection.
    """

    def __init__(
        self,
        baseline: BaselineProfile,
        *,
        gas_spike_factor: float = 2.5,
        failed_cluster_window_secs: float = 300,
        failed_cluster_threshold: int = 5,
        drain_threshold_wei: int = 10**18,  # 1 ETH
        drain_window_secs: float = 600,
    ) -> None:
        self.baseline = baseline
        self.gas_spike_factor = gas_spike_factor
        self.failed_cluster_window_secs = failed_cluster_window_secs
        self.failed_cluster_threshold = failed_cluster_threshold
        self.drain_threshold_wei = drain_threshold_wei
        self.drain_window_secs = drain_window_secs

        # Rolling buffers
        self._recent_failures: list[TransactionRecord] = []
        self._recent_outflows: list[TransactionRecord] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, record: TransactionRecord) -> list[MonitorAlert]:
        """Run all rules against *record* and return any alerts."""
        alerts: list[MonitorAlert] = []
        for rule in (
            self._rule_gas_spike,
            self._rule_failed_cluster,
            self._rule_rapid_drain,
            self._rule_unusual_call,
            self._rule_reentrancy_indicator,
        ):
            alert = rule(record)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def check_many(self, records: list[TransactionRecord]) -> list[MonitorAlert]:
        alerts: list[MonitorAlert] = []
        for rec in records:
            alerts.extend(self.check(rec))
        return alerts

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def _rule_gas_spike(self, rec: TransactionRecord) -> MonitorAlert | None:
        """Rule 1: Detect gas usage significantly above the baseline."""
        threshold = self.baseline.avg_gas + self.baseline.std_gas * self.gas_spike_factor
        if threshold <= 0:
            return None
        if rec.gas_used <= threshold:
            return None

        return MonitorAlert(
            alert_id=_alert_id(),
            severity=AlertSeverity.WARNING,
            rule_name="gas_spike",
            title="Abnormal gas usage detected",
            description=(
                f"Transaction {rec.tx_hash} used {rec.gas_used:,} gas, "
                f"which exceeds the baseline threshold of {threshold:,.0f} "
                f"(mean {self.baseline.avg_gas:,.0f} + {self.gas_spike_factor}*stddev "
                f"{self.baseline.std_gas:,.0f})."
            ),
            contract_address=self.baseline.contract_address,
            tx_hash=rec.tx_hash,
            metadata={"gas_used": rec.gas_used, "threshold": int(threshold)},
        )

    def _rule_failed_cluster(self, rec: TransactionRecord) -> MonitorAlert | None:
        """Rule 2: Cluster of failed transactions within a time window."""
        now = rec.timestamp
        cutoff = now - timedelta(seconds=self.failed_cluster_window_secs)
        self._recent_failures = [r for r in self._recent_failures if r.timestamp >= cutoff]
        if not rec.success:
            self._recent_failures.append(rec)

        if len(self._recent_failures) >= self.failed_cluster_threshold:
            alert = MonitorAlert(
                alert_id=_alert_id(),
                severity=AlertSeverity.CRITICAL,
                rule_name="failed_tx_cluster",
                title="Cluster of failed transactions",
                description=(
                    f"{len(self._recent_failures)} failed transactions observed in the "
                    f"last {self.failed_cluster_window_secs:.0f}s window."
                ),
                contract_address=self.baseline.contract_address,
                tx_hash=rec.tx_hash,
                metadata={"failures": len(self._recent_failures)},
            )
            self._recent_failures.clear()
            return alert
        return None

    def _rule_rapid_drain(self, rec: TransactionRecord) -> MonitorAlert | None:
        """Rule 3: Large outgoing value in a short window."""
        # Only consider outgoing from contract (contract is sender)
        if rec.from_address != self.baseline.contract_address:
            return None
        if rec.value_wei <= 0:
            return None

        now = rec.timestamp
        cutoff = now - timedelta(seconds=self.drain_window_secs)
        self._recent_outflows = [r for r in self._recent_outflows if r.timestamp >= cutoff]
        self._recent_outflows.append(rec)

        total = sum(r.value_wei for r in self._recent_outflows)
        if total < self.drain_threshold_wei:
            return None

        alert = MonitorAlert(
            alert_id=_alert_id(),
            severity=AlertSeverity.CRITICAL,
            rule_name="rapid_balance_drain",
            title="Rapid balance drain detected",
            description=(
                f"Total outflow of {total / 10**18:.4f} ETH in the last "
                f"{self.drain_window_secs:.0f}s exceeds threshold of "
                f"{self.drain_threshold_wei / 10**18:.4f} ETH."
            ),
            contract_address=self.baseline.contract_address,
            tx_hash=rec.tx_hash,
            metadata={"total_outflow_wei": total, "threshold_wei": self.drain_threshold_wei},
        )
        self._recent_outflows.clear()
        return alert

    def _rule_unusual_call(self, rec: TransactionRecord) -> MonitorAlert | None:
        """Rule 4: Function selector never seen in the baseline."""
        if not rec.function_selector:
            return None
        if not self.baseline.function_call_counts:
            return None
        if rec.function_selector in self.baseline.function_call_counts:
            return None

        return MonitorAlert(
            alert_id=_alert_id(),
            severity=AlertSeverity.WARNING,
            rule_name="unusual_call_pattern",
            title="Unknown function selector invoked",
            description=(
                f"Transaction {rec.tx_hash} invoked selector {rec.function_selector} "
                "which was never observed during the baseline window."
            ),
            contract_address=self.baseline.contract_address,
            tx_hash=rec.tx_hash,
            metadata={"selector": rec.function_selector},
        )

    def _rule_reentrancy_indicator(self, rec: TransactionRecord) -> MonitorAlert | None:
        """Rule 5: Heuristic reentrancy detection.

        Flags transactions with very high gas AND a ``withdraw`` / ``0x3ccfd60b``
        selector, since reentrancy attacks typically exhaust the gas limit.
        """
        suspicious_selectors = {"0x3ccfd60b", "0x2e1a7d4d"}  # withdraw(), withdraw(uint256)
        if rec.function_selector not in suspicious_selectors:
            return None

        # Gas must be well above baseline
        gas_threshold = self.baseline.avg_gas + self.baseline.std_gas * 2.0
        if gas_threshold <= 0 or rec.gas_used <= gas_threshold:
            return None

        return MonitorAlert(
            alert_id=_alert_id(),
            severity=AlertSeverity.CRITICAL,
            rule_name="reentrancy_indicator",
            title="Possible reentrancy attack",
            description=(
                f"Withdraw-like transaction {rec.tx_hash} consumed {rec.gas_used:,} gas "
                f"(threshold {gas_threshold:,.0f}).  This pattern is consistent with a "
                "reentrancy exploit."
            ),
            contract_address=self.baseline.contract_address,
            tx_hash=rec.tx_hash,
            metadata={"gas_used": rec.gas_used, "selector": rec.function_selector},
        )
