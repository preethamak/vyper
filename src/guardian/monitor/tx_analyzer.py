"""Transaction pattern analyser.

Decodes raw transaction records into structured insights: function
selectors, gas statistics, value flows, and call frequency tables.
All logic is pure Python — no platform-specific code.
"""

from __future__ import annotations

import itertools
import statistics
from collections import Counter

from guardian.models import BaselineProfile, TransactionRecord
from guardian.utils.logger import get_logger

log = get_logger("monitor.tx_analyzer")


# Well-known 4-byte selectors for common patterns (expand as needed).
_KNOWN_SELECTORS: dict[str, str] = {
    "0xa9059cbb": "transfer(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0x70a08231": "balanceOf(address)",
    "0x18160ddd": "totalSupply()",
    "0xdd62ed3e": "allowance(address,address)",
    "0x3ccfd60b": "withdraw()",
    "0xd0e30db0": "deposit()",
}


class TxAnalyzer:
    """Analyse decoded transactions against expected patterns.

    Maintains rolling statistics across all transactions fed to it and
    produces derived metrics consumed by the pattern matcher and
    baseline profiler.
    """

    def __init__(self, *, max_records: int = 50_000) -> None:
        self._max_records = max(1, int(max_records))
        self._records: list[TransactionRecord] = []
        self._selector_counts: Counter[str] = Counter()
        self._gas_values: list[int] = []
        self._value_flows: list[int] = []
        self._failure_count: int = 0
        self._sender_counts: Counter[str] = Counter()

    # ------------------------------------------------------------------
    # Feed API
    # ------------------------------------------------------------------

    def ingest(self, record: TransactionRecord) -> None:
        """Process a single ``TransactionRecord``."""
        if len(self._records) >= self._max_records:
            self._evict_oldest()

        self._records.append(record)

        if record.function_selector:
            self._selector_counts[record.function_selector] += 1

        self._gas_values.append(record.gas_used)
        self._value_flows.append(record.value_wei)
        self._sender_counts[record.from_address] += 1

        if not record.success:
            self._failure_count += 1

    def _evict_oldest(self) -> None:
        """Drop oldest record to keep memory bounded."""
        if not self._records:
            return
        oldest = self._records.pop(0)

        if oldest.function_selector:
            selector = oldest.function_selector
            self._selector_counts[selector] -= 1
            if self._selector_counts[selector] <= 0:
                self._selector_counts.pop(selector, None)

        if self._gas_values:
            self._gas_values.pop(0)
        if self._value_flows:
            self._value_flows.pop(0)

        self._sender_counts[oldest.from_address] -= 1
        if self._sender_counts[oldest.from_address] <= 0:
            self._sender_counts.pop(oldest.from_address, None)

        if not oldest.success and self._failure_count > 0:
            self._failure_count -= 1

    def ingest_many(self, records: list[TransactionRecord]) -> None:
        for rec in records:
            self.ingest(rec)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @property
    def total(self) -> int:
        return len(self._records)

    @property
    def failed_ratio(self) -> float:
        if not self._records:
            return 0.0
        return self._failure_count / len(self._records)

    def gas_stats(self) -> dict[str, float]:
        """Return min / max / mean / stdev of gas usage."""
        if not self._gas_values:
            return {"min": 0, "max": 0, "mean": 0, "stdev": 0}
        vals = self._gas_values
        return {
            "min": float(min(vals)),
            "max": float(max(vals)),
            "mean": statistics.mean(vals),
            "stdev": statistics.pstdev(vals),
        }

    def value_stats(self) -> dict[str, float]:
        """Return min / max / mean / stdev of ETH value transferred (in wei)."""
        if not self._value_flows:
            return {"min": 0, "max": 0, "mean": 0, "stdev": 0}
        vals = self._value_flows
        return {
            "min": float(min(vals)),
            "max": float(max(vals)),
            "mean": statistics.mean(vals),
            "stdev": statistics.pstdev(vals),
        }

    def function_frequency(self) -> dict[str, int]:
        """Return selector → call-count mapping."""
        return dict(self._selector_counts.most_common())

    def resolve_selector(self, selector: str) -> str:
        """Return a human-readable function name if known, else the raw hex."""
        return _KNOWN_SELECTORS.get(selector.lower(), selector)

    def top_senders(self, n: int = 10) -> list[tuple[str, int]]:
        return self._sender_counts.most_common(n)

    def average_tx_interval(self) -> float:
        """Average seconds between consecutive transactions."""
        if len(self._records) < 2:
            return 0.0
        sorted_recs = sorted(self._records, key=lambda r: r.timestamp)
        deltas: list[float] = []
        for a, b in itertools.pairwise(sorted_recs):
            deltas.append((b.timestamp - a.timestamp).total_seconds())
        return statistics.mean(deltas) if deltas else 0.0

    def build_baseline_snapshot(self, contract_address: str) -> BaselineProfile | None:
        """Build a ``BaselineProfile`` from ingested records."""
        if not self._records:
            return None

        sorted_recs = sorted(self._records, key=lambda r: r.timestamp)
        gas = self.gas_stats()

        return BaselineProfile(
            contract_address=contract_address,
            window_start=sorted_recs[0].timestamp,
            window_end=sorted_recs[-1].timestamp,
            tx_count=len(self._records),
            avg_gas=gas["mean"],
            std_gas=gas["stdev"],
            avg_value_wei=self.value_stats()["mean"],
            function_call_counts=self.function_frequency(),
            avg_tx_interval_secs=self.average_tx_interval(),
            failed_tx_ratio=self.failed_ratio,
            max_observed_gas=int(gas["max"]),
        )

    def reset(self) -> None:
        """Clear all accumulated data."""
        self._records.clear()
        self._selector_counts.clear()
        self._gas_values.clear()
        self._value_flows.clear()
        self._failure_count = 0
        self._sender_counts.clear()
