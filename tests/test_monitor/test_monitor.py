"""Tests for the live monitoring sub-package (Phase 2).

All tests use synthetic TransactionRecord objects — no real Web3
connection or RPC node required.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guardian.models import (
    AlertSeverity,
    BaselineProfile,
    MonitorAlert,
    TransactionRecord,
)

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

CONTRACT = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
OTHER = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _tx(
    *,
    tx_hash: str = "0xabc123",
    block_number: int = 100,
    from_addr: str = OTHER,
    to_addr: str = CONTRACT,
    gas_used: int = 50_000,
    gas_price: int = 20_000_000_000,
    value_wei: int = 0,
    selector: str | None = None,
    success: bool = True,
    ts_offset_secs: float = 0,
) -> TransactionRecord:
    return TransactionRecord(
        tx_hash=tx_hash,
        block_number=block_number,
        timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=ts_offset_secs),
        from_address=from_addr,
        to_address=to_addr,
        value_wei=value_wei,
        gas_used=gas_used,
        gas_price_wei=gas_price,
        input_data=f"{selector}000000" if selector else "0x",
        function_selector=selector,
        success=success,
    )


def _baseline(**overrides: Any) -> BaselineProfile:
    defaults = dict(
        contract_address=CONTRACT,
        window_start=datetime(2025, 1, 1, tzinfo=timezone.utc),
        window_end=datetime(2025, 1, 1, 1, tzinfo=timezone.utc),
        tx_count=100,
        avg_gas=50_000,
        std_gas=5_000,
        avg_value_wei=0,
        function_call_counts={"0xa9059cbb": 60, "0x3ccfd60b": 40},
        avg_tx_interval_secs=36,
        failed_tx_ratio=0.02,
        max_observed_gas=80_000,
    )
    defaults.update(overrides)
    return BaselineProfile(**defaults)


# ===================================================================
# TxAnalyzer
# ===================================================================


class TestTxAnalyzer:
    def test_ingest_and_totals(self) -> None:
        from guardian.monitor.tx_analyzer import TxAnalyzer

        a = TxAnalyzer()
        assert a.total == 0

        a.ingest(_tx())
        assert a.total == 1

        a.ingest_many([_tx(), _tx(success=False)])
        assert a.total == 3
        assert a.failed_ratio == pytest.approx(1 / 3)

    def test_gas_stats(self) -> None:
        from guardian.monitor.tx_analyzer import TxAnalyzer

        a = TxAnalyzer()
        a.ingest(_tx(gas_used=100))
        a.ingest(_tx(gas_used=200))
        a.ingest(_tx(gas_used=300))

        g = a.gas_stats()
        assert g["min"] == 100
        assert g["max"] == 300
        assert g["mean"] == 200

    def test_value_stats(self) -> None:
        from guardian.monitor.tx_analyzer import TxAnalyzer

        a = TxAnalyzer()
        a.ingest(_tx(value_wei=10**18))
        a.ingest(_tx(value_wei=0))

        v = a.value_stats()
        assert v["min"] == 0
        assert v["max"] == 10**18
        assert v["mean"] == 5 * 10**17

    def test_function_frequency_and_resolve(self) -> None:
        from guardian.monitor.tx_analyzer import TxAnalyzer

        a = TxAnalyzer()
        a.ingest(_tx(selector="0xa9059cbb"))
        a.ingest(_tx(selector="0xa9059cbb"))
        a.ingest(_tx(selector="0x3ccfd60b"))

        freq = a.function_frequency()
        assert freq["0xa9059cbb"] == 2
        assert freq["0x3ccfd60b"] == 1
        assert a.resolve_selector("0xa9059cbb") == "transfer(address,uint256)"
        assert a.resolve_selector("0xdeadbeef") == "0xdeadbeef"  # unknown

    def test_top_senders(self) -> None:
        from guardian.monitor.tx_analyzer import TxAnalyzer

        a = TxAnalyzer()
        a.ingest(_tx(from_addr="0x111"))
        a.ingest(_tx(from_addr="0x111"))
        a.ingest(_tx(from_addr="0x222"))

        top = a.top_senders(2)
        assert top[0] == ("0x111", 2)

    def test_average_tx_interval(self) -> None:
        from guardian.monitor.tx_analyzer import TxAnalyzer

        a = TxAnalyzer()
        a.ingest(_tx(ts_offset_secs=0))
        a.ingest(_tx(ts_offset_secs=10))
        a.ingest(_tx(ts_offset_secs=20))

        assert a.average_tx_interval() == pytest.approx(10.0)

    def test_build_baseline_snapshot(self) -> None:
        from guardian.monitor.tx_analyzer import TxAnalyzer

        a = TxAnalyzer()
        a.ingest(_tx(gas_used=100, selector="0xa9059cbb", ts_offset_secs=0))
        a.ingest(_tx(gas_used=200, selector="0xa9059cbb", ts_offset_secs=10))

        profile = a.build_baseline_snapshot(CONTRACT)
        assert profile is not None
        assert profile.contract_address == CONTRACT
        assert profile.tx_count == 2
        assert profile.avg_gas == pytest.approx(150.0)
        assert "0xa9059cbb" in profile.function_call_counts

    def test_build_baseline_empty(self) -> None:
        from guardian.monitor.tx_analyzer import TxAnalyzer

        a = TxAnalyzer()
        assert a.build_baseline_snapshot(CONTRACT) is None

    def test_reset(self) -> None:
        from guardian.monitor.tx_analyzer import TxAnalyzer

        a = TxAnalyzer()
        a.ingest(_tx())
        a.reset()
        assert a.total == 0
        assert a.gas_stats()["mean"] == 0


# ===================================================================
# PatternMatcher
# ===================================================================


class TestPatternMatcher:
    def test_gas_spike_alert(self) -> None:
        from guardian.monitor.pattern_matcher import PatternMatcher

        bl = _baseline(avg_gas=50_000, std_gas=5_000)
        pm = PatternMatcher(bl, gas_spike_factor=2.0)

        # Below threshold → no alert
        normal = _tx(gas_used=59_000)
        assert pm.check(normal) == []

        # Above threshold (50_000 + 2*5_000 = 60_000) → alert
        spike = _tx(gas_used=70_000, tx_hash="0xspike")
        alerts = pm.check(spike)
        assert any(a.rule_name == "gas_spike" for a in alerts)

    def test_failed_tx_cluster_alert(self) -> None:
        from guardian.monitor.pattern_matcher import PatternMatcher

        bl = _baseline()
        pm = PatternMatcher(bl, failed_cluster_threshold=3, failed_cluster_window_secs=60)

        # 3 failures in quick succession
        alerts = []
        for i in range(3):
            alerts.extend(
                pm.check(_tx(success=False, tx_hash=f"0xfail{i}", ts_offset_secs=float(i)))
            )
        assert any(a.rule_name == "failed_tx_cluster" for a in alerts)

    def test_rapid_drain_alert(self) -> None:
        from guardian.monitor.pattern_matcher import PatternMatcher

        bl = _baseline()
        pm = PatternMatcher(bl, drain_threshold_wei=10**18, drain_window_secs=600)

        # Outflow from contract
        big_tx = _tx(
            from_addr=CONTRACT,
            to_addr=OTHER,
            value_wei=2 * 10**18,
            tx_hash="0xdrain",
        )
        alerts = pm.check(big_tx)
        assert any(a.rule_name == "rapid_balance_drain" for a in alerts)

    def test_rapid_drain_ignores_inbound(self) -> None:
        from guardian.monitor.pattern_matcher import PatternMatcher

        bl = _baseline()
        pm = PatternMatcher(bl, drain_threshold_wei=10**18)

        inbound = _tx(from_addr=OTHER, to_addr=CONTRACT, value_wei=5 * 10**18)
        assert pm.check(inbound) == [] or all(
            a.rule_name != "rapid_balance_drain" for a in pm.check(inbound)
        )

    def test_unusual_call_alert(self) -> None:
        from guardian.monitor.pattern_matcher import PatternMatcher

        bl = _baseline(function_call_counts={"0xa9059cbb": 50})
        pm = PatternMatcher(bl)

        # Known selector → no alert
        known = _tx(selector="0xa9059cbb")
        alerts_known = [a for a in pm.check(known) if a.rule_name == "unusual_call_pattern"]
        assert len(alerts_known) == 0

        # Unknown selector → alert
        unknown = _tx(selector="0xdeadbeef", tx_hash="0xunknown")
        alerts_unknown = [a for a in pm.check(unknown) if a.rule_name == "unusual_call_pattern"]
        assert len(alerts_unknown) == 1

    def test_reentrancy_indicator(self) -> None:
        from guardian.monitor.pattern_matcher import PatternMatcher

        bl = _baseline(avg_gas=50_000, std_gas=5_000)
        pm = PatternMatcher(bl)

        # withdraw selector + high gas → alert
        reentrant = _tx(
            selector="0x3ccfd60b",
            gas_used=200_000,
            tx_hash="0xreenter",
        )
        alerts = pm.check(reentrant)
        assert any(a.rule_name == "reentrancy_indicator" for a in alerts)

    def test_check_many(self) -> None:
        from guardian.monitor.pattern_matcher import PatternMatcher

        bl = _baseline(avg_gas=50_000, std_gas=5_000)
        pm = PatternMatcher(bl, gas_spike_factor=2.0)

        txs = [_tx(gas_used=70_000, tx_hash=f"0xbatch{i}") for i in range(3)]
        alerts = pm.check_many(txs)
        gas_alerts = [a for a in alerts if a.rule_name == "gas_spike"]
        assert len(gas_alerts) == 3


# ===================================================================
# BaselineProfiler
# ===================================================================


class TestBaselineProfiler:
    def test_build_profile(self) -> None:
        from guardian.monitor.baseline import BaselineProfiler

        bp = BaselineProfiler(CONTRACT, storage_dir=Path("/tmp/guardian_test_baselines"))
        bp.ingest(_tx(gas_used=100, ts_offset_secs=0))
        bp.ingest(_tx(gas_used=200, ts_offset_secs=10))

        profile = bp.build()
        assert profile.contract_address == CONTRACT.lower()
        assert profile.tx_count == 2
        assert profile.avg_gas == pytest.approx(150.0)

    def test_save_and_load(self, tmp_path: Path) -> None:
        from guardian.monitor.baseline import BaselineProfiler

        bp = BaselineProfiler(CONTRACT, storage_dir=tmp_path)
        bp.ingest(_tx(gas_used=100, selector="0xa9059cbb", ts_offset_secs=0))
        bp.ingest(_tx(gas_used=200, selector="0xa9059cbb", ts_offset_secs=10))
        profile = bp.build()
        saved = bp.save()
        assert saved.exists()

        # Load in a fresh profiler
        bp2 = BaselineProfiler(CONTRACT, storage_dir=tmp_path)
        loaded = bp2.load()
        assert loaded is not None
        assert loaded.tx_count == 2
        assert loaded.avg_gas == profile.avg_gas

    def test_load_missing_returns_none(self, tmp_path: Path) -> None:
        from guardian.monitor.baseline import BaselineProfiler

        bp = BaselineProfiler("0x" + "f" * 40, storage_dir=tmp_path)
        assert bp.load() is None

    def test_reset_clears_state(self) -> None:
        from guardian.monitor.baseline import BaselineProfiler

        bp = BaselineProfiler(CONTRACT, storage_dir=Path("/tmp/guardian_test"))
        bp.ingest(_tx())
        bp.build()
        bp.reset()
        assert bp.profile is None

    def test_save_without_build_raises(self, tmp_path: Path) -> None:
        from guardian.monitor.baseline import BaselineProfiler

        bp = BaselineProfiler(CONTRACT, storage_dir=tmp_path)
        with pytest.raises(ValueError, match="No baseline"):
            bp.save()


# ===================================================================
# AlertManager
# ===================================================================


class TestAlertManager:
    def _make_alert(
        self, severity: AlertSeverity = AlertSeverity.CRITICAL, rule: str = "test_rule"
    ) -> MonitorAlert:
        return MonitorAlert(
            alert_id="test123",
            severity=severity,
            rule_name=rule,
            title="Test alert",
            description="This is a test alert.",
            contract_address=CONTRACT,
            tx_hash="0xabc",
        )

    def test_dispatch_console(self, capsys: pytest.CaptureFixture[str]) -> None:
        from guardian.monitor.alerting import AlertManager

        mgr = AlertManager(enable_console=True, rate_limit_secs=0)
        alert = self._make_alert()
        assert mgr.dispatch(alert) is True

    def test_severity_filter(self) -> None:
        from guardian.monitor.alerting import AlertManager

        mgr = AlertManager(
            min_severity=AlertSeverity.CRITICAL,
            enable_console=False,
            rate_limit_secs=0,
        )
        # WARNING below CRITICAL → suppressed
        warn = self._make_alert(severity=AlertSeverity.WARNING)
        assert mgr.dispatch(warn) is False

        # CRITICAL passes
        crit = self._make_alert(severity=AlertSeverity.CRITICAL, rule="rule2")
        assert mgr.dispatch(crit) is True

    def test_rate_limiting(self) -> None:
        from guardian.monitor.alerting import AlertManager

        mgr = AlertManager(enable_console=False, rate_limit_secs=100)
        a1 = self._make_alert()
        a2 = self._make_alert()  # same rule + contract

        assert mgr.dispatch(a1) is True
        assert mgr.dispatch(a2) is False  # rate-limited

    def test_dispatch_many(self) -> None:
        from guardian.monitor.alerting import AlertManager

        mgr = AlertManager(enable_console=False, rate_limit_secs=0)
        alerts = [self._make_alert(rule=f"rule_{i}") for i in range(5)]
        count = mgr.dispatch_many(alerts)
        assert count == 5

    def test_webhook_dispatch(self) -> None:
        from guardian.monitor.alerting import AlertManager

        mgr = AlertManager(
            webhook_url="https://hooks.example.com/test",
            enable_console=False,
            rate_limit_secs=0,
        )
        alert = self._make_alert()

        with patch("guardian.monitor.alerting.urllib.request.urlopen") as mock_open:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_open.return_value = mock_resp

            assert mgr.dispatch(alert) is True
            mock_open.assert_called_once()

    def test_email_dispatch(self) -> None:
        from guardian.monitor.alerting import AlertManager

        email_cfg = {
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "from_addr": "guardian@example.com",
            "to_addrs": ["admin@example.com"],
            "username": "user",
            "password": "pass",
            "use_tls": True,
        }
        mgr = AlertManager(
            email_config=email_cfg,
            enable_console=False,
            rate_limit_secs=0,
        )
        alert = self._make_alert()

        with patch("guardian.monitor.alerting.smtplib.SMTP") as mock_smtp_class:
            mock_srv = MagicMock()
            mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_srv)
            mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

            assert mgr.dispatch(alert) is True
            mock_smtp_class.assert_called_once_with("smtp.example.com", 587, timeout=15)


# ===================================================================
# ChainWatcher (mocked Web3)
# ===================================================================


class TestChainWatcher:
    def _mock_web3_module(self) -> MagicMock:
        """Build a mock that mimics the web3 module structure."""
        mock_mod = MagicMock()
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_w3.eth.block_number = 100
        mock_w3.eth.get_block.return_value = {
            "timestamp": 1704067200,
            "transactions": [
                {
                    "hash": bytes.fromhex("abcd" * 8),
                    "from": OTHER,
                    "to": CONTRACT,
                    "value": 10**18,
                    "gas": 21000,
                    "gasPrice": 20 * 10**9,
                    "input": "0xa9059cbb" + "0" * 56,
                }
            ],
        }
        mock_w3.eth.get_transaction_receipt.return_value = {
            "gasUsed": 21000,
            "status": 1,
        }
        mock_mod.Web3.return_value = mock_w3
        mock_mod.HTTPProvider = MagicMock()
        mock_mod.WebSocketProvider = MagicMock()
        return mock_mod

    def test_is_connected(self) -> None:
        mock_mod = self._mock_web3_module()
        with patch.dict("sys.modules", {"web3": mock_mod}):
            # Must reimport after patching
            from guardian.monitor import chain_watcher

            # Clear module cache so _require_web3 picks up our mock
            _ = chain_watcher.__class__.__module__  # just for context
            cw = chain_watcher.ChainWatcher(
                contract_address=CONTRACT,
                rpc_url="http://localhost:8545",
            )
            # The mock w3 should be connected
            assert cw.is_connected() is True

    def test_fetch_block_transactions(self) -> None:
        mock_mod = self._mock_web3_module()
        with patch.dict("sys.modules", {"web3": mock_mod}):
            from guardian.monitor.chain_watcher import ChainWatcher

            cw = ChainWatcher(
                contract_address=CONTRACT,
                rpc_url="http://localhost:8545",
            )
            records = cw.fetch_block_transactions(100)
            assert len(records) == 1
            assert records[0].to_address == CONTRACT.lower()
            assert records[0].value_wei == 10**18
            assert records[0].success is True

    def test_poll_once(self) -> None:
        mock_mod = self._mock_web3_module()
        with patch.dict("sys.modules", {"web3": mock_mod}):
            from guardian.monitor.chain_watcher import ChainWatcher

            cw = ChainWatcher(
                contract_address=CONTRACT,
                rpc_url="http://localhost:8545",
            )
            records = cw.poll_once()
            # First poll: last_block starts at 0 → gets set to 99, fetches block 100
            assert len(records) == 1

    def test_on_transaction_callback(self) -> None:
        mock_mod = self._mock_web3_module()
        captured: list[TransactionRecord] = []

        with patch.dict("sys.modules", {"web3": mock_mod}):
            from guardian.monitor.chain_watcher import ChainWatcher

            cw = ChainWatcher(
                contract_address=CONTRACT,
                rpc_url="http://localhost:8545",
                on_transaction=captured.append,
            )
            cw.fetch_block_transactions(100)
            assert len(captured) == 1
            assert captured[0].gas_used == 21000

    def test_run_sync_with_max_iterations(self) -> None:
        mock_mod = self._mock_web3_module()
        with patch.dict("sys.modules", {"web3": mock_mod}):
            from guardian.monitor.chain_watcher import ChainWatcher

            cw = ChainWatcher(
                contract_address=CONTRACT,
                rpc_url="http://localhost:8545",
                poll_interval=0.01,
            )
            # Should not hang — exits after 2 iterations
            cw.run_sync(max_iterations=2)

    def test_stop(self) -> None:
        mock_mod = self._mock_web3_module()
        with patch.dict("sys.modules", {"web3": mock_mod}):
            from guardian.monitor.chain_watcher import ChainWatcher

            cw = ChainWatcher(
                contract_address=CONTRACT,
                rpc_url="http://localhost:8545",
            )
            cw.stop()
            assert cw._running is False


# ===================================================================
# Integration: Full pipeline (no Web3)
# ===================================================================


class TestMonitorPipeline:
    """End-to-end test of the monitoring pipeline with synthetic data."""

    def test_ingest_detect_alert(self) -> None:
        from guardian.monitor.alerting import AlertManager
        from guardian.monitor.pattern_matcher import PatternMatcher
        from guardian.monitor.tx_analyzer import TxAnalyzer

        analyzer = TxAnalyzer()
        bl = _baseline(avg_gas=50_000, std_gas=5_000)
        matcher = PatternMatcher(bl, gas_spike_factor=2.0)
        alert_mgr = AlertManager(enable_console=False, rate_limit_secs=0)

        # Normal transaction → no alert
        normal = _tx(gas_used=40_000)
        analyzer.ingest(normal)
        alerts = matcher.check(normal)
        assert len(alerts) == 0

        # Spike → alert dispatched
        spike = _tx(gas_used=100_000, tx_hash="0xspike_pipe")
        analyzer.ingest(spike)
        alerts = matcher.check(spike)
        assert len(alerts) >= 1
        count = alert_mgr.dispatch_many(alerts)
        assert count >= 1

    def test_baseline_round_trip(self, tmp_path: Path) -> None:
        from guardian.monitor.baseline import BaselineProfiler
        from guardian.monitor.pattern_matcher import PatternMatcher

        bp = BaselineProfiler(CONTRACT, storage_dir=tmp_path)
        for i in range(20):
            bp.ingest(
                _tx(
                    gas_used=50_000 + i * 100,
                    selector="0xa9059cbb",
                    ts_offset_secs=float(i * 10),
                    tx_hash=f"0xrt{i:03d}",
                )
            )
        bp.build()
        bp.save()

        # Load and use for matching
        bp2 = BaselineProfiler(CONTRACT, storage_dir=tmp_path)
        loaded = bp2.load()
        assert loaded is not None

        matcher = PatternMatcher(loaded, gas_spike_factor=2.0)
        spike = _tx(gas_used=200_000, tx_hash="0xspike_rt")
        alerts = matcher.check(spike)
        assert any(a.rule_name == "gas_spike" for a in alerts)
