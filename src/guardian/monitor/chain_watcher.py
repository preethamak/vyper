"""Blockchain event listener for deployed Vyper contracts.

Connects to an Ethereum-compatible JSON-RPC endpoint via HTTP(S) or
WebSocket and polls for new transactions involving the target contract.

Cross-platform notes
--------------------
* Uses ``asyncio`` event-loop APIs that work identically on Windows,
  macOS and Linux.
* Avoids ``add_signal_handler`` (Unix-only) — relies on
  ``KeyboardInterrupt`` for graceful shutdown on every OS.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Callable
from datetime import datetime, timezone

from guardian.models import TransactionRecord
from guardian.utils.logger import get_logger

log = get_logger("monitor.chain_watcher")


class Web3NotAvailableError(Exception):
    """Raised when the ``web3`` package is not installed."""


def _require_web3():  # type: ignore[no-untyped-def]
    """Import and return the ``web3`` module, or raise with a clear message."""
    try:
        import web3 as _web3  # type: ignore[import-untyped]

        return _web3
    except ImportError:
        raise Web3NotAvailableError(
            "The 'web3' package is required for live monitoring.  "
            "Install it with:  pip install 'vyper-guard[monitor]'"
        ) from None


class ChainWatcher:
    """Watch a deployed contract for new transactions.

    Args:
        contract_address: Checksummed Ethereum address to monitor.
        rpc_url: HTTP(S) or WebSocket JSON-RPC endpoint.
        poll_interval: Seconds between block polls (HTTP mode).
        on_transaction: Optional callback invoked for every new
            ``TransactionRecord``.
    """

    def __init__(
        self,
        contract_address: str,
        rpc_url: str,
        poll_interval: float = 2.0,
        on_transaction: Callable[[TransactionRecord], None] | None = None,
    ) -> None:
        self._web3_mod = _require_web3()
        web3_cls = self._web3_mod.Web3

        self.contract_address = contract_address.lower()
        self.rpc_url = rpc_url
        self.poll_interval = max(0.5, poll_interval)
        self.on_transaction = on_transaction

        # Connect
        if rpc_url.startswith("ws://") or rpc_url.startswith("wss://"):
            provider = self._web3_mod.WebSocketProvider(rpc_url)
        else:
            provider = self._web3_mod.HTTPProvider(rpc_url)
        self.w3 = web3_cls(provider)

        self._last_block: int = 0
        self._running = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_connected(self) -> bool:
        """Return True if the RPC node is reachable."""
        try:
            return self.w3.is_connected()
        except Exception:
            return False

    def get_latest_block(self) -> int:
        """Return the latest block number from the RPC."""
        return self.w3.eth.block_number

    def fetch_block_transactions(self, block_number: int) -> list[TransactionRecord]:
        """Fetch all transactions in *block_number* that touch our contract."""
        records: list[TransactionRecord] = []
        try:
            block = self.w3.eth.get_block(block_number, full_transactions=True)
        except Exception as exc:
            log.warning("Failed to fetch block %d: %s", block_number, exc)
            return records

        ts = block.get("timestamp", 0)
        block_time = datetime.fromtimestamp(ts, tz=timezone.utc)

        for tx in block.get("transactions", []):
            tx_to = (tx.get("to") or "").lower()
            tx_from = (tx.get("from") or "").lower()

            if tx_to != self.contract_address and tx_from != self.contract_address:
                continue

            tx_hash = tx["hash"].hex() if isinstance(tx["hash"], bytes) else str(tx["hash"])
            try:
                receipt = self.w3.eth.get_transaction_receipt(tx_hash)
                gas_used = receipt.get("gasUsed", tx.get("gas", 0))
                success = receipt.get("status", 1) == 1
            except Exception:
                gas_used = tx.get("gas", 0)
                success = True

            input_data = tx.get("input", "0x")
            if isinstance(input_data, bytes):
                input_data = "0x" + input_data.hex()
            elif not isinstance(input_data, str):
                input_data = str(input_data)

            func_selector = input_data[:10] if len(input_data) >= 10 else None

            record = TransactionRecord(
                tx_hash=tx_hash,
                block_number=block_number,
                timestamp=block_time,
                from_address=tx_from,
                to_address=tx_to,
                value_wei=tx.get("value", 0),
                gas_used=gas_used,
                gas_price_wei=tx.get("gasPrice", 0),
                input_data=input_data,
                function_selector=func_selector,
                success=success,
            )
            records.append(record)
            if self.on_transaction:
                self.on_transaction(record)

        return records

    def poll_once(self) -> list[TransactionRecord]:
        """Check for new blocks since last poll and return new txs."""
        latest = self.get_latest_block()
        if self._last_block == 0:
            self._last_block = latest - 1

        all_records: list[TransactionRecord] = []
        for blk in range(self._last_block + 1, latest + 1):
            records = self.fetch_block_transactions(blk)
            all_records.extend(records)

        self._last_block = latest
        return all_records

    def run_sync(self, max_iterations: int = 0) -> None:
        """Blocking poll loop.  Runs until Ctrl+C or *max_iterations*.

        Works identically on Windows, macOS, and Linux.
        """
        log.info(
            "Monitoring %s via %s (poll every %.1fs)",
            self.contract_address,
            self.rpc_url,
            self.poll_interval,
        )
        self._running = True
        iteration = 0
        try:
            while self._running:
                self.poll_once()
                iteration += 1
                if 0 < max_iterations <= iteration:
                    break
                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            log.info("Monitoring stopped by user.")
        finally:
            self._running = False

    def stop(self) -> None:
        """Signal the poll loop to stop after the current iteration."""
        self._running = False

    async def run_async(self, max_iterations: int = 0) -> None:
        """Async poll loop — yields control between polls."""
        log.info(
            "Monitoring %s (async, poll every %.1fs)",
            self.contract_address,
            self.poll_interval,
        )
        stop_event = asyncio.Event()
        iteration = 0
        try:
            while not stop_event.is_set():
                self.poll_once()
                iteration += 1
                if 0 < max_iterations <= iteration:
                    break
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop_event.wait(), timeout=self.poll_interval)
        except KeyboardInterrupt:
            log.info("Async monitoring stopped by user.")
