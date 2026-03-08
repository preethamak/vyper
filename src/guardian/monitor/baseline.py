"""Normal-behaviour baseline profiler.

Learns typical transaction patterns (gas, frequency, call distribution)
over a configurable window and persists the profile as JSON for later
anomaly comparison.

Cross-platform notes
--------------------
* Profile files are stored under the user data directory via
  ``platformdirs`` conventions (XDG on Linux, AppData on Windows,
  ~/Library on macOS).  Falls back to ``~/.guardian/baselines/`` when
  ``platformdirs`` is unavailable.
* All path handling uses ``pathlib.Path`` — no hard-coded separators.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from guardian.models import BaselineProfile, TransactionRecord
from guardian.monitor.tx_analyzer import TxAnalyzer
from guardian.utils.logger import get_logger

log = get_logger("monitor.baseline")


def _default_baseline_dir() -> Path:
    """Return a cross-platform directory for storing baseline profiles."""
    try:
        from platformdirs import user_data_dir  # type: ignore[import-untyped]

        return Path(user_data_dir("vyper-guard", ensure_exists=True)) / "baselines"
    except ImportError:
        return Path.home() / ".guardian" / "baselines"


class BaselineProfiler:
    """Build, store, and load baseline profiles for deployed contracts.

    Args:
        contract_address: Checksummed Ethereum address.
        storage_dir: Directory for JSON profile files.  ``None`` → platform default.
    """

    def __init__(
        self,
        contract_address: str,
        storage_dir: Path | None = None,
    ) -> None:
        self.contract_address = contract_address.lower()
        self.storage_dir = storage_dir or _default_baseline_dir()
        self._analyzer = TxAnalyzer()
        self._profile: BaselineProfile | None = None

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(self, record: TransactionRecord) -> None:
        """Add a single transaction to the learning window."""
        self._analyzer.ingest(record)

    def ingest_many(self, records: list[TransactionRecord]) -> None:
        for rec in records:
            self._analyzer.ingest(rec)

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    def build(self) -> BaselineProfile:
        """Compute a baseline profile from all ingested transactions."""
        profile = self._analyzer.build_baseline_snapshot(self.contract_address)
        if profile is None:
            profile = BaselineProfile(
                contract_address=self.contract_address,
                window_start=datetime.now(timezone.utc),
                window_end=datetime.now(timezone.utc),
            )
        self._profile = profile
        return profile

    @property
    def profile(self) -> BaselineProfile | None:
        return self._profile

    # ------------------------------------------------------------------
    # Persistence (JSON)
    # ------------------------------------------------------------------

    def _profile_path(self) -> Path:
        return self.storage_dir / f"{self.contract_address}.json"

    def save(self, profile: BaselineProfile | None = None) -> Path:
        """Persist *profile* (or the current one) to disk."""
        prof = profile or self._profile
        if prof is None:
            raise ValueError("No baseline profile to save.  Call build() first.")

        self.storage_dir.mkdir(parents=True, exist_ok=True)
        out = self._profile_path()
        out.write_text(prof.model_dump_json(indent=2), encoding="utf-8")
        log.info("Baseline saved → %s", out)
        return out

    def load(self) -> BaselineProfile | None:
        """Load a previously saved baseline from disk."""
        p = self._profile_path()
        if not p.exists():
            log.warning("No saved baseline for %s", self.contract_address)
            return None

        data = json.loads(p.read_text(encoding="utf-8"))
        self._profile = BaselineProfile.model_validate(data)
        log.info("Baseline loaded ← %s", p)
        return self._profile

    def reset(self) -> None:
        """Clear ingested data and the in-memory profile."""
        self._analyzer.reset()
        self._profile = None
