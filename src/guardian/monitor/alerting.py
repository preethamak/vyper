"""Alert dispatch system.

Supports multiple notification channels:
  - Console / Rich output
  - Webhook notifications (Slack-compatible JSON, Discord)
  - Email alerts via SMTP (stdlib ``smtplib``)

Includes severity-based routing, rate limiting, and deduplication.

Cross-platform notes
--------------------
* Uses only ``smtplib``, ``json``, ``urllib`` from stdlib — no
  platform-specific dependencies.
* ``requests`` / ``httpx`` / ``aiohttp`` are NOT required;
  webhooks are sent with ``urllib.request`` for maximum portability.
"""

from __future__ import annotations

import ipaddress
import json
import os
import smtplib
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from email.message import EmailMessage
from typing import ClassVar

from rich.console import Console

from guardian.models import AlertSeverity, MonitorAlert
from guardian.utils.logger import get_logger

log = get_logger("monitor.alerting")

_console = Console(stderr=True)


class AlertManager:
    """Dispatch ``MonitorAlert`` objects through configured channels.

    Args:
        webhook_url: Slack / Discord / generic webhook endpoint.
        email_config: Dict with keys ``smtp_host``, ``smtp_port``,
            ``from_addr``, ``to_addrs`` (list), and optionally
            ``username``, ``password``, ``use_tls``.
        min_severity: Only dispatch alerts at or above this severity.
        rate_limit_secs: Minimum seconds between identical alerts
            (same rule + contract).
        enable_console: Print alerts to stderr via Rich.
    """

    # Severity ranking for filtering
    _SEVERITY_RANK: ClassVar[dict[AlertSeverity, int]] = {
        AlertSeverity.INFO: 0,
        AlertSeverity.WARNING: 1,
        AlertSeverity.CRITICAL: 2,
    }

    def __init__(
        self,
        *,
        webhook_url: str | None = None,
        email_config: dict[str, object] | None = None,
        min_severity: AlertSeverity = AlertSeverity.INFO,
        rate_limit_secs: float = 60.0,
        enable_console: bool = True,
        allow_private_webhooks: bool = False,
    ) -> None:
        self.webhook_url = webhook_url
        self.email_config = email_config or {}
        self.min_severity = min_severity
        self.rate_limit_secs = rate_limit_secs
        self.enable_console = enable_console
        self.allow_private_webhooks = allow_private_webhooks

        # Dedup / rate-limit: key → last-dispatch epoch
        self._last_dispatch: dict[str, float] = defaultdict(float)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch(self, alert: MonitorAlert) -> bool:
        """Send *alert* through all configured channels.

        Returns ``True`` if the alert was dispatched (not suppressed).
        """
        if not self._passes_severity(alert):
            return False
        if self._is_rate_limited(alert):
            return False

        self._record_dispatch(alert)

        if self.enable_console:
            self._dispatch_console(alert)
        if self.webhook_url:
            self._dispatch_webhook(alert)
        if self.email_config:
            self._dispatch_email(alert)

        return True

    def dispatch_many(self, alerts: list[MonitorAlert]) -> int:
        """Dispatch a batch; return the count of non-suppressed alerts."""
        return sum(1 for a in alerts if self.dispatch(a))

    # ------------------------------------------------------------------
    # Severity filtering
    # ------------------------------------------------------------------

    def _passes_severity(self, alert: MonitorAlert) -> bool:
        return self._SEVERITY_RANK.get(alert.severity, 0) >= self._SEVERITY_RANK.get(
            self.min_severity, 0
        )

    # ------------------------------------------------------------------
    # Rate limiting / dedup
    # ------------------------------------------------------------------

    def _dedup_key(self, alert: MonitorAlert) -> str:
        return f"{alert.rule_name}:{alert.contract_address}"

    def _is_rate_limited(self, alert: MonitorAlert) -> bool:
        key = self._dedup_key(alert)
        last = self._last_dispatch.get(key)
        if last is None:
            return False
        if time.monotonic() - last < self.rate_limit_secs:
            log.debug("Rate-limited alert %s (%s)", alert.alert_id, key)
            return True
        return False

    def _record_dispatch(self, alert: MonitorAlert) -> None:
        self._last_dispatch[self._dedup_key(alert)] = time.monotonic()

    # ------------------------------------------------------------------
    # Console channel
    # ------------------------------------------------------------------

    def _dispatch_console(self, alert: MonitorAlert) -> None:
        colour_map = {
            AlertSeverity.CRITICAL: "bold red",
            AlertSeverity.WARNING: "yellow",
            AlertSeverity.INFO: "cyan",
        }
        style = colour_map.get(alert.severity, "white")
        _console.print(f"[{style}]⚡ [{alert.severity.value}] {alert.title}[/{style}]")
        _console.print(f"   Rule: {alert.rule_name}  |  Contract: {alert.contract_address}")
        if alert.tx_hash:
            _console.print(f"   Tx: {alert.tx_hash}")
        _console.print(f"   {alert.description}\n")

    # ------------------------------------------------------------------
    # Webhook channel (Slack / Discord / generic)
    # ------------------------------------------------------------------

    def _dispatch_webhook(self, alert: MonitorAlert) -> None:
        url = str(self.webhook_url or "").strip()
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https":
            log.error("Webhook dispatch blocked: unsupported URL scheme '%s'", parsed.scheme or "")
            return
        if not parsed.netloc:
            log.error("Webhook dispatch blocked: invalid URL (missing host)")
            return

        host = (parsed.hostname or "").strip().lower()
        if not host:
            log.error("Webhook dispatch blocked: invalid URL host")
            return

        if not self.allow_private_webhooks and _is_private_or_local_host(host):
            log.error("Webhook dispatch blocked: private/local host '%s'", host)
            return

        payload = {
            "text": f"[{alert.severity.value}] {alert.title}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*{alert.severity.value}: {alert.title}*\n"
                            f"Rule: `{alert.rule_name}`  |  "
                            f"Contract: `{alert.contract_address}`\n"
                            f"Tx: `{alert.tx_hash or 'N/A'}`\n"
                            f"{alert.description}"
                        ),
                    },
                }
            ],
        }
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 - scheme validated above
                log.debug("Webhook response %d", resp.status)
        except Exception as exc:
            log.error("Webhook dispatch failed: %s", exc)

    # ------------------------------------------------------------------
    # Email channel
    # ------------------------------------------------------------------

    def _dispatch_email(self, alert: MonitorAlert) -> None:
        smtp_host = str(self.email_config.get("smtp_host", "localhost"))
        smtp_port = int(self.email_config.get("smtp_port", 587))  # type: ignore[arg-type]
        from_addr = str(self.email_config.get("from_addr", "guardian@localhost"))
        to_addrs: list[str] = list(self.email_config.get("to_addrs", []))  # type: ignore[arg-type]
        username = _resolve_secret(
            direct=self.email_config.get("username"),
            env_name=self.email_config.get("username_env"),
        )
        password = _resolve_secret(
            direct=self.email_config.get("password"),
            env_name=self.email_config.get("password_env"),
        )
        use_tls = bool(self.email_config.get("use_tls", True))

        if isinstance(self.email_config.get("password"), str) and not self.email_config.get(
            "password_env"
        ):
            log.warning(
                "Email config uses plaintext password; prefer password_env or env:VAR secret references."
            )

        if not to_addrs:
            log.warning("Email dispatch skipped — no 'to_addrs' configured.")
            return

        msg = EmailMessage()
        msg["Subject"] = f"[Guardian {alert.severity.value}] {alert.title}"
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        msg.set_content(
            f"Severity: {alert.severity.value}\n"
            f"Rule:     {alert.rule_name}\n"
            f"Contract: {alert.contract_address}\n"
            f"Tx Hash:  {alert.tx_hash or 'N/A'}\n\n"
            f"{alert.description}\n\n"
            f"Metadata: {json.dumps(alert.metadata, indent=2)}"
        )

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as srv:
                if use_tls:
                    srv.starttls()
                if username and password:
                    srv.login(username, password)
                srv.send_message(msg)
            log.info("Email alert sent to %s", to_addrs)
        except Exception as exc:
            log.error("Email dispatch failed: %s", exc)


def _is_private_or_local_host(host: str) -> bool:
    """Return True when host resolves to local/private address patterns.

    This is a conservative SSRF guard for webhook egress.
    """
    lowered = host.lower().strip()
    if lowered in {"localhost", "localhost.localdomain"}:
        return True
    if lowered.endswith(".local"):
        return True

    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        # Domain-name heuristics for common local/private targets.
        return lowered.endswith(".internal")

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve_secret(*, direct: object, env_name: object) -> str | None:
    """Resolve credential values from explicit config or environment.

    Supported patterns:
    - direct='env:MY_VAR'
    - direct='${MY_VAR}'
    - env_name='MY_VAR'
    - direct plain value (fallback)
    """
    if isinstance(env_name, str) and env_name.strip():
        return os.getenv(env_name.strip())

    if not isinstance(direct, str):
        return None

    value = direct.strip()
    if not value:
        return None

    if value.startswith("env:"):
        return os.getenv(value[4:].strip())
    if value.startswith("${") and value.endswith("}"):
        return os.getenv(value[2:-1].strip())
    return value
