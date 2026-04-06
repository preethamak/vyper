"""Lightweight agent runtime (ADK-style) for guided security assistance."""

from __future__ import annotations

import contextlib
import json
import subprocess  # nosec B404 - controlled internal sandbox execution only
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import requests


class AgentError(RuntimeError):
    """Raised when agent execution fails."""


class AgentMemory:
    """Simple append-only JSONL memory store."""

    def __init__(self, file_path: Path, max_entries: int = 2000) -> None:
        self.file_path = file_path
        self.max_entries = max(1, int(max_entries))

    def append(self, entry: dict[str, Any]) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, ensure_ascii=False)
        with self.file_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        with contextlib.suppress(OSError):
            self.file_path.chmod(0o600)

        # Keep memory bounded for predictable prompt context and disk usage.
        with self.file_path.open(encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        if len(lines) > self.max_entries:
            trimmed = lines[-self.max_entries :]
            self.file_path.write_text("\n".join(trimmed) + "\n", encoding="utf-8")

    def tail(self, n: int = 8) -> list[dict[str, Any]]:
        if not self.file_path.exists():
            return []
        lines = self.file_path.read_text(encoding="utf-8").splitlines()
        out: list[dict[str, Any]] = []
        for line in lines[-max(1, n) :]:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                out.append(item)
        return out


class SecurityAgent:
    """OpenAI-compatible security assistant with memory + optional sandbox tool."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        provider: str = "openai_compatible",
        memory: AgentMemory | None = None,
        timeout: float = 60.0,
        max_retries: int = 2,
        retry_backoff_seconds: float = 1.0,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.provider = provider.strip().lower()
        self.memory = memory
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))
        self.retry_backoff_seconds = max(0.1, float(retry_backoff_seconds))

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
        }
        headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _gemini_base_url(self) -> str:
        base = self.base_url.rstrip("/")
        if base.endswith("/openai"):
            base = base[: -len("/openai")]
        return base

    def ask(self, prompt: str, *, context: dict[str, Any] | None = None) -> str:
        if not self.api_key.strip():
            raise AgentError("Missing API key")

        memory_context = self.memory.tail(6) if self.memory else []

        system_prompt = (
            "You are Vyper Guard Agent. "
            "Focus on smart contract security. "
            "Use only provided context; avoid fabricated claims. "
            "If uncertain, explicitly say uncertain and suggest deterministic checks."
        )

        user_payload = {
            "prompt": prompt,
            "context": context or {},
            "memory": memory_context,
            "instructions": {
                "format": "concise_plain_text",
                "must_include": [
                    "risk_summary",
                    "prioritized_actions",
                    "validation_steps",
                ],
            },
        }

        body = {
            "model": self.model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
            ],
        }

        headers = self._build_headers()

        answer = ""
        last_error: str | None = None
        model_candidates: list[str] = [self.model]
        if self.provider in {"gemini", "google", "google_gemini"}:
            for alt in [
                "gemini-2.5-flash",
                "gemini-flash-latest",
                "gemini-2.0-flash",
                "gemini-2.0-flash-lite",
                "gemini-2.5-flash-lite",
            ]:
                if alt not in model_candidates:
                    model_candidates.append(alt)
        elif self.model.startswith("gpt-5"):
            # Best-effort fallback candidates for accounts with restricted access/rate limits.
            for alt in ["gpt-4.1-mini", "gpt-4o-mini"]:
                if alt not in model_candidates:
                    model_candidates.append(alt)

        for candidate_model in model_candidates:
            body["model"] = candidate_model
            for attempt in range(self.max_retries + 1):
                try:
                    if self.provider in {
                        "gemini",
                        "google",
                        "google_gemini",
                    } and not self.base_url.endswith("/openai"):
                        gemini_url = (
                            self._gemini_base_url() + f"/models/{candidate_model}:generateContent"
                        )
                        gemini_payload = {
                            "contents": [
                                {
                                    "role": "user",
                                    "parts": [
                                        {
                                            "text": system_prompt
                                            + "\n\n"
                                            + json.dumps(user_payload, ensure_ascii=False)
                                        }
                                    ],
                                }
                            ],
                            "generationConfig": {
                                "temperature": 0.1,
                            },
                        }
                        resp = requests.post(
                            gemini_url,
                            headers={"Content-Type": "application/json"},
                            params={"key": self.api_key},
                            json=gemini_payload,
                            timeout=self.timeout,
                        )
                    else:
                        resp = requests.post(
                            self.base_url + "/chat/completions",
                            headers=headers,
                            json=body,
                            timeout=self.timeout,
                        )
                except requests.RequestException as exc:
                    last_error = f"network error: {exc.__class__.__name__}: {exc}"
                    if attempt < self.max_retries:
                        time.sleep(self.retry_backoff_seconds * (2**attempt))
                        continue
                    break

                if 200 <= resp.status_code < 300:
                    try:
                        data = resp.json()
                        if self.provider in {
                            "gemini",
                            "google",
                            "google_gemini",
                        } and not self.base_url.endswith("/openai"):
                            answer = str(data["candidates"][0]["content"]["parts"][0]["text"])
                        else:
                            answer = str(data["choices"][0]["message"]["content"])
                    except Exception as exc:  # pragma: no cover - defensive parse path
                        raise AgentError("Agent response format invalid") from exc
                    break

                # Immediate hard-fail auth/config errors.
                if resp.status_code in {400, 401, 403, 404}:
                    snippet = (resp.text or "").strip().replace("\n", " ")[:220]
                    last_error = (
                        f"{resp.status_code} {resp.reason} — {snippet}"
                        if snippet
                        else f"{resp.status_code} {resp.reason}"
                    )
                    break

                # Retry transient failures/rate limits.
                if resp.status_code in {429, 500, 502, 503, 504} and attempt < self.max_retries:
                    retry_after_raw = resp.headers.get("Retry-After", "").strip()
                    if retry_after_raw:
                        try:
                            sleep_for = max(self.retry_backoff_seconds, float(retry_after_raw))
                        except ValueError:
                            sleep_for = self.retry_backoff_seconds * (2**attempt)
                    else:
                        sleep_for = self.retry_backoff_seconds * (2**attempt)
                    time.sleep(sleep_for)
                    continue

                snippet = (resp.text or "").strip().replace("\n", " ")[:220]
                last_error = (
                    f"{resp.status_code} {resp.reason} — {snippet}"
                    if snippet
                    else f"{resp.status_code} {resp.reason}"
                )
                break

            if answer:
                break

        if not answer:
            if last_error:
                endpoint = (
                    self._gemini_base_url() + f"/models/{self.model}:generateContent"
                    if self.provider in {"gemini", "google", "google_gemini"}
                    and not self.base_url.endswith("/openai")
                    else self.base_url + "/chat/completions"
                )
                raise AgentError(f"Agent LLM request failed: {last_error} for url: {endpoint}")
            raise AgentError("Agent response format invalid")

        if self.memory:
            self.memory.append(
                {
                    "ts": int(time.time()),
                    "prompt": prompt,
                    "context_keys": sorted((context or {}).keys()),
                    "answer": answer[:8000],
                }
            )

        return answer

    @staticmethod
    def run_python_sandbox(script: str, *, timeout: float = 10.0) -> dict[str, Any]:
        """Run a Python snippet in an isolated temp directory.

        Intended for quick deterministic helpers, not untrusted code execution.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            wd = Path(tmpdir)
            script_path = wd / "sandbox.py"
            script_path.write_text(script, encoding="utf-8")

            python_exec = sys.executable or "python"
            proc = subprocess.run(  # nosec B603 - no shell, fixed interpreter + temp file path
                [python_exec, "-I", str(script_path)],
                cwd=str(wd),
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            return {
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            }
