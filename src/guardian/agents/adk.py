"""Lightweight agent runtime (ADK-style) for guided security assistance."""

from __future__ import annotations

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

    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path

    def append(self, entry: dict[str, Any]) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, ensure_ascii=False)
        with self.file_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

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
        memory: AgentMemory | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.memory = memory
        self.timeout = timeout

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
                "format": "concise_markdown",
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

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            resp = requests.post(
                self.base_url + "/chat/completions",
                headers=headers,
                json=body,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            answer = str(data["choices"][0]["message"]["content"])
        except requests.RequestException as exc:
            raise AgentError(f"Agent LLM request failed: {exc}") from exc
        except Exception as exc:
            raise AgentError("Agent response format invalid") from exc

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
