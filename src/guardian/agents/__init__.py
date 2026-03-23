"""LLM/agent integrations for advanced security triage."""

from guardian.agents.llm_triage import LLMTriageError, apply_llm_triage

__all__ = ["LLMTriageError", "apply_llm_triage"]
