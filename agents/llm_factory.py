"""Deterministic local text helper used by the legacy supervisor command."""

from __future__ import annotations

from .base import PHIGuard


class MockLLM:
    def __init__(self, system_name: str = "Constant Time Crypto Verifier"):
        self.system_name = system_name

    def invoke(self, prompt: str) -> str:
        PHIGuard.assert_no_phi(prompt)
        return (
            f"[{self.system_name}] Deterministic helper received: {prompt[:120]!r}. "
            "This response is informational and does not establish cryptographic conformance."
        )


class LLMFactory:
    """Return the deterministic helper supported by this repository."""

    @staticmethod
    def create(provider: str = "mock", system_name: str = "Constant Time Crypto Verifier"):
        provider_name = str(provider).lower()
        if provider_name not in {"mock", "deterministic", "test"}:
            raise ValueError(
                f"unsupported model provider {provider!r}; only the deterministic local helper is implemented"
            )
        return MockLLM(system_name)
