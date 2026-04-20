"""Explorer client for fetching verified contract metadata.

Supports provider-specific lookups and automatic fallback across:
    etherscan -> blockscout -> sourcify
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import requests


class ExplorerError(RuntimeError):
    """Raised when explorer metadata retrieval fails."""


@dataclass
class ExplorerResponse:
    """Normalized explorer response payload."""

    address: str
    network: str
    source_code: str | None
    abi: list[dict[str, Any]] | None
    contract_name: str | None
    compiler_version: str | None
    optimization_used: bool | None
    runs: int | None
    is_proxy: bool | None
    implementation: str | None
    function_names: list[str]
    raw: dict[str, Any]
    provider: str = "etherscan"


_ETHERSCAN_API_BY_NETWORK: dict[str, str] = {
    "ethereum": "https://api.etherscan.io/api",
    "sepolia": "https://api-sepolia.etherscan.io/api",
    "polygon": "https://api.polygonscan.com/api",
    "arbitrum": "https://api.arbiscan.io/api",
    "optimism": "https://api-optimistic.etherscan.io/api",
    "base": "https://api.basescan.org/api",
}

_ETHERSCAN_V2_ENDPOINT = "https://api.etherscan.io/v2/api"

_CHAIN_ID_BY_NETWORK: dict[str, int] = {
    "ethereum": 1,
    "sepolia": 11155111,
    "polygon": 137,
    "arbitrum": 42161,
    "optimism": 10,
    "base": 8453,
}

_BLOCKSCOUT_API_BY_NETWORK: dict[str, str] = {
    "ethereum": "https://eth.blockscout.com/api",
    "sepolia": "https://eth-sepolia.blockscout.com/api",
    "polygon": "https://polygon.blockscout.com/api",
    "arbitrum": "https://arbitrum.blockscout.com/api",
    "optimism": "https://optimism.blockscout.com/api",
    "base": "https://base.blockscout.com/api",
}

_SOURCIFY_CHAIN_ID_BY_NETWORK: dict[str, int] = {
    "ethereum": 1,
    "sepolia": 11155111,
    "polygon": 137,
    "arbitrum": 42161,
    "optimism": 10,
    "base": 8453,
}

_DEFAULT_PROVIDER_CHAIN: list[str] = ["etherscan", "blockscout", "sourcify"]


class ExplorerClient:
    """Fetch verified source code and ABI from explorer providers with fallback."""

    def __init__(
        self,
        *,
        provider: str = "etherscan",
        network: str = "ethereum",
        api_key: str | None = None,
        timeout: float = 25.0,
        session: requests.Session | None = None,
    ) -> None:
        self.provider = provider.lower().strip()
        self.network = network.lower().strip()
        self.api_key = api_key
        self.timeout = timeout
        self._session = session or requests.Session()

        self.providers = self._resolve_provider_chain(self.provider)
        if self.network not in {
            *_ETHERSCAN_API_BY_NETWORK,
            *_BLOCKSCOUT_API_BY_NETWORK,
            *_SOURCIFY_CHAIN_ID_BY_NETWORK,
        }:
            raise ExplorerError(
                f"Unsupported network: {network}. Supported: {', '.join(sorted(_ETHERSCAN_API_BY_NETWORK))}"
            )

    @property
    def endpoint(self) -> str:
        if self.provider == "etherscan":
            return _ETHERSCAN_API_BY_NETWORK[self.network]
        if self.provider == "blockscout":
            return _BLOCKSCOUT_API_BY_NETWORK[self.network]
        raise ExplorerError("Sourcify does not use the Etherscan-compatible endpoint property")

    def fetch_contract(self, address: str) -> ExplorerResponse:
        """Fetch verified contract source + ABI metadata for an address."""
        failures: list[str] = []
        metadata_only: ExplorerResponse | None = None
        for provider in self.providers:
            try:
                response = self._fetch_from_provider(provider, address)
                if response.source_code:
                    return response
                if metadata_only is None:
                    metadata_only = response
                failures.append(f"{provider}: verified source unavailable")
            except ExplorerError as exc:
                failures.append(f"{provider}: {exc}")

        if metadata_only is not None:
            return metadata_only

        details = "; ".join(failures) if failures else "no providers attempted"
        raise ExplorerError(f"Explorer lookup failed across providers: {details}")

    def _fetch_from_provider(self, provider: str, address: str) -> ExplorerResponse:
        if provider == "etherscan":
            chain_id = _CHAIN_ID_BY_NETWORK.get(self.network)
            if chain_id is None:
                raise ExplorerError(f"Network '{self.network}' is not supported by etherscan")
            return self._fetch_etherscan_v2(provider, chain_id, address)
        if provider == "blockscout":
            endpoint = _BLOCKSCOUT_API_BY_NETWORK.get(self.network)
            if not endpoint:
                raise ExplorerError(f"Network '{self.network}' is not supported by blockscout")
            return self._fetch_etherscan_like(provider, endpoint, address)
        if provider == "sourcify":
            sourcify_chain_id = _SOURCIFY_CHAIN_ID_BY_NETWORK.get(self.network)
            if sourcify_chain_id is None:
                raise ExplorerError(f"Network '{self.network}' is not supported by sourcify")
            return self._fetch_sourcify(sourcify_chain_id, address)
        raise ExplorerError(f"Unsupported explorer provider: {provider}")

    def _fetch_etherscan_v2(self, provider: str, chain_id: int, address: str) -> ExplorerResponse:
        source_payload = self._call_endpoint(
            _ETHERSCAN_V2_ENDPOINT,
            chainid=str(chain_id),
            module="contract",
            action="getsourcecode",
            address=address,
        )
        source_result = self._extract_first_result(source_payload)

        abi: list[dict[str, Any]] | None = None
        abi_payload: dict[str, Any] | None = None
        try:
            abi_payload = self._call_endpoint(
                _ETHERSCAN_V2_ENDPOINT,
                chainid=str(chain_id),
                module="contract",
                action="getabi",
                address=address,
            )
            abi_raw = self._extract_result_text(abi_payload)
            loaded = json.loads(abi_raw)
            if isinstance(loaded, list):
                abi = [item for item in loaded if isinstance(item, dict)]
        except Exception:
            abi = None

        function_names = sorted(
            {
                str(item.get("name"))
                for item in (abi or [])
                if item.get("type") == "function" and item.get("name")
            }
        )

        source_code = (source_result.get("SourceCode") or "").strip() or None
        contract_name = (source_result.get("ContractName") or "").strip() or None
        compiler_version = (source_result.get("CompilerVersion") or "").strip() or None
        optimization_used = self._parse_bool(
            source_result.get("OptimizationUsed") or source_result.get("OptimizationEnabled")
        )
        runs = self._parse_int(source_result.get("Runs") or source_result.get("OptimizationRuns"))
        is_proxy = self._parse_bool(source_result.get("Proxy"))
        implementation = (source_result.get("Implementation") or "").strip() or None

        return ExplorerResponse(
            address=address,
            network=self.network,
            source_code=source_code,
            abi=abi,
            contract_name=contract_name,
            compiler_version=compiler_version,
            optimization_used=optimization_used,
            runs=runs,
            is_proxy=is_proxy,
            implementation=implementation,
            function_names=function_names,
            raw={
                "source": source_payload,
                "abi": abi_payload,
            },
            provider=provider,
        )

    def _fetch_etherscan_like(self, provider: str, endpoint: str, address: str) -> ExplorerResponse:
        source_payload = self._call_endpoint(
            endpoint,
            module="contract",
            action="getsourcecode",
            address=address,
        )
        source_result = self._extract_first_result(source_payload)

        abi: list[dict[str, Any]] | None = None
        abi_payload: dict[str, Any] | None = None
        try:
            abi_payload = self._call_endpoint(
                endpoint,
                module="contract",
                action="getabi",
                address=address,
            )
            abi_raw = self._extract_result_text(abi_payload)
            loaded = json.loads(abi_raw)
            if isinstance(loaded, list):
                abi = [item for item in loaded if isinstance(item, dict)]
        except Exception:
            abi = None

        function_names = sorted(
            {
                str(item.get("name"))
                for item in (abi or [])
                if item.get("type") == "function" and item.get("name")
            }
        )

        source_code = (source_result.get("SourceCode") or "").strip() or None
        contract_name = (source_result.get("ContractName") or "").strip() or None
        compiler_version = (source_result.get("CompilerVersion") or "").strip() or None
        optimization_used = self._parse_bool(
            source_result.get("OptimizationUsed") or source_result.get("OptimizationEnabled")
        )
        runs = self._parse_int(source_result.get("Runs") or source_result.get("OptimizationRuns"))
        is_proxy = self._parse_bool(source_result.get("Proxy"))
        implementation = (source_result.get("Implementation") or "").strip() or None

        return ExplorerResponse(
            address=address,
            network=self.network,
            source_code=source_code,
            abi=abi,
            contract_name=contract_name,
            compiler_version=compiler_version,
            optimization_used=optimization_used,
            runs=runs,
            is_proxy=is_proxy,
            implementation=implementation,
            function_names=function_names,
            raw={
                "source": source_payload,
                "abi": abi_payload,
            },
            provider=provider,
        )

    def _fetch_sourcify(self, chain_id: int, address: str) -> ExplorerResponse:
        endpoint = f"https://sourcify.dev/server/v2/contract/{chain_id}/{address}?fields=all"
        try:
            payload = self._get_json_with_retry(endpoint)
        except requests.RequestException as exc:
            raise ExplorerError(f"Explorer request failed: {exc}") from exc
        except ValueError as exc:
            raise ExplorerError("Explorer returned non-JSON response") from exc

        if not isinstance(payload, dict):
            raise ExplorerError("Explorer response was not a JSON object")

        file_entries = payload.get("files")
        source_code = self._extract_sourcify_source(file_entries)

        abi_raw = payload.get("abi")
        if abi_raw is None and isinstance(payload.get("metadata"), dict):
            output = payload["metadata"].get("output")
            if isinstance(output, dict):
                abi_raw = output.get("abi")
        abi: list[dict[str, Any]] | None = None
        if isinstance(abi_raw, list):
            abi = [item for item in abi_raw if isinstance(item, dict)]

        function_names = sorted(
            {
                str(item.get("name"))
                for item in (abi or [])
                if item.get("type") == "function" and item.get("name")
            }
        )

        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        compiler_info = (
            metadata.get("compiler") if isinstance(metadata.get("compiler"), dict) else {}
        )
        settings = metadata.get("settings") if isinstance(metadata.get("settings"), dict) else {}
        optimizer = settings.get("optimizer") if isinstance(settings.get("optimizer"), dict) else {}

        contract_name = (
            payload.get("contractName")
            or payload.get("name")
            or (metadata.get("contractName") if isinstance(metadata, dict) else None)
        )
        compiler_version = payload.get("compilerVersion") or compiler_info.get("version")
        optimization_used = self._parse_bool(optimizer.get("enabled"))
        runs = self._parse_int(optimizer.get("runs"))

        return ExplorerResponse(
            address=address,
            network=self.network,
            source_code=source_code,
            abi=abi,
            contract_name=str(contract_name).strip() if contract_name else None,
            compiler_version=str(compiler_version).strip() if compiler_version else None,
            optimization_used=optimization_used,
            runs=runs,
            is_proxy=None,
            implementation=None,
            function_names=function_names,
            raw={"sourcify": payload},
            provider="sourcify",
        )

    def _call_endpoint(self, endpoint: str, **params: str) -> dict[str, Any]:
        query = dict(params)
        query["apikey"] = self.api_key or ""
        try:
            payload = self._get_json_with_retry(endpoint, params=query)
        except requests.RequestException as exc:
            raise ExplorerError(f"Explorer request failed: {exc}") from exc
        except ValueError as exc:
            raise ExplorerError("Explorer returned non-JSON response") from exc

        if not isinstance(payload, dict):
            raise ExplorerError("Explorer response was not a JSON object")

        status = str(payload.get("status", ""))
        message = str(payload.get("message", ""))
        if status not in {"1", ""} and "no data" not in message.lower():
            result = payload.get("result")
            raise ExplorerError(f"Explorer error: {message or 'request failed'} ({result})")

        return payload

    def _get_json_with_retry(
        self,
        endpoint: str,
        *,
        params: dict[str, str] | None = None,
        max_attempts: int = 3,
    ) -> dict[str, Any]:
        last_error: requests.RequestException | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                resp = self._session.get(endpoint, params=params, timeout=self.timeout)
                resp.raise_for_status()
                payload = resp.json()
                if isinstance(payload, dict):
                    return payload
                raise ExplorerError("Explorer response was not a JSON object")
            except requests.RequestException as exc:
                last_error = exc
                is_retryable = isinstance(
                    exc,
                    (
                        requests.ReadTimeout,
                        requests.ConnectTimeout,
                        requests.ConnectionError,
                    ),
                )
                if not is_retryable or attempt >= max_attempts:
                    raise
                time.sleep(0.4 * attempt)
            except ValueError:
                # Non-JSON response; do not retry blindly.
                raise

        if last_error is not None:
            raise last_error
        raise ExplorerError("Explorer request failed without a concrete error")

    @staticmethod
    def _resolve_provider_chain(provider: str) -> list[str]:
        normalized = (provider or "auto").strip().lower()
        if normalized in {"", "auto"}:
            return list(_DEFAULT_PROVIDER_CHAIN)

        requested = [p.strip().lower() for p in normalized.split(",") if p.strip()]
        if not requested:
            return list(_DEFAULT_PROVIDER_CHAIN)

        valid = {"etherscan", "blockscout", "sourcify"}
        unknown = [p for p in requested if p not in valid]
        if unknown:
            raise ExplorerError(
                f"Unsupported explorer provider: {', '.join(unknown)}. "
                "Use etherscan, blockscout, sourcify, auto, or a comma-separated chain."
            )

        seen: set[str] = set()
        ordered: list[str] = []
        for provider_name in requested:
            if provider_name not in seen:
                ordered.append(provider_name)
                seen.add(provider_name)
        return ordered

    @staticmethod
    def _extract_sourcify_source(file_entries: Any) -> str | None:
        if not isinstance(file_entries, list):
            return None

        vyper_sources: list[str] = []
        fallback_sources: list[str] = []
        for item in file_entries:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if not isinstance(content, str) or not content.strip():
                continue

            name = str(item.get("name") or "").lower()
            if name.endswith(".vy"):
                vyper_sources.append(content)
            elif name.endswith((".sol", ".json")):
                continue
            else:
                fallback_sources.append(content)

        picked = vyper_sources or fallback_sources
        if not picked:
            return None
        if len(picked) == 1:
            return picked[0]
        return "\n\n".join(picked)

    @staticmethod
    def _extract_first_result(payload: dict[str, Any]) -> dict[str, Any]:
        result = payload.get("result")
        if isinstance(result, list) and result and isinstance(result[0], dict):
            return result[0]
        raise ExplorerError("Explorer did not return source metadata for this address")

    @staticmethod
    def _extract_result_text(payload: dict[str, Any]) -> str:
        result = payload.get("result")
        if isinstance(result, str):
            return result
        raise ExplorerError("Explorer ABI payload missing string result")

    @staticmethod
    def _parse_bool(value: Any) -> bool | None:
        if value is None:
            return None
        text = str(value).strip().lower()
        if text in {"1", "true", "yes"}:
            return True
        if text in {"0", "false", "no"}:
            return False
        return None

    @staticmethod
    def _parse_int(value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None
