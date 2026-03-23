from __future__ import annotations

from guardian.explorer.client import ExplorerClient, ExplorerError


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self._payload


class _Session:
    def __init__(self, payloads):
        self._payloads = list(payloads)

    def get(self, *args, **kwargs):
        return _Resp(self._payloads.pop(0))


def test_fetch_contract_parses_source_and_abi() -> None:
    source_payload = {
        "status": "1",
        "message": "OK",
        "result": [
            {
                "SourceCode": "# pragma version ^0.4.0\n@external\ndef ping():\n    pass\n",
                "ContractName": "Ping",
                "CompilerVersion": "v0.4.0",
                "OptimizationUsed": "1",
                "Runs": "200",
                "Proxy": "0",
                "Implementation": "",
            }
        ],
    }
    abi_payload = {
        "status": "1",
        "message": "OK",
        "result": '[{"type":"function","name":"ping","inputs":[],"outputs":[]}]',
    }

    client = ExplorerClient(
        provider="etherscan",
        network="ethereum",
        api_key="test",
        session=_Session([source_payload, abi_payload]),
    )

    info = client.fetch_contract("0x123")
    assert info.contract_name == "Ping"
    assert info.compiler_version == "v0.4.0"
    assert info.optimization_used is True
    assert info.function_names == ["ping"]


def test_fetch_contract_raises_when_source_missing() -> None:
    client = ExplorerClient(
        provider="etherscan",
        network="ethereum",
        api_key="test",
        session=_Session([{"status": "1", "message": "OK", "result": []}]),
    )

    try:
        client.fetch_contract("0x123")
    except ExplorerError as exc:
        assert "source metadata" in str(exc)
    else:
        raise AssertionError("Expected ExplorerError")


def test_fetch_contract_falls_back_to_blockscout_when_etherscan_fails() -> None:
    etherscan_error_payload = {
        "status": "0",
        "message": "NOTOK",
        "result": "Contract source code not verified",
    }
    source_payload = {
        "status": "1",
        "message": "OK",
        "result": [
            {
                "SourceCode": "# pragma version ^0.4.0\n@external\ndef ping():\n    pass\n",
                "ContractName": "Ping",
                "CompilerVersion": "v0.4.0",
                "OptimizationUsed": "1",
                "Runs": "200",
                "Proxy": "0",
                "Implementation": "",
            }
        ],
    }
    abi_payload = {
        "status": "1",
        "message": "OK",
        "result": '[{"type":"function","name":"ping","inputs":[],"outputs":[]}]',
    }

    client = ExplorerClient(
        provider="auto",
        network="ethereum",
        api_key="test",
        session=_Session([etherscan_error_payload, source_payload, abi_payload]),
    )

    info = client.fetch_contract("0x123")
    assert info.provider == "blockscout"
    assert info.contract_name == "Ping"
    assert info.function_names == ["ping"]


def test_fetch_contract_rejects_unknown_provider_name() -> None:
    try:
        ExplorerClient(provider="unknown", network="ethereum", api_key="test")
    except ExplorerError as exc:
        assert "Unsupported explorer provider" in str(exc)
    else:
        raise AssertionError("Expected ExplorerError")
