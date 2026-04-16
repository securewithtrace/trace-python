from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TraceClient:
    api_key: str
    base_url: str = "https://api.securewithtrace.com"

    def list_vulnerabilities(self, *args: object, **kwargs: object) -> object:
        raise NotImplementedError("TraceClient.list_vulnerabilities is not implemented yet.")

    def get_vulnerability(self, id: str) -> object:
        raise NotImplementedError("TraceClient.get_vulnerability is not implemented yet.")
