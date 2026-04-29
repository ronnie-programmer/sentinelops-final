from abc import abstractmethod
from typing import Any
from integrations.base import IntegrationAdapter


class EDRAdapter(IntegrationAdapter):
    """EDR adapters extend the standard integration adapter with response actions
    (host isolation, process termination) that are specific to endpoint detection
    and response platforms."""

    @abstractmethod
    def isolate_host(self, host_id: str) -> dict[str, Any]:
        """Network-quarantine a host. Returns {ok: bool, message: str}."""
        ...

    @abstractmethod
    def kill_process(self, host_id: str, process_id: str) -> dict[str, Any]:
        """Terminate a process on a host. Returns {ok: bool, message: str}."""
        ...
