from abc import ABC, abstractmethod
from typing import Any


class IntegrationAdapter(ABC):
    """Abstract base for security tool integration adapters."""

    provider_name: str = "unknown"
    is_mock: bool = True

    @abstractmethod
    def poll_alerts(self) -> list[dict[str, Any]]:
        """Fetch new alerts/events from the provider. Returns list of normalized alert dicts."""
        ...

    @abstractmethod
    def push_acknowledgement(self, alert_id: str) -> bool:
        """Acknowledge an alert back to the provider. Returns True on success."""
        ...

    def normalize_alert(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize provider-specific alert into SentinelOps schema."""
        return raw
