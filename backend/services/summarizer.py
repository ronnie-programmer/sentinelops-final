import os
import logging

logger = logging.getLogger(__name__)

SUMMARIZER_PROVIDER = os.getenv("SUMMARIZER_PROVIDER", "rule")

RISK_PHRASES = {
    "CRITICAL": "Immediate action required — critical risk",
    "HIGH": "High-priority response needed",
    "MEDIUM": "Review recommended — moderate risk",
    "LOW": "Low-risk event logged for awareness",
}


class RuleSummarizer:
    """Rule-based summarizer. Replace with LLM adapter by subclassing BaseSummarizer."""

    def summarize(
        self,
        alert_type: str,
        asset_name: str,
        source_ip: str,
        indicator_count: int,
        risk_phrase: str,
    ) -> str:
        return (
            f"{alert_type} detected on {asset_name} from {source_ip}. "
            f"{risk_phrase} based on {indicator_count} indicator(s)."
        )


def get_summarizer() -> RuleSummarizer:
    # In the future: if SUMMARIZER_PROVIDER == "anthropic" return AnthropicSummarizer()
    # if SUMMARIZER_PROVIDER == "openai" return OpenAISummarizer()
    return RuleSummarizer()


def summarize_alert(alert, threat) -> str:
    """Generate a human-readable 2-sentence summary for a security alert."""
    summarizer = get_summarizer()
    alert_type = getattr(threat, "threat_type", None) or "Security event"
    asset = (
        getattr(threat, "affected_system", None)
        or getattr(threat, "destination_ip", None)
        or "unknown asset"
    )
    source_ip = getattr(threat, "source_ip", None) or "unknown source"
    severity = getattr(alert, "severity", None) or getattr(threat, "severity", "MEDIUM")
    risk_phrase = RISK_PHRASES.get(severity, "Review recommended")
    indicator_count = 1  # Rule-based: always 1; LLM adapter can compute dynamically
    try:
        return summarizer.summarize(alert_type, asset, source_ip, indicator_count, risk_phrase)
    except Exception as exc:
        logger.warning("Summarizer failed: %s", exc)
        return f"{alert_type} event detected. {risk_phrase}."
