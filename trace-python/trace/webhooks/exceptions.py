from __future__ import annotations


class WebhookVerificationError(Exception):
    """Raised when webhook signature verification fails."""


class WebhookParseError(Exception):
    """Raised when webhook payload parsing fails."""
