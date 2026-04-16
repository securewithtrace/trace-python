from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from tracepy.webhooks.events import TraceEvent, parse_event
from tracepy.webhooks.exceptions import WebhookParseError, WebhookVerificationError


@dataclass(frozen=True)
class WebhookHandler:
    secret: str

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        return self._is_valid_signature(payload=payload, signature=signature)

    def verify_and_parse(self, payload: bytes, signature: str, event_type: str) -> TraceEvent:
        if not self._is_valid_signature(payload, signature):
            raise WebhookVerificationError("Invalid webhook signature.")

        try:
            parsed_payload = json.loads(payload)
        except json.JSONDecodeError as error:
            raise WebhookParseError("Payload is not valid JSON.") from error

        if not isinstance(parsed_payload, dict):
            raise WebhookParseError("Payload root must be a JSON object.")

        return parse_event(event_type=event_type, data=parsed_payload)

    def _is_valid_signature(self, payload: bytes, signature: str) -> bool:
        if not signature.startswith("sha256="):
            return False
        expected = self._compute_signature(payload)
        return hmac.compare_digest(expected, signature)

    def _compute_signature(self, payload: bytes) -> str:
        digest = hmac.new(
            key=self.secret.encode("utf-8"),
            msg=payload,
            digestmod=hashlib.sha256,
        ).hexdigest()
        return f"sha256={digest}"


__all__ = ["WebhookHandler"]
