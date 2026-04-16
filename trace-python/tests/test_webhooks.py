from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from trace.webhooks import (
    VulnerabilityDetectedEvent,
    VulnerabilityFixedEvent,
    VulnerabilityReopenedEvent,
    VulnerabilitySeverityChangedEvent,
    VulnerabilityStatusUpdatedEvent,
    WebhookHandler,
    WebhookParseError,
    WebhookVerificationError,
)
from typing import Callable, TypeAlias

import pytest

WEBHOOK_SECRET = "whsec_test_secret"
EVENT_TYPE = "vulnerability.detected"
EventClass: TypeAlias = type[
    VulnerabilityDetectedEvent
    | VulnerabilityFixedEvent
    | VulnerabilityReopenedEvent
    | VulnerabilityStatusUpdatedEvent
    | VulnerabilitySeverityChangedEvent
]


def sign_payload(payload: bytes, secret: str = WEBHOOK_SECRET) -> str:
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


@pytest.fixture
def signer() -> Callable[[bytes, str], str]:
    def _signer(payload: bytes, secret: str = WEBHOOK_SECRET) -> str:
        return sign_payload(payload=payload, secret=secret)

    return _signer


def make_envelope(data: dict[str, object]) -> dict[str, object]:
    return {
        "id": "evt_123",
        "type": "vulnerability.detected",
        "created_at": "2026-04-16T10:00:00+00:00",
        "organization_id": "org_123",
        "data": data,
    }


def test_valid_signature_passes_verification(signer: Callable[[bytes, str], str]) -> None:
    payload = b'{"hello":"trace"}'
    handler = WebhookHandler(secret=WEBHOOK_SECRET)
    signature = signer(payload)

    assert handler.verify_signature(payload=payload, signature=signature)


def test_tampered_payload_raises_verification_error(signer: Callable[[bytes, str], str]) -> None:
    original_payload = b'{"id":"evt_1"}'
    tampered_payload = b'{"id":"evt_2"}'
    handler = WebhookHandler(secret=WEBHOOK_SECRET)
    signature = signer(original_payload)

    with pytest.raises(WebhookVerificationError):
        handler.verify_and_parse(
            payload=tampered_payload,
            signature=signature,
            event_type=EVENT_TYPE,
        )


def test_wrong_secret_raises_verification_error(signer: Callable[[bytes, str], str]) -> None:
    payload = b'{"id":"evt_1"}'
    handler = WebhookHandler(secret="whsec_wrong_secret")
    signature = signer(payload, WEBHOOK_SECRET)

    with pytest.raises(WebhookVerificationError):
        handler.verify_and_parse(
            payload=payload,
            signature=signature,
            event_type=EVENT_TYPE,
        )


@pytest.mark.parametrize(
    ("event_type", "payload_data", "event_class"),
    [
        (
            "vulnerability.detected",
            {
                "vulnerability_id": "vuln_1",
                "title": "Hardcoded secret",
                "severity": "HIGH",
                "scanner_type": "SECRETS",
                "repository_name": "trace-api",
                "file_path": "src/app.py",
                "line_number": 42,
                "cwe": "CWE-798",
                "description": "Hardcoded credential found in source.",
            },
            VulnerabilityDetectedEvent,
        ),
        (
            "vulnerability.fixed",
            {
                "vulnerability_id": "vuln_1",
                "title": "Hardcoded secret",
                "severity": "HIGH",
                "repository_name": "trace-api",
                "fixed_at": "2026-04-16T10:05:00+00:00",
            },
            VulnerabilityFixedEvent,
        ),
        (
            "vulnerability.reopened",
            {
                "vulnerability_id": "vuln_1",
                "title": "Hardcoded secret",
                "severity": "MEDIUM",
                "scanner_type": "SAST",
                "repository_name": "trace-api",
                "file_path": "src/app.py",
                "description": "Issue re-detected after regression.",
                "reopened_at": "2026-04-16T10:07:00+00:00",
            },
            VulnerabilityReopenedEvent,
        ),
        (
            "vulnerability.status_updated",
            {
                "vulnerability_id": "vuln_2",
                "old_status": "OPEN",
                "new_status": "IN_PROGRESS",
                "changed_by": "usr_123",
                "changed_at": "2026-04-16T10:10:00+00:00",
            },
            VulnerabilityStatusUpdatedEvent,
        ),
        (
            "vulnerability.severity_changed",
            {
                "vulnerability_id": "vuln_3",
                "old_severity": "LOW",
                "new_severity": "CRITICAL",
                "changed_by": "usr_999",
                "changed_at": "2026-04-16T10:11:00+00:00",
            },
            VulnerabilitySeverityChangedEvent,
        ),
    ],
)
def test_event_types_parse_into_dataclasses(
    event_type: str,
    payload_data: dict[str, object],
    event_class: EventClass,
    signer: Callable[[bytes, str], str],
) -> None:
    envelope = make_envelope(payload_data)
    envelope["type"] = event_type
    payload = json.dumps(envelope).encode("utf-8")
    signature = signer(payload)
    handler = WebhookHandler(secret=WEBHOOK_SECRET)

    event = handler.verify_and_parse(payload=payload, signature=signature, event_type=event_type)

    assert isinstance(event, event_class)
    assert event.id == "evt_123"
    assert event.created_at == datetime.fromisoformat("2026-04-16T10:00:00+00:00")
    assert event.organization_id == "org_123"


def test_unknown_event_type_raises_parse_error(signer: Callable[[bytes, str], str]) -> None:
    envelope = make_envelope(
        {
            "vulnerability_id": "vuln_1",
        }
    )
    payload = json.dumps(envelope).encode("utf-8")
    signature = signer(payload)
    handler = WebhookHandler(secret=WEBHOOK_SECRET)

    with pytest.raises(WebhookParseError):
        handler.verify_and_parse(
            payload=payload,
            signature=signature,
            event_type="vulnerability.unknown",
        )
