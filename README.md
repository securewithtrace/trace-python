# Trace Python SDK

[![pypi](https://img.shields.io/pypi/v/securewithtrace)](https://pypi.org/project/securewithtrace)
[![CI](https://github.com/securewithtrace/trace-python/actions/workflows/ci.yml/badge.svg)](https://github.com/securewithtrace/trace-python/actions/workflows/ci.yml)

The Trace Python SDK provides convenient access to webhook event parsing and signature verification for the [Trace](https://securewithtrace.com) security platform.

## Installation

```sh
# pip
pip install securewithtrace

# uv
uv add securewithtrace

# poetry
poetry add securewithtrace
```

## Requirements

Python 3.12+

## Usage

### Webhook Verification

Verify and parse incoming webhook events from Trace. The SDK validates HMAC-SHA256 signatures and parses the payload into strongly-typed dataclasses.

```python
from securewithtrace import WebhookHandler, WebhookVerificationError, WebhookParseError

handler = WebhookHandler(secret="whsec_your_webhook_secret")

# In your webhook endpoint handler:
def handle_webhook(request):
    try:
        event = handler.verify_and_parse(
            payload=request.body,
            signature=request.headers["X-Trace-Signature"],
            event_type=request.headers["X-Trace-Event"],
        )
    except WebhookVerificationError:
        return Response(status=401)  # Invalid signature
    except WebhookParseError:
        return Response(status=400)  # Malformed payload

    match event.type:
        case "vulnerability.detected":
            print(f"New vulnerability: {event.data.title} ({event.data.severity.value})")
        case "vulnerability.fixed":
            print(f"Fixed: {event.data.title}")
        case "vulnerability.reopened":
            print(f"Reopened: {event.data.title}")
        case "vulnerability.status_updated":
            print(f"Status changed: {event.data.old_status.value} -> {event.data.new_status.value}")
        case "vulnerability.severity_changed":
            print(f"Severity changed: {event.data.old_severity.value} -> {event.data.new_severity.value}")

    return Response(status=200)
```

### Signature Verification Only

If you need to verify the signature without parsing:

```python
handler = WebhookHandler(secret="whsec_your_webhook_secret")

is_valid = handler.verify_signature(
    payload=request.body,
    signature=request.headers["X-Trace-Signature"],
)
```

### Event Types

The SDK provides typed dataclasses for all webhook event types:

| Event Type | Class |
|---|---|
| `vulnerability.detected` | `VulnerabilityDetectedEvent` |
| `vulnerability.fixed` | `VulnerabilityFixedEvent` |
| `vulnerability.reopened` | `VulnerabilityReopenedEvent` |
| `vulnerability.status_updated` | `VulnerabilityStatusUpdatedEvent` |
| `vulnerability.severity_changed` | `VulnerabilitySeverityChangedEvent` |

### Exception Handling

```python
from securewithtrace import WebhookVerificationError, WebhookParseError

try:
    event = handler.verify_and_parse(payload, signature, event_type)
except WebhookVerificationError:
    # Signature mismatch — reject the request
    ...
except WebhookParseError:
    # Payload could not be parsed — unknown event type, missing fields, etc.
    ...
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.
