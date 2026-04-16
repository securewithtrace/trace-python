from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Mapping, TypeAlias, TypeVar, cast

from securewithtrace.webhooks.exceptions import WebhookParseError


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScannerType(str, Enum):
    SAST = "SAST"
    SCA = "SCA"
    SECRETS = "SECRETS"
    DAST = "DAST"


class VulnerabilityStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    ARCHIVED = "ARCHIVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FIXED = "FIXED"


@dataclass(frozen=True)
class VulnerabilityDetectedData:
    vulnerability_id: str
    title: str
    severity: Severity
    scanner_type: ScannerType
    repository_name: str
    file_path: str
    description: str
    line_number: int | None = None
    cwe: str | None = None


@dataclass(frozen=True)
class VulnerabilityFixedData:
    vulnerability_id: str
    title: str
    severity: Severity
    repository_name: str
    fixed_at: datetime


@dataclass(frozen=True)
class VulnerabilityReopenedData:
    vulnerability_id: str
    title: str
    severity: Severity
    scanner_type: ScannerType
    repository_name: str
    file_path: str
    description: str
    reopened_at: datetime
    line_number: int | None = None
    cwe: str | None = None


@dataclass(frozen=True)
class VulnerabilityStatusUpdatedData:
    vulnerability_id: str
    old_status: VulnerabilityStatus
    new_status: VulnerabilityStatus
    changed_by: str
    changed_at: datetime


@dataclass(frozen=True)
class VulnerabilitySeverityChangedData:
    vulnerability_id: str
    old_severity: Severity
    new_severity: Severity
    changed_by: str
    changed_at: datetime


@dataclass(frozen=True)
class TraceEventEnvelope:
    id: str
    type: str
    created_at: datetime
    organization_id: str
    data: Any


@dataclass(frozen=True)
class VulnerabilityDetectedEvent(TraceEventEnvelope):
    type: Literal["vulnerability.detected"]
    data: VulnerabilityDetectedData


@dataclass(frozen=True)
class VulnerabilityFixedEvent(TraceEventEnvelope):
    type: Literal["vulnerability.fixed"]
    data: VulnerabilityFixedData


@dataclass(frozen=True)
class VulnerabilityReopenedEvent(TraceEventEnvelope):
    type: Literal["vulnerability.reopened"]
    data: VulnerabilityReopenedData


@dataclass(frozen=True)
class VulnerabilityStatusUpdatedEvent(TraceEventEnvelope):
    type: Literal["vulnerability.status_updated"]
    data: VulnerabilityStatusUpdatedData


@dataclass(frozen=True)
class VulnerabilitySeverityChangedEvent(TraceEventEnvelope):
    type: Literal["vulnerability.severity_changed"]
    data: VulnerabilitySeverityChangedData


TraceEvent: TypeAlias = (
    VulnerabilityDetectedEvent
    | VulnerabilityFixedEvent
    | VulnerabilityReopenedEvent
    | VulnerabilityStatusUpdatedEvent
    | VulnerabilitySeverityChangedEvent
)


def parse_event(event_type: str, data: Mapping[str, Any]) -> TraceEvent:
    event_id = _require_str(data, "id")
    payload_type = _require_str(data, "type")
    created_at = _require_datetime(data, "created_at")
    organization_id = _require_str(data, "organization_id")
    payload_data = _require_mapping(data, "data")
    if payload_type != event_type:
        raise WebhookParseError(
            f"Event type mismatch: header '{event_type}' does not match payload '{payload_type}'."
        )

    if event_type == "vulnerability.detected":
        return VulnerabilityDetectedEvent(
            id=event_id,
            type="vulnerability.detected",
            created_at=created_at,
            organization_id=organization_id,
            data=VulnerabilityDetectedData(
                vulnerability_id=_require_str(payload_data, "vulnerability_id"),
                title=_require_str(payload_data, "title"),
                severity=_require_enum(payload_data, "severity", Severity),
                scanner_type=_require_enum(payload_data, "scanner_type", ScannerType),
                repository_name=_require_str(payload_data, "repository_name"),
                file_path=_require_str(payload_data, "file_path"),
                line_number=_optional_int(payload_data, "line_number"),
                cwe=_optional_str(payload_data, "cwe"),
                description=_require_str(payload_data, "description"),
            ),
        )
    if event_type == "vulnerability.fixed":
        return VulnerabilityFixedEvent(
            id=event_id,
            type="vulnerability.fixed",
            created_at=created_at,
            organization_id=organization_id,
            data=VulnerabilityFixedData(
                vulnerability_id=_require_str(payload_data, "vulnerability_id"),
                title=_require_str(payload_data, "title"),
                severity=_require_enum(payload_data, "severity", Severity),
                repository_name=_require_str(payload_data, "repository_name"),
                fixed_at=_require_datetime(payload_data, "fixed_at"),
            ),
        )
    if event_type == "vulnerability.reopened":
        return VulnerabilityReopenedEvent(
            id=event_id,
            type="vulnerability.reopened",
            created_at=created_at,
            organization_id=organization_id,
            data=VulnerabilityReopenedData(
                vulnerability_id=_require_str(payload_data, "vulnerability_id"),
                title=_require_str(payload_data, "title"),
                severity=_require_enum(payload_data, "severity", Severity),
                scanner_type=_require_enum(payload_data, "scanner_type", ScannerType),
                repository_name=_require_str(payload_data, "repository_name"),
                file_path=_require_str(payload_data, "file_path"),
                line_number=_optional_int(payload_data, "line_number"),
                cwe=_optional_str(payload_data, "cwe"),
                description=_require_str(payload_data, "description"),
                reopened_at=_require_datetime(payload_data, "reopened_at"),
            ),
        )
    if event_type == "vulnerability.status_updated":
        return VulnerabilityStatusUpdatedEvent(
            id=event_id,
            type="vulnerability.status_updated",
            created_at=created_at,
            organization_id=organization_id,
            data=VulnerabilityStatusUpdatedData(
                vulnerability_id=_require_str(payload_data, "vulnerability_id"),
                old_status=_require_enum(payload_data, "old_status", VulnerabilityStatus),
                new_status=_require_enum(payload_data, "new_status", VulnerabilityStatus),
                changed_by=_require_str(payload_data, "changed_by"),
                changed_at=_require_datetime(payload_data, "changed_at"),
            ),
        )
    if event_type == "vulnerability.severity_changed":
        return VulnerabilitySeverityChangedEvent(
            id=event_id,
            type="vulnerability.severity_changed",
            created_at=created_at,
            organization_id=organization_id,
            data=VulnerabilitySeverityChangedData(
                vulnerability_id=_require_str(payload_data, "vulnerability_id"),
                old_severity=_require_enum(payload_data, "old_severity", Severity),
                new_severity=_require_enum(payload_data, "new_severity", Severity),
                changed_by=_require_str(payload_data, "changed_by"),
                changed_at=_require_datetime(payload_data, "changed_at"),
            ),
        )

    raise WebhookParseError(f"Unknown event type: {event_type}")


def _require_str(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if isinstance(value, str):
        return value
    raise WebhookParseError(f"Expected '{key}' to be a string.")


def _optional_str(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise WebhookParseError(f"Expected '{key}' to be a string if provided.")


def _optional_int(data: Mapping[str, Any], key: str) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise WebhookParseError(f"Expected '{key}' to be an integer if provided.")


def _require_mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key)
    if isinstance(value, Mapping):
        return cast(Mapping[str, Any], value)
    raise WebhookParseError(f"Expected '{key}' to be an object.")


def _require_datetime(data: Mapping[str, Any], key: str) -> datetime:
    raw = _require_str(data, key)
    try:
        return datetime.fromisoformat(raw)
    except ValueError as error:
        raise WebhookParseError(f"Invalid ISO-8601 datetime for '{key}'.") from error


TEnum = TypeVar("TEnum", bound=Enum)


def _require_enum(data: Mapping[str, Any], key: str, enum_type: type[TEnum]) -> TEnum:
    raw = _require_str(data, key)
    try:
        return enum_type(raw)
    except ValueError as error:
        valid = ", ".join(item.value for item in enum_type)
        raise WebhookParseError(
            f"Invalid value '{raw}' for '{key}'. Expected one of: {valid}."
        ) from error


__all__ = [
    "Severity",
    "ScannerType",
    "VulnerabilityStatus",
    "VulnerabilityDetectedData",
    "VulnerabilityFixedData",
    "VulnerabilityReopenedData",
    "VulnerabilityStatusUpdatedData",
    "VulnerabilitySeverityChangedData",
    "TraceEventEnvelope",
    "VulnerabilityDetectedEvent",
    "VulnerabilityFixedEvent",
    "VulnerabilityReopenedEvent",
    "VulnerabilityStatusUpdatedEvent",
    "VulnerabilitySeverityChangedEvent",
    "TraceEvent",
    "parse_event",
]
