"""Dataclass models describing the mutable state of the Nexora Systems estate.

The models are intentionally *descriptive only*: they record what the telemetry
of a real estate would record (who, where, from which device, with what result).
No field labels an actor as malicious and no field names a compromised account —
that conclusion has to be inferred from the evidence by whatever consumes the
state.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Severity shared by alerts and incidents."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UserAccessLevel(str, Enum):
    """Coarse entitlement tier assigned to a directory account."""

    STANDARD = "standard"
    SECURITY = "security"
    PRIVILEGED = "privileged"


class AssetType(str, Enum):
    IDENTITY = "identity"
    SOURCE_CONTROL = "source_control"
    CLOUD_ACCOUNT = "cloud_account"
    NETWORK_EDGE = "network_edge"
    COMPUTE = "compute"
    DATA_STORE = "data_store"


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CROWN_JEWEL = "crown_jewel"


class SessionStatus(str, Enum):
    ACTIVE = "active"
    TERMINATED = "terminated"
    EXPIRED = "expired"


class TokenStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class EnvironmentStatus(str, Enum):
    """Overall posture reported by the environment."""

    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    COMPROMISED = "COMPROMISED"
    CONTAINED = "CONTAINED"


def _plain(value: Any) -> Any:
    """Recursively replace enum members with their values."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


@dataclass
class Organization:
    """The fictional company the environment simulates."""

    name: str
    domain: str
    industry: str
    headquarters: str
    offices: List[str]
    employee_count: int
    soc_tier: str


@dataclass
class User:
    """A directory account."""

    user_id: str
    full_name: str
    email: str
    role: str
    department: str
    office_location: str
    home_country: str
    access_level: UserAccessLevel
    groups: List[str]
    mfa_enrolled: bool
    mfa_methods: List[str]
    account_created: str
    last_password_rotation: str
    typical_login_hours_local: str
    known_devices: List[str]
    status: str = "enabled"


@dataclass
class Asset:
    """A system Nexora depends on."""

    asset_id: str
    name: str
    asset_type: AssetType
    criticality: AssetCriticality
    owner: str
    environment: str
    region: str
    internet_facing: bool
    data_classification: str
    depends_on: List[str] = field(default_factory=list)
    status: str = "online"


@dataclass
class GeoLocation:
    """Where a network source resolves to, as reported by GeoIP enrichment."""

    city: str
    country: str
    country_code: str
    latitude: float
    longitude: float


@dataclass
class Session:
    """An authenticated session held against the identity provider."""

    session_id: str
    user_id: str
    started_at: str
    last_activity_at: str
    source_ip: str
    geo: GeoLocation
    asn: str
    isp: str
    network_type: str
    device_id: str
    device_managed: bool
    user_agent: str
    client_platform: str
    mfa_satisfied: bool
    auth_method: str
    status: SessionStatus
    assets_touched: List[str] = field(default_factory=list)


@dataclass
class Token:
    """An OAuth token or personal access token issued against an account."""

    token_id: str
    owner: str
    token_type: str
    issued_at: str
    expires_at: str
    issued_via_session: str
    issued_from_ip: str
    permissions: List[str]
    status: TokenStatus
    consent_prompt_shown: bool
    client_name: str
    client_registered_at: str
    last_used_at: Optional[str] = None


@dataclass
class AuthenticationEvent:
    """An identity-provider event: sign-in, MFA challenge, token issuance."""

    event_id: str
    timestamp: str
    user_id: str
    event_type: str
    outcome: EventOutcome
    source_ip: str
    geo: GeoLocation
    asn: str
    device_id: str
    user_agent: str
    auth_method: str
    mfa_satisfied: bool
    session_id: Optional[str] = None
    target_asset: str = "identity-provider"
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CloudEvent:
    """An audited action taken against a SaaS or cloud control plane."""

    event_id: str
    timestamp: str
    actor: str
    asset_id: str
    service: str
    action: str
    resource: str
    outcome: EventOutcome
    source_ip: str
    session_id: Optional[str] = None
    token_id: Optional[str] = None
    user_agent: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkEvent:
    """A flow record observed at the network edge."""

    event_id: str
    timestamp: str
    source_ip: str
    source_geo: GeoLocation
    destination_asset: str
    destination_port: int
    protocol: str
    action: str
    bytes_in: int
    bytes_out: int
    duration_seconds: int
    tls_fingerprint: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityAlert:
    """A detection produced by one of Nexora's monitoring rules."""

    alert_id: str
    timestamp: str
    rule_id: str
    title: str
    severity: Severity
    source: str
    description: str
    related_users: List[str]
    related_assets: List[str]
    related_sessions: List[str]
    related_events: List[str]
    evidence: Dict[str, Any]
    status: AlertStatus = AlertStatus.OPEN


@dataclass
class BlockedIP:
    """A source address currently denied at the network edge."""

    ip_address: str
    reason: str
    blocked_at: str
    blocked_by: str
    scope: str
    expires_at: Optional[str] = None


@dataclass
class IncidentStatus:
    """Aggregate posture of the environment."""

    incident_id: str
    status: EnvironmentStatus
    severity: Severity
    declared_at: str
    declared_by: str
    open_alert_count: int
    highest_alert_severity: Severity
    containment_actions: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class EnvironmentState:
    """The complete mutable state of the simulated estate."""

    scenario: str
    simulation_time: str
    organization: Organization
    users: Dict[str, User]
    assets: Dict[str, Asset]
    sessions: Dict[str, Session]
    tokens: Dict[str, Token]
    authentication_events: List[AuthenticationEvent]
    cloud_events: List[CloudEvent]
    network_events: List[NetworkEvent]
    security_alerts: List[SecurityAlert]
    blocked_ips: List[BlockedIP]
    incident_status: IncidentStatus

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain, JSON-serializable deep copy of the state."""
        return _plain(asdict(self))
