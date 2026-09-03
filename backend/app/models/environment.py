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

    HEALTHY = "HEALTHY"
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
    restricted: bool = False
    exposed: bool = False
    recent_activity: List[str] = field(default_factory=list)


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


# --------------------------------------------------------------------------
# Digital-twin extensions (Phase 1B): endpoints, SaaS/cloud, telemetry, clock,
# safety governor and sandbox metadata. Everything below is synthetic data
# only — nothing here reads a real file, device, account or network.
# --------------------------------------------------------------------------


class TelemetrySource(str, Enum):
    """Where a unified telemetry event was observed."""

    IDENTITY = "IDENTITY"
    ENDPOINT = "ENDPOINT"
    SAAS = "SAAS"
    CLOUD = "CLOUD"
    NETWORK = "NETWORK"
    DATA = "DATA"


class SimulationStatus(str, Enum):
    """Lifecycle of the simulation itself, owned by the safety governor."""

    READY = "READY"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    EMERGENCY_STOPPED = "EMERGENCY_STOPPED"


class ScheduledEventStatus(str, Enum):
    PENDING = "pending"
    PROCESSED = "processed"
    CANCELLED = "cancelled"


@dataclass
class Process:
    """A process listed by the endpoint agent. Purely synthetic."""

    pid: int
    name: str
    command_line: str
    user: str
    started_at: str
    signed: bool
    parent_pid: Optional[int] = None
    status: str = "running"


@dataclass
class SyntheticFile:
    """A file recorded by the endpoint agent's inventory. Never read from disk."""

    path: str
    name: str
    type: str
    size: int
    sensitivity: str
    modified_at: str
    quarantined: bool = False


@dataclass
class Application:
    """Software inventory entry."""

    name: str
    version: str
    publisher: str
    installed_at: str
    managed: bool


@dataclass
class BrowserSession:
    """A browser profile session summary. No real browser data is touched."""

    session_id: str
    browser: str
    profile: str
    domain: str
    started_at: str
    active: bool = True


@dataclass
class EndpointConnection:
    """A socket observed on an endpoint."""

    connection_id: str
    process: str
    protocol: str
    remote_address: str
    remote_port: int
    direction: str
    state: str
    bytes_in: int
    bytes_out: int
    started_at: str


@dataclass
class PersistenceEntry:
    """A launch/startup item recorded on an endpoint."""

    entry_id: str
    mechanism: str
    name: str
    target: str
    created_at: str
    enabled: bool = True


@dataclass
class Download:
    """A file the endpoint agent saw arrive from the network."""

    download_id: str
    file_name: str
    source_domain: str
    downloaded_at: str
    size: int
    path: str


@dataclass
class Endpoint:
    """A managed workstation in the estate."""

    endpoint_id: str
    hostname: str
    owner: str
    os: str
    os_version: str
    status: str = "online"
    isolated: bool = False
    managed: bool = True
    last_seen: str = ""
    processes: List[Process] = field(default_factory=list)
    files: List[SyntheticFile] = field(default_factory=list)
    applications: List[Application] = field(default_factory=list)
    browser_sessions: List[BrowserSession] = field(default_factory=list)
    network_connections: List[EndpointConnection] = field(default_factory=list)
    persistence_entries: List[PersistenceEntry] = field(default_factory=list)
    downloads: List[Download] = field(default_factory=list)


@dataclass
class RegisteredDevice:
    """A device enrolled against a directory account."""

    device_id: str
    owner: str
    platform: str
    enrolled_at: str
    managed: bool
    compliant: bool
    endpoint_id: Optional[str] = None


@dataclass
class OAuthGrant:
    """A standing consent an account has given to a client application."""

    grant_id: str
    user_id: str
    client_name: str
    scopes: List[str]
    granted_at: str
    first_party: bool
    status: str = "active"


@dataclass
class MailboxEvent:
    """An audited mailbox action."""

    event_id: str
    timestamp: str
    mailbox: str
    event_type: str
    subject: str
    sender: str
    recipient: str
    outcome: EventOutcome
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MailboxRule:
    """An inbox rule configured on a mailbox."""

    rule_id: str
    mailbox: str
    name: str
    created_at: str
    created_by: str
    conditions: Dict[str, Any]
    actions: List[str]
    enabled: bool = True


@dataclass
class DriveEvent:
    """A cloud-drive access, preview or download."""

    event_id: str
    timestamp: str
    actor: str
    file_id: str
    file_name: str
    action: str
    sensitivity: str
    source_ip: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DnsEvent:
    """A DNS query seen by the resolver."""

    event_id: str
    timestamp: str
    source_endpoint: str
    query: str
    record_type: str
    resolved_ip: str
    action: str
    category: str


@dataclass
class OutboundTransferEvent:
    """An egress flow summary produced by the DLP/egress sensor."""

    event_id: str
    timestamp: str
    source_endpoint: str
    destination_domain: str
    destination_ip: str
    protocol: str
    bytes_out: int
    duration_seconds: int
    classification: str


@dataclass
class TelemetryEvent:
    """One normalised event on the unified telemetry bus.

    Records an observation only. No field states scenario truth.
    """

    id: str
    timestamp: str
    source: TelemetrySource
    category: str
    event_type: str
    severity: Severity
    message: str
    related_user: Optional[str] = None
    related_asset: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScheduledEvent:
    """A future simulation event sitting on the deterministic queue."""

    event_id: str
    name: str
    category: str
    scheduled_at: str
    attack_capable: bool = False
    status: ScheduledEventStatus = ScheduledEventStatus.PENDING
    payload: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SimulationClock:
    """Deterministic simulation time and its event queue. No real clock reads."""

    start_time: str
    current_time: str
    elapsed_seconds: int = 0
    scheduled_events: List[ScheduledEvent] = field(default_factory=list)
    processed_events: List[ScheduledEvent] = field(default_factory=list)
    cancelled_events: List[ScheduledEvent] = field(default_factory=list)


@dataclass
class SafetyState:
    """State the safety governor owns. Scoring itself lands in a later phase."""

    simulation_status: SimulationStatus = SimulationStatus.READY
    resilience_score: int = 100
    critical_failure_threshold: int = 15
    emergency_stop_reason: Optional[str] = None
    emergency_stopped_at: Optional[str] = None
    mutations_locked: bool = False


@dataclass
class SandboxBoundary:
    """Metadata for a future user-authorised workspace.

    Phase 1B carries the data model only: no path here is opened, copied or
    written, and `allowed_workspace` stays None until a user authorises one.
    """

    allowed_workspace: Optional[str] = None
    original_workspace_readonly: bool = True
    sandbox_copies: List[Dict[str, Any]] = field(default_factory=list)
    detached: bool = False
    detached_reason: Optional[str] = None


@dataclass
class HiddenState:
    """Internal simulation metadata.

    Excluded from observable snapshots. A future Red Engine may read scenario
    truth from here; the Blue Agent only ever sees what tools return.
    """

    scenario_truth: Dict[str, Any] = field(default_factory=dict)
    red_engine_notes: List[str] = field(default_factory=list)


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
    endpoints: Dict[str, Endpoint] = field(default_factory=dict)
    devices: Dict[str, RegisteredDevice] = field(default_factory=dict)
    oauth_grants: Dict[str, OAuthGrant] = field(default_factory=dict)
    mailbox_events: List[MailboxEvent] = field(default_factory=list)
    mailbox_rules: List[MailboxRule] = field(default_factory=list)
    drive_events: List[DriveEvent] = field(default_factory=list)
    dns_events: List[DnsEvent] = field(default_factory=list)
    outbound_transfer_events: List[OutboundTransferEvent] = field(default_factory=list)
    telemetry: List[TelemetryEvent] = field(default_factory=list)
    clock: SimulationClock = field(
        default_factory=lambda: SimulationClock(start_time="", current_time="")
    )
    safety: SafetyState = field(default_factory=SafetyState)
    sandbox: SandboxBoundary = field(default_factory=SandboxBoundary)
    hidden: HiddenState = field(default_factory=HiddenState)

    def to_dict(self, include_hidden: bool = False) -> Dict[str, Any]:
        """Return a plain, JSON-serializable deep copy of the observable state.

        `hidden` is dropped unless explicitly requested, so a snapshot handed to
        a defender never carries scenario truth.
        """
        snapshot = _plain(asdict(self))
        if not include_hidden:
            snapshot.pop("hidden", None)
        return snapshot
