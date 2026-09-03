"""The Red side of the Nexora cyber range.

`RedAttackEngine` schedules a scripted attack onto the *existing* simulation
event queue and mutates synthetic state as each stage comes due. There is no
second clock, no randomness, no exploit code, no payload and no I/O of any
kind — every "attack" here is a dataclass being appended to an in-memory list.

Two rules shape the design:

* Everything the Red side *knows* (which account it is riding, which session,
  what it is after) lives in `state.hidden`, which observable snapshots drop.
  The Blue side only ever sees the evidence: a device that enrolled itself, a
  consent-less token, an inbox rule that hides mail, a clone burst at 09:03.
* Every mutation goes through the SafetyGovernor. Paused means no progress,
  emergency-stopped means no further mutation, and crossing the critical
  resilience threshold stops the range on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from app.models.environment import (
    AuthenticationEvent,
    CloudEvent,
    DnsEvent,
    DriveEvent,
    EnvironmentStatus,
    EventOutcome,
    MailboxEvent,
    MailboxRule,
    NetworkEvent,
    OAuthGrant,
    OutboundTransferEvent,
    RegisteredDevice,
    ScheduledEvent,
    ScheduledEventStatus,
    SecurityAlert,
    Session,
    SessionStatus,
    Severity,
    SimulationStatus,
    TelemetrySource,
    Token,
    TokenStatus,
)
from app.simulator.environment import CyberEnvironment
from app.simulator.scenarios import (
    ENDPOINT_ARJUN,
    IP_ARJUN_BANGALORE,
    JA3_UNKNOWN_LINUX,
    MOSCOW,
    UA_LINUX_CHROME,
)

FLAGSHIP_SCENARIO = "operation_maya"

# Synthetic adversary infrastructure. These addresses and domains are invented
# for the simulation; `.example` is the reserved documentation TLD.
IP_RED_INFRA = "185.220.101.61"
ASN_RED_INFRA = "AS49505 OOO Network of Data-Centers Selectel"
SUPPLIER_DOMAIN = "northwind-supply.example"
RED_PORTAL_DOMAIN = "vendor-portal-login.example"
RED_EGRESS_DOMAIN = "cdn-sync.vendor-portal-login.example"
IP_RED_EGRESS = "185.220.101.94"

ROGUE_DEVICE_ID = "device-unmanaged-9f2c"
ROGUE_SESSION_ID = "sess-3101"
ROGUE_TOKEN_ID = "oauth-9001"
ROGUE_GRANT_ID = "grant-2101"
TARGET_USER = "arjun.rao"


class AttackStatus(str):
    """Lifecycle of a red operation."""

    IDLE = "IDLE"
    ACTIVE = "ACTIVE"
    DISRUPTED = "DISRUPTED"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"
    EMERGENCY_STOPPED = "EMERGENCY_STOPPED"


@dataclass(frozen=True)
class AttackStage:
    """One scripted step: when it fires, what it costs, what it looks like."""

    key: str
    offset_seconds: int
    resilience_cost: int
    source: TelemetrySource
    category: str
    event_type: str
    severity: Severity
    message: str
    related_asset: str
    metadata: Dict[str, Any] = field(default_factory=dict)


# The flagship progression: identity -> SaaS -> developer/cloud -> data risk.
OPERATION_MAYA: List[AttackStage] = [
    AttackStage(
        "supplier_contact", 20, 4, TelemetrySource.IDENTITY, "authentication",
        "device_code_authorization_requested", Severity.LOW,
        "Device-code authorization requested for an account moments after a "
        "supplier message linking to an external portal.",
        "identity-provider",
        {"source_ip": IP_RED_INFRA, "link_domain": RED_PORTAL_DOMAIN, "dmarc": "fail"},
    ),
    AttackStage(
        "rogue_device", 45, 4, TelemetrySource.IDENTITY, "authentication",
        "unmanaged_device_enrolled", Severity.MEDIUM,
        "Sign-in accepted from an unmanaged device on a hosting network never "
        "seen for this account.",
        "identity-provider",
        {"device_id": ROGUE_DEVICE_ID, "source_ip": IP_RED_INFRA, "managed": False},
    ),
    AttackStage(
        "oauth_grant", 70, 8, TelemetrySource.IDENTITY, "authorization",
        "oauth_token_issued", Severity.HIGH,
        "Broad-scope OAuth token issued to a third-party client with no consent "
        "prompt recorded.",
        "identity-provider",
        {"token_id": ROGUE_TOKEN_ID, "consent_prompt_shown": False},
    ),
    AttackStage(
        "mailbox_discovery", 100, 6, TelemetrySource.SAAS, "mail",
        "mailbox_search", Severity.MEDIUM,
        "Bulk mailbox searches for financial and credential keywords from a "
        "non-interactive client.",
        "identity-provider",
        {"queries": ["invoice", "wire transfer", "vpn", "password"]},
    ),
    AttackStage(
        "mailbox_rule", 130, 6, TelemetrySource.SAAS, "mail",
        "inbox_rule_created", Severity.HIGH,
        "Inbox rule created that marks security and finance mail read and files "
        "it out of the inbox.",
        "identity-provider",
        {"rule_id": "rule-2001", "actions": ["mark_as_read", "move_to:RSS Feeds"]},
    ),
    AttackStage(
        "drive_access", 165, 7, TelemetrySource.SAAS, "drive",
        "bulk_file_access", Severity.MEDIUM,
        "Confidential finance documents searched, previewed and downloaded in "
        "rapid succession.",
        "identity-provider",
        {"files": 3, "sensitivity": "confidential"},
    ),
    AttackStage(
        "github_activity", 200, 6, TelemetrySource.CLOUD, "source_control",
        "repository_clone_burst", Severity.HIGH,
        "Three private repositories cloned in full by an account averaging under "
        "one clone a day.",
        "github",
        {"repository_count": 3, "bytes_transferred": 418_942_976},
    ),
    AttackStage(
        "cloud_privilege", 240, 9, TelemetrySource.CLOUD, "cloud_api",
        "privileged_role_assumed", Severity.HIGH,
        "Production administrator role assumed by a principal with no prior use "
        "of that role.",
        "aws",
        {"role": "arn:aws:iam::418322947610:role/NexoraProdAdmin"},
    ),
    AttackStage(
        "prod_discovery", 285, 8, TelemetrySource.NETWORK, "flow",
        "infrastructure_enumeration", Severity.HIGH,
        "Production compute and data endpoints enumerated, followed by refused "
        "direct connection attempts.",
        "production-server",
        {"assets_enumerated": 12, "denied_attempts": 3},
    ),
    AttackStage(
        "data_query", 330, 12, TelemetrySource.DATA, "database",
        "bulk_record_read", Severity.CRITICAL,
        "Bulk read of the customer PII store followed by a write to an "
        "unfamiliar staging bucket.",
        "customer-database",
        {"rows_returned": 48_000, "table_classification": "restricted-pii"},
    ),
    AttackStage(
        "exfiltration", 370, 15, TelemetrySource.NETWORK, "egress",
        "large_outbound_transfer", Severity.CRITICAL,
        "Sustained outbound transfer of staged data to a newly registered "
        "external domain.",
        "api-gateway",
        {"destination_domain": RED_EGRESS_DOMAIN, "bytes_out": 2_147_483_648},
    ),
]

# The one adaptive continuation: the cloud stage retried over the rogue
# session after its token was revoked.
CLOUD_FALLBACK_DELAY_SECONDS = 30


class RedAttackEngine:
    """Drives `operation_maya` over the shared simulation clock."""

    def __init__(self, env: CyberEnvironment) -> None:
        self._env = env
        self._status: str = AttackStatus.IDLE
        self._scenario: Optional[str] = None
        env.event_handlers.append(self._on_event)

    # -- control ----------------------------------------------------------

    def launch_scenario(self, scenario: str = FLAGSHIP_SCENARIO) -> Dict[str, Any]:
        """Queue every stage of the operation onto the simulation event queue."""
        if scenario != FLAGSHIP_SCENARIO:
            raise ValueError(f"Unknown red scenario {scenario!r}. Available: {FLAGSHIP_SCENARIO}")
        self._require_governor_allows()
        self._scenario = scenario
        self._status = AttackStatus.ACTIVE
        for stage in OPERATION_MAYA:
            self._schedule(stage, stage.offset_seconds)
        self._env.state.hidden.scenario_truth["red"] = {
            "scenario": scenario,
            "status": self._status,
            "objective": "stage and exfiltrate customer records via a supplier-themed lure",
            "targeted_identity": TARGET_USER,
            "compromised_session": ROGUE_SESSION_ID,
            "rogue_device": ROGUE_DEVICE_ID,
            "rogue_token": ROGUE_TOKEN_ID,
            "current_stage": None,
            "completed_stages": [],
            "branch": "primary",
        }
        self._env.state.hidden.red_engine_notes.append(
            f"{scenario} queued: {len(OPERATION_MAYA)} stages from {self._env.get_current_time()}."
        )
        return self.get_attack_status()

    def get_attack_status(self) -> Dict[str, Any]:
        """Red-side view of the operation. Not reachable from any Blue tool."""
        state = self._env.state
        truth = self._red_truth()
        if state.safety.simulation_status is SimulationStatus.EMERGENCY_STOPPED:
            self._status = AttackStatus.EMERGENCY_STOPPED
        return {
            "status": self._status,
            "scenario": self._scenario,
            "current_stage": truth.get("current_stage"),
            "completed_stages": list(truth.get("completed_stages", [])),
            "pending_stages": [e.payload["red_stage"] for e in self._pending()],
            "branch": truth.get("branch"),
            "resilience_score": state.safety.resilience_score,
            "simulation_status": state.safety.simulation_status.value,
            "telemetry_events": len(state.telemetry),
        }

    def stop_attack(self) -> Dict[str, Any]:
        """Cancel future red events. Everything already done to the range stays."""
        cancelled = self._cancel_pending()
        if self._status == AttackStatus.ACTIVE:
            self._status = AttackStatus.STOPPED
        self._sync_truth(status=self._status)
        return {"status": self._status, "cancelled_events": cancelled}

    def reset_attack(self) -> Dict[str, Any]:
        """Restore the clean baseline through the governor and go idle."""
        self._env.safety.restore_baseline()
        self._status = AttackStatus.IDLE
        self._scenario = None
        return self.get_attack_status()

    # -- scheduling and dispatch -----------------------------------------

    def _schedule(self, stage: AttackStage, delay_seconds: int, branch: str = "primary") -> None:
        payload = {
            "source": stage.source.value,
            "category": stage.category,
            "event_type": stage.event_type,
            "severity": stage.severity.value,
            "message": stage.message,
            "related_user": TARGET_USER,
            "related_asset": stage.related_asset,
            "metadata": dict(stage.metadata),
            "red_stage": stage.key,
            "red_branch": branch,
        }
        self._env.schedule_event(
            name=f"red:{stage.key}",
            delay_seconds=delay_seconds,
            category="red_operation",
            attack_capable=True,
            payload=payload,
        )

    def _on_event(self, event: ScheduledEvent) -> None:
        """Apply a stage's synthetic effects as its queued event comes due."""
        stage_key = event.payload.get("red_stage")
        if stage_key is None or self._status not in (AttackStatus.ACTIVE, AttackStatus.DISRUPTED):
            return
        if not self._governor_allows():
            return
        stage = STAGES_BY_KEY[stage_key]
        # Past the foothold stages the operation needs a live route. Blue closing
        # both the token and the session is what disrupts it.
        if stage_key not in ("supplier_contact", "rogue_device", "oauth_grant", "cloud_privilege"):
            token_ok, session_ok = self._route()
            if not (token_ok or session_ok):
                self._disrupt(event.scheduled_at, "no usable credential or session remains")
                return
        applied = self._MUTATIONS[stage_key](self, stage, event)
        if not applied:
            return
        self._record_stage(stage_key)
        self._raise_alert(stage, event)
        self._apply_cost(stage.resilience_cost)

    def _route(self) -> tuple:
        """Whether the rogue token and the rogue session are still usable."""
        state = self._env.state
        token = state.tokens.get(ROGUE_TOKEN_ID)
        session = state.sessions.get(ROGUE_SESSION_ID)
        return (
            token is not None and token.status is TokenStatus.ACTIVE,
            session is not None and session.status is SessionStatus.ACTIVE,
        )

    def _raise_alert(self, stage: AttackStage, event: ScheduledEvent) -> None:
        """Nexora's own monitoring firing on the evidence, not on scenario truth."""
        if stage.severity not in (Severity.HIGH, Severity.CRITICAL):
            return
        state = self._env.state
        state.security_alerts.append(
            SecurityAlert(
                alert_id=f"alert-{1000 + len(state.security_alerts) + 1}",
                timestamp=event.scheduled_at,
                rule_id=f"NX-{stage.source.value[:3]}-{stage.offset_seconds:03d}",
                title=stage.message.split(".")[0],
                severity=stage.severity,
                source=stage.source.value.lower(),
                description=stage.message,
                related_users=[TARGET_USER],
                related_assets=[stage.related_asset],
                related_sessions=[ROGUE_SESSION_ID],
                related_events=[],
                evidence=dict(stage.metadata),
            )
        )

    # -- stage effects ----------------------------------------------------

    def _supplier_contact(self, stage: AttackStage, event: ScheduledEvent) -> bool:
        state = self._env.state
        at = event.scheduled_at
        state.mailbox_events.append(
            MailboxEvent(
                event_id="mail-2001",
                timestamp=at,
                mailbox=f"{TARGET_USER}@nexorasystems.io",
                event_type="message_received",
                subject="Updated vendor portal access — action required",
                sender=f"procurement@{SUPPLIER_DOMAIN}",
                recipient=f"{TARGET_USER}@nexorasystems.io",
                outcome=EventOutcome.SUCCESS,
                details={
                    "spf": "pass",
                    "dkim": "fail",
                    "dmarc": "fail",
                    "sender_domain_age_days": 6,
                    "link_domain": RED_PORTAL_DOMAIN,
                    "first_contact_with_domain": True,
                },
            )
        )
        state.authentication_events.append(
            AuthenticationEvent(
                event_id="auth-2001",
                timestamp=at,
                user_id=TARGET_USER,
                event_type="device_code_authorization_requested",
                outcome=EventOutcome.SUCCESS,
                source_ip=IP_RED_INFRA,
                geo=MOSCOW,
                asn=ASN_RED_INFRA,
                device_id=ROGUE_DEVICE_ID,
                user_agent=UA_LINUX_CHROME,
                auth_method="device_code",
                mfa_satisfied=False,
                details={
                    "device_registered": False,
                    "risk_score": 62,
                    "approved_from_ip": IP_ARJUN_BANGALORE,
                },
            )
        )
        return True

    def _rogue_device(self, stage: AttackStage, event: ScheduledEvent) -> bool:
        state = self._env.state
        at = event.scheduled_at
        state.devices[ROGUE_DEVICE_ID] = RegisteredDevice(
            device_id=ROGUE_DEVICE_ID,
            owner=TARGET_USER,
            platform="Linux x86_64",
            enrolled_at=at,
            managed=False,
            compliant=False,
        )
        state.users[TARGET_USER].known_devices.append(ROGUE_DEVICE_ID)
        state.sessions[ROGUE_SESSION_ID] = Session(
            session_id=ROGUE_SESSION_ID,
            user_id=TARGET_USER,
            started_at=at,
            last_activity_at=at,
            source_ip=IP_RED_INFRA,
            geo=MOSCOW,
            asn=ASN_RED_INFRA,
            isp="Selectel",
            network_type="hosting_provider",
            device_id=ROGUE_DEVICE_ID,
            device_managed=False,
            user_agent=UA_LINUX_CHROME,
            client_platform="Linux x86_64",
            mfa_satisfied=True,
            auth_method="device_code",
            status=SessionStatus.ACTIVE,
            assets_touched=["identity-provider"],
        )
        state.authentication_events.append(
            AuthenticationEvent(
                event_id="auth-2002",
                timestamp=at,
                user_id=TARGET_USER,
                event_type="user_login",
                outcome=EventOutcome.SUCCESS,
                source_ip=IP_RED_INFRA,
                geo=MOSCOW,
                asn=ASN_RED_INFRA,
                device_id=ROGUE_DEVICE_ID,
                user_agent=UA_LINUX_CHROME,
                auth_method="device_code",
                mfa_satisfied=True,
                session_id=ROGUE_SESSION_ID,
                details={
                    "device_registered": False,
                    "risk_score": 88,
                    "network_type": "hosting_provider",
                    "account_login_countries_90d": ["IN"],
                },
            )
        )
        return True

    def _oauth_grant(self, stage: AttackStage, event: ScheduledEvent) -> bool:
        state = self._env.state
        at = event.scheduled_at
        scopes = ["mail.read", "drive.read", "github.read", "aws.assume_role", "database.read"]
        state.oauth_grants[ROGUE_GRANT_ID] = OAuthGrant(
            grant_id=ROGUE_GRANT_ID,
            user_id=TARGET_USER,
            client_name="vendor-portal-sync",
            scopes=scopes,
            granted_at=at,
            first_party=False,
        )
        state.tokens[ROGUE_TOKEN_ID] = Token(
            token_id=ROGUE_TOKEN_ID,
            owner=TARGET_USER,
            token_type="oauth_access_token",
            issued_at=at,
            expires_at=at,
            issued_via_session=ROGUE_SESSION_ID,
            issued_from_ip=IP_RED_INFRA,
            permissions=scopes,
            status=TokenStatus.ACTIVE,
            consent_prompt_shown=False,
            client_name="vendor-portal-sync",
            client_registered_at=at,
            last_used_at=at,
        )
        state.authentication_events.append(
            AuthenticationEvent(
                event_id="auth-2003",
                timestamp=at,
                user_id=TARGET_USER,
                event_type="oauth_token_issued",
                outcome=EventOutcome.SUCCESS,
                source_ip=IP_RED_INFRA,
                geo=MOSCOW,
                asn=ASN_RED_INFRA,
                device_id=ROGUE_DEVICE_ID,
                user_agent=UA_LINUX_CHROME,
                auth_method="session_bearer",
                mfa_satisfied=False,
                session_id=ROGUE_SESSION_ID,
                details={
                    "token_id": ROGUE_TOKEN_ID,
                    "client_name": "vendor-portal-sync",
                    "client_first_party": False,
                    "client_registered_at": at,
                    "consent_prompt_shown": False,
                    "permissions": scopes,
                },
            )
        )
        return True

    def _mailbox_discovery(self, stage: AttackStage, event: ScheduledEvent) -> bool:
        state = self._env.state
        at = event.scheduled_at
        for index, query in enumerate(stage.metadata["queries"], start=1):
            state.mailbox_events.append(
                MailboxEvent(
                    event_id=f"mail-21{index:02d}",
                    timestamp=at,
                    mailbox=f"{TARGET_USER}@nexorasystems.io",
                    event_type="mailbox_search",
                    subject=f"search: {query}",
                    sender="",
                    recipient=f"{TARGET_USER}@nexorasystems.io",
                    outcome=EventOutcome.SUCCESS,
                    details={
                        "query": query,
                        "results": 40 + index * 7,
                        "client": "vendor-portal-sync",
                        "source_ip": IP_RED_INFRA,
                    },
                )
            )
        return True

    def _mailbox_rule(self, stage: AttackStage, event: ScheduledEvent) -> bool:
        state = self._env.state
        at = event.scheduled_at
        state.mailbox_rules.append(
            MailboxRule(
                rule_id="rule-2001",
                mailbox=f"{TARGET_USER}@nexorasystems.io",
                name=".",
                created_at=at,
                created_by="vendor-portal-sync",
                conditions={
                    "subject_or_body_contains": [
                        "invoice", "payment", "security alert", "sign-in",
                    ]
                },
                actions=["mark_as_read", "move_to:RSS Feeds"],
            )
        )
        state.mailbox_events.append(
            MailboxEvent(
                event_id="mail-2201",
                timestamp=at,
                mailbox=f"{TARGET_USER}@nexorasystems.io",
                event_type="inbox_rule_created",
                subject="rule created: .",
                sender="",
                recipient=f"{TARGET_USER}@nexorasystems.io",
                outcome=EventOutcome.SUCCESS,
                details={
                    "rule_id": "rule-2001",
                    "created_via": "api",
                    "source_ip": IP_RED_INFRA,
                    "rule_name_length": 1,
                },
            )
        )
        return True

    def _drive_access(self, stage: AttackStage, event: ScheduledEvent) -> bool:
        state = self._env.state
        at = event.scheduled_at
        documents = [
            ("file-9001", "finance-budget.xlsx", "preview", "confidential"),
            ("file-9003", "vendor-invoice.pdf", "download", "confidential"),
            ("file-9004", "customer-contracts-2026.zip", "download", "restricted"),
        ]
        for index, (file_id, name, action, sensitivity) in enumerate(documents, start=1):
            state.drive_events.append(
                DriveEvent(
                    event_id=f"drive-22{index:02d}",
                    timestamp=at,
                    actor=TARGET_USER,
                    file_id=file_id,
                    file_name=name,
                    action=action,
                    sensitivity=sensitivity,
                    source_ip=IP_RED_INFRA,
                    details={
                        "client": "vendor-portal-sync",
                        "shared_externally": False,
                        "actor_30d_avg_downloads_per_day": 1.2,
                    },
                )
            )
        return True

    def _github_activity(self, stage: AttackStage, event: ScheduledEvent) -> bool:
        state = self._env.state
        at = event.scheduled_at
        state.cloud_events.append(
            CloudEvent(
                event_id="cloud-2301",
                timestamp=at,
                actor=TARGET_USER,
                asset_id="github",
                service="github",
                action="repo.clone",
                resource="nexora/infra-terraform, nexora/customer-platform, nexora/secrets-rotation",
                outcome=EventOutcome.SUCCESS,
                source_ip=IP_RED_INFRA,
                session_id=ROGUE_SESSION_ID,
                token_id=ROGUE_TOKEN_ID,
                user_agent="git/2.39.5",
                details={
                    "repository_count": 3,
                    "repository_visibility": "private",
                    "bytes_transferred": stage.metadata["bytes_transferred"],
                    "clone_depth": "full",
                    "actor_30d_avg_repo_clones_per_day": 0.4,
                },
            )
        )
        state.assets["github"].recent_activity.append("3 private repositories cloned in full")
        return True

    def _cloud_privilege(self, stage: AttackStage, event: ScheduledEvent) -> bool:
        """The one adaptive branch: the world reacts to what Blue has already done.

        If the rogue token is gone, the operation does not keep using it. It
        falls back to the rogue session if one is still live, and is disrupted
        outright if both routes have been closed.
        """
        state = self._env.state
        at = event.scheduled_at
        branch = event.payload.get("red_branch", "primary")
        token = state.tokens.get(ROGUE_TOKEN_ID)
        token_usable = token is not None and token.status is TokenStatus.ACTIVE
        session = state.sessions.get(ROGUE_SESSION_ID)
        session_usable = session is not None and session.status is SessionStatus.ACTIVE

        if not token_usable and branch == "primary":
            if session_usable:
                self._schedule(stage, CLOUD_FALLBACK_DELAY_SECONDS, branch="session_fallback")
                self._sync_truth(branch="session_fallback")
                self._env.state.hidden.red_engine_notes.append(
                    f"{at}: token route closed; retrying cloud stage over {ROGUE_SESSION_ID}."
                )
                return False
            self._disrupt(at, "token revoked and rogue session terminated")
            return False
        if not token_usable and not session_usable:
            self._disrupt(at, "no usable credential or session remains")
            return False

        credential_source = "oauth_token_exchange" if token_usable else "session_bearer"
        state.cloud_events.append(
            CloudEvent(
                event_id="cloud-2401" if branch == "primary" else "cloud-2402",
                timestamp=at,
                actor=TARGET_USER,
                asset_id="aws",
                service="sts",
                action="sts:AssumeRole",
                resource=stage.metadata["role"],
                outcome=EventOutcome.SUCCESS,
                source_ip=IP_RED_INFRA,
                session_id=ROGUE_SESSION_ID,
                token_id=ROGUE_TOKEN_ID if token_usable else None,
                user_agent="aws-sdk-go/1.55.5",
                details={
                    "role_permission_scope": "administrator",
                    "credential_source": credential_source,
                    "session_duration_seconds": 3600,
                    "actor_prior_assumptions_180d": 0,
                    "usual_credential_source": "sso_saml",
                },
            )
        )
        state.assets["aws"].recent_activity.append("NexoraProdAdmin assumed from a new principal")
        if session is not None:
            session.assets_touched.append("aws")
        return True

    def _prod_discovery(self, stage: AttackStage, event: ScheduledEvent) -> bool:
        state = self._env.state
        at = event.scheduled_at
        state.cloud_events.append(
            CloudEvent(
                event_id="cloud-2501",
                timestamp=at,
                actor=TARGET_USER,
                asset_id="aws",
                service="rds",
                action="rds:DescribeDBClusters",
                resource="arn:aws:rds:ap-south-1:418322947610:cluster:*",
                outcome=EventOutcome.SUCCESS,
                source_ip=IP_RED_INFRA,
                session_id=ROGUE_SESSION_ID,
                user_agent="aws-cli/2.15.30",
                details={"clusters_returned": 4, "read_only": True},
            )
        )
        state.network_events.extend(
            [
                NetworkEvent(
                    event_id="net-2501",
                    timestamp=at,
                    source_ip=IP_RED_INFRA,
                    source_geo=MOSCOW,
                    destination_asset="production-server",
                    destination_port=22,
                    protocol="tcp",
                    action="denied",
                    bytes_in=0,
                    bytes_out=0,
                    duration_seconds=0,
                    tls_fingerprint=JA3_UNKNOWN_LINUX,
                    details={"rule": "sg-prod-ssh: bastion sources only", "attempts": 3},
                ),
                NetworkEvent(
                    event_id="net-2502",
                    timestamp=at,
                    source_ip=IP_RED_INFRA,
                    source_geo=MOSCOW,
                    destination_asset="api-gateway",
                    destination_port=443,
                    protocol="tcp",
                    action="allowed",
                    bytes_in=88_112,
                    bytes_out=1_204_480,
                    duration_seconds=142,
                    tls_fingerprint=JA3_UNKNOWN_LINUX,
                    details={"rule": "edge-allow-authenticated", "requests": 412},
                ),
            ]
        )
        state.assets["production-server"].recent_activity.append(
            "3 refused SSH attempts from an external source"
        )
        return True

    def _data_query(self, stage: AttackStage, event: ScheduledEvent) -> bool:
        state = self._env.state
        at = event.scheduled_at
        database = state.assets["customer-database"]
        if database.restricted or database.status == "restricted":
            # Blue protected the store first: the read is refused at the policy.
            state.cloud_events.append(
                CloudEvent(
                    event_id="cloud-2603",
                    timestamp=at,
                    actor=TARGET_USER,
                    asset_id="customer-database",
                    service="rds",
                    action="rds-data:ExecuteStatement",
                    resource="arn:aws:rds:ap-south-1:418322947610:cluster:nexora-customers",
                    outcome=EventOutcome.DENIED,
                    source_ip=IP_RED_INFRA,
                    session_id=ROGUE_SESSION_ID,
                    user_agent="psql/16.2",
                    details={
                        "statement": "SELECT * FROM customers",
                        "rows_returned": 0,
                        "deny_reason": "data_protection_policy: access refused",
                    },
                )
            )
            self._env.state.hidden.red_engine_notes.append(
                f"{at}: data stage refused — customer-database is under protection."
            )
            return False
        state.cloud_events.extend(
            [
                CloudEvent(
                    event_id="cloud-2601",
                    timestamp=at,
                    actor=TARGET_USER,
                    asset_id="customer-database",
                    service="rds",
                    action="rds-data:ExecuteStatement",
                    resource="arn:aws:rds:ap-south-1:418322947610:cluster:nexora-customers",
                    outcome=EventOutcome.SUCCESS,
                    source_ip=IP_RED_INFRA,
                    session_id=ROGUE_SESSION_ID,
                    user_agent="psql/16.2",
                    details={
                        "statement": "SELECT * FROM customers",
                        "rows_returned": stage.metadata["rows_returned"],
                        "table_classification": "restricted-pii",
                        "actor_prior_access_180d": 0,
                    },
                ),
                CloudEvent(
                    event_id="cloud-2602",
                    timestamp=at,
                    actor=TARGET_USER,
                    asset_id="aws",
                    service="s3",
                    action="s3:PutObject",
                    resource="arn:aws:s3:::nexora-tmp-sync/customer-export-2026-03-11.csv",
                    outcome=EventOutcome.SUCCESS,
                    source_ip=IP_RED_INFRA,
                    session_id=ROGUE_SESSION_ID,
                    user_agent="aws-cli/2.15.30",
                    details={
                        "bucket_created_minutes_ago": 4,
                        "bucket_public": False,
                        "object_size": 2_147_483_648,
                    },
                ),
            ]
        )
        state.assets["customer-database"].recent_activity.append(
            "full-table read of customers by a first-time principal"
        )
        return True

    def _exfiltration(self, stage: AttackStage, event: ScheduledEvent) -> bool:
        state = self._env.state
        at = event.scheduled_at
        endpoint = state.endpoints.get(ENDPOINT_ARJUN)
        if endpoint is not None and endpoint.isolated:
            # Blue isolated the endpoint: nothing leaves it.
            state.network_events.append(
                NetworkEvent(
                    event_id="net-2702",
                    timestamp=at,
                    source_ip=IP_RED_INFRA,
                    source_geo=MOSCOW,
                    destination_asset="api-gateway",
                    destination_port=443,
                    protocol="tcp",
                    action="denied",
                    bytes_in=0,
                    bytes_out=0,
                    duration_seconds=0,
                    tls_fingerprint=JA3_UNKNOWN_LINUX,
                    details={"rule": "host-isolation: endpoint quarantined"},
                )
            )
            self._env.state.hidden.red_engine_notes.append(
                f"{at}: egress stage blocked — {ENDPOINT_ARJUN} is isolated."
            )
            return False
        state.dns_events.append(
            DnsEvent(
                event_id="dns-2701",
                timestamp=at,
                source_endpoint=ENDPOINT_ARJUN,
                query=RED_EGRESS_DOMAIN,
                record_type="A",
                resolved_ip=IP_RED_EGRESS,
                action="allowed",
                category="uncategorised",
            )
        )
        state.outbound_transfer_events.append(
            OutboundTransferEvent(
                event_id="xfer-2701",
                timestamp=at,
                source_endpoint=ENDPOINT_ARJUN,
                destination_domain=RED_EGRESS_DOMAIN,
                destination_ip=IP_RED_EGRESS,
                protocol="https",
                bytes_out=stage.metadata["bytes_out"],
                duration_seconds=214,
                classification="customer_records",
            )
        )
        state.network_events.append(
            NetworkEvent(
                event_id="net-2701",
                timestamp=at,
                source_ip=IP_RED_INFRA,
                source_geo=MOSCOW,
                destination_asset="api-gateway",
                destination_port=443,
                protocol="tcp",
                action="allowed",
                bytes_in=12_804,
                bytes_out=stage.metadata["bytes_out"],
                duration_seconds=214,
                tls_fingerprint=JA3_UNKNOWN_LINUX,
                details={"rule": "edge-allow-authenticated", "destination_domain_age_days": 2},
            )
        )
        return True

    _MUTATIONS: Dict[str, Callable[["RedAttackEngine", AttackStage, ScheduledEvent], bool]] = {
        "supplier_contact": _supplier_contact,
        "rogue_device": _rogue_device,
        "oauth_grant": _oauth_grant,
        "mailbox_discovery": _mailbox_discovery,
        "mailbox_rule": _mailbox_rule,
        "drive_access": _drive_access,
        "github_activity": _github_activity,
        "cloud_privilege": _cloud_privilege,
        "prod_discovery": _prod_discovery,
        "data_query": _data_query,
        "exfiltration": _exfiltration,
    }

    # -- resilience, posture and bookkeeping ------------------------------

    def _apply_cost(self, cost: int) -> None:
        """Deterministic scoring: each completed stage costs a fixed amount."""
        state = self._env.state
        safety = state.safety
        safety.resilience_score = max(0, safety.resilience_score - cost)
        self._update_posture()
        if safety.resilience_score <= safety.critical_failure_threshold:
            self._env.safety.emergency_stop("critical resilience threshold exceeded")
            self._status = AttackStatus.EMERGENCY_STOPPED
            self._sync_truth(status=self._status)

    def _update_posture(self) -> None:
        """Derive the estate's posture from resilience. Purely observable."""
        state = self._env.state
        score = state.safety.resilience_score
        incident = state.incident_status
        if score >= 85:
            incident.status = EnvironmentStatus.HEALTHY
            incident.severity = Severity.LOW
        elif score >= 60:
            incident.status = EnvironmentStatus.ELEVATED
            incident.severity = Severity.MEDIUM
        else:
            incident.status = EnvironmentStatus.COMPROMISED
            incident.severity = Severity.CRITICAL
        if incident.status is not EnvironmentStatus.HEALTHY and incident.incident_id == "INC-NONE":
            incident.incident_id = "INC-2026-0311-011"
            incident.declared_at = self._env.get_current_time()

    def _record_stage(self, stage_key: str) -> None:
        truth = self._red_truth()
        truth["current_stage"] = stage_key
        truth.setdefault("completed_stages", []).append(stage_key)
        if stage_key == OPERATION_MAYA[-1].key and self._status == AttackStatus.ACTIVE:
            self._status = AttackStatus.COMPLETED
        truth["status"] = self._status

    def _disrupt(self, at: str, reason: str) -> None:
        self._status = AttackStatus.DISRUPTED
        self._cancel_pending()
        self._sync_truth(status=self._status)
        self._env.state.hidden.red_engine_notes.append(f"{at}: operation disrupted — {reason}.")

    def _pending(self) -> List[ScheduledEvent]:
        return [
            e for e in self._env.state.clock.scheduled_events if "red_stage" in e.payload
        ]

    def _cancel_pending(self) -> List[str]:
        clock = self._env.state.clock
        cancelled = self._pending()
        for event in cancelled:
            clock.scheduled_events.remove(event)
            event.status = ScheduledEventStatus.CANCELLED
            clock.cancelled_events.append(event)
        return [e.event_id for e in cancelled]

    def _red_truth(self) -> Dict[str, Any]:
        return self._env.state.hidden.scenario_truth.setdefault("red", {})

    def _sync_truth(self, **fields: Any) -> None:
        self._red_truth().update(fields)

    # -- governor ---------------------------------------------------------

    def _governor_allows(self) -> bool:
        """No red mutation happens while the range is paused or stopped."""
        safety = self._env.state.safety
        return (
            not safety.mutations_locked
            and safety.simulation_status
            not in (SimulationStatus.PAUSED, SimulationStatus.EMERGENCY_STOPPED)
        )

    def _require_governor_allows(self) -> None:
        if not self._governor_allows():
            raise RuntimeError(
                "SafetyGovernor is "
                f"{self._env.state.safety.simulation_status.value}; the red engine cannot run."
            )


STAGES_BY_KEY: Dict[str, AttackStage] = {stage.key: stage for stage in OPERATION_MAYA}
