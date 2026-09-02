"""Scenario builders for the Nexora Systems synthetic estate.

Every builder is a pure function: called twice it produces two structurally
identical `EnvironmentState` objects. There is no randomness, no clock read and
no I/O anywhere in this module, which is what makes `CyberEnvironment.reset()`
byte-for-byte reproducible.

Design rule for the data itself: the telemetry describes *observations*, never
conclusions. Nothing here flags an actor as an attacker or an account as
compromised — the geography, the ASN, the device trust, the token consent
record and the timing are all present, and the inference is left to the reader.
"""

from __future__ import annotations

import math
from typing import Callable, Dict, List, Tuple

from app.models.environment import (
    AlertStatus,
    Asset,
    AssetCriticality,
    AssetType,
    AuthenticationEvent,
    BlockedIP,
    CloudEvent,
    EnvironmentState,
    EnvironmentStatus,
    EventOutcome,
    GeoLocation,
    IncidentStatus,
    NetworkEvent,
    Organization,
    SecurityAlert,
    Session,
    SessionStatus,
    Severity,
    Token,
    TokenStatus,
    User,
    UserAccessLevel,
)

DEFAULT_SCENARIO = "credential_compromise"

# The whole simulation happens on one fixed day, expressed in the SOC's
# reference timezone (IST, UTC+05:30).
SIMULATION_DATE = "2026-03-11"
TZ_OFFSET = "+05:30"

# Geo enrichment output for the three source locations in play.
BANGALORE = GeoLocation("Bangalore", "India", "IN", 12.9716, 77.5946)
MOSCOW = GeoLocation("Moscow", "Russia", "RU", 55.7558, 37.6173)
SINGAPORE = GeoLocation("Singapore", "Singapore", "SG", 1.3521, 103.8198)

# Source addresses observed during the simulated day.
IP_ARJUN_BANGALORE = "49.207.184.22"
IP_ARJUN_MOSCOW = "185.220.101.47"
IP_MAYA_BANGALORE = "49.207.190.104"
IP_ETHAN_SINGAPORE = "118.201.44.9"

# TLS client fingerprints. Corporate builds share one; the Moscow traffic
# presents a different one throughout.
JA3_CORPORATE_MAC = "ja3:6f1c2a8d9b4e7a3c5d0f81b2c4e6a90d"
JA3_CORPORATE_WIN = "ja3:1d9e4c7b02af35618cd2e7409bb1f6a3"
JA3_UNKNOWN_LINUX = "ja3:b7e0143a55c98d21fe6470a3d9c82b15"

UA_MAC_CHROME = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
)
UA_WIN_EDGE = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0"
)
UA_LINUX_CHROME = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
)

EARTH_RADIUS_KM = 6371.0
# Fastest realistic commercial travel, used by the impossible-travel rule.
MAX_FEASIBLE_TRAVEL_KMH = 900.0


def _ts(clock: str, date: str = SIMULATION_DATE) -> str:
    """Build an ISO-8601 timestamp in the SOC reference timezone."""
    return f"{date}T{clock}{TZ_OFFSET}"


def _haversine_km(origin: GeoLocation, destination: GeoLocation) -> float:
    """Great-circle distance between two geo-located points, in kilometres."""
    lat1, lon1 = math.radians(origin.latitude), math.radians(origin.longitude)
    lat2, lon2 = math.radians(destination.latitude), math.radians(destination.longitude)
    delta_lat, delta_lon = lat2 - lat1, lon2 - lon1
    a = math.sin(delta_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    return round(2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a)), 1)


def _implied_speed_kmh(distance_km: float, elapsed_seconds: int) -> float:
    """Speed a traveller would need to cover `distance_km` in `elapsed_seconds`."""
    return round(distance_km / (elapsed_seconds / 3600.0), 1)


def _build_organization() -> Organization:
    return Organization(
        name="Nexora Systems",
        domain="nexorasystems.io",
        industry="B2B SaaS — logistics analytics",
        headquarters="Bangalore, India",
        offices=["Bangalore, India", "Singapore"],
        employee_count=412,
        soc_tier="24x7 follow-the-sun, Tier 1-2 in-house",
    )


def _build_users() -> Dict[str, User]:
    return {
        "arjun.rao": User(
            user_id="arjun.rao",
            full_name="Arjun Rao",
            email="arjun.rao@nexorasystems.io",
            role="DevOps Engineer",
            department="Platform Engineering",
            office_location="Bangalore, India",
            home_country="IN",
            access_level=UserAccessLevel.PRIVILEGED,
            groups=["devops", "aws-prod-admins", "github-maintainers", "vpn-users"],
            mfa_enrolled=True,
            mfa_methods=["totp", "webauthn"],
            account_created="2023-04-17",
            last_password_rotation="2026-01-08",
            typical_login_hours_local="09:30-19:30 IST",
            known_devices=["NX-LT-2291", "NX-MB-7741"],
        ),
        "maya.shah": User(
            user_id="maya.shah",
            full_name="Maya Shah",
            email="maya.shah@nexorasystems.io",
            role="Security Analyst",
            department="Security Operations",
            office_location="Bangalore, India",
            home_country="IN",
            access_level=UserAccessLevel.SECURITY,
            groups=["soc-analysts", "siem-readers", "vpn-users"],
            mfa_enrolled=True,
            mfa_methods=["webauthn"],
            account_created="2024-02-05",
            last_password_rotation="2026-02-14",
            typical_login_hours_local="09:00-18:00 IST",
            known_devices=["NX-LT-1877"],
        ),
        "ethan.lee": User(
            user_id="ethan.lee",
            full_name="Ethan Lee",
            email="ethan.lee@nexorasystems.io",
            role="Backend Engineer",
            department="Product Engineering",
            office_location="Singapore",
            home_country="SG",
            access_level=UserAccessLevel.STANDARD,
            groups=["engineering", "github-contributors", "vpn-users"],
            mfa_enrolled=True,
            mfa_methods=["totp"],
            account_created="2024-09-23",
            last_password_rotation="2026-01-30",
            typical_login_hours_local="09:00-18:30 SGT",
            known_devices=["NX-LT-2043"],
        ),
    }


def _build_assets() -> Dict[str, Asset]:
    return {
        "identity-provider": Asset(
            asset_id="identity-provider",
            name="Nexora Identity Cloud (SSO)",
            asset_type=AssetType.IDENTITY,
            criticality=AssetCriticality.HIGH,
            owner="identity-platform-team",
            environment="production",
            region="ap-south-1",
            internet_facing=True,
            data_classification="confidential",
        ),
        "github": Asset(
            asset_id="github",
            name="GitHub Organisation (nexora)",
            asset_type=AssetType.SOURCE_CONTROL,
            criticality=AssetCriticality.HIGH,
            owner="engineering-platform-team",
            environment="saas",
            region="global",
            internet_facing=True,
            data_classification="confidential",
            depends_on=["identity-provider"],
        ),
        "aws": Asset(
            asset_id="aws",
            name="AWS Production Account 418322947610",
            asset_type=AssetType.CLOUD_ACCOUNT,
            criticality=AssetCriticality.HIGH,
            owner="platform-engineering",
            environment="production",
            region="ap-south-1",
            internet_facing=True,
            data_classification="restricted",
            depends_on=["identity-provider"],
        ),
        "api-gateway": Asset(
            asset_id="api-gateway",
            name="Nexora Edge API Gateway",
            asset_type=AssetType.NETWORK_EDGE,
            criticality=AssetCriticality.HIGH,
            owner="platform-engineering",
            environment="production",
            region="ap-south-1",
            internet_facing=True,
            data_classification="restricted",
            depends_on=["aws"],
        ),
        "production-server": Asset(
            asset_id="production-server",
            name="prod-app-01 (Nexora Core Services)",
            asset_type=AssetType.COMPUTE,
            criticality=AssetCriticality.HIGH,
            owner="platform-engineering",
            environment="production",
            region="ap-south-1",
            internet_facing=False,
            data_classification="restricted",
            depends_on=["aws", "api-gateway"],
        ),
        "customer-database": Asset(
            asset_id="customer-database",
            name="nexora-customers (PostgreSQL, primary)",
            asset_type=AssetType.DATA_STORE,
            criticality=AssetCriticality.CROWN_JEWEL,
            owner="data-platform-team",
            environment="production",
            region="ap-south-1",
            internet_facing=False,
            data_classification="restricted-pii",
            depends_on=["aws", "production-server"],
        ),
    }


def _build_sessions() -> Dict[str, Session]:
    return {
        "sess-0977": Session(
            session_id="sess-0977",
            user_id="maya.shah",
            started_at=_ts("09:12:07"),
            last_activity_at=_ts("17:36:20"),
            source_ip=IP_MAYA_BANGALORE,
            geo=BANGALORE,
            asn="AS24560 Bharti Airtel Ltd.",
            isp="Bharti Airtel",
            network_type="corporate_broadband",
            device_id="NX-LT-1877",
            device_managed=True,
            user_agent=UA_WIN_EDGE,
            client_platform="Windows 11",
            mfa_satisfied=True,
            auth_method="password+webauthn",
            status=SessionStatus.ACTIVE,
            assets_touched=["identity-provider", "api-gateway"],
        ),
        "sess-0984": Session(
            session_id="sess-0984",
            user_id="ethan.lee",
            started_at=_ts("10:04:55"),
            last_activity_at=_ts("17:21:48"),
            source_ip=IP_ETHAN_SINGAPORE,
            geo=SINGAPORE,
            asn="AS3758 SingNet Pte Ltd",
            isp="SingNet",
            network_type="corporate_broadband",
            device_id="NX-LT-2043",
            device_managed=True,
            user_agent=UA_MAC_CHROME,
            client_platform="macOS 14.4",
            mfa_satisfied=True,
            auth_method="password+totp",
            status=SessionStatus.ACTIVE,
            assets_touched=["identity-provider", "github", "api-gateway"],
        ),
        "sess-1001": Session(
            session_id="sess-1001",
            user_id="arjun.rao",
            started_at=_ts("17:31:14"),
            last_activity_at=_ts("17:32:58"),
            source_ip=IP_ARJUN_BANGALORE,
            geo=BANGALORE,
            asn="AS24560 Bharti Airtel Ltd.",
            isp="Bharti Airtel",
            network_type="corporate_broadband",
            device_id="NX-LT-2291",
            device_managed=True,
            user_agent=UA_MAC_CHROME,
            client_platform="macOS 14.4",
            mfa_satisfied=True,
            auth_method="password+totp",
            status=SessionStatus.ACTIVE,
            assets_touched=["identity-provider"],
        ),
        "sess-1002": Session(
            session_id="sess-1002",
            user_id="arjun.rao",
            started_at=_ts("17:33:02"),
            last_activity_at=_ts("17:38:42"),
            source_ip=IP_ARJUN_MOSCOW,
            geo=MOSCOW,
            asn="AS49505 OOO Network of Data-Centers Selectel",
            isp="Selectel",
            network_type="hosting_provider",
            device_id="unregistered-9f2c",
            device_managed=False,
            user_agent=UA_LINUX_CHROME,
            client_platform="Linux x86_64",
            mfa_satisfied=True,
            auth_method="password",
            status=SessionStatus.ACTIVE,
            assets_touched=["identity-provider", "github", "aws", "customer-database"],
        ),
    }


def _build_tokens() -> Dict[str, Token]:
    return {
        "oauth-7710": Token(
            token_id="oauth-7710",
            owner="arjun.rao",
            token_type="oauth_access_token",
            issued_at="2026-02-27T10:41:08+05:30",
            expires_at="2026-05-28T10:41:08+05:30",
            issued_via_session="sess-0912",
            issued_from_ip=IP_ARJUN_BANGALORE,
            permissions=["github.read"],
            status=TokenStatus.ACTIVE,
            consent_prompt_shown=True,
            client_name="nexora-ci-bot",
            client_registered_at="2024-06-11T12:00:00+05:30",
            last_used_at=_ts("14:05:19"),
        ),
        "pat-3312": Token(
            token_id="pat-3312",
            owner="maya.shah",
            token_type="personal_access_token",
            issued_at="2026-01-19T09:33:51+05:30",
            expires_at="2026-07-18T09:33:51+05:30",
            issued_via_session="sess-0641",
            issued_from_ip=IP_MAYA_BANGALORE,
            permissions=["github.read", "siem.read"],
            status=TokenStatus.ACTIVE,
            consent_prompt_shown=True,
            client_name="nexora-soc-tooling",
            client_registered_at="2024-03-02T12:00:00+05:30",
            last_used_at=_ts("17:36:20"),
        ),
        "oauth-6321": Token(
            token_id="oauth-6321",
            owner="ethan.lee",
            token_type="oauth_access_token",
            issued_at="2026-02-02T11:15:36+05:30",
            expires_at="2026-05-03T11:15:36+05:30",
            issued_via_session="sess-0788",
            issued_from_ip=IP_ETHAN_SINGAPORE,
            permissions=["github.read"],
            status=TokenStatus.ACTIVE,
            consent_prompt_shown=True,
            client_name="nexora-ci-bot",
            client_registered_at="2024-06-11T12:00:00+05:30",
            last_used_at=_ts("11:22:40"),
        ),
        "oauth-8492": Token(
            token_id="oauth-8492",
            owner="arjun.rao",
            token_type="oauth_access_token",
            issued_at=_ts("17:34:21"),
            expires_at="2026-03-12T17:34:21+05:30",
            issued_via_session="sess-1002",
            issued_from_ip=IP_ARJUN_MOSCOW,
            permissions=["github.read", "aws.assume_role", "database.read"],
            status=TokenStatus.ACTIVE,
            consent_prompt_shown=False,
            client_name="nexora-devops-sync",
            client_registered_at=_ts("17:34:02"),
            last_used_at=_ts("17:38:42"),
        ),
    }


def _build_authentication_events() -> List[AuthenticationEvent]:
    return [
        AuthenticationEvent(
            event_id="auth-0001",
            timestamp=_ts("09:12:07"),
            user_id="maya.shah",
            event_type="user_login",
            outcome=EventOutcome.SUCCESS,
            source_ip=IP_MAYA_BANGALORE,
            geo=BANGALORE,
            asn="AS24560 Bharti Airtel Ltd.",
            device_id="NX-LT-1877",
            user_agent=UA_WIN_EDGE,
            auth_method="password+webauthn",
            mfa_satisfied=True,
            session_id="sess-0977",
            details={"device_registered": True, "risk_score": 4},
        ),
        AuthenticationEvent(
            event_id="auth-0002",
            timestamp=_ts("10:04:55"),
            user_id="ethan.lee",
            event_type="user_login",
            outcome=EventOutcome.SUCCESS,
            source_ip=IP_ETHAN_SINGAPORE,
            geo=SINGAPORE,
            asn="AS3758 SingNet Pte Ltd",
            device_id="NX-LT-2043",
            user_agent=UA_MAC_CHROME,
            auth_method="password+totp",
            mfa_satisfied=True,
            session_id="sess-0984",
            details={"device_registered": True, "risk_score": 6},
        ),
        AuthenticationEvent(
            event_id="auth-0003",
            timestamp=_ts("17:31:14"),
            user_id="arjun.rao",
            event_type="user_login",
            outcome=EventOutcome.SUCCESS,
            source_ip=IP_ARJUN_BANGALORE,
            geo=BANGALORE,
            asn="AS24560 Bharti Airtel Ltd.",
            device_id="NX-LT-2291",
            user_agent=UA_MAC_CHROME,
            auth_method="password+totp",
            mfa_satisfied=True,
            session_id="sess-1001",
            details={
                "device_registered": True,
                "risk_score": 3,
                "mfa_factor": "totp",
                "device_trust_cookie": "dtc-4471",
            },
        ),
        AuthenticationEvent(
            event_id="auth-0004",
            timestamp=_ts("17:33:02"),
            user_id="arjun.rao",
            event_type="user_login",
            outcome=EventOutcome.SUCCESS,
            source_ip=IP_ARJUN_MOSCOW,
            geo=MOSCOW,
            asn="AS49505 OOO Network of Data-Centers Selectel",
            device_id="unregistered-9f2c",
            user_agent=UA_LINUX_CHROME,
            auth_method="password",
            mfa_satisfied=True,
            session_id="sess-1002",
            details={
                "device_registered": False,
                "risk_score": 91,
                "mfa_factor": "none",
                "mfa_prompt": "skipped",
                "mfa_skip_reason": "device_trust_cookie_presented",
                "device_trust_cookie": "dtc-4471",
                "network_type": "hosting_provider",
            },
        ),
        AuthenticationEvent(
            event_id="auth-0005",
            timestamp=_ts("17:34:21"),
            user_id="arjun.rao",
            event_type="oauth_token_issued",
            outcome=EventOutcome.SUCCESS,
            source_ip=IP_ARJUN_MOSCOW,
            geo=MOSCOW,
            asn="AS49505 OOO Network of Data-Centers Selectel",
            device_id="unregistered-9f2c",
            user_agent=UA_LINUX_CHROME,
            auth_method="session_bearer",
            mfa_satisfied=False,
            session_id="sess-1002",
            details={
                "token_id": "oauth-8492",
                "client_name": "nexora-devops-sync",
                "client_registered_at": _ts("17:34:02"),
                "client_first_party": False,
                "consent_prompt_shown": False,
                "permissions": ["github.read", "aws.assume_role", "database.read"],
                "grant_type": "authorization_code",
            },
        ),
    ]


def _build_cloud_events() -> List[CloudEvent]:
    return [
        CloudEvent(
            event_id="cloud-0001",
            timestamp=_ts("11:22:40"),
            actor="ethan.lee",
            asset_id="github",
            service="github",
            action="repo.pull",
            resource="nexora/payments-api",
            outcome=EventOutcome.SUCCESS,
            source_ip=IP_ETHAN_SINGAPORE,
            session_id="sess-0984",
            token_id="oauth-6321",
            user_agent="git/2.44.0",
            details={"repository_count": 1, "bytes_transferred": 8_412_160},
        ),
        CloudEvent(
            event_id="cloud-0002",
            timestamp=_ts("14:05:19"),
            actor="arjun.rao",
            asset_id="aws",
            service="ec2",
            action="ec2:DescribeInstances",
            resource="arn:aws:ec2:ap-south-1:418322947610:instance/*",
            outcome=EventOutcome.SUCCESS,
            source_ip=IP_ARJUN_BANGALORE,
            session_id=None,
            token_id="oauth-7710",
            user_agent="aws-cli/2.15.30",
            details={"read_only": True, "instances_returned": 34},
        ),
        CloudEvent(
            event_id="cloud-0003",
            timestamp=_ts("17:35:11"),
            actor="arjun.rao",
            asset_id="github",
            service="github",
            action="repo.clone",
            resource="nexora/infra-terraform, nexora/customer-platform, nexora/secrets-rotation",
            outcome=EventOutcome.SUCCESS,
            source_ip=IP_ARJUN_MOSCOW,
            session_id="sess-1002",
            token_id="oauth-8492",
            user_agent="git/2.39.5",
            details={
                "repository_count": 3,
                "repository_visibility": "private",
                "bytes_transferred": 432_112_640,
                "clone_depth": "full",
                "actor_30d_avg_repo_clones_per_day": 0.4,
            },
        ),
        CloudEvent(
            event_id="cloud-0004",
            timestamp=_ts("17:37:04"),
            actor="arjun.rao",
            asset_id="aws",
            service="sts",
            action="sts:AssumeRole",
            resource="arn:aws:iam::418322947610:role/NexoraProdAdmin",
            outcome=EventOutcome.SUCCESS,
            source_ip=IP_ARJUN_MOSCOW,
            session_id="sess-1002",
            token_id="oauth-8492",
            user_agent="aws-sdk-go/1.55.5",
            details={
                "role_permission_scope": "administrator",
                "credential_source": "oauth_token_exchange",
                "session_duration_seconds": 3600,
                "actor_prior_assumptions_180d": 0,
                "role_assumptions_180d_by_others": 118,
            },
        ),
        CloudEvent(
            event_id="cloud-0005",
            timestamp=_ts("17:38:42"),
            actor="arjun.rao",
            asset_id="customer-database",
            service="rds",
            action="rds-data:ExecuteStatement",
            resource="arn:aws:rds:ap-south-1:418322947610:cluster:nexora-customers",
            outcome=EventOutcome.DENIED,
            source_ip=IP_ARJUN_MOSCOW,
            session_id="sess-1002",
            token_id="oauth-8492",
            user_agent="psql/16.2",
            details={
                "statement": "SELECT * FROM customers LIMIT 50000",
                "rows_returned": 0,
                "deny_reason": "vpc_endpoint_policy: source address outside allowlist",
                "table_classification": "restricted-pii",
                "actor_prior_access_180d": 0,
            },
        ),
    ]


def _build_network_events() -> List[NetworkEvent]:
    return [
        NetworkEvent(
            event_id="net-0001",
            timestamp=_ts("10:05:02"),
            source_ip=IP_ETHAN_SINGAPORE,
            source_geo=SINGAPORE,
            destination_asset="api-gateway",
            destination_port=443,
            protocol="tcp",
            action="allowed",
            bytes_in=182_400,
            bytes_out=61_240,
            duration_seconds=1_842,
            tls_fingerprint=JA3_CORPORATE_MAC,
            details={"rule": "edge-allow-corp-vpn"},
        ),
        NetworkEvent(
            event_id="net-0002",
            timestamp=_ts("17:31:20"),
            source_ip=IP_ARJUN_BANGALORE,
            source_geo=BANGALORE,
            destination_asset="identity-provider",
            destination_port=443,
            protocol="tcp",
            action="allowed",
            bytes_in=41_820,
            bytes_out=12_940,
            duration_seconds=104,
            tls_fingerprint=JA3_CORPORATE_MAC,
            details={"rule": "edge-allow-idp"},
        ),
        NetworkEvent(
            event_id="net-0003",
            timestamp=_ts("17:33:05"),
            source_ip=IP_ARJUN_MOSCOW,
            source_geo=MOSCOW,
            destination_asset="identity-provider",
            destination_port=443,
            protocol="tcp",
            action="allowed",
            bytes_in=38_110,
            bytes_out=14_602,
            duration_seconds=337,
            tls_fingerprint=JA3_UNKNOWN_LINUX,
            details={"rule": "edge-allow-idp", "geo_first_seen_for_source": True},
        ),
        NetworkEvent(
            event_id="net-0004",
            timestamp=_ts("17:36:58"),
            source_ip=IP_ARJUN_MOSCOW,
            source_geo=MOSCOW,
            destination_asset="api-gateway",
            destination_port=443,
            protocol="tcp",
            action="allowed",
            bytes_in=96_512,
            bytes_out=1_284_096,
            duration_seconds=126,
            tls_fingerprint=JA3_UNKNOWN_LINUX,
            details={"rule": "edge-allow-authenticated", "requests": 412},
        ),
        NetworkEvent(
            event_id="net-0005",
            timestamp=_ts("17:37:09"),
            source_ip=IP_ARJUN_MOSCOW,
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
            event_id="net-0006",
            timestamp=_ts("17:38:42"),
            source_ip=IP_ARJUN_MOSCOW,
            source_geo=MOSCOW,
            destination_asset="customer-database",
            destination_port=5432,
            protocol="tcp",
            action="denied",
            bytes_in=0,
            bytes_out=0,
            duration_seconds=0,
            tls_fingerprint=JA3_UNKNOWN_LINUX,
            details={"rule": "vpc-endpoint-policy: source address outside allowlist"},
        ),
    ]


def _travel_evidence() -> Tuple[float, int, float]:
    """Distance, elapsed seconds and implied speed between the two Arjun logins."""
    distance_km = _haversine_km(BANGALORE, MOSCOW)
    elapsed_seconds = 108  # 17:31:14 -> 17:33:02
    return distance_km, elapsed_seconds, _implied_speed_kmh(distance_km, elapsed_seconds)


def _build_security_alerts() -> List[SecurityAlert]:
    distance_km, elapsed_seconds, implied_speed_kmh = _travel_evidence()
    return [
        SecurityAlert(
            alert_id="alert-0001",
            timestamp=_ts("17:33:09"),
            rule_id="NX-IDP-014",
            title="Unusual geographic login location",
            severity=Severity.HIGH,
            source="identity-provider",
            description=(
                "Sign-in accepted from a country and network type never previously "
                "observed for this account."
            ),
            related_users=["arjun.rao"],
            related_assets=["identity-provider"],
            related_sessions=["sess-1002"],
            related_events=["auth-0004"],
            evidence={
                "observed_country": "RU",
                "observed_city": "Moscow",
                "source_ip": IP_ARJUN_MOSCOW,
                "asn": "AS49505 OOO Network of Data-Centers Selectel",
                "network_type": "hosting_provider",
                "account_login_countries_90d": ["IN"],
                "first_login_from_country": True,
                "device_registered": False,
                "idp_risk_score": 91,
            },
        ),
        SecurityAlert(
            alert_id="alert-0002",
            timestamp=_ts("17:33:11"),
            rule_id="NX-IDP-021",
            title="Impossible travel between consecutive logins",
            severity=Severity.CRITICAL,
            source="identity-provider",
            description=(
                "Two successful sign-ins for the same account are separated by a "
                "distance no physical travel could cover in the elapsed time."
            ),
            related_users=["arjun.rao"],
            related_assets=["identity-provider"],
            related_sessions=["sess-1001", "sess-1002"],
            related_events=["auth-0003", "auth-0004"],
            evidence={
                "previous_login": {
                    "event_id": "auth-0003",
                    "timestamp": _ts("17:31:14"),
                    "city": "Bangalore",
                    "country": "IN",
                    "source_ip": IP_ARJUN_BANGALORE,
                },
                "current_login": {
                    "event_id": "auth-0004",
                    "timestamp": _ts("17:33:02"),
                    "city": "Moscow",
                    "country": "RU",
                    "source_ip": IP_ARJUN_MOSCOW,
                },
                "distance_km": distance_km,
                "elapsed_seconds": elapsed_seconds,
                "implied_speed_kmh": implied_speed_kmh,
                "max_feasible_speed_kmh": MAX_FEASIBLE_TRAVEL_KMH,
                "both_sessions_active": True,
            },
        ),
        SecurityAlert(
            alert_id="alert-0003",
            timestamp=_ts("17:34:26"),
            rule_id="NX-IDP-033",
            title="Privileged OAuth token created",
            severity=Severity.HIGH,
            source="identity-provider",
            description=(
                "An OAuth token carrying cloud and data permissions was issued to a "
                "client application registered moments earlier, with no user consent "
                "prompt recorded."
            ),
            related_users=["arjun.rao"],
            related_assets=["identity-provider", "github", "aws", "customer-database"],
            related_sessions=["sess-1002"],
            related_events=["auth-0005"],
            evidence={
                "token_id": "oauth-8492",
                "permissions": ["github.read", "aws.assume_role", "database.read"],
                "issued_from_ip": IP_ARJUN_MOSCOW,
                "issued_via_session": "sess-1002",
                "client_name": "nexora-devops-sync",
                "client_registered_at": _ts("17:34:02"),
                "client_age_seconds_at_issuance": 19,
                "client_first_party": False,
                "consent_prompt_shown": False,
                "mfa_satisfied_at_issuance": False,
            },
        ),
        SecurityAlert(
            alert_id="alert-0004",
            timestamp=_ts("17:37:09"),
            rule_id="NX-CLD-052",
            title="Unusual cloud privilege use",
            severity=Severity.CRITICAL,
            source="aws-cloudtrail",
            description=(
                "An administrator role in the production account was assumed by a "
                "principal with no prior use of that role, via an OAuth token exchange "
                "rather than the usual SSO path."
            ),
            related_users=["arjun.rao"],
            related_assets=["aws", "production-server"],
            related_sessions=["sess-1002"],
            related_events=["cloud-0004", "net-0005"],
            evidence={
                "role_arn": "arn:aws:iam::418322947610:role/NexoraProdAdmin",
                "role_permission_scope": "administrator",
                "credential_source": "oauth_token_exchange",
                "token_id": "oauth-8492",
                "source_ip": IP_ARJUN_MOSCOW,
                "actor_prior_assumptions_180d": 0,
                "usual_credential_source": "sso_saml",
                "followed_by_denied_ssh_attempts": 3,
            },
        ),
        SecurityAlert(
            alert_id="alert-0005",
            timestamp=_ts("17:38:45"),
            rule_id="NX-DAT-007",
            title="Sensitive database access attempt",
            severity=Severity.CRITICAL,
            source="data-platform-audit",
            description=(
                "A bulk read against the customer PII store was attempted with the "
                "newly issued token and refused by the VPC endpoint policy."
            ),
            related_users=["arjun.rao"],
            related_assets=["customer-database"],
            related_sessions=["sess-1002"],
            related_events=["cloud-0005", "net-0006"],
            evidence={
                "statement": "SELECT * FROM customers LIMIT 50000",
                "outcome": "denied",
                "deny_reason": "vpc_endpoint_policy: source address outside allowlist",
                "table_classification": "restricted-pii",
                "asset_criticality": "crown_jewel",
                "token_id": "oauth-8492",
                "source_ip": IP_ARJUN_MOSCOW,
                "actor_prior_access_180d": 0,
                "estimated_records_exposed_if_allowed": 50_000,
            },
        ),
    ]


def _build_blocked_ips() -> List[BlockedIP]:
    """Pre-existing edge blocks, unrelated to today's alert cluster."""
    return [
        BlockedIP(
            ip_address="45.155.205.233",
            reason="Sustained credential stuffing against api-gateway (NX-EDGE-003)",
            blocked_at="2026-03-09T02:14:33+05:30",
            blocked_by="edge-waf-autoblock",
            scope="api-gateway",
            expires_at="2026-04-08T02:14:33+05:30",
        ),
    ]


def _build_incident_status(alerts: List[SecurityAlert]) -> IncidentStatus:
    severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    open_alerts = [alert for alert in alerts if alert.status is AlertStatus.OPEN]
    highest = max((alert.severity for alert in open_alerts), key=severity_order.index)
    return IncidentStatus(
        incident_id="INC-2026-0311-004",
        status=EnvironmentStatus.COMPROMISED,
        severity=Severity.CRITICAL,
        declared_at=_ts("17:38:50"),
        declared_by="nexora-soc-correlation-engine",
        open_alert_count=len(open_alerts),
        highest_alert_severity=highest,
        containment_actions=[],
        notes=[
            "Correlated identity, cloud and data-layer detections fired inside a "
            "six-minute window on one account.",
            "No containment action has been taken; all sessions and tokens remain live.",
        ],
    )


def build_credential_compromise() -> EnvironmentState:
    """Build the `credential_compromise` scenario at the moment of detection."""
    alerts = _build_security_alerts()
    return EnvironmentState(
        scenario="credential_compromise",
        simulation_time=_ts("17:39:00"),
        organization=_build_organization(),
        users=_build_users(),
        assets=_build_assets(),
        sessions=_build_sessions(),
        tokens=_build_tokens(),
        authentication_events=_build_authentication_events(),
        cloud_events=_build_cloud_events(),
        network_events=_build_network_events(),
        security_alerts=alerts,
        blocked_ips=_build_blocked_ips(),
        incident_status=_build_incident_status(alerts),
    )


SCENARIO_BUILDERS: Dict[str, Callable[[], EnvironmentState]] = {
    "credential_compromise": build_credential_compromise,
}


def available_scenarios() -> List[str]:
    """Names accepted by `CyberEnvironment.load_scenario`."""
    return sorted(SCENARIO_BUILDERS)
