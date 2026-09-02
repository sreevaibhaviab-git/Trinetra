# TRINETRA — Backend (Phase 1)

Deterministic synthetic cyber environment for **Nexora Systems**, a fictional
B2B SaaS company. This phase contains the *world* only: no AI, no LLM calls, no
API server, no database, no agent framework, and no real security tooling.

Everything is plain Python 3 + dataclasses, and the whole environment is a pure
function of code — no clocks, no randomness, no I/O.

## Run it

```bash
cd backend
python3 run_demo.py
```

No dependencies to install (standard library only, Python 3.9+).

## Layout

```
backend/
  app/
    __init__.py
    models/
      __init__.py
      environment.py      # dataclasses + enums describing the estate
    simulator/
      __init__.py
      environment.py      # CyberEnvironment: get_state / reset / load_scenario
      scenarios.py        # pure builders for each scenario's initial state
  run_demo.py             # prints the environment, then verifies reset()
  requirements.txt
  README.md
```

## The environment

`CyberEnvironment` owns one mutable `EnvironmentState` and exposes three things:

| Method | Behaviour |
| --- | --- |
| `get_state()` | JSON-serializable deep-copy snapshot; mutating it cannot affect the estate. |
| `reset()` | Rebuilds the current scenario from its pure builder, discarding every mutation. |
| `load_scenario(name)` | Swaps in a different scenario (raises `ValueError` on an unknown name). |

`env.state` exposes the live dataclass object for future phases that need to
mutate the estate (terminate a session, revoke a token, block an IP).

Determinism comes from `reset()` calling the same pure builder that `__init__`
called, rather than copying a template that earlier code may have touched. Two
`CyberEnvironment()` instances serialize byte-for-byte identically.

### Modelled state

`users`, `assets`, `sessions`, `tokens`, `authentication_events`,
`cloud_events`, `network_events`, `security_alerts`, `blocked_ips`,
`incident_status` — plus `organization`, `scenario` and `simulation_time`.

**Nexora Systems** — 412 employees, HQ Bangalore, office Singapore.

| User | Name | Role | Location | Access |
| --- | --- | --- | --- | --- |
| `arjun.rao` | Arjun Rao | DevOps Engineer | Bangalore | privileged |
| `maya.shah` | Maya Shah | Security Analyst | Bangalore | security |
| `ethan.lee` | Ethan Lee | Backend Engineer | Singapore | standard |

Assets: `identity-provider`, `github`, `aws`, `api-gateway`,
`production-server`, `customer-database` (the crown jewel, `restricted-pii`).

## Scenario: `credential_compromise`

The state is captured at **2026-03-11T17:39:00+05:30**, moments after the last
detection fired. All timestamps use the SOC reference timezone (IST, UTC+05:30).

| Time | What the telemetry recorded |
| --- | --- |
| 17:31:14 | `arjun.rao` signs in from Bangalore, managed device `NX-LT-2291`, password + TOTP → `sess-1001` |
| 17:33:02 | `arjun.rao` signs in from Moscow, unregistered device, hosting-provider ASN, MFA prompt skipped → `sess-1002` |
| 17:34:21 | OAuth token `oauth-8492` issued via `sess-1002` to a client registered 19 s earlier, no consent prompt |
| 17:35:11 | Three private GitHub repositories cloned in full (412 MB) using `oauth-8492` |
| 17:37:04 | `sts:AssumeRole` on `NexoraProdAdmin` via OAuth token exchange (0 prior assumptions in 180 days) |
| 17:38:42 | `SELECT * FROM customers LIMIT 50000` against `customer-database` — **denied** by the VPC endpoint policy |

Both Arjun sessions are **active**. `maya.shah` and `ethan.lee` hold ordinary
active sessions from their home offices as a behavioural baseline.

Token `oauth-8492` — owner `arjun.rao`, status `active`, permissions
`github.read`, `aws.assume_role`, `database.read`. Three benign tokens
(`oauth-7710`, `pat-3312`, `oauth-6321`) exist alongside it for contrast.

### Alerts

| ID | Rule | Severity | Title |
| --- | --- | --- | --- |
| `alert-0001` | NX-IDP-014 | high | Unusual geographic login location |
| `alert-0002` | NX-IDP-021 | critical | Impossible travel between consecutive logins |
| `alert-0003` | NX-IDP-033 | high | Privileged OAuth token created |
| `alert-0004` | NX-CLD-052 | critical | Unusual cloud privilege use |
| `alert-0005` | NX-DAT-007 | critical | Sensitive database access attempt |

Each alert carries an `evidence` dictionary with the specific fields the rule
fired on — e.g. `alert-0002` records a 5861.8 km separation across 108 seconds,
an implied 195,393 km/h against a 900 km/h feasible maximum.

`incident_status` reports `INC-2026-0311-004`, status **COMPROMISED**, severity
`critical`, with `containment_actions` empty — nothing has been contained yet.
The only entry in `blocked_ips` is an unrelated credential-stuffing block from
two days earlier.

### No labelled ground truth

There is deliberately **no** `attacker`, `is_malicious` or `compromised_user`
field anywhere in the state. The telemetry describes observations only —
geography, ASN and network type, device registration and management, the
device-trust cookie reused across both sessions, the MFA factor actually
presented, OAuth client age and consent record, 180-day behavioural baselines,
and each action's outcome. Which account is compromised, and what to do about
it, has to be *inferred* from that evidence by whatever consumes `get_state()`.

## Phase 1 scope

Not present, by design: FastAPI, databases, LLM/agent code, and any real
network or security operation. The demo exercises the environment in-process
and exits.
