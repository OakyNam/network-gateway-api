# Network Gateway API improvement plan

## Scope and completion standard

The active project is the Network Gateway API only. The portfolio milestone is
a reproducible local demo with meaningful tests and honest documentation, not
production readiness or unverified vendor support.

The approved architecture is **UI / API / BL / DAL**. Device and proxy operations
remain API-first; the UI configures connections and runs tests, rather than
implementing network behavior in the browser.

The product direction is a unified navigation/control plane rather than a
credential inventory. Vendor clients encapsulate syntax and data-access
differences while the API exposes consistent device, interface, routing,
statistics and transaction resources. Connectivity profiles and network role
accounts support that primary goal.

## Completed identity and transaction milestone

- Microsoft Entra ID/OIDC for enterprise users with Viewer, Operator and
  Administrator app roles.
- Configurable local and production redirect URIs; production fails closed when
  Entra settings are incomplete.
- Explicit local demo identity only while demo mode and demo auth are both
  enabled.
- Server-enforced permission policy across reads, tests, device changes and
  administrative CRUD. UI control visibility is not a security boundary.
- Immediate device changes with immutable user-attributed transactions,
  normalized before/after state, outcome and correlation ID.
- Secret-safe transaction persistence and a read-only Transactions UI/API.
- Apply the complete flow to simulated static-route CRUD before adding any real
  vendor write command.
- Require Viewer authorization for legacy reads and disable every legacy mutation
  until it is implemented through the authenticated, audited service boundary.

Future vendor work should expand normalized interface, global/private routing
table, BGP, static-route and statistics contracts without leaking native command
formats into the UI.

## Implemented milestones

### 1. Restore metadata lookup and preserve legacy behavior

- Retrieve all configured metadata columns using validated identifiers and bound
  search values.
- Give each lookup its own SQLAlchemy session and close it on every outcome.
- Preserve legacy route shapes and configuration-driven client selection.
- Retain regression coverage for lookup, dispatch and offline PostgreSQL SQL
  compilation.

### 2. Make device protocols demonstrable locally

- Add SQLite-backed fake device metadata and actual loopback NETCONF-over-SSH,
  SSH exec and generic custom-port Telnet peers.
- Generate demo trust without disabling host-key verification.
- Preserve edited seed records on normal startup.
- Reject unsafe inherited demo settings before database/socket use.
- Clean up listeners on startup failure and shutdown.
- Reject incomplete Telnet responses, invalid prompt sequences and invalid
  timeouts/ports; handle fragmented IAC negotiation across reads.

### 3. Establish layer boundaries

| Layer | Responsibility | Implementation |
|---|---|---|
| UI | Navigation, forms, inventory, progress/export presentation | `app/ui/` |
| API | HTTP contracts, validation, redaction, serialization | `app/api/` |
| BL | Profile orchestration, connection tests, bulk jobs | `app/bl/` |
| DAL | Database access, encryption, device/proxy transports | `app/dal/` |

Tests live under `test/unit_test`, `test/integration_test` and `test/fixtures`.
The existing 36 legacy/transport tests passed after relocation.

### 4. Persist reusable configuration

- Configurable SQLite file or PostgreSQL URL; explicit persistent encryption key.
- Reusable role accounts with exclusive password or pasted-key authentication.
- Optional encrypted-key passphrase, secret-preserving edits and atomic
  authentication-method switching.
- Reusable proxy profiles, independently referenced device/bastion accounts, and
  rejection of deletes that would break references.
- Redacted public records, encrypted secret fields and immutable encrypted
  bulk-test credential snapshots.
- Lazy setup so unconfigured management storage does not break legacy imports.

### 5. Add explicit connector paths

- Direct, SSH TCP forwarding, SOCKS5 and HTTP CONNECT for SSH/NETCONF/Telnet.
- Constrained interactive SSH jump shell for generic Telnet only.
- Independent device/bastion host-key checks; no direct fallback after failure.
- Shared connection-test deadlines, failure outcomes and resource cleanup.
- Real loopback connector/protocol tests, including authentication, trust,
  malformed responses, denial and timeout cases.

### 6. Add API-first management and bulk tests

- Typed CRUD routes for devices, proxies and role accounts.
- Individual tests resolve current referenced credentials and proxy settings.
- One API-owned worker processes persisted job snapshots sequentially, isolating
  each device failure and recording progress.
- Interrupted-job recovery, bounded submissions, orderly worker/store shutdown.
- Credential-free CSV/JSON export, unfinished-export rejection and CSV formula
  neutralization.
- Same-origin browser mutation checks, sanitized validation/errors and explicit
  storage-failure reporting; these do not provide application authentication.

### 7. Integrate the management UI

- Default inventory table and Devices / Proxies / Role Accounts navigation.
- Separate New/Edit Device views, browser history, Back/Cancel controls.
- Exclusive role-auth fields and reusable account/proxy selection.
- Per-device test outcomes, bulk progress and CSV/JSON download links.
- Correct JavaScript-module MIME serving on Windows.
- API-docs link appears only when actual documentation endpoints respond.
- Real FastAPI composition tests verify routes, unconfigured storage behavior
  and worker shutdown before database closure.

### 8. Exercise all layers with a persisted fake device

- Explicit `client_type=fake` selects the fake device client; a separate
  application setting enables simulation. Network profiles remain network-backed.

### 9. Add application identity, authorization and immutable auditing

- Microsoft Entra authorization-code flow with PKCE, strict token validation,
  exact redirect allowlisting and Viewer/Operator/Administrator app roles.
- Explicit offline demo identity that fails closed unless both demo auth and
  application demo mode are enabled.
- Server-enforced read, test, configuration and administration policies.
- Append-only transaction persistence with safe actor metadata, correlation IDs,
  outcomes and recursively redacted normalized before/after state.
- Atomic successful static-route mutation/audit writes and durable failed-attempt
  records that preserve the original API error.
- Read-only, paginated transaction API and browser presentation.

Verification evidence for this local milestone:

- 257 Python tests passed.
- 31 JavaScript browser-model tests passed.
- Python compilation, dependency consistency and JavaScript syntax checks passed.
- Live simulated route create/update/delete returned 201/200/204 with distinct
  correlation IDs; an invalid delete returned 404 and produced a failed audit.
- A mixed live batch completed 8/8: seven loopback network transports and one
  explicitly simulated fake device.
- Browser acceptance rendered the fake Administrator identity and immutable
  before/after transaction records.
- Seed a real saved fake connection, device role, proxy and proxy role, resolving
  their current values before each fake operation.
- Reject wrong device credentials, wrong proxy credentials and changed proxy
  destinations rather than accepting whatever was saved.
- Expose fictional interfaces, BGP and MPLS information via typed APIs and
  separate device views with subnavigation.
- Persist simulated static-route CRUD with per-device ownership, validation,
  duplicate prevention and one-time initialization.
- Preserve edited/deleted route state across restart; never execute a device
  command or open a socket for fake operations.
- Mark single/bulk outcomes and CSV/JSON rows with `simulated`, including a
  backward-compatible false default for existing network-job history.
- Verify real HTTP, browser, BL and SQLite flows, not mocked API/storage success.

## Integration acceptance gate

**Status: local demo milestone validated and independently approved.**
That earlier fake-device baseline passed 214 Python tests and 24 Node tests.
The current identity/audit milestone passes 257 Python tests and 31 Node tests.
Live HTTP and browser checks use the actual application and persistent SQLite,
not the retired UI contract fixture.

- [x] Preserve the relocated legacy suite.
- [x] Pass isolated storage and actual SQLite/API reference/update tests.
- [x] Pass UI-model, asset-serving and application-composition tests.
- [x] Pass the combined Python suite after demo/connector integration.
- [x] Start the documented demo against actual local peers.
- [x] Demonstrate real browser CRUD, separate device routes and API docs.
- [x] Demonstrate individual/bulk tests and exact secret-free CSV/JSON exports.
- [x] Demonstrate a failing device without disrupting the rest of the run.
- [x] Verify explicit configurable storage, restart persistence and cleanup.
- [x] Verify the persisted fake device/role/proxy path and credential failures.
- [x] Verify simulated route browser CRUD and survival across a process restart.
- [x] Obtain independent final review and update this gate with final evidence.

The earlier temporary UI contract fixture is not evidence of backend or device
integration and must not be presented as the finished demo.

Observed acceptance includes seven successful real loopback paths, an isolated
bad-login failure without aborting a batch, and a later eight-result run with
seven network results and one explicitly simulated result. CSV/JSON exports have
the expected rows/fields without credential values, including older job history.
Browser checks cover device/account/proxy CRUD, data subnavigation and simulated
route create/edit/delete; an edited route survived an actual process restart.
Browser field filling and DOM activation were used where the integrated
browser's pointer-stability checks stalled; this is not a complete pointer or
accessibility audit. Hosted CI, Linux execution and external PostgreSQL remain
unverified.

Independent review approved the candidate claims using source review, the
214-test Python log, an independent 24-test Node run and read-only live API
checks. Browser/restart exercises were supported by the recorded acceptance
evidence rather than independently repeated. Approval does not extend to real
hardware, live PostgreSQL, hosted CI or production readiness.

### Additional approved configuration cleanup

- Move logger setup into `config/logger.py` with no example JSON dependency.
- Reserve `config/` for application bootstrap, logging and authentication
  configuration, not device/proxy/vendor data.
- Persist the remaining legacy client/proxy/device-lookup mappings in the
  database and expose them through validated administrative APIs.
- Remove root example JSON files and migrate demo initialization away from
  runtime JSON mapping files without losing existing records.
- Restore accidentally deleted shared exceptions in `app/common/errors.py`,
  not in the application root, and update all dependent imports.
- Revalidate legacy dispatch and the integrated demo after the migration.

## Deferred roadmap

| Priority | Remaining work | Exit criteria |
|---|---|---|
| P1 | Production access control and deployment hardening | Authenticated/authorized administration, audit policy, secret management, protected network boundaries and deployment verification |
| P1 | Real-device and bastion validation | Verified device-specific login transcripts, commands, host-key onboarding and supported bastion policies; no guessed DDM2200 behavior |
| P1 | Legacy placeholder operations | Implement supported operations or return explicit unsupported outcomes instead of success-shaped placeholders |
| P1 | Legacy client/proxy lifecycle | Dedicated cleanup/error-preservation coverage for historical operation routes |
| P2 | Live PostgreSQL validation | Integration tests against an explicitly provisioned isolated database, including TLS and concurrency behavior |
| P2 | Schema evolution and multi-instance execution | Versioned migrations, job leasing/coordination and restart semantics beyond the single-process demo |
| P2 | Wider vendor capabilities | Explicit capability contracts and hardware-backed validation for each supported operation |
| P2 | Portfolio publication | Hosted CI evidence, chosen license, screenshots/demo recording and repository publication only when requested |

## Verification commands

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s test -p "test_*.py" -v
node --test test\unit_test\ui_model.test.mjs test\unit_test\device_model.test.mjs
.\.venv\Scripts\python.exe -m pip check
git --no-pager diff --check
```

No real equipment, external database, cloud deployment, commit or push is
required for the local milestone. PostgreSQL compilation tests and loopback
emulators must not be described as live infrastructure validation.
