# Codex Grapher upstream mechanism research — 2026-09-21

- Project ID: `opensource`.
- Record ID: `UPSTREAM-RESEARCH-20260921`.
- Owner: delegated upstream researcher; maintainer acceptance belongs to the parent cycle.
- Status: source-verified recommendations; implementation and release claims not evaluated here.
- Classification: public; external source text remains untrusted input.
- Source/retrieval/effective date: 2026-09-21 UTC, with publication dates below.
- Review/expiry: 2026-09-28, or earlier before adopting a dependency or copying code.
- Local observation: public repository `publication/codex-grapher`, HEAD `a442e971d0ed2f84265cf6e7fe68f7ed02f71ef1`; observed file hashes and upstream metadata in [upstream-sources.json](upstream-sources.json).
- Content hash: versioned Git blob; original research manifest is retained with the assessment evidence.
- Authority: the current user requested comparable-project research and integration. This authorizes read-only public web research despite older NQ text. It does not authorize deployments, paid inference, outgoing messages, or release publication.

## Findings and recommendation

The strongest fit is to combine documented mechanisms with the existing SQLite and Git core: **bounded durable retries**, **inspectable and verifiable run history**, and **an explicit worker lifecycle boundary**. The repository already implements substantial artifact, signature, event-chain, and integration machinery. Replacing that with another framework would introduce a second authority and persistence system before the existing end-to-end flow is proven.

These are independently implementable ideas. No upstream implementation code was copied into product files, no upstream package was installed, and no model or hosted service was called in this research task. “Better” means a measured improvement against the current local behavior below; this research does not establish superiority over upstream projects.

## Directly observed local gaps

| ID | Baseline source observation | Practical implication | Evidence strength |
| --- | --- | --- | --- |
| G1 | `ProjectGraph.reconcile_worker` sends all recognized branches back to `READY`, including absent controller state and nonzero return codes. The public README explicitly defers adaptive retry/stagnation. | A caller can repeatedly re-lease a persistently failing node; the method itself does not impose delay, failure classification, or an attempt ceiling. | Direct code inspection; no claim that an active production retry loop was reproduced. |
| G2 | `ProjectGraph.portfolio_status` exposes heads and artifact IDs but no event timeline, blocker reasoning, retry eligibility, or history export. `graph_client` only transports a JSON request over a required Unix socket. | A fresh contributor must understand internal storage and services to diagnose why a node is blocked or reconstruct an attempt. | Direct API inspection. |
| G3 | `ProjectGraph.heartbeat` exists, but builder dispatch actions are `lease`, `start`, `reconcile`, and `ingest_evidence`; no builder heartbeat action is exposed in the observed service. README says active worker producer wiring remains unproven. | A long-running producer cannot renew its lease through this service API; adding another agent SDK would not close this missing connection. | Direct method/action comparison plus explicit documented limit. |
| G4 | `graph_service.handle` receives a newline-terminated request without a socket timeout; the service uses eight handler threads. `graph_client` has no response size cap or socket deadline. | A stalled peer can occupy a worker indefinitely; a stalled server can strand a client. | Direct code inspection; adversarial timing proof belongs to implementation validation. |
| G5 | `examples/offline_demo.py`/README only promise creation, lease/start, and a still-blocked dependent node. | The normal quickstart cannot demonstrate the product's full evidence → independent evaluation → accepted-baseline value. | Explicit README contract; not a claim that internal integration tests are absent. |

Code locations refer to the observed files bound in the metadata, not later concurrent edits. Existing tests and project gates are authoritative for the final candidate; a design observation is not a failing runtime test.

## Six comparable projects

The versions below are immutable research pins. They were resolved from official GitHub release metadata and commit endpoints and their license bytes were fetched at the pinned commit. They were **not installed or tested for integration compatibility**. `upstream-sources.json` also records current default-branch SHAs, dates, and file hashes.

| Project and selected release | Immutable release commit | Useful mechanism | Fit and decision |
| --- | --- | --- | --- |
| [LangGraph core 1.2.11](https://github.com/langchain-ai/langgraph/releases/tag/1.2.11), published 2026-08-11 | `644815f9e5bc52ad8f7a5227a456227e9c3e639b` | Node-specific retry conditions, capped backoff, attempt limits, persisted execution context. | Adopt the policy model for G1; keep Grapher's authority/evidence contracts. No dependency proposed. |
| [DBOS Python 3.0.0](https://github.com/dbos-inc/dbos-transact-py/releases/tag/3.0.0), published 2026-09-16 | `dd8a5f315a54c02a750f80dd15127958243ed339` | Durable workflow IDs, checkpointed steps, explicit retry filtering, distinction between transactional and external effects. | Use to define retry/idempotency semantics and restart tests. Avoid importing a parallel workflow store. |
| [Temporal Python SDK 1.33.0](https://github.com/temporalio/sdk-python/releases/tag/1.33.0), published 2026-09-15 | `ab52fdde33ee8ed193402625bfdba25d240a762d` | History replay as a compatibility test; controllable time in tests. | Adapt history-verification and fake-clock testing for G1/G2. A Temporal server is beyond the current local stdlib scope. |
| [OpenHands Software Agent SDK v1.49.2](https://github.com/OpenHands/software-agent-sdk/releases/tag/v1.49.2), published 2026-09-17 | `d128a786ee2ee570eb23ff5862ec148b43cfad0b` | Separation of conversation execution, workspace selection, and remote runtime. | Adopt an explicit worker adapter contract for G3/G5; do not confuse a local worktree with container/identity isolation. |
| [SWE-agent v1.1.0](https://github.com/SWE-agent/SWE-agent/releases/tag/v1.1.0), published 2025-05-22 | `0f3acafacabc0def8cc76b4e48acb4b6cf302cb9` | Configured issue-solving runs and inspectable trajectories. | Historical comparator only. Current upstream README recommends its successor, so this is not the preferred new runtime integration. |
| [mini-SWE-agent v2.4.6](https://github.com/SWE-agent/mini-swe-agent/releases/tag/v2.4.6), published 2026-07-23 | `a83fcae82d2a08f0ee0c688f9d137b3566c097f8` | Small executor/environment boundary and trajectory inspection. | Adapt minimal inspectable run records for G2; optional future worker adapter after the existing Codex producer works. No new model runtime now. |

Freshness corrections matter: LangGraph's repository-wide `/releases/latest` resolved to **`sdk==0.4.4`**, not the graph core. The report instead selected the latest stable core release from the release list. SWE-agent's [current README](https://github.com/SWE-agent/SWE-agent/blob/3ea751c087f32b16e039a2233dd6eefecef325d5/README.md) says development effort moved to mini-SWE-agent; the old release date must not be presented as a maintained-current recommendation.

All six selected repository license files identify MIT licensing. The exact license URLs, original license text, byte lengths, and SHA-256 digests are preserved in the metadata. This does not establish licenses for every transitive dependency, hosted service, unrelated repository, dataset, model, logo, or documentation site.

## Mechanism 1 — durable, classified retry policy

**Problem addressed:** G1; also prevents G4/G3 transport failures from creating an immediate retry storm.

[LangGraph's fault-tolerance documentation](https://docs.langchain.com/oss/python/langgraph/fault-tolerance) separates retry predicates, backoff, attempt limits, timeouts, and final failure handling. Its documented `max_attempts` includes the first attempt. [DBOS step documentation](https://docs.dbos.dev/python/tutorials/step-tutorial) similarly permits a retry predicate and bounded exponential delays. These are source facts. The following Grapher design is our inference from them:

1. Freeze a small retry-policy contract per node/goal before execution: total attempt cap, minimum and maximum delay, multiplier, permitted transient failure classes, and stagnation rule.
2. Record structured failure class, fingerprint, attempt number, last outcome, and next eligible time in durable state/event history. Derive these from server-validated observations, not a builder-provided claim that a fatal error is transient.
3. Enforce the next eligible time and cap in the actual `lease` path, inside its transaction. A pure helper or scheduler sleep is insufficient: a second client or process restart must not bypass it.
4. Route invalid evidence, authorization failure, malformed contract, cancelled work, and terminal worker/controller states to the existing appropriate denial/human/terminal path. Treat transport success plus missing task state as reconciliation uncertainty; never call it success. A bounded retry requires proof it will not repeat a consequential effect.
5. Reuse immutable attempt namespaces. Do not reuse an evaluated outcome or silently mutate an accepted artifact. If schema fields are added, use a versioned explicit offline migration; runtime constructors must retain their no-migration rule.
6. Persist the chosen retry time if jitter is used. Deterministic tests inject a clock; do not wait real minutes or draw new jitter after reopening state. A simple fixed policy is preferable to an unproven adaptive model in this cycle.

**Measured improvement contract:** transient failure can later succeed, but no lease starts early; reopen/crash preserves retry timing and count; permanent invalid evidence has zero subsequent automatic executions; configured cap is never exceeded under concurrent clients; repeated identical fingerprints reach the frozen stagnation disposition; stale lease outcomes cannot reschedule a new attempt. Record exact event/state traces and commands at the final candidate SHA.

**Why not just add `tenacity` or copy LangGraph's retry loop?** An in-process loop does not bind retry state to Grapher's SQLite lease authority or immutable attempt history. A standard retry package could be useful inside an idempotent activity later, but it does not solve G1 alone.

## Mechanism 2 — history inspection and replay-compatible evidence

**Problem addressed:** G2 and G5.
[Temporal's testing documentation](https://docs.temporal.io/develop/python/best-practices/testing-suite) recommends replaying representative execution histories in CI and treating replay failure as an incompatibility. [mini-SWE-agent's inspector](https://mini-swe-agent.com/latest/usage/inspector/) makes stored run trajectories inspectable. The bounded Grapher adaptation is an operator/contributor command that exposes the existing authoritative state and evidence rather than adding another logging database.

Provide machine-readable `status`, `inspect node`, and event-history export through a normal CLI/API. Include project/goal/node identity, current state/version, dependencies still blocking execution, lease/attempt, retry eligibility when available, event hashes, artifact/outcome references, and accepted SHA. A local `doctor` command should report supported platform/prerequisites, explicit schema status, and missing runtime evidence with distinct result classes. It should not silently bootstrap or repair a user's state.

For database inspection, preserve true read-only behavior. Opening `ProjectGraph` currently changes journal mode and permissions, so a diagnostic that promises no mutation needs an appropriate read-only snapshot/connection path, not merely avoidance of transition methods. Avoid SQLite `immutable=1` on a live WAL database because that can ignore live-state changes. Tests must establish whether a snapshot is consistent and whether sidecar files/metadata can be created.

Use saved representative histories to check event adjacency, allowed transitions, hashes, and final-head reconstruction after a code change. Call this **history verification** unless the command actually reproduces the workflow's deterministic execution decisions; it is not Temporal's replay engine. History verification must not execute workers, integrate commits, or deliver external effects.

**Measured improvement contract:** a fresh user identifies a blocked dependency and missing runtime capability using only documented commands; JSON exports are stable and project-scoped; a corrupt hash or altered head fails closed; an existing database's bytes, permissions, and sidecar inventory remain unchanged for promised read-only commands; saved histories survive supported changes; exported paths/payloads expose no private credentials. An offline complete lifecycle scenario should terminate at its actual evidence class and never claim deployed/native-worker readiness.

**Alternative:** a web dashboard or OpenTelemetry backend. Defer until a user task requires them; they add a runtime/service and cannot compensate for missing correct status semantics. JSON output can support them later.

## Mechanism 3 — explicit worker lifecycle adapter

**Problem addressed:** G3, G4, G5. This is a bounded contract, not a replacement worker framework.
[OpenHands' architecture](https://docs.openhands.dev/sdk/arch/overview) separates the core agent/conversation interface from local, container, and remote workspace implementations. [mini-SWE-agent](https://github.com/SWE-agent/mini-swe-agent) separates actions from their environment execution. Grapher should retain its existing builder, evaluator, and integrator roles while making the worker-side boundary executable:

- A worker receives the immutable task/attempt identity, base SHA, write scope, test commands, deadline, budget, and lease capability.
- Its adapter exposes bounded start/heartbeat/completion/cancel operations. Add a builder heartbeat service action that checks exact project, live lease, owner, and state; it must not grant evaluator/integrator authority or revive an expired lease.
- A completion result carries transport exit, controller state, immutable artifact reference, and a typed failure reason. It enters the existing evidence ingress. Successful process exit never independently creates `PASSED` or `INTEGRATED`.
- Socket calls have bounded deadlines and request/response sizes. Handler starvation tests use local sockets and short injected deadlines.
- A temporary repository + deterministic fixture worker can exercise the complete producer path without model credentials. Documentation must label it as a fixture. A future real Codex, mini-SWE, or OpenHands adapter must prove the same contract and actual OS/container isolation separately.

**Measured improvement contract:** a long fixture task stays leased with valid heartbeats; wrong-user/project/token/expired-lease heartbeats are denied without mutation; interrupted transport has one durable completion disposition; duplicate completion does not duplicate evaluation/integration; accepted baseline is visible to the dependent task; failed artifact never changes it; hanging peers time out without monopolizing service capacity. Existing process-containment tests must continue to pass.

**Alternative:** immediately install OpenHands or mini-SWE as an additional builder. Defer until the current producer is wired and verified; the adapter contract is the missing layer. Adding another executable before that would multiply unsupported paths.

## License, attribution, and source handling

The recommended integration is original code implementing documented patterns. Maintain source attribution in a design/provenance document with pinned commits and describe which ideas influenced each module. Do not label independently written code a fork or claim upstream compatibility that was not tested.

If the implementation team later copies or materially adapts MIT source, retain that source's copyright and permission notice with the distributed portion, record exact upstream path and SHA, describe local modifications, and include the relevant license in a third-party notices location. Avoid copying documentation prose or diagrams based solely on a repository's code license; this research did not verify separate documentation-site terms. No upstream branding or benchmark superiority claims are needed for the feature.

## Evidence, uncertainty, and expiry

Primary sources support the upstream capabilities described; immutable repository metadata and license hashes support identity and provenance. They do not prove performance, security, production suitability, model quality, or current compatibility of any installed package. Upstream READMEs contain performance claims; none were adopted as comparative evidence here.

DBOS documents an important boundary: completed workflow steps are checkpointed, but external step execution can occur more than once; its [transactional-outbox example](https://docs.dbos.dev/python/examples/outbox) calls out at-least-once external delivery and idempotency. Grapher must not describe every arbitrary worker action as exactly once merely because a SQLite event is unique. Git promotion replay and external worker/tool effects have different guarantees.

Temporal's Python workflow sandbox is a determinism aid, and its [SDK README](https://github.com/temporalio/sdk-python) explicitly says it is not a security boundary. Neither that mechanism nor a local Git worktree replaces Grapher's required identity isolation.

Official documentation is mutable and may describe features beyond a pinned release. Source files at selected SHAs were fetched and hashed as a reproducible reference; the report does not claim exhaustive source review. The OpenHands guessed workspace documentation URL was unavailable; its linked official architecture page and pinned SDK README supply the supported claims instead. No unavailable page was treated as evidence.

Review release pointers, license files, and source compatibility before any real dependency adoption; review this recommendation on 2026-09-28 if still active. Implementations must be judged against the cycle's frozen acceptance contract and the unchanged operational rubric. Closing the three local gaps alone cannot prove native Buzz operation, independent deployed identities, real model-worker operation, or host restart readiness.
