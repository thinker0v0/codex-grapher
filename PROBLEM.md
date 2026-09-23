# Problem

> Current cycle: [2026-09-21 portable workers](docs/cycles/20260921-portable-workers/HANDOFF.md).
> The user authorized generic repository tasks, real Codex subscription execution,
> OS role separation, disposable guest restart/backup validation and SQLite support,
> followed by a separate `claude-grapher` repository and OSS publication. Claude
> live execution is explicitly deferred until the user obtains an account.
> This supersedes historical NQ restrictions for the authorized cycle. Preserve
> all legacy rubrics. No production changes, purchases or protected merges are
> authorized; publication and owner delivery are separate actions, never tests.


Status: verified historical baseline with unresolved release residual

## Observable costly problem

The operator could start long Codex work from Hermes, but the inspected campaign
did not reliably convert compute into cumulative project progress. On 2026-08-27
the live state marked `nomad`, `business`, and `hynix` `needs_human` after repeated
`router_rc_0` outcomes with `controller_state=UNKNOWN`. `opensource` reached stage
3, but its successful tasks remained `EVIDENCE_PENDING` in isolated attempt
workspaces. There is no proven evaluator-to-integrator path that makes an accepted
artifact the next task's baseline. No native Buzz configuration was found in the
deployed profile during that inspection.

## Causal mechanism

1. The legacy campaign infers success from incomplete controller/stdout parsing.
2. Builder attempts are copied from a fixed workspace and never transactionally
   promoted after evaluation.
3. A timer loop owns a fixed three-stage script rather than a durable task graph
   derived from user value and dependencies.
4. High token/time ceilings remove premature budget failure but do not allocate
   compute based on uncertainty, verifier feedback, or marginal progress.
5. Evaluator identities and controller states exist, but no end-to-end evaluator
   service consumes evidence, freezes a rubric, transitions tasks, and authorizes
   an integrator.
6. Slack-specific prompts and requester identity assumptions are embedded in the
   public route even though Buzz is the intended interface.

## Residual as of 2026-08-30

Local fixture/controller mechanisms are being hardened, but there is not yet a
final evidence packet binding the complete candidate to exact Git, schema,
configuration, command-output, and artifact hashes. More importantly, active
manifest-v4 producer wiring, installed/deployed services, real project workers,
native Buzz staging, restart/host recovery, and final-user evidence remain absent.
Therefore local fixture results cannot resolve the operator's unattended deployed
workflow problem or satisfy the frozen release rubric.

Slack and `fin-global` are now explicitly frozen legacy surfaces. The residual
operator problem applies only to Hermes native Buzz and the exact routes `nomad`,
`opensource`, `business`, and `hynix`.

## Current workaround

The historical workaround was to ask for status, restart campaigns, interpret
artifacts, and copy useful results manually. Under the active NQ boundary the
operator can only inspect and improve secret-free local fixtures; they cannot use
deployment or real workers to close the residual. This avoids unsafe inference
but does not deliver unattended operation.

## Historical baseline — 2026-08-27/28

- Read-only inspection found the router, controllers, Hermes OSS, and campaign
  timer active on the VPS at that time.
- The inspected configuration could launch four routed high-budget contracts
  concurrently.
- The observed campaign state was OpenSource at three staged attempts; the other
  three routes had stopped at stage 1 after four attempts each.
- No repository evidence proves native Buzz E2E, independent evaluation, atomic
  promotion, or restart-safe graph continuation.

These are dated observations tied to the evidence summarized as R009, not claims
about current service state. This NQ cycle forbids a new live inspection, service
restart, staging run, or real-worker experiment.

## Assumptions and falsification tests

- **A1:** Durable graph state improves unattended completion. Falsified if kill and
  restart tests duplicate nodes or lose accepted progress.
- **A2:** Independent verification plus promotion produces cumulative progress.
  Falsified if the next task cannot observe the prior passed artifact at the new
  bound SHA.
- **A3:** Adaptive compute outperforms fixed long runs for verified outcomes.
  Falsified if matched representative tasks produce no improvement in gate pass
  rate or time-to-verified-result after noise is considered.
- **A4:** Buzz native gateway is a better operator surface without weakening
  authority. Falsified if identities/routes/approvals cannot be mapped and audited.
- **A5:** Finance research can be highly autonomous while live action remains
  gated. Falsified if the graph cannot prevent a research/model artifact from
  reaching a live executor without an explicit human capability grant.

## Falsifiable success measure

On four representative safe goals, the system must survive interruption, maintain
route isolation, produce hashed evidence, independently evaluate results, promote
only passed artifacts, expose accurate Buzz/status output, and achieve at least
95/100 under `RUBRIC.md`. Finance validation must end at backtest/paper evidence and
prove live-order denial without a human authorization grant.

The bounded cycle measure is narrower: a clean final candidate may earn only
`LOCAL_FIXTURE_PASS` when its no-cost, secret-free controller and native-like Buzz
fixtures satisfy the frozen local contract and an exact machine evidence packet is
recorded. That result does not satisfy the success measure above. Until later
authorized deployed/native/real-worker evidence closes every hard gate, release is
`NOT_PASS`.
