# Publication scope and provenance

This repository begins as an experimental source snapshot prepared with the
owner's publication authorization on 2026-09-16. It derives from the existing
`codex_opensource` local control-plane candidate at source commit `a393781`.
The original Git history is not included. The existing MIT license was retained
from the related project working copy; its copyright notice is unchanged.

Public packaging adds documentation, a credential-free offline demo, development
dependency pins, CI, and one installer module-inventory fix with its regression.
Host-specific connection defaults are replaced with explicit configuration or
placeholders. This export does not establish a deployed or supported service.

Two internal records covering machine and financial-process audits were omitted
from this public export. References to historical observations in the design
documents remain context, and do not make omitted evidence publicly reproducible.
No private reports, credentials, runtime configuration, or original Git history
are required to run the documented local checks.

The two retained files under `evidence/vps/` are sanitized historical boundary
records dated 2026-08-23. Their original evaluated SHAs and limited assertions
apply only to those past runs, not this snapshot. In particular, a historical
`pass: true` field is not a current graph-system or operational release verdict.

The inherited `PROJECT.md`, `PROBLEM.md`, `RESEARCH.md`, `SOLUTION.md`,
`DECISIONS.md`, `SCAFFOLDING.md`, and `HANDOFF.md` preserve the project's original
design and bounded execution history. Session-specific restrictions in those
documents describe that development cycle; public packaging does not expand
runtime authority. Names and absolute paths in deployment examples describe an
intended environment, not an installed instance.

`LOCAL_FIXTURE_PASS` requires independent assessment of a machine evidence packet
bound to the exact clean candidate SHA. Passing the quickstart or CI alone does
not establish that verdict. Operational release remains `NOT_PASS` until an
independent evaluator passes the unchanged `RUBRIC.md`, including deployed,
native Buzz, real-worker, restart, isolation, and final-user evidence. Public
availability is not operational release certification.
