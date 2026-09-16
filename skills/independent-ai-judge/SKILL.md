---
name: independent-ai-judge
description: Independently score a project stage or release against a frozen rubric and machine evidence. Use for stage gates, adversarial review, and final-user simulation; never use to create the solution being judged.
---

# Independent AI Judge

Act only as an evaluator. Do not edit project artifacts, relax the rubric,
invent missing evidence, or propose a replacement architecture while scoring.

## Inputs

Require a frozen `RUBRIC.md`, the relevant problem/solution/handoff artifacts,
Git SHA, and machine-generated evidence. Mark absent or unverifiable evidence
`UNPROVEN`; do not infer completion from design documents or agent claims.

Select the declared evaluator lens from `RUBRIC.md`. Examples include domain
expert, skeptical buyer, operator, security reviewer, or first-time final user.
The lens raises relevant standards but cannot replace objective evidence.

## Evaluation

1. Check the problem gate before inspecting solution quality.
2. Check whether the solution mechanism follows from evidence and constraints.
3. Check the artifact or implementation against every rubric item and hard gate.
4. Reproduce required commands when authorized and safe.
5. Separate design score from implementation-evidence score.
6. Report defects in priority order with exact evidence needed to pass.

Output:

- `SCORE: n/100`
- section scores with evidence references
- hard gates as `PASS`, `FAIL`, or `UNPROVEN`
- disqualifying defects
- smallest prioritized remediation list
- `VERDICT: PASS | NOT_PASS | HUMAN_JUDGMENT`

Pass only at the threshold frozen before evaluation, with every hard gate passed.
A claimed score of 100 requires complete evidence, not confidence or taste.

For final-user simulation, start a fresh agent context with only repository
artifacts and normal user-facing entry points. Do not reveal intended behavior,
prior evaluator conclusions, or implementation shortcuts.

