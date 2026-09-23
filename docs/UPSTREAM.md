# Upstream ideas and provenance

The developer reliability cycle implements selected mechanisms inside Grapher's
existing SQLite, immutable evidence and Git integration protocol. It adds no
upstream runtime dependency and vendors no upstream source code.

| Project | Mechanism adapted | Grapher-specific integration |
| --- | --- | --- |
| [LangGraph](https://docs.langchain.com/oss/python/langgraph/fault-tolerance) and [DBOS](https://docs.dbos.dev/python/tutorials/step-tutorial) | Classified finite retries and capped backoff | Persist retry decisions in the existing event chain; enforce eligibility during leasing and recovery. |
| [Temporal](https://docs.temporal.io/develop/python/best-practices/testing-suite) | Inspect execution history and test recovery compatibility | Read-only state/event inspection and process interruption tests of the existing publication journal. This is history verification, not Temporal's replay engine. |
| [OpenHands SDK](https://docs.openhands.dev/sdk/arch/overview) and [mini-SWE-agent](https://mini-swe-agent.com/latest/usage/inspector/) | Explicit execution/workspace boundary and inspectable runs | A local producer/evaluator/integrator workflow, renewed worker leases, bounded transport, and visible artifact identities. |

The [research ledger](cycles/20260921-reliability/RESEARCH.md) compares six
projects, alternatives and limitations. Its [source metadata](cycles/20260921-reliability/upstream-sources.json)
records immutable release commits, access dates and license hashes. The selected
repository snapshots use MIT licenses. This finding does not cover all their
dependencies, models, datasets, logos or hosted services.

These mechanisms address reproduced gaps in the prior Grapher snapshot. We have
not benchmarked Grapher against those projects and do not claim it outperforms
them. Any future source-code reuse must preserve the applicable copyright and
license notices and undergo a new compatibility review.
