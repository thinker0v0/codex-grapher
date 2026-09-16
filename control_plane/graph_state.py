"""Single source of truth for the durable VAPG node-state contract."""

from __future__ import annotations


ACTIVE_PROJECTS = frozenset({"nomad", "opensource", "business", "hynix"})
INITIAL_NODE_STATES = frozenset({"BLOCKED", "READY"})
TERMINAL = frozenset({"INTEGRATED", "CANCELLED", "FAILED_GATE"})
TRANSITIONS = {
    "BLOCKED": frozenset({"READY", "CANCELLED"}),
    "READY": frozenset({"LEASED", "CANCELLED", "NEEDS_HUMAN"}),
    "LEASED": frozenset({"RUNNING", "READY", "CANCELLED"}),
    "RUNNING": frozenset({"EVIDENCE_PENDING", "READY", "FAILED_GATE", "CANCELLED"}),
    "EVIDENCE_PENDING": frozenset({"EVALUATING", "FAILED_GATE", "READY"}),
    "EVALUATING": frozenset({"PASSED", "READY", "FAILED_GATE", "NEEDS_HUMAN"}),
    "PASSED": frozenset({"INTEGRATING", "FAILED_GATE"}),
    "INTEGRATING": frozenset({"INTEGRATED", "PASSED", "FAILED_GATE"}),
    "NEEDS_HUMAN": frozenset({"READY", "CANCELLED", "FAILED_GATE"}),
}
KNOWN_NODE_STATES = frozenset(
    set(INITIAL_NODE_STATES)
    | set(TERMINAL)
    | set(TRANSITIONS)
    | {target for targets in TRANSITIONS.values() for target in targets}
)
SENSITIVE_NODE_STATES = frozenset({
    "PASS", "EVIDENCE_PENDING", "EVALUATING", "PASSED", "INTEGRATING",
    "INTEGRATED",
})

# These are audit events emitted only by internal recovery/publication code. They
# are deliberately not added to TRANSITIONS: ProjectGraph additionally requires
# the corresponding EXPIRED claim or completed journal/affected-node proof.
EXCEPTIONAL_EVENT_TRANSITIONS = {
    ("EVALUATING", "EVIDENCE_PENDING"): frozenset({
        "expired evaluator claim recovered",
    }),
    ("BLOCKED", "BLOCKED"): frozenset({
        "project-global promotion baseline rebind",
        "project-global publication rollback baseline rebind",
    }),
    ("READY", "READY"): frozenset({
        "project-global promotion baseline rebind",
        "project-global publication rollback baseline rebind",
    }),
    ("NEEDS_HUMAN", "NEEDS_HUMAN"): frozenset({
        "project-global promotion baseline rebind",
        "project-global publication rollback baseline rebind",
    }),
    ("CANCELLED", "CANCELLED"): frozenset({
        "project-global promotion baseline rebind",
        "project-global publication rollback baseline rebind",
    }),
    ("FAILED_GATE", "FAILED_GATE"): frozenset({
        "project-global promotion baseline rebind",
        "project-global publication rollback baseline rebind",
    }),
}
