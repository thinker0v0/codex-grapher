# Changelog

## 0.2.0 — Portable repository workflows

- Add strict repository tasks, frozen checks and profiles, a bounded Codex CLI
  provider, and public initialization, execution, verification and recovery commands.
- Add explicit Linux role isolation and independent test/signing receipts while
  retaining trusted local development and the account-free demonstration.
- Add complete offline workspace archives and verified restore at the original
  absolute root, excluding private keys and provider authentication.
- Default SQLite writers to DELETE/EXTRA with one OS owner; require actual fixed
  runtime provenance for optional WAL/FULL and explicit legacy WAL maintenance.
- Ship setup guides, schemas and examples in the installed distribution, plus
  disposable guest recovery and role verification tools.

Portable acceptance is governed by its own frozen contract. The original
operational release remains `NOT_PASS`; no Claude execution is claimed here.

## Initial experimental snapshot — 2026-09-16

- Exported the existing local control-plane candidate at source commit `a393781`
  into Codex Grapher, without its original Git history or two private reports.
- Added a local quickstart, offline two-node scheduling example, pinned
  development dependencies, and Ubuntu/Python 3.12 CI.
- Fixed the installer module inventory to include `graph_state.py` and added an
  isolated staged-import regression.
- Added contribution, security, and publication provenance documentation.

Operational release status remains `NOT_PASS`; the frozen rubric is unchanged.
See [publication scope and provenance](docs/PUBLICATION.md).
