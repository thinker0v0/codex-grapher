# Evaluation Rubric v1.0.0

Total: 100. Passing requires total >= 95, every section minimum, and all mandatory gates.

| Section | Weight | Minimum |
|---|---:|---:|
| Gold CFD and Nasdaq futures research | 20 | 18 |
| KOSPI/KOSDAQ data, ranking, and conditional entry research | 20 | 18 |
| Open-source and AI-native business operations | 15 | 13 |
| Hermes, Slack, and Codex operations | 15 | 13 |
| Shared quality, safety, reproducibility, and recovery | 30 | 27 |

## Mandatory gates

- Point-in-time and future-information leakage tests pass.
- Delisted securities remain in historical universes.
- Locked time-ordered OOS evaluation passes.
- Multiple-testing and overfitting controls are recorded.
- Costs, spread, slippage, liquidity, roll, and financing are modeled.
- Code, data, model, configuration, prompt, and environment versions are pinned.
- Research, paper, and live credentials and environments are isolated.
- Independent risk limits and kill switch cannot be bypassed by an agent.
- Slack cannot activate live trading, raise risk, or withdraw.
- Stale or corrupt data results in no trade.
- Legal, broker, market-data, and news-license reviews are owned by humans.
- Restore and failure drills pass.
- Builder and evaluator identities and permissions are independent.
- Every prediction and order is traceable to evidence and immutable artifacts.

## Evidence levels

- Idea only: at most 20% of item score.
- Detailed design and acceptance criteria: at most 60%.
- Automated tests and reproducible evidence: at most 85%.
- Isolated execution and failure-drill evidence: up to 100%.

## Loop policy

- Maximum iterations: 5
- Maximum wall clock: 6 hours
- Stop after two iterations without improvement.
- Escalate after two repeated critical-gate failures.
- A blind second evaluator is required at the threshold.
- A score difference of 5 or more requires human adjudication.
