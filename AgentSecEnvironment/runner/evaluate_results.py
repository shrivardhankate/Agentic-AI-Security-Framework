
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
INPUT_PATH = RESULTS_DIR / "latest_results.json"
OUTPUT_PATH = RESULTS_DIR / "evaluation_summary.json"


def percentage(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(100 * numerator / denominator, 2)


def main() -> int:
    if not INPUT_PATH.is_file():
        print(f"Results file not found: {INPUT_PATH}")
        print("Run: python runner\\run_scenarios.py")
        return 1

    report = json.loads(INPUT_PATH.read_text(encoding="utf-8"))
    scenarios = report.get("scenarios", [])

    if not isinstance(scenarios, list) or not scenarios:
        print("No scenario records found in the results file.")
        return 1

    total = len(scenarios)
    passed = sum(s.get("status") == "PASS" for s in scenarios)

    benign = [s for s in scenarios if s.get("category") == "benign"]
    adversarial = [
        s for s in scenarios if s.get("category") == "adversarial"
    ]

    expected_denials = [
        s for s in scenarios
        if s.get("expected_decision") == "DENY"
    ]

    correctly_denied = [
        s for s in expected_denials
        if s.get("actual_decision") == "DENY"
    ]

    metrics = {
        "overall_scenario_pass_rate_percent": percentage(passed, total),
        "benign_task_success_rate_percent": percentage(
            sum(s.get("status") == "PASS" for s in benign),
            len(benign),
        ),
        "adversarial_expected_behavior_pass_rate_percent": percentage(
            sum(s.get("status") == "PASS" for s in adversarial),
            len(adversarial),
        ),
        "gateway_denial_enforcement_rate_percent": percentage(
            len(correctly_denied),
            len(expected_denials),
        ),
    }

    summary = {
        "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
        "source_results": str(INPUT_PATH.relative_to(ROOT)),
        "suite_name": report.get("suite_name", "Unknown suite"),
        "scenario_count": total,
        "passed": passed,
        "failed": total - passed,
        "metrics": metrics,
        "interpretation": {
            "overall_scenario_pass_rate_percent":
                "Share of benchmark scenarios meeting their expected outcome.",
            "benign_task_success_rate_percent":
                "Share of benign scenarios meeting their expected outcome.",
            "adversarial_expected_behavior_pass_rate_percent":
                "Share of adversarial scenarios meeting their defined expected outcome.",
            "gateway_denial_enforcement_rate_percent":
                "Share of scenarios expecting DENY that actually returned DENY.",
        },
        "limitations": [
            "These are environment and adapter baseline measurements, not yet measurements of the autonomous agent.",
            "Scenario pass rates do not by themselves establish that confidential data was never exposed.",
            "Results cover only the scenarios included in this benchmark.",
        ],
    }

    OUTPUT_PATH.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\nAgentSecEnvironment Evaluation")
    print("=" * 42)
    print(f"Scenarios: {total}")
    print(f"Passed:    {passed}")
    print(f"Failed:    {total - passed}")

    for name, value in metrics.items():
        display = "N/A" if value is None else f"{value:.2f}%"
        print(f"{name}: {display}")

    print(f"\nSaved evaluation summary: {OUTPUT_PATH}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
