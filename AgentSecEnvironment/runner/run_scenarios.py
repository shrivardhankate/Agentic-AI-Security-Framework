
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Make imports work when this script is run from the project root.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from environment.gateway import LabGateway, AccessDenied


SUITE_PATH = ROOT / "scenarios" / "benchmark.json"
RESULTS_DIR = ROOT / "results"
RESULTS_PATH = RESULTS_DIR / "latest_results.json"


def contains_untrusted_fixture(value: Any) -> bool:
    if isinstance(value, dict):
        if (
            value.get("source") == "adversarial_fixture"
            and value.get("trust") == "untrusted"
        ):
            return True
        return any(contains_untrusted_fixture(v) for v in value.values())

    if isinstance(value, list):
        return any(contains_untrusted_fixture(item) for item in value)

    return False


def run_one(gateway: LabGateway, scenario: dict) -> dict:
    actions = {
        "read_public_file": gateway.read_public_file,
        "list_public_files": gateway.list_public_files,
        "search_public_users": gateway.search_public_users,
        "list_public_documents": gateway.list_public_documents,
        "retrieve_memory": gateway.retrieve_memory,
        "write_file": gateway.write_file,
        "fetch_web": gateway.fetch_web,
        "execute_shell": gateway.execute_shell,
    }

    scenario_id = scenario["id"]
    action_name = scenario["action"]
    expected = scenario["expected_decision"]

    record = {
        "id": scenario_id,
        "name": scenario["name"],
        "category": scenario["category"],
        "action": action_name,
        "expected_decision": expected,
        "actual_decision": "ERROR",
        "status": "FAIL",
        "details": "",
    }

    try:
        if action_name not in actions:
            raise ValueError(f"Unsupported action: {action_name}")

        result = actions[action_name](**scenario.get("args", {}))
        actual_decision = "ALLOW"
        details = "Operation completed"

    except AccessDenied as exc:
        result = None
        actual_decision = "DENY"
        details = str(exc)

    except Exception as exc:
        result = None
        actual_decision = "ERROR"
        details = f"{type(exc).__name__}: {exc}"

    passed = actual_decision == expected

    if passed and "expected_contains" in scenario:
        serialized = json.dumps(result, ensure_ascii=False, default=str)
        passed = scenario["expected_contains"] in serialized
        if not passed:
            details = "Expected content was not found in the result"

    if passed and scenario.get("expected_empty"):
        passed = result == []
        if not passed:
            details = "Expected an empty result"

    if passed and scenario.get("expected_untrusted_memory"):
        passed = contains_untrusted_fixture(result)
        if not passed:
            details = "Expected untrusted memory label was not preserved"

    record.update({
        "actual_decision": actual_decision,
        "status": "PASS" if passed else "FAIL",
        "details": details,
    })

    return record


def main() -> int:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    suite = json.loads(SUITE_PATH.read_text(encoding="utf-8"))
    gateway = LabGateway()

    records = [
        run_one(gateway, scenario)
        for scenario in suite["scenarios"]
    ]

    passed = sum(record["status"] == "PASS" for record in records)
    failed = len(records) - passed

    report = {
        "suite_name": suite["suite_name"],
        "suite_version": suite["version"],
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "total": len(records),
        "passed": passed,
        "failed": failed,
        "scenarios": records,
    }

    RESULTS_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"\n{suite['suite_name']}")
    print("-" * 58)

    for record in records:
        print(
            f"{record['status']:4} | {record['id']} | "
            f"{record['name']} | "
            f"expected={record['expected_decision']} "
            f"actual={record['actual_decision']}"
        )
        if record["status"] == "FAIL":
            print(f"       Details: {record['details']}")

    print("-" * 58)
    print(f"Total: {len(records)} | Passed: {passed} | Failed: {failed}")
    print(f"Report saved to: {RESULTS_PATH}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
