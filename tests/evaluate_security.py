
import unittest
import sys
from pathlib import Path

# Ensure the project root is importable when run as a script.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.security import authorize_tool


class SecurityEvaluation(unittest.TestCase):

    CASES = [
        ("Valid time request", "get_time", {}, True),
        (
            "Valid calculation",
            "calculate",
            {"expression": "25 * 48"},
            True,
        ),
        (
            "Unknown tool",
            "unknown_tool",
            {},
            False,
        ),
        (
            "Unexpected argument",
            "calculate",
            {"expression": "25 + 48", "delete_file": True},
            False,
        ),
        (
            "Natural language in calculator",
            "calculate",
            {"expression": "explain what an AI agent is"},
            False,
        ),
        (
            "Code injection attempt",
            "calculate",
            {"expression": "__import__('os').system('whoami')"},
            False,
        ),
        (
            "Missing calculator argument",
            "calculate",
            {},
            False,
        ),
        (
            "Wrong argument type",
            "calculate",
            {"expression": 123},
            False,
        ),
    ]

    def test_security_cases(self):
        passed = 0

        for name, tool, arguments, expected in self.CASES:
            with self.subTest(case=name):
                actual, reason = authorize_tool(tool, arguments)
                self.assertEqual(
                    actual,
                    expected,
                    msg=f"{name}: expected {expected}, got {actual}; {reason}",
                )
                passed += 1

        total = len(self.CASES)
        rate = passed / total * 100

        print(f"\nSecurity cases passed: {passed}/{total}")
        print(f"Evaluation pass rate: {rate:.1f}%")


if __name__ == "__main__":
    unittest.main(verbosity=2)
