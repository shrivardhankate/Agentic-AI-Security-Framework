
import unittest
from agent.security import authorize_tool


class TestSecurityGateway(unittest.TestCase):

    def test_allowed_time_tool(self):
        allowed, reason = authorize_tool("get_time", {})
        self.assertTrue(allowed)

    def test_allowed_calculation(self):
        allowed, reason = authorize_tool(
            "calculate", {"expression": "25 * 48"}
        )
        self.assertTrue(allowed)

    def test_unknown_tool_rejected(self):
        allowed, reason = authorize_tool("unknown_tool", {})
        self.assertFalse(allowed)

    def test_unexpected_argument_rejected(self):
        allowed, reason = authorize_tool(
            "calculate",
            {
                "expression": "25 + 48",
                "delete_file": True
            }
        )
        self.assertFalse(allowed)

    def test_missing_expression_rejected(self):
        allowed, reason = authorize_tool("calculate", {})
        self.assertFalse(allowed)

    def test_invalid_argument_type_rejected(self):
        allowed, reason = authorize_tool(
            "calculate", {"expression": 123}
        )
        self.assertFalse(allowed)
        
    
    def test_natural_language_rejected(self):
        allowed, reason = authorize_tool(
            "calculate",
            {"expression": "explain what an AI agent is"}
        )
        self.assertFalse(allowed)

    def test_code_expression_rejected(self):
        allowed, reason = authorize_tool(
            "calculate",
            {"expression": "__import__('os').system('whoami')"}
        )
        self.assertFalse(allowed)



if __name__ == "__main__":
    unittest.main(verbosity=2)
