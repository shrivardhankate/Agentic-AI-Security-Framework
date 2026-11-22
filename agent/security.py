
import ast
import json
from datetime import datetime, timezone

ALLOWED_TOOLS = {"get_time", "calculate"}

ALLOWED_OPERATORS = (
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv,
    ast.Mod, ast.UAdd, ast.USub,
)

ALLOWED_NODES = (
    ast.Expression, ast.Constant, ast.BinOp, ast.UnaryOp,
    *ALLOWED_OPERATORS,
)


def valid_arithmetic_expression(expression):
    if not isinstance(expression, str) or not expression.strip():
        return False

    if len(expression) > 100:
        return False

    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return False

    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            return False

        if isinstance(node, ast.Constant):
            if type(node.value) not in (int, float):
                return False
            if abs(node.value) > 10**12:
                return False

    return True


def authorize_tool(name, arguments):
    if name not in ALLOWED_TOOLS:
        return False, "Tool is not allowlisted."

    if not isinstance(arguments, dict):
        return False, "Tool arguments must be a dictionary."

    if name == "get_time" and arguments:
        return False, "get_time does not accept arguments."

    if name == "calculate":
        if set(arguments) != {"expression"}:
            return False, "calculate requires only an expression argument."

        if not valid_arithmetic_expression(arguments["expression"]):
            return False, "Invalid or unsupported arithmetic expression."

    return True, "Allowed"


def log_security_event(name, arguments, allowed, reason):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": name,
        "arguments": arguments,
        "allowed": allowed,
        "reason": reason,
    }

    with open("logs/security_events.jsonl", "a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")
