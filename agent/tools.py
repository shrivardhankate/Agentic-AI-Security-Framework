from datetime import datetime
import ast
import operator

#Get time tool
def get_time():
    """Return the current local date and time."""

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    
#Calculate tool

def calculate(expression):
    """Evaluate basic arithmetic without executing arbitrary Python code."""

    if not isinstance(expression, str) or len(expression) > 100:
        raise ValueError("Expression must be a string of at most 100 characters.")

    allowed_operators = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
    }

    def evaluate(node):
        if isinstance(node, ast.Expression):
            return evaluate(node.body)

        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value

        if isinstance(node, ast.BinOp) and type(node.op) in allowed_operators:
            left = evaluate(node.left)
            right = evaluate(node.right)

            if abs(left) > 10**12 or abs(right) > 10**12:
                raise ValueError("Number is too large.")

            result = allowed_operators[type(node.op)](left, right)

            if abs(result) > 10**12:
                raise ValueError("Result is too large.")

            return result

        if isinstance(node, ast.UnaryOp) and type(node.op) in allowed_operators:
            return allowed_operators[type(node.op)](evaluate(node.operand))

        raise ValueError("Only basic arithmetic expressions are allowed.")

    try:
        tree = ast.parse(expression, mode="eval")
        return evaluate(tree)
    except (SyntaxError, ZeroDivisionError, OverflowError) as exc:
        raise ValueError(f"Invalid arithmetic expression: {exc}") from exc




TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_time",
            "description": "Get the current local date and time.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    
    {
    "type": "function",
    "function": {
        "name": "calculate",
        "description": "Perform a basic mathematical calculation.",
        "parameters": {
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": "A basic mathematical expression."
                }
            },
            "required": ["expression"]
        }
    }
}
  
]

def execute_tool(name, arguments):

    if name == "get_time":
        return get_time()

    if name == "calculate":
        return calculate(
            arguments["expression"]
        )

    raise ValueError(f"Unknown tool: {name}")