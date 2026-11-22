from ast import arguments

from ollama import chat
from tools import TOOLS, execute_tool
from pathlib import Path
from security import authorize_tool, log_security_event

Path("logs").mkdir(exist_ok=True)
class Agent:

    def __init__(self, model):

        self.model = model

        self.messages = [
           {
                "role": "system",
                "content": (                    
                        "You are an AI research agent running in a controlled laboratory.\n"
                        "Answer general knowledge, definitions, explanations, and conceptual "                            "questions directly without using tools.\n"
                        "Use get_time only when the user asks for the current date or time.\n"
                        "Use calculate only when the user asks you to evaluate a mathematical "
                        "expression or solve a numerical calculation.\n"
                        "Never send ordinary sentences, questions, or explanations to calculate.\n"
                        "Never call a tool just because a tool is available.\n"
                        "Choose tools based only on the user's current request.\n"
                        "If a tool fails, explain the issue briefly and answer directly if possible."
                )
            }
        ]
    
    def run(self, user_input):
        self.messages.append({
            "role": "user",
            "content": user_input
        })

    # Limit tool iterations to prevent an endless loop.
        max_iterations = 5

        for _ in range(max_iterations):
            response = chat(
                model=self.model,
                messages=self.messages,
                tools=TOOLS
            )

            message = response.message
            tool_calls = message.tool_calls or []

            # No tool requested: return the normal answer.
            if not tool_calls:
                self.messages.append(message)
                return message.content or ""

            # Preserve the assistant message containing tool calls.
            self.messages.append(message)

            for tool_call in tool_calls:
                tool_name = tool_call.function.name
                arguments = tool_call.function.arguments

                print(f"\n[Agent requested tool: {tool_name}]")
                print(f"[Arguments: {arguments}]")

                try:
                    allowed, reason = authorize_tool(tool_name, arguments)
                    log_security_event(
                        tool_name,
                        arguments,
                        allowed,
                        reason
                    )

                    if not allowed:
                        result_text = f"Security gateway rejected tool call: {reason}"
                        print(f"[SECURITY BLOCK] {reason}")
                    else:
                        try:
                            result = execute_tool(tool_name, arguments)
                            result_text = str(result)
                        except Exception as exc:
                            result_text = f"Tool execution failed: {exc}"
                            print(f"[Tool error: {exc}]")

                    print(f"[Tool result: {result_text}]")
                except Exception as exc:
                    result_text = f"Tool execution failed: {exc}"
                    print(f"[Tool error: {exc}]")

                self.messages.append({
                    "role": "tool",
                    "content": result_text,
                })

        return "Stopped: maximum tool-call iterations reached."



def main():

    agent = Agent("llama3.2")

    print("AI Security Research Agent")
    print("Type 'exit' to stop.\n")

    while True:

        user_input = input("User: ")

        if user_input.lower() == "exit":
            break

        answer = agent.run(user_input)

        print("\nAgent:", answer)
        print()


if __name__ == "__main__":
    main()