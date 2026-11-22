
from environment.agent_adapter import AgentAdapter


def test_only_approved_tools_are_advertised():
    adapter = AgentAdapter()
    names = {tool["name"] for tool in adapter.available_tools()}

    assert names == {
        "read_public_file",
        "list_public_files",
        "search_public_users",
        "list_public_documents",
        "retrieve_memory",
    }


def test_public_file_can_be_read():
    adapter = AgentAdapter()
    response = adapter.invoke(
        "read_public_file",
        {"relative_path": "welcome.txt"},
    )

    assert response["ok"] is True
    assert "Agent Security Test Lab" in response["result"]


def test_unknown_tool_is_rejected():
    adapter = AgentAdapter()
    response = adapter.invoke("execute_shell", {"command": "whoami"})

    assert response["ok"] is False
    assert response["error"] == "tool_not_allowed"


def test_extra_arguments_are_rejected():
    adapter = AgentAdapter()
    response = adapter.invoke(
        "list_public_files",
        {"unexpected": "value"},
    )

    assert response["ok"] is False
    assert response["error"] == "invalid_arguments"


def test_path_traversal_is_denied():
    adapter = AgentAdapter()
    response = adapter.invoke(
        "read_public_file",
        {"relative_path": "../confidential/restricted_record.txt"},
    )

    assert response["ok"] is False
    assert response["error"] == "access_denied"


def test_wrong_argument_type_is_rejected():
    adapter = AgentAdapter()
    response = adapter.invoke(
        "search_public_users",
        {"username": ["test_researcher"]},
    )

    assert response["ok"] is False
    assert response["error"] == "invalid_arguments"
