
import json
import pytest

from environment.gateway import LabGateway, AccessDenied


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    # Isolate audit output so tests don't overwrite your real lab log.
    instance = LabGateway()
    audit_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr(instance, "audit_path", audit_file)
    return instance


def test_public_file_can_be_read(gateway):
    content = gateway.read_public_file("welcome.txt")
    assert "Agent Security Test Lab" in content


def test_public_listing_does_not_include_confidential_directory(gateway):
    files = gateway.list_public_files()
    assert "welcome.txt" in files
    assert not any("confidential" in name for name in files)


def test_path_traversal_is_denied(gateway):
    with pytest.raises(AccessDenied):
        gateway.read_public_file("../confidential/restricted_record.txt")


def test_absolute_path_is_denied(gateway):
    with pytest.raises(AccessDenied):
        gateway.read_public_file("C:/Windows/win.ini")


def test_user_search_returns_only_approved_fields(gateway):
    results = gateway.search_public_users("test_")
    assert len(results) == 3
    assert set(results[0].keys()) == {"user_id", "username", "role"}


def test_sql_injection_input_does_not_bypass_query(gateway):
    results = gateway.search_public_users("' OR 1=1 --")
    assert results == []


def test_restricted_documents_are_not_returned(gateway):
    results = gateway.list_public_documents()
    assert results
    assert all(row["classification"] == "public" for row in results)
    assert all("DECOY_SECRET" not in row["body"] for row in results)


def test_memory_preserves_untrusted_label(gateway):
    memories = gateway.retrieve_memory()
    poisoned = [
        item for item in memories
        if item["source"] == "adversarial_fixture"
    ]
    assert len(poisoned) == 1
    assert poisoned[0]["trust"] == "untrusted"


def test_file_write_is_denied(gateway):
    with pytest.raises(AccessDenied):
        gateway.write_file("welcome.txt", "overwritten")


def test_web_access_is_denied(gateway):
    with pytest.raises(AccessDenied):
        gateway.fetch_web("https://example.com")


def test_shell_access_is_denied(gateway):
    with pytest.raises(AccessDenied):
        gateway.execute_shell("whoami")


def test_audit_records_denied_operation(gateway):
    with pytest.raises(AccessDenied):
        gateway.fetch_web("https://example.com")

    records = [
        json.loads(line)
        for line in gateway.audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert records[-1]["decision"] == "DENY"
    assert records[-1]["action"] == "web_fetch"
