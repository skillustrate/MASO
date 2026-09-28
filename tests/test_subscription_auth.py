import asyncio
import json
import os
import tempfile

import pytest

from masa.framework import SubscriptionManager


def test_subscription_manager_initialization():
    mgr = SubscriptionManager(os.getcwd())
    assert set(["agy", "claude", "codex", "bionic", "local"]).issubset(
        set(mgr.SUPPORTED_PROVIDERS)
    )


def test_find_executable_helper():
    path = SubscriptionManager.find_executable("sh")
    assert path is not None
    assert os.path.exists(path)

    non_existent = SubscriptionManager.find_executable("non_existent_binary_xyz_123")
    assert non_existent is None


def test_get_all_statuses_structure():
    mgr = SubscriptionManager(os.getcwd())
    statuses = mgr.get_all_statuses()
    for prov in ["agy", "claude", "codex", "local", "bionic"]:
        assert prov in statuses
        assert "status" in statuses[prov]
        assert "details" in statuses[prov]
        assert "installed" in statuses[prov]


def test_bionic_session_file_detection(monkeypatch):
    import urllib.request
    from urllib.error import URLError

    def mock_urlopen(*args, **kwargs):
        raise URLError("Mock network offline")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)
    monkeypatch.setattr(
        SubscriptionManager, "find_executable", lambda *args, **kwargs: None
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        from masa import framework

        orig_home = framework.MASA_HOME_DIR
        try:
            framework.MASA_HOME_DIR = tmpdir
            mgr = SubscriptionManager(os.getcwd())

            # Initially not configured
            res1 = mgr.check_bionic_status()
            assert res1["status"] == "NOT CONFIGURED" or res1["installed"] is False

            # Create mock session file
            session_file = os.path.join(tmpdir, "bionic_session.json")
            with open(session_file, "w") as f:
                f.write(
                    '{"portal_url": "https://test.bionic.internal", "status": "ACTIVE"}'
                )

            res2 = mgr.check_bionic_status()
            assert res2["status"] == "ACTIVE"
            assert "https://test.bionic.internal" in res2["details"]
        finally:
            framework.MASA_HOME_DIR = orig_home


def test_bionic_ai_rig_detection(monkeypatch):
    import urllib.request

    class MockResponse:
        status = 200

        def read(self):
            return b'{"data": [{"id": "mock/model-1"}]}'

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    def mock_urlopen(req, *args, **kwargs):
        return MockResponse()

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    with tempfile.TemporaryDirectory() as tmpdir:
        from masa import framework

        orig_home = framework.MASA_HOME_DIR
        try:
            framework.MASA_HOME_DIR = tmpdir
            mgr = SubscriptionManager(os.getcwd())
            res = mgr.check_bionic_status()
            assert res["status"] == "ACTIVE"
            assert "mock/model-1" in res["details"]
        finally:
            framework.MASA_HOME_DIR = orig_home


def test_trust_directory_configuration():
    with tempfile.TemporaryDirectory() as tmp_home:
        # Patch home directory
        orig_home = os.environ.get("HOME")
        os.environ["HOME"] = tmp_home
        try:
            mgr = SubscriptionManager(tmp_home)
            target_folder = os.path.join(tmp_home, "my_trusted_project")
            os.makedirs(target_folder, exist_ok=True)

            res = mgr.trust_directory(target_folder)
            assert res["claude"] is True

            # Verify Claude Code JSON
            claude_json_path = os.path.join(tmp_home, ".claude.json")
            assert os.path.exists(claude_json_path)
            with open(claude_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert target_folder in data["projects"]
            assert data["projects"][target_folder]["hasTrustDialogAccepted"] is True
        finally:
            if orig_home:
                os.environ["HOME"] = orig_home


def test_query_local_models(monkeypatch):
    import urllib.request

    class MockResponse:
        status = 200

        def read(self):
            return b'{"data": [{"id": "gpt-oss-20b"}, {"id": "phi-4"}]}'

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    def mock_urlopen(req, *args, **kwargs):
        return MockResponse()

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)
    models = SubscriptionManager.query_local_models("localhost", 1234)
    assert models == ["gpt-oss-20b", "phi-4"]


def test_custom_local_model_configuration():
    with tempfile.TemporaryDirectory() as tmpdir:
        from masa import framework

        orig_home = framework.MASA_HOME_DIR
        try:
            framework.MASA_HOME_DIR = tmpdir
            mgr = SubscriptionManager(os.getcwd())

            cfg_file = os.path.join(tmpdir, "local_model.json")
            with open(cfg_file, "w") as f:
                json.dump(
                    {
                        "provider": "local",
                        "name": "LM Studio",
                        "host": "localhost",
                        "port": 1234,
                        "selected_model": "custom-model-abc",
                        "status": "ACTIVE",
                    },
                    f,
                )

            st = mgr.check_local_status()
            assert st["installed"] is True
            assert st["status"] == "ACTIVE"
            assert st["name"] == "LM Studio"
            assert "custom-model-abc" in st["details"]
        finally:
            framework.MASA_HOME_DIR = orig_home
