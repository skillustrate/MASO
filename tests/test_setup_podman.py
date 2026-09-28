"""
Unit and integration tests for Guided Podman Setup across common operating systems.
"""

import sys
from unittest.mock import MagicMock, patch
import pytest

from masa.sandbox.setup_podman import (
    build_sandbox_images,
    check_images_status,
    detect_os_info,
    execute_install_plan,
    get_install_plan,
    is_podman_installed,
    is_podman_rootless,
    run_guided_podman_setup,
)


class TestDetectOsInfo:
    def test_detect_ubuntu_debian(self):
        with patch("platform.system", return_value="Linux"), \
             patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open_file('ID=ubuntu\nNAME="Ubuntu"\nPRETTY_NAME="Ubuntu 22.04 LTS"')):
            info = detect_os_info()
            assert info["system"] == "Linux"
            assert info["distro_id"] == "ubuntu"
            assert info["pkg_manager"] == "apt-get"

    def test_detect_fedora_rhel(self):
        with patch("platform.system", return_value="Linux"), \
             patch("os.path.exists", return_value=True), \
             patch("shutil.which", return_value="/usr/bin/dnf"), \
             patch("builtins.open", mock_open_file('ID=fedora\nNAME="Fedora Linux"\nPRETTY_NAME="Fedora Linux 39"')):
            info = detect_os_info()
            assert info["distro_id"] == "fedora"
            assert info["pkg_manager"] == "dnf"

    def test_detect_arch_linux(self):
        with patch("platform.system", return_value="Linux"), \
             patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open_file('ID=arch\nNAME="Arch Linux"')):
            info = detect_os_info()
            assert info["distro_id"] == "arch"
            assert info["pkg_manager"] == "pacman"

    def test_detect_opensuse(self):
        with patch("platform.system", return_value="Linux"), \
             patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open_file('ID=opensuse-leap\nNAME="openSUSE Leap"')):
            info = detect_os_info()
            assert info["distro_id"] == "opensuse-leap"
            assert info["pkg_manager"] == "zypper"

    def test_detect_alpine(self):
        with patch("platform.system", return_value="Linux"), \
             patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open_file('ID=alpine\nNAME="Alpine Linux"')):
            info = detect_os_info()
            assert info["distro_id"] == "alpine"
            assert info["pkg_manager"] == "apk"

    def test_detect_macos_with_brew(self):
        with patch("platform.system", return_value="Darwin"), \
             patch("platform.mac_ver", return_value=("14.2.1", ("", "", ""), "arm64")), \
             patch("shutil.which", side_effect=lambda x: "/opt/homebrew/bin/brew" if x == "brew" else None):
            info = detect_os_info()
            assert info["system"] == "Darwin"
            assert info["pkg_manager"] == "brew"

    def test_detect_windows_winget(self):
        with patch("platform.system", return_value="Windows"), \
             patch("platform.version", return_value="10.0.22631"), \
             patch("shutil.which", side_effect=lambda x: "C:\\winget.exe" if x == "winget" else None):
            info = detect_os_info()
            assert info["system"] == "Windows"
            assert info["pkg_manager"] == "winget"


class TestInstallPlan:
    def test_apt_plan(self):
        plan = get_install_plan({"system": "Linux", "pkg_manager": "apt-get", "distro_name": "Ubuntu"})
        assert plan["supported"] is True
        assert "apt-get install -y podman" in plan["install_cmd_str"]

    def test_dnf_plan(self):
        plan = get_install_plan({"system": "Linux", "pkg_manager": "dnf", "distro_name": "Fedora"})
        assert plan["supported"] is True
        assert "dnf install -y podman" in plan["install_cmd_str"]

    def test_pacman_plan(self):
        plan = get_install_plan({"system": "Linux", "pkg_manager": "pacman", "distro_name": "Arch"})
        assert plan["supported"] is True
        assert "pacman -S --noconfirm podman" in plan["install_cmd_str"]

    def test_macos_brew_plan(self):
        plan = get_install_plan({"system": "Darwin", "pkg_manager": "brew", "distro_name": "macOS Sonoma"})
        assert plan["supported"] is True
        assert "brew install podman" in plan["install_cmd_str"]
        assert len(plan["post_install_commands"]) == 2
        assert plan["post_install_commands"][0] == ["podman", "machine", "init"]

    def test_windows_winget_plan(self):
        plan = get_install_plan({"system": "Windows", "pkg_manager": "winget", "distro_name": "Windows 11", "is_wsl": False})
        assert plan["supported"] is True
        assert "winget install RedHat.Podman" in plan["install_cmd_str"]

    def test_unsupported_os_plan(self):
        plan = get_install_plan({"system": "Solaris", "pkg_manager": "none", "distro_name": "Solaris"})
        assert plan["supported"] is False


class TestExecutionAndStatus:
    def test_is_podman_installed_true(self):
        with patch("shutil.which", return_value="/usr/bin/podman"):
            assert is_podman_installed() is True

    def test_is_podman_installed_false(self):
        with patch("shutil.which", return_value=None):
            assert is_podman_installed() is False

    def test_is_podman_rootless(self):
        with patch("masa.sandbox.setup_podman.is_podman_installed", return_value=True), \
             patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(stdout="true\n", returncode=0)
            assert is_podman_rootless() is True

            mock_sub.return_value = MagicMock(stdout="false\n", returncode=0)
            assert is_podman_rootless() is False

    def test_check_images_status(self):
        with patch("masa.sandbox.setup_podman.is_podman_installed", return_value=True), \
             patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(
                stdout="localhost/maso-skill-worker:v1.1\nlocalhost/maso-egress-proxy:v1.1\n",
                returncode=0
            )
            st = check_images_status()
            assert st["worker"] is True
            assert st["proxy"] is True

    def test_run_guided_podman_setup_already_installed(self):
        with patch("masa.sandbox.setup_podman.is_podman_installed", return_value=True), \
             patch("masa.sandbox.setup_podman.get_podman_version", return_value="podman 5.0.0"), \
             patch("masa.sandbox.setup_podman.is_podman_rootless", return_value=True), \
             patch("masa.sandbox.setup_podman.check_images_status", return_value={"worker": True, "proxy": True}):
            rc = run_guided_podman_setup(auto_confirm=True, skip_images=True)
            assert rc == 0

    def test_run_guided_podman_setup_not_installed_aborted(self):
        with patch("masa.sandbox.setup_podman.is_podman_installed", return_value=False), \
             patch("builtins.input", return_value="n"):
            rc = run_guided_podman_setup(auto_confirm=False, interactive=True)
            assert rc == 0

    def test_run_guided_podman_setup_not_installed_installed_success(self):
        install_state = {"installed": False}

        def fake_is_installed():
            return install_state["installed"]

        with patch("masa.sandbox.setup_podman.is_podman_installed", side_effect=fake_is_installed), \
             patch("masa.sandbox.setup_podman.execute_install_plan") as mock_exec, \
             patch("masa.sandbox.setup_podman.get_podman_version", return_value="podman 5.0.0"), \
             patch("masa.sandbox.setup_podman.is_podman_rootless", return_value=True):

            def fake_exec(plan):
                install_state["installed"] = True
                return True

            mock_exec.side_effect = fake_exec
            rc = run_guided_podman_setup(auto_confirm=True, skip_images=True)
            assert rc == 0
            assert mock_exec.called


class TestCliDispatch:
    def test_cli_setup_podman(self):
        from masa.framework import main
        with patch.object(sys, "argv", ["maso", "setup-podman", "--yes", "--skip-images"]), \
             patch("masa.sandbox.setup_podman.run_guided_podman_setup", return_value=0) as mock_setup, \
             pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        mock_setup.assert_called_once_with(auto_confirm=True, skip_images=True)

    def test_cli_setup_with_podman_flag(self):
        from masa.framework import main
        with patch.object(sys, "argv", ["maso", "setup", "--podman", "-y", "--skip-images"]), \
             patch("masa.sandbox.setup_podman.run_guided_podman_setup", return_value=0) as mock_setup, \
             pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        mock_setup.assert_called_once_with(auto_confirm=True, skip_images=True)


def mock_open_file(content: str):
    from unittest.mock import mock_open
    return mock_open(read_data=content)

