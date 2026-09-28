"""
Guided Podman Setup and Provisioning for MASO (v1.1.0).
Supports automated detection and guided setup for all major operating systems:
- Linux: Debian/Ubuntu, Fedora/RHEL/CentOS, Arch/Manjaro, openSUSE, Alpine, Void
- macOS: Homebrew + podman machine
- Windows: WSL2 (recommended) or native winget
"""

import os
import platform
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple


def is_wsl() -> bool:
    """Detect if running inside Windows Subsystem for Linux (WSL)."""
    if sys.platform != "linux":
        return False
    try:
        with open("/proc/version", "r", encoding="utf-8") as f:
            v = f.read().lower()
            return "microsoft" in v or "wsl" in v
    except Exception:
        return False


def detect_os_info() -> Dict[str, Any]:
    """Detect host operating system, distribution, and available package manager."""
    system = platform.system()
    info: Dict[str, Any] = {
        "system": system,
        "is_wsl": is_wsl(),
        "distro_id": "",
        "distro_name": "",
        "pkg_manager": "",
    }

    if system == "Linux":
        # Parse /etc/os-release if available
        os_release: Dict[str, str] = {}
        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    for line in f.read().splitlines():
                        line = line.strip()
                        if "=" in line and not line.startswith("#"):
                            k, v = line.split("=", 1)
                            os_release[k.strip()] = v.strip().strip('"\'')
            except Exception:
                pass

        distro_id = os_release.get("ID", "").lower()
        id_like = os_release.get("ID_LIKE", "").lower()
        info["distro_id"] = distro_id
        info["distro_name"] = os_release.get("PRETTY_NAME") or os_release.get("NAME") or "Linux"

        # Determine package manager based on distro and presence on PATH
        if distro_id in ["ubuntu", "debian", "pop", "mint", "kali", "elementary", "raspbian"] or "debian" in id_like or "ubuntu" in id_like:
            info["pkg_manager"] = "apt-get"
        elif distro_id in ["fedora", "rhel", "centos", "rocky", "almalinux", "amzn"] or "fedora" in id_like or "rhel" in id_like:
            info["pkg_manager"] = "dnf" if shutil.which("dnf") else "yum"
        elif distro_id in ["arch", "manjaro", "endeavouros"] or "arch" in id_like:
            info["pkg_manager"] = "pacman"
        elif distro_id in ["opensuse-leap", "opensuse-tumbleweed", "sles"] or "suse" in id_like:
            info["pkg_manager"] = "zypper"
        elif distro_id == "alpine":
            info["pkg_manager"] = "apk"
        elif distro_id == "void":
            info["pkg_manager"] = "xbps-install"
        else:
            # Fallback probe
            for pm in ["apt-get", "dnf", "yum", "pacman", "zypper", "apk"]:
                if shutil.which(pm):
                    info["pkg_manager"] = pm
                    break

    elif system == "Darwin":
        info["distro_name"] = f"macOS {platform.mac_ver()[0]}"
        if shutil.which("brew"):
            info["pkg_manager"] = "brew"
        else:
            info["pkg_manager"] = "none"

    elif system == "Windows":
        info["distro_name"] = f"Windows {platform.version()}"
        if shutil.which("winget"):
            info["pkg_manager"] = "winget"
        else:
            info["pkg_manager"] = "none"

    return info


def get_install_plan(os_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Generate the precise installation commands, post-install commands, and notes
    tailored to the detected operating system.
    """
    if os_info is None:
        os_info = detect_os_info()

    system = os_info["system"]
    pkg_manager = os_info["pkg_manager"]
    distro_name = os_info["distro_name"]

    plan: Dict[str, Any] = {
        "supported": True,
        "platform_title": distro_name or system,
        "pkg_manager": pkg_manager,
        "install_command": [],
        "install_cmd_str": "",
        "post_install_commands": [],
        "notes": [],
    }

    if system == "Linux":
        if pkg_manager == "apt-get":
            plan["install_command"] = ["sudo", "apt-get", "update", "&&", "sudo", "apt-get", "install", "-y", "podman"]
            plan["install_cmd_str"] = "sudo apt-get update && sudo apt-get install -y podman"
            plan["notes"] = [
                "Podman will be installed natively from official Ubuntu/Debian repositories.",
                "Rootless user namespaces (/etc/subuid, /etc/subgid) are typically initialized automatically."
            ]
        elif pkg_manager in ["dnf", "yum"]:
            plan["install_command"] = ["sudo", pkg_manager, "install", "-y", "podman"]
            plan["install_cmd_str"] = f"sudo {pkg_manager} install -y podman"
            plan["notes"] = [
                "Podman is maintained natively by Red Hat / Fedora / CentOS.",
                "Full rootless support and cgroups v2 are enabled by default."
            ]
        elif pkg_manager == "pacman":
            plan["install_command"] = ["sudo", "pacman", "-S", "--noconfirm", "podman"]
            plan["install_cmd_str"] = "sudo pacman -S --noconfirm podman"
            plan["notes"] = [
                "Arch Linux provides Podman in the official extra repository.",
                "Ensure subuid/subgid are configured for your user if you encounter unprivileged mapping issues."
            ]
        elif pkg_manager == "zypper":
            plan["install_command"] = ["sudo", "zypper", "install", "-y", "podman"]
            plan["install_cmd_str"] = "sudo zypper install -y podman"
            plan["notes"] = ["Podman is packaged natively for openSUSE Leap & Tumbleweed."]
        elif pkg_manager == "apk":
            plan["install_command"] = ["sudo", "apk", "add", "podman"]
            plan["install_cmd_str"] = "sudo apk add podman"
            plan["notes"] = ["Alpine Linux package."]
        elif pkg_manager == "xbps-install":
            plan["install_command"] = ["sudo", "xbps-install", "-Sy", "podman"]
            plan["install_cmd_str"] = "sudo xbps-install -Sy podman"
        else:
            plan["supported"] = False
            plan["install_cmd_str"] = "Please install Podman via your system package manager or download from https://podman.io"
            plan["notes"] = ["No supported package manager detected automatically on Linux."]

    elif system == "Darwin":
        if pkg_manager == "brew":
            plan["install_command"] = ["brew", "install", "podman"]
            plan["install_cmd_str"] = "brew install podman"
            plan["post_install_commands"] = [
                ["podman", "machine", "init"],
                ["podman", "machine", "start"],
            ]
            plan["notes"] = [
                "On macOS, Podman runs containers inside a lightweight rootless Linux VM managed by 'podman machine'.",
                "After installation, 'podman machine init' and 'podman machine start' will initialize the VM."
            ]
        else:
            plan["supported"] = False
            plan["install_cmd_str"] = '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" && brew install podman'
            plan["notes"] = [
                "Homebrew was not found on PATH.",
                "Install Homebrew first, then run 'brew install podman'."
            ]

    elif system == "Windows":
        if os_info.get("is_wsl"):
            plan["install_cmd_str"] = "sudo apt-get update && sudo apt-get install -y podman"
            plan["notes"] = ["Running inside WSL2. Native Linux package manager will be used."]
        elif pkg_manager == "winget":
            plan["install_command"] = ["winget", "install", "RedHat.Podman", "--accept-package-agreements", "--accept-source-agreements"]
            plan["install_cmd_str"] = "winget install RedHat.Podman"
            plan["post_install_commands"] = [
                ["podman", "machine", "init"],
                ["podman", "machine", "start"]
            ]
            plan["notes"] = [
                "Podman for Windows uses WSL2 backend to provide native Linux container isolation.",
                "Requires 'podman machine init' and 'podman machine start' after install."
            ]
        else:
            plan["supported"] = False
            plan["install_cmd_str"] = "winget install RedHat.Podman OR install inside WSL2 (Ubuntu)"
            plan["notes"] = ["Recommended: Run MASO inside WSL2 (Ubuntu) for optimal rootless performance."]

    else:
        plan["supported"] = False
        plan["install_cmd_str"] = "Visit https://podman.io/getting-started/installation"
        plan["notes"] = [f"Unsupported operating system: {system}"]

    return plan


def is_podman_installed() -> bool:
    """Check if the 'podman' executable is present on PATH."""
    return shutil.which("podman") is not None


def get_podman_version() -> str:
    """Retrieve the installed Podman version string."""
    try:
        res = subprocess.run(["podman", "--version"], capture_output=True, text=True, check=False)
        return res.stdout.strip()
    except Exception:
        return "unknown"


def is_podman_rootless() -> bool:
    """Check if Podman is configured to run rootless."""
    if not is_podman_installed():
        return False
    try:
        res = subprocess.run(
            ["podman", "info", "--format", "{{.Host.Security.Rootless}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        return res.stdout.strip().lower() == "true"
    except Exception:
        return False


def check_images_status() -> Dict[str, bool]:
    """Check whether the necessary MASO sandbox worker and egress images exist locally."""
    status = {"worker": False, "proxy": False}
    if not is_podman_installed():
        return status
    try:
        res = subprocess.run(
            ["podman", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5
        )
        images = res.stdout.splitlines()
        for img in images:
            if "maso-skill-worker" in img:
                status["worker"] = True
            if "maso-egress-proxy" in img:
                status["proxy"] = True
    except Exception:
        pass
    return status


def build_sandbox_images(project_root: Optional[str] = None) -> Tuple[bool, str]:
    """
    Build and tag the MASO worker and proxy images using Podman.
    """
    if project_root is None:
        # Determine root containing Containerfile.worker
        curr = os.path.dirname(os.path.abspath(__file__))
        while curr and curr != os.path.dirname(curr):
            if os.path.exists(os.path.join(curr, "Containerfile.worker")):
                project_root = curr
                break
            curr = os.path.dirname(curr)
        if not project_root:
            project_root = os.getcwd()

    worker_file = os.path.join(project_root, "Containerfile.worker")
    proxy_file = os.path.join(project_root, "Containerfile.proxy")

    if not os.path.exists(worker_file):
        return False, f"Worker Containerfile not found at '{worker_file}'"

    print("\n🔨 Building MASO Worker container image ('maso-skill-worker:v1.1')...")
    res1 = subprocess.run(
        [
            "podman", "build",
            "-t", "maso-skill-worker:v1.1",
            "-t", "maso-skill-worker:v1.1.0",
            "-f", worker_file,
            project_root,
        ],
        check=False
    )
    if res1.returncode != 0:
        return False, f"Failed to build maso-skill-worker (exit code {res1.returncode})"

    if os.path.exists(proxy_file):
        print("\n🔨 Building MASO Egress Proxy container image ('maso-egress-proxy:v1.1')...")
        res2 = subprocess.run(
            [
                "podman", "build",
                "-t", "maso-egress-proxy:v1.1",
                "-t", "maso-egress-proxy:v1.1.0",
                "-f", proxy_file,
                project_root,
            ],
            check=False
        )
        if res2.returncode != 0:
            return False, f"Failed to build maso-egress-proxy (exit code {res2.returncode})"

    return True, "All MASO sandbox images built successfully."


def execute_install_plan(plan: Dict[str, Any]) -> bool:
    """Execute the installation command and any post-install hooks."""
    cmd_str = plan.get("install_cmd_str")
    if not cmd_str:
        print("❌ Error: No installation command available.")
        return False

    print(f"\n🚀 Running installation command:\n   {cmd_str}\n")
    try:
        # Run in shell so pipelines/&& work seamlessly
        res = subprocess.run(cmd_str, shell=True, check=False)
        if res.returncode != 0:
            print(f"❌ Installation failed with exit code {res.returncode}")
            return False

        # Execute post-install commands (e.g. for macOS / Windows VM init)
        for post_cmd in plan.get("post_install_commands", []):
            cmd_disp = " ".join(post_cmd)
            print(f"\n⚙️ Running post-installation setup: {cmd_disp}...")
            post_res = subprocess.run(post_cmd, check=False)
            if post_res.returncode != 0:
                print(f"⚠️ Warning: Post-install step '{cmd_disp}' returned {post_res.returncode}")

        return True
    except Exception as e:
        print(f"❌ Exception occurred during installation: {e}")
        return False


def run_guided_podman_setup(
    auto_confirm: bool = False,
    skip_images: bool = False,
    interactive: bool = True
) -> int:
    """
    Main interactive entry point for guided Podman setup across all operating systems.
    """
    print("======================================================================")
    print(" 🛡️  MASO Guided Podman Sandbox Setup (Multi-OS)")
    print("======================================================================")

    os_info = detect_os_info()
    plan = get_install_plan(os_info)

    print(f"Platform:           {os_info['distro_name'] or os_info['system']}")
    print(f"Package Manager:    {os_info['pkg_manager'] or 'None detected'}")
    if os_info.get("is_wsl"):
        print("Subsystem:          WSL2 (Windows Subsystem for Linux)")

    # 1. Check if already installed
    if is_podman_installed():
        ver = get_podman_version()
        rootless = is_podman_rootless()
        print(f"\n✅ Podman is already installed on this machine!")
        print(f"   Version:    {ver}")
        print(f"   Rootless:   {'Yes (Active)' if rootless else 'No (Root-bound / Needs subuid setup)'}")

        # Check images
        img_status = check_images_status()
        print("\nContainer Image Status:")
        print(f"   maso-skill-worker:v1.1:  {'✅ Present' if img_status['worker'] else '❌ Missing'}")
        print(f"   maso-egress-proxy:v1.1:  {'✅ Present' if img_status['proxy'] else '❌ Missing'}")

        if not img_status["worker"] or not img_status["proxy"]:
            if not skip_images:
                prompt_text = "Would you like MASO to build the sandbox container images now? [Y/n]: "
                if auto_confirm or not interactive:
                    confirm_build = True
                else:
                    ans = input(prompt_text).strip().lower()
                    confirm_build = ans in ["", "y", "yes"]

                if confirm_build:
                    ok, msg = build_sandbox_images()
                    if ok:
                        print(f"\n✅ {msg}")
                    else:
                        print(f"\n❌ {msg}")
                        return 1
            else:
                print("Skipping image build (--skip-images passed).")

        print("\n✨ Sandbox environment is fully ready for 'maso run'!")
        return 0

    # 2. Podman is NOT installed
    print("\n⚠️  Podman is NOT currently installed.")
    print("MASO requires rootless Podman to execute untrusted specialist skills in an unprivileged,")
    print("isolated container boundary (REVISED §7.2).\n")

    if not plan["supported"]:
        print(f"❌ Automated installation is not supported for your environment ({os_info['system']}).")
        print(f"   Please follow the official Podman installation guide:")
        print(f"   👉 https://podman.io/getting-started/installation\n")
        return 1

    print("Proposed Installation Plan:")
    print(f"   Command: {plan['install_cmd_str']}")
    for note in plan["notes"]:
        print(f"   Note:    {note}")

    # Prompt user
    if auto_confirm:
        proceed = True
    elif not interactive:
        print("\nError: Non-interactive environment and --yes was not provided. Aborting.")
        return 1
    else:
        print("")
        ans = input("Would you like MASO to install Podman now? [y/N]: ").strip().lower()
        proceed = ans in ["y", "yes"]

    if not proceed:
        print("\nInstallation aborted by user.")
        print("You can manually run:")
        print(f"   {plan['install_cmd_str']}\n")
        return 0

    # Execute install
    success = execute_install_plan(plan)
    if not success:
        return 1

    # Verify newly installed podman
    if not is_podman_installed():
        print("❌ 'podman' executable was not found on PATH after installation.")
        print("   You may need to open a new terminal session or reload your shell profile.")
        return 1

    ver = get_podman_version()
    rootless = is_podman_rootless()
    print(f"\n🎉 Podman successfully installed! ({ver})")
    print(f"   Rootless mode: {'Active' if rootless else 'Needs subuid/subgid verification'}")

    # Build container images
    if not skip_images:
        prompt_text = "\nWould you like MASO to build the sandbox container images now? [Y/n]: "
        if auto_confirm or not interactive:
            confirm_build = True
        else:
            ans = input(prompt_text).strip().lower()
            confirm_build = ans in ["", "y", "yes"]

        if confirm_build:
            ok, msg = build_sandbox_images()
            if ok:
                print(f"\n✅ {msg}")
            else:
                print(f"\n❌ {msg}")
                return 1

    print("\n✨ Podman setup complete! You are ready to run MASO with full container isolation.")
    print("   Test with: maso status")
    print("   Run with:  maso run \"<your objective>\"\n")
    return 0
