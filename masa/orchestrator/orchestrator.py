"""
Multi-Agent Scaffolding Architecture (MASA / MASO) Orchestrator.
Modular orchestration engine implementing the Super-Engage-Signoff pattern.
"""

import asyncio
import json
import logging
import os
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from masa.broker import TaskBroker
from masa.crypto import ConfigCrypto, SensitiveDataFilter
from masa.evals import AuditorAssertionEngine, ContentSanitizer

logger = logging.getLogger("MASAOrchestrator")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    handler.addFilter(SensitiveDataFilter())
    logger.addHandler(handler)

USER_CONFIG_PATH = os.path.expanduser("~/.masa_user_config.json")
MASA_HOME_DIR = os.path.expanduser("~/.masa")


class RetryPolicy:
    """Exponential backoff retry policy with jitter."""

    def __init__(
        self, max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 10.0
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay

    async def execute(self, coro_func, *args, **kwargs) -> Any:
        import random

        retries = 0
        while True:
            try:
                return await coro_func(*args, **kwargs)
            except Exception as e:
                retries += 1
                if retries > self.max_retries:
                    raise e
                delay = min(self.max_delay, self.base_delay * (2 ** (retries - 1)))
                jitter = random.uniform(0, 0.1 * delay)
                await asyncio.sleep(delay + jitter)


class MetaAuditor:
    """Meta-auditor that sanity-checks signoff agent evaluations to prevent forged PASS verdicts."""

    @staticmethod
    def sanity_check(eval_result: dict, file_to_eval: str) -> dict:
        if eval_result.get("passed") is True:
            try:
                with open(file_to_eval, "r", encoding="utf-8") as f:
                    content = f.read()
                    if "SUCCESS" not in content and '"verdict": "PASS"' not in content:
                        eval_result["passed"] = False
                        eval_result["verdict"] = "FAIL"
                        eval_result.setdefault("failures_checklist", []).append(
                            "MetaAuditor: Inconsistent PASS detected."
                        )
            except Exception:
                pass
        return eval_result


class TelemetryEventBus:
    """In-memory event bus for agent telemetry."""

    _queue = None

    @classmethod
    def get_queue(cls):
        if cls._queue is None:
            cls._queue = asyncio.Queue()
        return cls._queue

    @classmethod
    async def publish(cls, topic: str, payload: dict):
        await cls.get_queue().put({"topic": topic, "payload": payload})

    @classmethod
    async def process_events(cls):
        q = cls.get_queue()
        while not q.empty():
            event = await q.get()
            logger.info(
                f"[EventBus] {event['topic']} - Task {event['payload'].get('task_id', 'unknown')}"
            )


class SubscriptionManager:
    """Manages CLI subscriptions, local AI rigs, and directory trust."""

    SUPPORTED_PROVIDERS = ["agy", "claude", "codex", "bionic", "local"]

    def __init__(self, root_dir: str = "."):
        self.root_dir = os.path.abspath(root_dir)
        self.scripts_dir = os.path.join(self.root_dir, "scripts")

    def _get_masa_home(self) -> str:
        try:
            import masa.framework as mf

            return getattr(mf, "MASA_HOME_DIR", MASA_HOME_DIR)
        except Exception:
            return MASA_HOME_DIR

    @staticmethod
    def find_executable(name: str) -> Optional[str]:
        import shutil

        found = shutil.which(name)
        if found:
            return found
        for user_dir in [
            "~/.local/bin",
            "~/.lmstudio/bin",
            "/usr/local/bin",
            "/opt/homebrew/bin",
        ]:
            candidate = os.path.expanduser(f"{user_dir}/{name}")
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return None

    @staticmethod
    def query_local_models(
        host: str = "localhost", port: int = 1234, timeout: float = 2.0
    ) -> List[str]:
        urls = [
            f"http://{host}:{port}/v1/models",
            f"http://{host}:{port}/models",
            f"http://{host}:{port}/api/tags",
        ]
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "MASA"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        raw = resp.read().decode("utf-8")
                        data = json.loads(raw)
                        models = []
                        if "data" in data and isinstance(data["data"], list):
                            models = [
                                m.get("id")
                                for m in data["data"]
                                if isinstance(m, dict) and m.get("id")
                            ]
                        elif "models" in data and isinstance(data["models"], list):
                            models = [
                                m.get("name") or m.get("model")
                                for m in data["models"]
                                if isinstance(m, dict)
                            ]
                        if models:
                            return models
            except Exception:
                continue
        return []

    def check_bionic_status(self) -> Dict[str, Any]:
        masa_home = self._get_masa_home()
        session_file = os.path.join(masa_home, "bionic_session.json")
        if os.path.exists(session_file):
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                portal = data.get("portal_url", "https://bionic.internal")
                return {
                    "status": data.get("status", "ACTIVE"),
                    "details": f"Portal: {portal}",
                    "installed": True,
                }
            except Exception as e:
                logger.debug(f"Failed to read bionic session: {e}")

        bionic_host = os.environ.get("BIONIC_HOST", "192.168.0.213")
        try:
            url = f"http://{bionic_host}:1234/v1/models"
            req = urllib.request.Request(url, headers={"User-Agent": "MASA"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    models = []
                    if "data" in payload and isinstance(payload["data"], list):
                        models = [
                            m.get("id")
                            for m in payload["data"]
                            if isinstance(m, dict) and m.get("id")
                        ]
                    if models:
                        return {
                            "status": "ACTIVE",
                            "details": f"AI Rig ({bionic_host}:1234) | Model: {models[0]}",
                            "installed": True,
                        }
        except Exception:
            pass

        bionic_bin = self.find_executable("bionic")
        if bionic_bin:
            return {
                "status": "INSTALLED",
                "details": "Enterprise CLI",
                "installed": True,
            }

        return {
            "status": "NOT CONFIGURED",
            "details": "Run 'masa login bionic' or configure AI Rig",
            "installed": False,
        }

    def check_local_status(self) -> Dict[str, Any]:
        masa_home = self._get_masa_home()
        cfg_file = os.path.join(masa_home, "local_model.json")
        if os.path.exists(cfg_file):
            try:
                with open(cfg_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return {
                    "installed": True,
                    "status": data.get("status", "ACTIVE"),
                    "name": data.get("name", "LM Studio"),
                    "details": f"Model: {data.get('selected_model', 'default')}",
                }
            except Exception:
                pass
        return {
            "installed": False,
            "status": "NOT CONFIGURED",
            "name": "LOCAL AI",
            "details": "Run 'masa setup' or 'masa setup-local'",
        }

    def get_all_statuses(self) -> Dict[str, Dict[str, Any]]:
        statuses = {}
        agy_bin = self.find_executable("agy")
        statuses["agy"] = {
            "status": "INSTALLED" if agy_bin else "NOT FOUND",
            "details": agy_bin or "Install via agy setup",
            "installed": bool(agy_bin),
        }
        claude_bin = self.find_executable("claude")
        statuses["claude"] = {
            "status": "INSTALLED" if claude_bin else "NOT FOUND",
            "details": claude_bin or "npm install -g @anthropic-ai/claude-code",
            "installed": bool(claude_bin),
        }
        codex_bin = self.find_executable("codex")
        gh_bin = self.find_executable("gh")
        statuses["codex"] = {
            "status": (
                "ACTIVE" if codex_bin else ("INSTALLED" if gh_bin else "NOT FOUND")
            ),
            "details": codex_bin or (gh_bin or "Install Codex CLI ('codex')"),
            "installed": bool(codex_bin or gh_bin),
        }
        statuses["local"] = self.check_local_status()
        statuses["bionic"] = self.check_bionic_status()
        return statuses

    def trust_directory(self, target_folder: str = ".") -> Dict[str, bool]:
        abs_target = os.path.abspath(target_folder)
        home_dir = os.environ.get("HOME", os.path.expanduser("~"))
        res = {"claude": False, "agy": False}

        # 1. Claude Code (~/.claude.json)
        claude_json_path = os.path.join(home_dir, ".claude.json")
        try:
            data = {}
            if os.path.exists(claude_json_path):
                with open(claude_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            projects = data.setdefault("projects", {})
            proj = projects.setdefault(abs_target, {})
            proj["hasTrustDialogAccepted"] = True
            with open(claude_json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            res["claude"] = True
        except Exception as e:
            logger.warning(f"Failed to update Claude trust config: {e}")

        # 2. Antigravity AGY (~/.gemini/antigravity-cli/settings.json)
        agy_dir = os.path.join(home_dir, ".gemini", "antigravity-cli")
        agy_settings_path = os.path.join(agy_dir, "settings.json")
        try:
            os.makedirs(agy_dir, exist_ok=True)
            data = {}
            if os.path.exists(agy_settings_path):
                with open(agy_settings_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            trusted = data.setdefault("trustedWorkspaces", [])
            if abs_target not in trusted:
                trusted.append(abs_target)
            with open(agy_settings_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            res["agy"] = True
        except Exception as e:
            logger.warning(f"Failed to update AGY settings: {e}")

        return res


class MultiAgentFramework:
    """
    Multi-Agent Scaffolding Architecture (MASA / MASO) Orchestrator.
    Super-Engage-Signoff workflow pattern.
    """

    def __init__(self, root_dir: str = "."):
        self.root_dir = os.path.abspath(root_dir)
        self.skills_dir = os.path.join(self.root_dir, "skills")
        self.mailboxes_dir = os.path.join(self.root_dir, "mailboxes")
        self.evals_dir = os.path.join(self.root_dir, "evals")
        self.core_dir = os.path.join(self.root_dir, "core")
        self.required_dirs = [
            "masa/core",
            "masa/skills/sample_skill",
            "masa/evals",
            "mailboxes",
        ]
        self.subscriptions = SubscriptionManager(self.root_dir)
        self.user_config = self._load_user_config()
        self.base_config = self._load_base_config()

    def _user_config_path(self) -> str:
        try:
            import masa.framework as mf

            return getattr(mf, "USER_CONFIG_PATH", USER_CONFIG_PATH)
        except Exception:
            return USER_CONFIG_PATH

    def base_config_path(self) -> str:
        candidates = [
            os.path.join(self.root_dir, "masa", "core", "config.json"),
            os.path.join(self.core_dir, "config.json"),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return candidates[0]

    def _load_base_config(self) -> Dict[str, Any]:
        path = self.base_config_path()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load base config: {e}")
        return {}

    def _load_user_config(self) -> Dict[str, Any]:
        path = self._user_config_path()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                decrypted = ConfigCrypto.decrypt(content)
                return json.loads(decrypted)
            except Exception as e:
                logger.debug(f"Failed to load/decrypt user config: {e}")
        return {}

    def setup_user_profile(
        self, super_model: str, signoff_model: str, engage_models: List[str]
    ):
        config = {
            "user_preferences": {
                "super": super_model,
                "signoff": signoff_model,
                "engage_pool": engage_models,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        }
        cfg_str = json.dumps(config, indent=2)
        encrypted_payload = ConfigCrypto.encrypt(cfg_str)
        target_path = Path(self._user_config_path())
        target_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(target_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(encrypted_payload)
            target_path.chmod(0o600)
            self.user_config = config
        except Exception as e:
            logger.error(f"Error saving profile: {e}")

    def initialize_environment(self):
        for folder in self.required_dirs:
            os.makedirs(os.path.join(self.root_dir, folder), exist_ok=True)

    def get_registered_skills(self) -> Dict[str, str]:
        package_skill = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__), "..", "skills", "sample_skill", "skill.py"
            )
        )
        candidates = [
            os.path.join(self.root_dir, "masa", "skills", "sample_skill", "skill.py"),
            os.path.join(self.root_dir, "skills", "sample_skill", "skill.py"),
            package_skill,
        ]
        for c in candidates:
            if os.path.exists(c):
                return {"data_refinement": c}
        return {"data_refinement": candidates[0]}

    def resolve_and_validate_skill(self, skill_name_or_path: str) -> str:
        registered = self.get_registered_skills()
        raw_target = registered.get(skill_name_or_path, skill_name_or_path)
        target_path = os.path.abspath(raw_target)

        package_skills_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "skills")
        )
        allowed_roots = [
            os.path.abspath(os.path.join(self.root_dir, "skills")),
            os.path.abspath(os.path.join(self.root_dir, "masa", "skills")),
            package_skills_root,
        ]

        real_target = os.path.realpath(target_path)
        is_safe = False
        for root in allowed_roots:
            try:
                if (
                    os.path.exists(root)
                    and os.path.commonpath([root, real_target]) == root
                ):
                    is_safe = True
                    break
            except ValueError:
                continue

        if not is_safe:
            raise PermissionError(
                f"Security Exception: Path traversal attempt '{skill_name_or_path}'"
            )

        if not os.path.isfile(real_target):
            raise FileNotFoundError(f"Skill not found: '{skill_name_or_path}'")

        return real_target

    def skill_script(self, skill_name: str = "data_refinement") -> str:
        return self.resolve_and_validate_skill(skill_name)

    def eval_script(self) -> str:
        package_eval = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "evals", "eval_template.py")
        )
        candidates = [
            os.path.join(self.root_dir, "masa", "evals", "eval_template.py"),
            os.path.join(self.evals_dir, "eval_template.py"),
            package_eval,
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return candidates[0]

    def mailbox_path(self) -> str:
        return os.path.join(self.mailboxes_dir, "main_task.md")

    def write_objective(self, objective: str, run_id: str):
        self.initialize_environment()
        os.makedirs(self.mailboxes_dir, exist_ok=True)
        with open(self.mailbox_path(), "w", encoding="utf-8") as f:
            f.write(f"# Main Task Objective\n\nRun ID: {run_id}\n\n{objective}\n")

    def _sanitize_environment(self) -> Dict[str, str]:
        SAFE_ENV_VARS = {
            "PATH",
            "PYTHONPATH",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TERM",
            "HOME",
            "USER",
            "TMPDIR",
            "TEMP",
            "TMP",
            "VIRTUAL_ENV",
            "MASA_HOME_DIR",
            "MASA_KEY_DIR",
            "PWD",
            "SHLVL",
        }
        SENSITIVE_KEYWORDS = [
            "SECRET",
            "KEY",
            "TOKEN",
            "PASSWORD",
            "AUTH",
            "CREDENTIAL",
            "PRIVATE",
        ]

        clean_env = {}
        for k, v in os.environ.items():
            if k in SAFE_ENV_VARS:
                if not any(kw in k.upper() for kw in SENSITIVE_KEYWORDS):
                    clean_env[k] = v

        python_paths = [self.root_dir, os.path.join(self.root_dir, "masa")]
        if "PYTHONPATH" in clean_env:
            python_paths.append(clean_env["PYTHONPATH"])
        clean_env["PYTHONPATH"] = ":".join(python_paths)

        if "PATH" not in clean_env and "PATH" in os.environ:
            clean_env["PATH"] = os.environ["PATH"]

        return clean_env

    async def dispatch_skill(
        self,
        skill_identifier: str,
        input_data: Dict[str, Any],
        model_name: str,
        task_id: str = "default_task",
    ) -> Dict[str, Any]:
        input_json = json.dumps(input_data)
        if len(input_json.encode("utf-8")) > 10 * 1024 * 1024:
            return {
                "status": "FAILURE",
                "task_id": task_id,
                "data_table": "",
                "metrics": {"rows_processed": 0, "error_count": 1},
                "audit_trail": ["Payload exceeded 10MB limit."],
                "errors": ["InputPayloadTooLarge"],
            }

        skill_path = self.resolve_and_validate_skill(skill_identifier)
        clean_env = self._sanitize_environment()

        try:
            cmd = [sys.executable, skill_path, "--task_id", task_id]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=clean_env,
                cwd=self.root_dir,
            )
            stdout, stderr = await proc.communicate(input=input_json.encode("utf-8"))
            out_str = stdout.decode("utf-8").strip()
            if proc.returncode != 0:
                try:
                    return json.loads(out_str)
                except Exception:
                    return {
                        "status": "FAILURE",
                        "task_id": task_id,
                        "data_table": "",
                        "metrics": {"rows_processed": 0, "error_count": 1},
                        "audit_trail": ["Subprocess returned non-zero code."],
                        "errors": [
                            stderr.decode("utf-8").strip()
                            or f"Exited with code {proc.returncode}"
                        ],
                    }
            return json.loads(out_str)
        except Exception as e:
            return {
                "status": "FAILURE",
                "task_id": task_id,
                "data_table": "",
                "metrics": {"rows_processed": 0, "error_count": 1},
                "audit_trail": [f"Execution failed: {e}"],
                "errors": [str(e)],
            }

    async def decompose_objective(
        self,
        objective: str,
        engage_pool: List[str],
        input_data: Optional[Dict[str, Any]] = None,
        num_agents: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        if (
            input_data is not None
            and isinstance(input_data, dict)
            and "raw_data" in input_data
        ):
            raw_items = input_data["raw_data"]
        elif input_data is None:
            raw_items = [
                {"id": 101, "sensor": "temp", "reading": 22.5},
                {"id": 102, "sensor": "hum", "reading": 45.0},
            ]
        else:
            raw_items = [
                {"id": 101, "sensor": "temp", "reading": 22.5},
                {"id": 102, "sensor": "hum", "reading": 45.0},
            ]

        if not isinstance(raw_items, list) or len(raw_items) == 0:
            return []

        if num_agents is not None:
            n = max(1, min(num_agents, len(raw_items)))
        else:
            n = max(1, len(raw_items) // 2)

        chunk_size = (len(raw_items) + n - 1) // n
        sub_tasks = []
        for i in range(n):
            chunk = raw_items[i * chunk_size : (i + 1) * chunk_size]
            if not chunk:
                continue
            sub_tasks.append(
                {
                    "task_id": f"subtask-{i+1:03d}",
                    "skill": "data_refinement",
                    "model": engage_pool[i % len(engage_pool)],
                    "description": f"Partition {i+1}",
                    "input_data": {"raw_data": chunk},
                }
            )
        return sub_tasks

    async def execute_engage_agents(
        self, sub_tasks: List[Dict[str, Any]], run_mailbox_dir: str
    ) -> List[Dict[str, Any]]:
        results = []

        async def _execute_single(task: Dict[str, Any]) -> Dict[str, Any]:
            task_id = task["task_id"]
            task_dir = os.path.join(run_mailbox_dir, "tasks", task_id)
            os.makedirs(task_dir, exist_ok=True)
            skill_output = await self.dispatch_skill(
                task["skill"], task["input_data"], task["model"], task_id
            )
            out_file = os.path.join(task_dir, "output.json")
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(skill_output, f, indent=2)
            return {
                "task_id": task_id,
                "model": task["model"],
                "skill": task["skill"],
                "result": skill_output,
            }

        try:
            tasks_coros = [_execute_single(t) for t in sub_tasks]
            results = await asyncio.gather(*tasks_coros)
        except Exception as e:
            logger.warning(
                f"Parallel worker glitch ({e}); engaging sequential fallback..."
            )
            results = []
            for t in sub_tasks:
                results.append(await _execute_single(t))

        results_list = list(results)
        results_list.sort(key=lambda r: r["task_id"])
        return results_list

    def synthesize_master_result(
        self, run_id: str, objective: str, executed_tasks: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        total_rows = 0
        total_errors = 0
        raw_errors = []
        combined_tables: List[str] = []

        for task in executed_tasks:
            res = task.get("result", {})
            metrics = res.get("metrics", {})
            total_rows += metrics.get("rows_processed", 0)
            total_errors += metrics.get("error_count", 0) + len(res.get("errors", []))
            for err in res.get("errors", []):
                cleaned = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", str(err))
                raw_errors.append(cleaned)
            tbl = res.get("data_table")
            if tbl:
                combined_tables.append(
                    f"### Sub-task: {task.get('task_id')} ({task.get('model')})\n{tbl}"
                )

        unique_errors = []
        for err in raw_errors:
            if err not in unique_errors:
                unique_errors.append(err)

        return {
            "run_id": run_id,
            "objective": objective,
            "total_sub_tasks": len(executed_tasks),
            "sub_tasks": executed_tasks,
            "aggregated_metrics": {
                "total_rows_processed": total_rows,
                "total_errors": total_errors,
                "unique_errors": unique_errors,
            },
            "synthesized_view": "\n\n".join(combined_tables),
        }

    def run_evaluator(self, file_to_eval: str, master: bool = False) -> Dict[str, Any]:
        engine = AuditorAssertionEngine()
        try:
            with open(file_to_eval, "r", encoding="utf-8") as f:
                content = f.read()
            if master:
                report = engine.verify_master_result(content)
            else:
                report = engine.verify_content(content)
            return report
        except Exception as e:
            return {
                "passed": False,
                "verdict": "FAIL",
                "failures_checklist": [f"Evaluator error: {e}"],
            }

    async def run_pipeline(
        self,
        user_objective: str,
        super_override: Optional[str] = None,
        signoff_override: Optional[str] = None,
        engage_override: Optional[List[str]] = None,
        input_file: Optional[str] = None,
        num_agents: Optional[int] = None,
    ) -> Dict[str, Any]:
        self.initialize_environment()
        run_id = f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        run_mailbox_dir = os.path.join(self.mailboxes_dir, run_id)
        os.makedirs(run_mailbox_dir, exist_ok=True)

        self.write_objective(user_objective, run_id)

        super_model = (
            super_override
            or self.user_config.get("user_preferences", {}).get("super")
            or self.base_config.get("orchestration", {})
            .get("roles", {})
            .get("super", "gemini")
        )
        signoff_model = (
            signoff_override
            or self.user_config.get("user_preferences", {}).get("signoff")
            or self.base_config.get("orchestration", {})
            .get("roles", {})
            .get("signoff", "claude")
        )
        engage_pool = (
            engage_override
            or self.user_config.get("user_preferences", {}).get("engage_pool")
            or self.base_config.get("orchestration", {}).get(
                "engage_agent_pool", ["gemini", "claude", "gpt-4o"]
            )
        )

        input_payload = None
        if input_file:
            if not os.path.exists(input_file):
                raise FileNotFoundError(f"Input file not found: {input_file}")
            try:
                with open(input_file, "r", encoding="utf-8") as f:
                    input_payload = json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Malformed JSON in input file: {e}")
                sys.exit(1)

        sub_tasks = await self.decompose_objective(
            objective=user_objective,
            engage_pool=engage_pool,
            input_data=input_payload,
            num_agents=num_agents,
        )

        manifest = {
            "run_id": run_id,
            "objective": user_objective,
            "super_model": super_model,
            "signoff_model": signoff_model,
            "sub_tasks": sub_tasks,
        }
        with open(
            os.path.join(run_mailbox_dir, "manifest.json"), "w", encoding="utf-8"
        ) as f:
            json.dump(manifest, f, indent=2)

        executed_tasks = await self.execute_engage_agents(sub_tasks, run_mailbox_dir)
        master_result = self.synthesize_master_result(
            run_id, user_objective, executed_tasks
        )
        master_file = os.path.join(run_mailbox_dir, "master_result.json")
        with open(master_file, "w", encoding="utf-8") as f:
            json.dump(master_result, f, indent=2)

        audit_report = self.run_evaluator(master_file, master=True)
        if not executed_tasks:
            audit_report["passed"] = False
            audit_report["verdict"] = "FAIL"
            audit_report.setdefault("failures_checklist", []).append(
                "No sub-tasks executed."
            )

        audit_file = os.path.join(run_mailbox_dir, "audit_report.json")
        with open(audit_file, "w", encoding="utf-8") as f:
            json.dump(audit_report, f, indent=2)

        passed = audit_report.get("passed", False)
        verdict = "PASS" if passed else "FAIL"

        return {
            "run_id": run_id,
            "passed": passed,
            "verdict": verdict,
            "master_result": master_result,
            "audit_report": audit_report,
        }
