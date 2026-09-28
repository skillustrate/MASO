"""
AST Scanner skill entrypoint for MASO worker container.
"""

import ast
from typing import Any, Dict, List


def execute_skill(task_context: Dict[str, Any], parameters: Dict[str, Any]) -> Dict[str, Any]:
    task_id = task_context.get("task_id", "task-default")
    code = parameters.get("code")

    if code is None:
        return {
            "status": "ERROR",
            "errors": ["Missing 'code' in input parameters"],
            "task_id": task_id
        }

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return {
            "status": "ERROR",
            "errors": [f"SyntaxError parsing code: {str(e)}"],
            "task_id": task_id
        }

    imports = []
    function_calls = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                function_calls.append(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                function_calls.append(node.func.attr)

    dangerous = [m for m in imports if m in ["os", "subprocess", "socket", "ctypes", "sys"]]

    return {
        "status": "SUCCESS",
        "task_id": task_id,
        "imports": sorted(list(set(imports))),
        "function_calls": sorted(list(set(function_calls))),
        "dangerous_imports": sorted(list(set(dangerous))),
        "has_dangerous_imports": len(dangerous) > 0
    }
