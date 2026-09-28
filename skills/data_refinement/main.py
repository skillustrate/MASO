"""
Data Refinement skill entrypoint for MASO worker container.
"""

from typing import Any, Dict, List


def execute_skill(task_context: Dict[str, Any], parameters: Dict[str, Any]) -> Dict[str, Any]:
    task_id = task_context.get("task_id", "task-default")
    raw_data = parameters.get("raw_data")

    if raw_data is None:
        return {
            "status": "ERROR",
            "errors": ["Missing 'raw_data' in input parameters"],
            "task_id": task_id
        }

    if not isinstance(raw_data, list):
        return {
            "status": "ERROR",
            "errors": ["'raw_data' must be a list of objects"],
            "task_id": task_id
        }

    if len(raw_data) == 0:
        return {
            "status": "SUCCESS",
            "task_id": task_id,
            "data_table": "| Message |\n| --- |\n| No data provided |",
            "rows_processed": 0
        }

    all_keys: List[str] = []
    for item in raw_data:
        if isinstance(item, dict):
            for k in item.keys():
                if k not in all_keys:
                    all_keys.append(k)

    header = "| " + " | ".join(all_keys) + " |"
    separator = "| " + " | ".join(["---"] * len(all_keys)) + " |"
    rows = []

    for item in raw_data:
        if isinstance(item, dict):
            row_vals = [str(item.get(k, "N/A")).replace("\n", " ").replace("|", "\\|") for k in all_keys]
            rows.append("| " + " | ".join(row_vals) + " |")

    data_table = "\n".join([header, separator] + rows)

    return {
        "status": "SUCCESS",
        "task_id": task_id,
        "data_table": data_table,
        "rows_processed": len(rows),
        "columns": all_keys
    }
