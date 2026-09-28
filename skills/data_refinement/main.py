"""
Data Refinement skill entrypoint for MASO worker container.
Adheres to strict schema required by AuditorAssertionEngine.
"""

from typing import Any, Dict, List


def execute_skill(task_context: Dict[str, Any], parameters: Dict[str, Any]) -> Dict[str, Any]:
    task_id = task_context.get("task_id", "task-default")
    raw_data = parameters.get("raw_data")

    if raw_data is None:
        return {
            "status": "FAILURE",
            "task_id": task_id,
            "data_table": "",
            "metrics": {"rows_processed": 0, "error_count": 1},
            "audit_trail": ["Validation failure: missing 'raw_data'"],
            "errors": ["Missing 'raw_data' in input parameters"]
        }

    if not isinstance(raw_data, list):
        return {
            "status": "FAILURE",
            "task_id": task_id,
            "data_table": "",
            "metrics": {"rows_processed": 0, "error_count": 1},
            "audit_trail": ["Validation failure: 'raw_data' is not a list"],
            "errors": ["'raw_data' must be a list of objects"]
        }

    if len(raw_data) == 0:
        return {
            "status": "SUCCESS",
            "task_id": task_id,
            "data_table": "| Message |\n| --- |\n| No data provided |",
            "metrics": {"rows_processed": 0, "error_count": 0},
            "audit_trail": ["Processed empty dataset."],
            "errors": []
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
        "metrics": {"rows_processed": len(rows), "error_count": 0},
        "audit_trail": [f"Processed {len(rows)} records into Markdown table."],
        "errors": []
    }
