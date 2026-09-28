import argparse
import json
import logging
import sys
from typing import Any, Dict, List, Optional

# Configure logging for telemetry
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("DataRefinementSkill")


def execute_skill(
    task_context: Dict[str, Any], inputs: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Core handler for the Data Refinement skill.
    Processes raw input data into a structured markdown table and returns telemetry
    in strict adherence to skills.md specification.
    """
    task_id = task_context.get("task_id", "default_task")
    logger.info(f"Starting skill execution for task {task_id}: Data Refinement")

    status = "SUCCESS"
    data_table = ""
    errors: List[str] = []
    audit_trail: List[str] = []
    rows_processed = 0

    try:
        raw_data = inputs.get("raw_data")
        if raw_data is None:
            raise ValueError(
                "CRITICAL_VALIDATION_FAILURE: Missing 'raw_data' in input payload."
            )

        if not isinstance(raw_data, list):
            raise ValueError(
                "CRITICAL_VALIDATION_FAILURE: 'raw_data' must be a list of objects."
            )

        audit_trail.append(f"Received {len(raw_data)} record(s) for processing.")

        if len(raw_data) == 0:
            data_table = "| Message |\n| --- |\n| No data provided |"
            audit_trail.append("Processed empty data list.")
        else:
            # Extract union of all keys while preserving first-seen order
            all_keys: List[str] = []
            for item in raw_data:
                if not isinstance(item, dict):
                    idx = raw_data.index(item)
                    raise ValueError(
                        f"CRITICAL_VALIDATION_FAILURE: Row at index {idx} is not an object/dictionary."
                    )
                for k in item.keys():
                    if k not in all_keys:
                        all_keys.append(k)

            audit_trail.append(f"Identified columns: {', '.join(all_keys)}")

            header = "| " + " | ".join(all_keys) + " |"
            separator = "| " + " | ".join(["---"] * len(all_keys)) + " |"
            rows = []

            for idx, item in enumerate(raw_data):
                row_values = []
                for k in all_keys:
                    val = item.get(k)
                    if val is None or val == "":
                        val_str = "N/A"
                    else:
                        # Sanitize any newlines or pipes inside table cells
                        val_str = str(val).replace("\n", " ").replace("|", "\\|")
                    row_values.append(val_str)
                rows.append("| " + " | ".join(row_values) + " |")
                rows_processed += 1

            data_table = "\n".join([header, separator] + rows)
            audit_trail.append(
                f"Successfully generated Markdown table for {rows_processed} rows."
            )

    except Exception as e:
        status = "FAILURE"
        error_msg = str(e)
        errors.append(error_msg)
        audit_trail.append(f"Execution failed: {error_msg}")
        logger.error(f"Skill execution failed for task {task_id}: {error_msg}")

    output = {
        "status": status,
        "task_id": task_id,
        "data_table": data_table,
        "metrics": {"rows_processed": rows_processed, "error_count": len(errors)},
        "audit_trail": audit_trail,
        "errors": errors,
    }

    return output


def main():
    parser = argparse.ArgumentParser(description="Data Refinement Skill Executable")
    parser.add_argument(
        "--task_id", type=str, default="default_task", help="ID of the current task"
    )
    parser.add_argument(
        "--input_file", type=str, help="Path to JSON file containing input payload"
    )

    args = parser.parse_args()
    task_context = {"task_id": args.task_id}

    inputs: Dict[str, Any] = {}
    if args.input_file:
        try:
            with open(args.input_file, "r", encoding="utf-8") as f:
                inputs = json.load(f)
        except Exception as e:
            err_output = {
                "status": "FAILURE",
                "task_id": args.task_id,
                "data_table": "",
                "metrics": {"rows_processed": 0, "error_count": 1},
                "audit_trail": ["Failed reading input file."],
                "errors": [f"Failed to read input file: {e}"],
            }
            print(json.dumps(err_output, indent=2))
            sys.exit(1)
    elif not sys.stdin.isatty():
        try:
            stdin_content = sys.stdin.read().strip()
            if stdin_content:
                inputs = json.loads(stdin_content)
        except Exception as e:
            err_output = {
                "status": "FAILURE",
                "task_id": args.task_id,
                "data_table": "",
                "metrics": {"rows_processed": 0, "error_count": 1},
                "audit_trail": ["Failed parsing stdin JSON."],
                "errors": [f"Failed to read stdin: {e}"],
            }
            print(json.dumps(err_output, indent=2))
            sys.exit(1)
    else:
        # Default fallback for testing
        inputs = {
            "raw_data": [
                {"id": 1, "name": "Sample A", "value": 10.5},
                {"id": 2, "name": "Sample B", "value": 20.0},
            ]
        }

    result = execute_skill(task_context, inputs)
    print(json.dumps(result, indent=2))
    if result["status"] != "SUCCESS":
        sys.exit(1)


if __name__ == "__main__":
    main()
