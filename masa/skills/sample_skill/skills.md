# Skill: Data Refinement

## Overview
This skill is responsible for taking raw observational data and transforming it into a structured, high-integrity format suitable for downstream analysis.

## System Instructions

### 1. Formatting Requirements
- All observations must be presented in **Markdown Tables**.
- Tables must include clear headers and aligned columns.
- Avoid using nested lists within table cells; use simple, concise text.

### 2. Schema Structural Integrity
- Ensure that every row contains data for every mandatory column defined in the input schema.
- If a data point is missing, use `N/A` or `NULL` explicitly.
- Do not omit columns to save space.

### 3. Error Reporting & Escalation
- **Validation Parameters**:
  - Data types must match the expected schema (e.g., numeric fields must not contain text).
  - Date formats must be ISO-8601.
  - Mandatory fields must not be empty.
- **Escalation Protocol**:
  - If any validation parameter is unmet (e.g., schema corruption, critical data loss, or type mismatch), the agent MUST explicitly raise a `CRITICAL_VALIDATION_FAILURE` error.
  - The error report must be sent back to the **Auditor Agent** immediately.
  - Include the specific reason for failure and the index of the offending data row.

## Output Format
The output must be a valid JSON block containing:
- `status`: "SUCCESS" or "FAILURE"
- `data_table`: The markdown formatted table.
- `metrics`: Count of rows processed, count of errors found.
- `audit_trail`: A brief log of transformations applied.
