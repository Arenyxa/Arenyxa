from __future__ import annotations


def is_target_row(row: dict) -> bool:
    sql = row.get("sql") or []
    lease_fast = sum(1 for item in sql if item and item[0] == "lease_fast")
    fallback = any(item and item[0] == "other_business" for item in sql)
    return (
        bool(row.get("success"))
        and not bool(row.get("recovery_yes"))
        and lease_fast == 1
        and not fallback
    )
