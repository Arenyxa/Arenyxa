from __future__ import annotations

from typing import Any, Iterable, Mapping


_MAX_RULE_OBSERVATIONS = 1024
_MAX_VALUES = 256

_RULE_GROUPS = {
    1: ("pdr", "create"),
    3: ("far", "create"),
    7: ("qer", "create"),
    9: ("pdr", "update"),
    10: ("far", "update"),
    14: ("qer", "update"),
    15: ("pdr", "remove"),
    16: ("far", "remove"),
    18: ("qer", "remove"),
}


def _children(row: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = row.get("children")
    return [item for item in raw if isinstance(item, Mapping)] if isinstance(raw, list) else []


def _walk(rows: Iterable[Mapping[str, Any]], *, depth: int = 0) -> Iterable[Mapping[str, Any]]:
    if depth > 4:
        return
    for row in rows:
        yield row
        children = _children(row)
        if children:
            yield from _walk(children, depth=depth + 1)


def _bounded_add(values: set[Any], value: Any) -> None:
    if value is not None and len(values) < _MAX_VALUES:
        values.add(value)


def _extract_group(row: Mapping[str, Any], kind: str, operation: str) -> dict[str, Any] | None:
    pdr_ids: set[int] = set()
    far_ids: set[int] = set()
    qer_ids: set[int] = set()
    qfis: set[int] = set()
    fteids: set[tuple[int, str, str]] = set()
    networks: set[str] = set()
    malformed = bool(row.get("children_malformed"))
    for child in _walk(_children(row)):
        try:
            ie_type = int(child.get("type") or 0)
        except (TypeError, ValueError, OverflowError):
            malformed = True
            continue
        try:
            if ie_type == 56 and child.get("pdr_id") is not None:
                _bounded_add(pdr_ids, int(child["pdr_id"]))
            elif ie_type == 108 and child.get("rule_id") is not None:
                _bounded_add(far_ids, int(child["rule_id"]))
            elif ie_type == 109 and child.get("rule_id") is not None:
                _bounded_add(qer_ids, int(child["rule_id"]))
            elif ie_type == 124 and child.get("qfi") is not None:
                _bounded_add(qfis, int(child["qfi"]))
            elif ie_type == 21 and child.get("teid") is not None:
                _bounded_add(
                    fteids,
                    (int(child["teid"]), str(child.get("ipv4") or ""), str(child.get("ipv6") or "")),
                )
            elif ie_type == 22 and child.get("network_instance"):
                _bounded_add(networks, str(child["network_instance"]))
        except (TypeError, ValueError, OverflowError):
            malformed = True
    ids = pdr_ids if kind == "pdr" else far_ids if kind == "far" else qer_ids
    if not ids and operation in {"remove", "update"}:
        malformed = True
    if not ids and not (fteids or qfis or networks):
        return None
    return {
        "rule_kind": kind,
        "operation": operation,
        "rule_ids": sorted(ids),
        "pdr_ids": sorted(pdr_ids),
        "far_ids": sorted(far_ids),
        "qer_ids": sorted(qer_ids),
        "qfis": sorted(qfis),
        "fteids": [
            {"teid": teid, "teid_hex": f"0x{teid:08x}", "ipv4": ipv4, "ipv6": ipv6}
            for teid, ipv4, ipv6 in sorted(fteids)
        ],
        "network_instances": sorted(networks),
        "malformed": malformed,
    }


def extract_pfcp_rule_observations(rows: Any) -> list[dict[str, Any]]:
    """Extract bounded PDR/FAR/QER graph evidence from top-level PFCP grouped IEs."""
    if not isinstance(rows, list):
        return []
    result: list[dict[str, Any]] = []
    for raw in rows[:_MAX_RULE_OBSERVATIONS]:
        if not isinstance(raw, Mapping):
            continue
        try:
            ie_type = int(raw.get("type") or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        meta = _RULE_GROUPS.get(ie_type)
        if meta is None:
            continue
        row = _extract_group(raw, meta[0], meta[1])
        if row is not None:
            result.append(row)
    # Resolve QER→QFI inside the same PFCP request. This is request-local evidence;
    # caller decides whether a matching successful response confirms the operation.
    qer_qfis: dict[int, set[int]] = {}
    for row in result:
        if row["rule_kind"] != "qer" or row["operation"] == "remove":
            continue
        for qer_id in row["qer_ids"]:
            qer_qfis.setdefault(qer_id, set()).update(row["qfis"])
    for row in result:
        resolved: set[int] = set(row["qfis"])
        if row["rule_kind"] == "pdr":
            for qer_id in row["qer_ids"]:
                resolved.update(qer_qfis.get(qer_id, ()))
        row["resolved_qfis"] = sorted(resolved)
    return result
