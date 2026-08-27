"""Repair diagnostics enrichment with no execution-side effects."""
from __future__ import annotations

from arenyxa.repair_models import HealthReport, RepairCategory, RepairFinding


def append_feature_integration_findings(report: HealthReport, context: object) -> HealthReport:
    from arenyxa.application.feature_audit import audit_advanced_features

    existing_codes = {item.code for item in report.findings}
    feature_report = audit_advanced_features(context)
    for issue in feature_report.issues:
        code = f"FEATURE_WIRING_{issue.feature_id.upper().replace('.', '_')}"
        if code in existing_codes:
            continue
        report.findings.append(
            RepairFinding(
                code=code,
                category=RepairCategory.FEATURE_INTEGRATION,
                severity="critical",
                title=f"高级功能接线异常：{issue.label}",
                detail=issue.detail or "高级界面存在，但对应运行时能力不完整。",
                evidence=", ".join(issue.missing),
            )
        )
        existing_codes.add(code)
    return report
