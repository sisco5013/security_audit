#!/usr/bin/env python3
"""Runtime-bound report submodule extracted from tianqing_external_audit_report.

The extracted functions keep the mature report logic intact. The main generator
binds its runtime namespace before calling these functions so shared policy,
HTML, ClickHouse, and classification helpers remain single-sourced during this
phase of modularization.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any


def bind_runtime_dependencies(namespace: dict[str, Any]) -> None:
    for key, value in namespace.items():
        if key.startswith("__"):
            continue
        globals()[key] = value


def build_tianqing_organization_risk_result(
    args: argparse.Namespace,
    events: list[AuditEvent],
    asset_analysis: AssetAnalysis,
    internal_domains: set[str],
    tz: timezone,
    report_period: str,
    source_label: str,
) -> TianqingOrganizationRiskResult:
    sidecar_pages: dict[str, str] = {}
    terminal_risk_page = sidecar_page_filename(args, "terminal", "risk-ranking")
    org_company_page = sidecar_page_filename(args, "org", "company")
    org_department_type_page = sidecar_page_filename(args, "org", "department-type")
    org_company_department_page = sidecar_page_filename(args, "org", "company-department")
    identity_gap_page = sidecar_page_filename(args, "org", "identity-gap")

    focus_events = [event for event in events if is_leadership_focus_event(event, internal_domains)]
    terminal_risk_findings = build_terminal_risk_findings(
        focus_events,
        getattr(args, "terminal_identity_history", {}),
        asset_analysis.asset_by_terminal,
    )
    terminal_links: dict[tuple[str, str], str] = {}
    terminal_matrix_detail_links: dict[tuple[str, str, str, str], str] = {}
    for finding in terminal_risk_findings:
        total_terminal_events = terminal_channel_events(finding, internal_domains)
        if not total_terminal_events:
            continue
        key = terminal_key(finding.client_name, finding.client_ip)
        page = sidecar_page_filename(args, "terminal-risk", "|".join(key))
        terminal_links[key] = page
        sidecar_pages[page] = build_event_detail_page(
            f"终端风险事件明细：{finding.client_name or '-'} / {finding.client_ip or '-'}",
            total_terminal_events,
            args,
            tz,
            report_period,
            source_label,
            f"{finding.client_name or '-'} / {finding.client_ip or '-'} 的外发、上传和外设拷贝重点事件。",
        )
        cell_counts = terminal_channel_object_counts(finding, internal_domains)
        for channel, bucket in sorted(cell_counts):
            cell_events = terminal_channel_events(finding, internal_domains, channel, bucket)
            if not cell_events:
                continue
            cell_page = sidecar_page_filename(args, "terminal-matrix", "|".join([finding.client_name or "", finding.client_ip or "", channel, bucket]))
            terminal_matrix_detail_links[terminal_matrix_detail_key(finding, channel, bucket)] = cell_page
            sidecar_pages[cell_page] = build_event_detail_page(
                f"终端矩阵明细：{finding.client_name or '-'} / {finding.client_ip or '-'} / {channel} / {bucket}",
                cell_events,
                args,
                tz,
                report_period,
                source_label,
                f"{finding.client_name or '-'} / {finding.client_ip or '-'} 在 {channel} 通道中属于 {bucket} 的事件。",
            )

    organization_analysis = build_organization_risk_analysis(terminal_risk_findings, asset_analysis, internal_domains)
    org_links: dict[tuple[str, str, str], str] = {}
    all_org_findings = (
        organization_analysis.companies
        + organization_analysis.department_types
        + organization_analysis.company_departments
    )
    for finding in all_org_findings:
        page = sidecar_page_filename(args, f"org-{finding.scope}", "|".join([finding.company, finding.department, finding.label]))
        org_links[organization_key(finding)] = page

    org_matrix_detail_links: dict[tuple[str, str, str, str, str], str] = {}
    for finding in all_org_findings:
        total_events = organization_channel_events(finding, internal_domains)
        if total_events:
            page = sidecar_page_filename(args, f"org-matrix-{finding.scope}", "|".join([finding.company, finding.department, "__all__", "__all__"]))
            org_matrix_detail_links[organization_matrix_detail_key(finding, "__all__", "__all__")] = page
            sidecar_pages[page] = build_event_detail_page(
                f"组织矩阵明细：{finding.label} / 全部外发与拷贝",
                total_events,
                args,
                tz,
                report_period,
                source_label,
                f"{finding.label} 下进入组织矩阵的全部真实外发/上传/外设拷贝事件。",
            )
        for bucket in CHANNEL_MATRIX_COLUMNS:
            bucket_events = organization_channel_events(finding, internal_domains, bucket=bucket)
            if not bucket_events:
                continue
            page = sidecar_page_filename(args, f"org-matrix-{finding.scope}", "|".join([finding.company, finding.department, "__all__", bucket]))
            org_matrix_detail_links[organization_matrix_detail_key(finding, "__all__", bucket)] = page
            sidecar_pages[page] = build_event_detail_page(
                f"组织矩阵明细：{finding.label} / {bucket}",
                bucket_events,
                args,
                tz,
                report_period,
                source_label,
                f"{finding.label} 组织范围内，全部通道中属于 {bucket} 的外发/拷贝明细。",
            )
        cell_counts = organization_channel_object_counts(finding, internal_domains)
        for channel in organization_matrix_channels([finding], internal_domains):
            channel_events = organization_channel_events(finding, internal_domains, channel=channel)
            if not channel_events:
                continue
            page = sidecar_page_filename(args, f"org-matrix-{finding.scope}", "|".join([finding.company, finding.department, channel, "__all__"]))
            org_matrix_detail_links[organization_matrix_detail_key(finding, channel, "__all__")] = page
            sidecar_pages[page] = build_event_detail_page(
                f"组织矩阵明细：{finding.label} / {channel}",
                channel_events,
                args,
                tz,
                report_period,
                source_label,
                f"{finding.label} 组织范围内，{channel} 通道下进入审计报告的全部明细。",
            )
        for channel, bucket in sorted(cell_counts):
            cell_events = organization_channel_events(finding, internal_domains, channel, bucket)
            if not cell_events:
                continue
            page = sidecar_page_filename(args, f"org-matrix-{finding.scope}", "|".join([finding.company, finding.department, channel, bucket]))
            org_matrix_detail_links[organization_matrix_detail_key(finding, channel, bucket)] = page
            sidecar_pages[page] = build_event_detail_page(
                f"组织矩阵明细：{finding.label} / {channel} / {bucket}",
                cell_events,
                args,
                tz,
                report_period,
                source_label,
                f"{finding.label} 组织范围内，{channel} 通道中属于 {bucket} 的外发/拷贝明细。",
            )

    for finding in organization_analysis.companies:
        child_findings = [item for item in organization_analysis.company_departments if item.company == finding.company]
        sidecar_pages[org_links[organization_key(finding)]] = build_organization_profile_page(
            finding,
            child_findings,
            org_links,
            org_matrix_detail_links,
            terminal_links,
            terminal_matrix_detail_links,
            args,
            tz,
            report_period,
            source_label,
            internal_domains,
        )
    for finding in organization_analysis.department_types:
        child_findings = [item for item in organization_analysis.company_departments if item.department == finding.department]
        sidecar_pages[org_links[organization_key(finding)]] = build_organization_profile_page(
            finding,
            child_findings,
            org_links,
            org_matrix_detail_links,
            terminal_links,
            terminal_matrix_detail_links,
            args,
            tz,
            report_period,
            source_label,
            internal_domains,
        )
    for finding in organization_analysis.company_departments:
        sidecar_pages[org_links[organization_key(finding)]] = build_organization_profile_page(
            finding,
            [],
            org_links,
            org_matrix_detail_links,
            terminal_links,
            terminal_matrix_detail_links,
            args,
            tz,
            report_period,
            source_label,
            internal_domains,
        )

    def build_org_list_metric_pages(scope_key: str, title: str, findings: list[OrganizationRiskFinding]) -> dict[str, str]:
        links: dict[str, str] = {}
        total_events = organization_scope_channel_events(findings, internal_domains)
        if total_events:
            page = sidecar_page_filename(args, "org-list-matrix", f"{scope_key}|__all__")
            links["__all__"] = page
            sidecar_pages[page] = build_event_detail_page(
                f"{title}：全部外发与拷贝",
                total_events,
                args,
                tz,
                report_period,
                source_label,
                f"{title}范围内进入组织矩阵的全部真实外发、上传和外设拷贝事件。",
            )
        for channel in organization_matrix_channels(findings, internal_domains):
            channel_events = organization_scope_channel_events(findings, internal_domains, channel=channel)
            if not channel_events:
                continue
            page = sidecar_page_filename(args, "org-list-matrix", f"{scope_key}|{channel}")
            links[channel] = page
            sidecar_pages[page] = build_event_detail_page(
                f"{title}：{channel}",
                channel_events,
                args,
                tz,
                report_period,
                source_label,
                f"{title}范围内，{channel} 通道下进入审计报告的全部明细。",
            )
        for bucket in CHANNEL_MATRIX_COLUMNS:
            bucket_events = organization_scope_channel_events(findings, internal_domains, bucket=bucket)
            if not bucket_events:
                continue
            page = sidecar_page_filename(args, "org-list-matrix", f"{scope_key}|__all__|{bucket}")
            links[organization_object_metric_key(bucket)] = page
            sidecar_pages[page] = build_event_detail_page(
                f"{title}：{bucket}",
                bucket_events,
                args,
                tz,
                report_period,
                source_label,
                f"{title}范围内，全部通道中属于 {bucket} 的外发、上传和外设拷贝明细。",
            )
        return links

    org_company_metric_links = build_org_list_metric_pages("company", "公司风险洞察", organization_analysis.companies)
    org_department_type_metric_links = build_org_list_metric_pages("department-type", "部门风险洞察", organization_analysis.department_types)
    org_company_department_metric_links = build_org_list_metric_pages("company-department", "公司内部门风险洞察", organization_analysis.company_departments)
    sidecar_pages[org_company_page] = build_organization_risk_list_page(
        "公司风险洞察",
        "公司维度",
        organization_analysis.companies,
        org_links,
        org_matrix_detail_links,
        org_company_metric_links,
        internal_domains,
        tz,
        report_period,
        source_label,
    )
    sidecar_pages[org_department_type_page] = build_organization_risk_list_page(
        "部门风险洞察",
        "跨公司部门维度",
        organization_analysis.department_types,
        org_links,
        org_matrix_detail_links,
        org_department_type_metric_links,
        internal_domains,
        tz,
        report_period,
        source_label,
    )
    sidecar_pages[org_company_department_page] = build_organization_risk_list_page(
        "公司内部门风险洞察",
        "公司 + 部门维度",
        organization_analysis.company_departments,
        org_links,
        org_matrix_detail_links,
        org_company_department_metric_links,
        internal_domains,
        tz,
        report_period,
        source_label,
    )
    sidecar_pages[identity_gap_page] = build_identity_gap_page(
        terminal_risk_findings,
        organization_analysis.company_departments,
        terminal_links,
        terminal_matrix_detail_links,
        org_links,
        org_matrix_detail_links,
        internal_domains,
        tz,
        report_period,
        source_label,
    )
    sidecar_pages[terminal_risk_page] = build_terminal_risk_detail_page(
        terminal_risk_findings,
        terminal_links,
        terminal_matrix_detail_links,
        internal_domains,
        tz,
        report_period,
        source_label,
    )
    terminal_risk_block = build_organization_risk_summary_html(
        organization_analysis,
        terminal_risk_findings,
        terminal_links,
        terminal_matrix_detail_links,
        terminal_risk_page,
        org_links,
        org_matrix_detail_links,
        org_company_page,
        org_department_type_page,
        org_company_department_page,
        identity_gap_page,
        tz,
        internal_domains,
    )
    return TianqingOrganizationRiskResult(
        terminal_risk_block=terminal_risk_block,
        terminal_risk_findings=terminal_risk_findings,
        organization_analysis=organization_analysis,
        terminal_links=terminal_links,
        terminal_matrix_detail_links=terminal_matrix_detail_links,
        org_links=org_links,
        org_matrix_detail_links=org_matrix_detail_links,
        sidecar_pages=sidecar_pages,
    )
