#!/usr/bin/env python3
"""Composable home-page modules for the audit report.

This file intentionally keeps only presentation shell objects and module
composition helpers. Heavy data extraction and aggregation stay in the main
generator until each audit domain can be split independently.
"""

from __future__ import annotations

import html as html_lib
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable


def _esc(value: Any) -> str:
    return html_lib.escape(str(value if value is not None else ""))


@dataclass(frozen=True)
class ReportHomeModule:
    module_id: str
    title: str
    eyebrow: str
    description: str
    source_label: str
    body_html: str
    css_class: str = ""
    title_id: str = ""
    enabled: bool = True
    status: str = "ready"


@dataclass
class ReportModuleResult:
    home_module: ReportHomeModule
    sidecar_pages: dict[str, str] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    status: str = "ready"


@dataclass
class TianqingChannelMatrixResult:
    block_html: str
    focus_metrics_html: str
    row_links: dict[str, str]
    cell_links: dict[tuple[str, str], str]
    object_links: dict[str, str]
    row_totals: Counter
    rows: list[str]
    sidecar_pages: dict[str, str] = field(default_factory=dict)


@dataclass
class TianqingRenameTrackingResult:
    three_d_block_html: str
    standard_block_html: str
    sidecar_pages: dict[str, str] = field(default_factory=dict)
    three_d_links: dict[str, str] = field(default_factory=dict)
    standard_links: dict[str, str] = field(default_factory=dict)


@dataclass
class TianqingOrganizationRiskResult:
    terminal_risk_block: str
    terminal_risk_findings: list[Any]
    organization_analysis: Any
    terminal_links: dict[tuple[str, str], str]
    terminal_matrix_detail_links: dict[tuple[str, str, str, str], str]
    org_links: dict[tuple[str, str, str], str]
    org_matrix_detail_links: dict[tuple[str, str, str, str, str], str]
    sidecar_pages: dict[str, str] = field(default_factory=dict)


@dataclass
class TianqingEvidenceDetailResult:
    sidecar_pages: dict[str, str] = field(default_factory=dict)
    kpi_pages: dict[str, str] = field(default_factory=dict)
    asset_pages: dict[str, str] = field(default_factory=dict)
    keyword_links: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class TianqingOutboundModuleBuilders:
    build_channel_matrix_result: Callable[..., TianqingChannelMatrixResult]
    build_rename_tracking_result: Callable[..., TianqingRenameTrackingResult]
    build_organization_risk_result: Callable[..., TianqingOrganizationRiskResult]
    build_evidence_detail_result: Callable[..., TianqingEvidenceDetailResult]
    build_trend_summary: Callable[..., Any]
    trend_comparison_html: Callable[..., str]
    build_rule_risk_overview_html: Callable[..., str]
    debug_timing: Callable[[str], None] = lambda _message: None


def render_report_home_module(module: ReportHomeModule) -> str:
    if not module.enabled:
        return ""
    module_id = re.sub(r"[^a-zA-Z0-9_-]+", "-", module.module_id).strip("-") or "audit-module"
    title_id = module.title_id or f"{module_id}-title"
    css_class = f" {module.css_class.strip()}" if module.css_class.strip() else ""
    status_attr = f' data-module-status="{_esc(module.status)}"' if module.status else ""
    return f"""
    <section id="{_esc(module_id)}" class="audit-domain{css_class}" aria-labelledby="{_esc(title_id)}"{status_attr}>
      <div class="audit-domain-head">
        <div>
          <span class="audit-domain-kicker">{_esc(module.eyebrow)}</span>
          <h2 id="{_esc(title_id)}">{_esc(module.title)}</h2>
          <p>{_esc(module.description)}</p>
        </div>
        <div class="audit-domain-source">{_esc(module.source_label)}</div>
      </div>
      {module.body_html}
    </section>
"""


def render_report_home_modules(modules: Iterable[ReportHomeModule]) -> str:
    return "\n".join(render_report_home_module(module) for module in modules if module.enabled)


def _metric_int(metrics: dict[str, Any] | None, key: str) -> int:
    if not metrics:
        return 0
    try:
        return int(metrics.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _metric_text(metrics: dict[str, Any] | None, key: str, default: str = "-") -> str:
    if not metrics:
        return default
    value = metrics.get(key)
    text = str(value if value is not None else "").strip()
    return text or default


def _summary_card_html(title: str, value: str, label: str, detail: str, href: str, tone: str) -> str:
    tag = "a" if href else "div"
    href_attr = f' href="{_esc(href)}"' if href else ""
    return f"""
        <{tag} class="management-module-card management-module-card-{_esc(tone)}"{href_attr}>
          <span>{_esc(title)}</span>
          <strong>{_esc(value)}</strong>
          <em>{_esc(label)}</em>
          <p>{_esc(detail)}</p>
        </{tag}>
"""


def build_global_management_summary_html(
    decrypt_metrics: dict[str, Any] | None,
    tianqing_metrics: dict[str, Any] | None,
    plm_metrics: dict[str, Any] | None = None,
) -> str:
    decrypt_total = _metric_int(decrypt_metrics, "records")
    decrypt_standard = _metric_int(decrypt_metrics, "standard")
    decrypt_linked = _metric_int(decrypt_metrics, "linked")
    decrypt_companies = _metric_int(decrypt_metrics, "company_count")

    tianqing_events = _metric_int(tianqing_metrics, "matrix_events") or _metric_int(tianqing_metrics, "events")
    tianqing_terminals = _metric_int(tianqing_metrics, "terminal_count")
    top_channel = _metric_text(tianqing_metrics, "top_channel")
    top_channel_count = _metric_int(tianqing_metrics, "top_channel_count")

    plm_enabled = bool(plm_metrics and plm_metrics.get("enabled"))
    plm_risks = _metric_int(plm_metrics, "risk_count")
    plm_label = "登录合规风险" if plm_enabled else "待接入"
    plm_value = str(plm_risks) if plm_enabled else "未纳入"
    plm_detail = (
        f"已纳入 PLM 登录合规审计，本期识别 {plm_risks} 条需复核登录记录。"
        if plm_enabled
        else "接口接入后重点校验技术、研发、工艺账号是否从 MAC+计算机名授信终端登录。"
    )

    if decrypt_total or tianqing_events:
        lead = (
            f"本周期风险概况：加密软件解密 {decrypt_total} 条，标准图纸 {decrypt_standard} 条；"
            f"天擎外发重点事件 {tianqing_events} 条，涉及风险终端 {tianqing_terminals} 台；"
            f"PLM 登录审计{plm_label}。"
        )
    else:
        lead = "本周期三大审计模块暂无显著风险数据，仍按解密记录、天擎外发和 PLM 登录三个入口保留持续监测。"

    action = (
        "管理动作建议：先看标准图纸解密和天擎外发矩阵，再下钻公司、部门和终端；"
        "PLM 模块上线后作为账号登录合规补充，不替代天擎外发和解密流转证据。"
    )

    cards = "".join(
        [
            _summary_card_html(
                "加密软件解密审计",
                f"{decrypt_total}",
                f"标准图纸 {decrypt_standard} / 后续流转 {decrypt_linked}",
                f"重点看结构、电气、三维和 DWG 解密；涉及公司 {decrypt_companies} 个，按审批依据和后续流转闭环。",
                "#decrypt-audit",
                "decrypt",
            ),
            _summary_card_html(
                "天擎外发审计",
                f"{tianqing_events}",
                f"风险终端 {tianqing_terminals} / Top通道 {top_channel} {top_channel_count}",
                "重点看邮件、IM、外部站点上传、外设拷贝中的结构、电气、三维、DWG、敏感名称和压缩包。",
                "#tianqing-audit",
                "tianqing",
            ),
            _summary_card_html(
                "PLM登录审计",
                plm_value,
                plm_label,
                plm_detail,
                "#plm-login-audit" if plm_enabled else "",
                "plm",
            ),
        ]
    )

    return f"""
    <section id="global-management-summary" class="global-management-summary" aria-labelledby="global-management-summary-title">
      <div class="global-management-head">
        <div>
          <span class="section-eyebrow">Management Summary</span>
          <h2 id="global-management-summary-title">三大模块管理结论</h2>
        </div>
        <p>{_esc(lead)}</p>
      </div>
      <div class="management-module-grid">
        {cards}
      </div>
      <p class="global-management-action">{_esc(action)}</p>
    </section>
"""


def build_decrypt_audit_home_module(decrypt_risk_tracking_block: str) -> ReportHomeModule:
    return ReportHomeModule(
        module_id="decrypt-audit",
        css_class="audit-domain-decrypt",
        title_id="decrypt-audit-title",
        eyebrow="Encryption Decrypt Audit",
        title="加密软件解密审计",
        description="基于解密/外发申请 Excel 入库记录，重点追踪结构、电气标准图纸和二三维设计图纸的解密、组织分布与后续可观测流转。",
        source_label="数据源：加密软件解密记录 / 组织别名映射",
        body_html=decrypt_risk_tracking_block,
    )


def build_tianqing_outbound_home_module(
    risk_overview_html: str,
    trend_html: str,
    three_d_rename_tracking_block: str,
    standard_rename_alert_block: str,
    channel_matrix_block: str,
    terminal_risk_block: str,
) -> ReportHomeModule:
    body_html = f"""
      {risk_overview_html}
      {trend_html}
      {three_d_rename_tracking_block}
      {standard_rename_alert_block}

      <section id="channel-matrix" class="section-block matrix-shell">
        <div class="section-title-row">
          <div>
            <span class="section-eyebrow">Channel Matrix</span>
            <h2>外发通道风险矩阵</h2>
            <p>按真实发生的发送、上传和拷贝行为拆分邮件外发、IM附件、外部站点上传和外设拷贝；发件箱类型在邮件明细中查看。</p>
          </div>
        </div>
        {channel_matrix_block}
      </section>

      <section id="terminal-risk" class="section-block terminal-risk-shell">
        <div class="section-title-row">
          <div>
            <span class="section-eyebrow">Organization Insight</span>
            <h2>组织风险洞察</h2>
            <p>从公司、跨公司部门和公司内部门三个视角聚合风险终端，先看组织规律，再下钻到具体终端和事件。</p>
          </div>
        </div>
        {terminal_risk_block}
      </section>
"""
    return ReportHomeModule(
        module_id="tianqing-audit",
        css_class="audit-domain-tianqing",
        title_id="tianqing-audit-title",
        eyebrow="Endpoint DLP Audit",
        title="天擎外发审计",
        description="基于奇安信天擎终端审计底稿，关注邮件、IM、外部站点上传和外设拷贝中的设计图纸、敏感名称与压缩包风险。",
        source_label="数据源：天擎 Syslog / ClickHouse 审计底稿",
        body_html=body_html,
    )


def build_tianqing_outbound_module_result(
    args: Any,
    events: list[Any],
    procurement_muted_events: list[Any],
    false_positive_events: list[Any],
    false_positive_reasons: dict[str, str],
    behavior_rows: dict[str, list[list[Any]]],
    keyword_counts: Counter,
    keyword_event_map: dict[str, list[Any]],
    asset_analysis: Any,
    asset_as_of: Any,
    three_d_rename_findings: list[Any],
    trend_windows: dict[int, dict[str, Any]],
    tz: Any,
    start: Any,
    end: Any,
    internal_domains: set[str],
    report_period: str,
    source_label: str,
    builders: TianqingOutboundModuleBuilders,
) -> ReportModuleResult:
    sidecar_pages: dict[str, str] = {}

    channel_matrix_result = builders.build_channel_matrix_result(
        args,
        events,
        internal_domains,
        tz,
        report_period,
        source_label,
    )
    sidecar_pages.update(channel_matrix_result.sidecar_pages)
    builders.debug_timing(f"channel matrix module complete pages={len(channel_matrix_result.sidecar_pages)}")

    rename_tracking_result = builders.build_rename_tracking_result(
        args,
        three_d_rename_findings,
        tz,
        report_period,
        source_label,
    )
    sidecar_pages.update(rename_tracking_result.sidecar_pages)
    builders.debug_timing(f"rename tracking module complete pages={len(rename_tracking_result.sidecar_pages)}")

    organization_result = builders.build_organization_risk_result(
        args,
        events,
        asset_analysis,
        internal_domains,
        tz,
        report_period,
        source_label,
    )
    sidecar_pages.update(organization_result.sidecar_pages)
    builders.debug_timing(
        f"organization risk module complete terminals={len(organization_result.terminal_risk_findings)} pages={len(organization_result.sidecar_pages)}"
    )

    evidence_detail_result = builders.build_evidence_detail_result(
        args,
        events,
        procurement_muted_events,
        false_positive_events,
        false_positive_reasons,
        behavior_rows,
        keyword_counts,
        keyword_event_map,
        asset_analysis,
        asset_as_of,
        channel_matrix_result.focus_metrics_html,
        internal_domains,
        tz,
        report_period,
        source_label,
    )
    sidecar_pages.update(evidence_detail_result.sidecar_pages)
    builders.debug_timing(f"evidence detail module complete pages={len(evidence_detail_result.sidecar_pages)}")

    object_trend_links = {
        "三维模型": channel_matrix_result.object_links.get("三维模型", evidence_detail_result.kpi_pages["3d_model"]),
        "DWG二维图纸": channel_matrix_result.object_links.get("DWG二维图纸", evidence_detail_result.kpi_pages["2d_cad"]),
        "敏感名称": channel_matrix_result.object_links.get("敏感名称", evidence_detail_result.kpi_pages["sensitive"]),
        "压缩包": channel_matrix_result.object_links.get("压缩包", evidence_detail_result.kpi_pages["archive"]),
    }
    trend_summary = builders.build_trend_summary(
        trend_windows,
        tz,
        internal_domains,
        channel_matrix_result.row_links,
        object_trend_links,
        organization_result.org_links,
        events,
        start,
        end,
    )
    trend_html = builders.trend_comparison_html(trend_summary)
    risk_overview_html = builders.build_rule_risk_overview_html(
        events,
        args,
        start,
        end,
        tz,
        internal_domains,
        organization_result.organization_analysis,
        organization_result.org_links,
        object_trend_links,
    )
    home_module = build_tianqing_outbound_home_module(
        risk_overview_html,
        trend_html,
        rename_tracking_result.three_d_block_html,
        rename_tracking_result.standard_block_html,
        channel_matrix_result.block_html,
        organization_result.terminal_risk_block,
    )
    return ReportModuleResult(
        home_module=home_module,
        sidecar_pages=sidecar_pages,
        metrics={
            "events": len(events),
            "matrix_events": sum(channel_matrix_result.row_totals.values()),
            "top_channel": channel_matrix_result.row_totals.most_common(1)[0][0] if channel_matrix_result.row_totals else "",
            "top_channel_count": channel_matrix_result.row_totals.most_common(1)[0][1] if channel_matrix_result.row_totals else 0,
            "channel_pages": len(channel_matrix_result.sidecar_pages),
            "rename_pages": len(rename_tracking_result.sidecar_pages),
            "organization_pages": len(organization_result.sidecar_pages),
            "evidence_pages": len(evidence_detail_result.sidecar_pages),
            "terminal_count": len(organization_result.terminal_risk_findings),
            "procurement_muted": len(procurement_muted_events),
            "false_positive": len(false_positive_events),
        },
    )


def build_plm_login_audit_home_module(enabled: bool = False) -> ReportHomeModule:
    return ReportHomeModule(
        module_id="plm-login-audit",
        css_class="audit-domain-plm",
        title_id="plm-login-audit-title",
        eyebrow="PLM Login Audit",
        title="PLM登录审计",
        description="预留 PLM 账号登录 IP 合规审计模块；接口接入后独立输出趋势、矩阵和下钻明细。",
        source_label="数据源：PLM 登录记录接口",
        body_html='<section class="section-block"><p class="empty">PLM 登录审计接口待接入。</p></section>',
        enabled=enabled,
        status="disabled" if not enabled else "ready",
    )
