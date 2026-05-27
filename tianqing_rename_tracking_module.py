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


def three_d_rename_is_confirmed(finding: ThreeDRenameFinding) -> bool:
    return finding.destination_confidence in THREE_D_RENAME_CONFIRMED_CONFIDENCES


def three_d_rename_is_outbound_or_copy(finding: ThreeDRenameFinding) -> bool:
    channel = (finding.destination_channel or "").split("/", 1)[0]
    return three_d_rename_is_confirmed(finding) and channel in THREE_D_RENAME_OUTBOUND_CHANNELS


def three_d_rename_change_label(finding: ThreeDRenameFinding) -> str:
    exts: list[str] = []
    for path in finding.rename_chain_paths or [finding.old_path, finding.new_path]:
        ext = path_extension(path) or "无后缀"
        if not exts or exts[-1] != ext:
            exts.append(ext)
    if not exts:
        new_ext = finding.new_ext or "无后缀"
        exts = [finding.old_ext or "-", new_ext]
    if len(exts) == 1 and finding.critical_design_label:
        return f"{exts[0]}更名"
    return "→".join(exts)


def three_d_rename_chain_cell(finding: ThreeDRenameFinding) -> HtmlCell:
    names = finding.rename_chain_names or [finding.old_name, finding.new_name]
    paths = finding.rename_chain_paths or [finding.old_path, finding.new_path]
    compact_names = [compact_id(name, 28) for name in names if name]
    display = " → ".join(compact_names) if compact_names else "-"
    title = " → ".join(path for path in paths if path) or display
    return tooltip_cell(display, title)


def three_d_rename_type_label(finding: ThreeDRenameFinding) -> str:
    if three_d_rename_is_suffix_mask(finding):
        if finding.critical_design_label:
            return finding.critical_design_label + "伪装"
        return "三维图纸伪装"
    if finding.critical_design_label:
        return finding.critical_design_label + "更名外发"
    return "三维图纸伪装"


def three_d_rename_card_html(label: str, value: Any, note: str, href: str | None, tone: str = "blue") -> str:
    inner = f"""
        <div class="rename-card-main">
          <span>{esc(label)}</span>
          <strong>{esc(value)}</strong>
        </div>
        <em>{esc(note)}</em>
    """
    if href:
        return f'<a class="rename-card rename-card-{esc(tone)}" href="{esc(href)}" title="{esc(note)}">{inner}</a>'
    return f'<div class="rename-card rename-card-{esc(tone)}" title="{esc(note)}">{inner}</div>'


def standard_design_rename_outbound(finding: ThreeDRenameFinding) -> bool:
    return bool(finding.critical_design_label) and not three_d_rename_is_suffix_mask(finding) and three_d_rename_is_outbound_or_copy(finding)


def three_d_rename_home_html(findings: list[ThreeDRenameFinding], links: dict[str, str]) -> str:
    total = len(findings)
    confirmed = sum(1 for finding in findings if three_d_rename_is_confirmed(finding))
    unresolved = sum(1 for finding in findings if finding.tracking_status == "未发现后续去向")
    outbound = sum(1 for finding in findings if three_d_rename_is_outbound_or_copy(finding))
    current_period = sum(1 for finding in findings if finding.in_report_period)
    rolling = max(0, total - current_period)
    change_counts = Counter(three_d_rename_change_label(finding) for finding in findings)
    top_change, top_change_count = ("-", 0)
    if change_counts:
        top_change, top_change_count = change_counts.most_common(1)[0]
    empty_text = ""
    if total <= 0:
        empty_text = '<p class="rename-empty">本周期及滚动追踪范围内未发现三维图纸后缀伪装记录。</p>'
    cards = [
        three_d_rename_card_html("伪装总数", total, f"本周期新增 {current_period} 条，跨周期未闭环 {rolling} 条", links.get("all"), "red"),
        three_d_rename_card_html("已发现后续去向", confirmed, "强匹配或可信匹配，点击查看追踪链路", links.get("confirmed"), "blue"),
        three_d_rename_card_html("未发现后续去向", unresolved, "仍需滚动追踪，后续周期继续回查", links.get("unresolved"), "amber"),
        three_d_rename_card_html("已外发/外设", outbound, "最终去向为邮件、IM、外部站点上传或外设拷贝", links.get("outbound"), "violet"),
        three_d_rename_card_html("主要后缀变化", f"{top_change} · {top_change_count}", "按后缀伪装变化聚合的最高频组合", links.get("top_change"), "slate"),
    ]
    return f"""
    <section id="three-d-rename-tracking" class="section-block rename-tracking-shell">
      <div class="section-title-row">
        <div>
          <span class="section-eyebrow">3D Masquerade Tracking</span>
          <h2>三维图纸后缀伪装追踪</h2>
          <p>识别 PRT/ASM/SLDASM/SLDPRT/STEP 等核心三维图纸被改成非三维后缀的行为，并向后追踪该文件的可观测去向。</p>
        </div>
      </div>
      <div class="rename-card-grid">{"".join(cards)}</div>
      {empty_text}
    </section>
"""


def standard_design_rename_home_html(findings: list[ThreeDRenameFinding], links: dict[str, str]) -> str:
    total = len(findings)
    current_period = sum(1 for finding in findings if finding.in_report_period)
    structure = [finding for finding in findings if finding.critical_design_label == CRITICAL_STRUCTURE_LABEL]
    electrical = [finding for finding in findings if finding.critical_design_label == CRITICAL_ELECTRICAL_LABEL]
    yb_standard = [finding for finding in findings if finding.critical_design_label == CRITICAL_YB_STANDARD_LABEL]
    channel_counts = Counter((finding.destination_channel or "未知去向").split("/", 1)[0] for finding in findings)
    top_channel, top_channel_count = ("-", 0)
    if channel_counts:
        top_channel, top_channel_count = channel_counts.most_common(1)[0]
    empty_text = ""
    if total <= 0:
        empty_text = '<p class="rename-empty">本周期及滚动追踪范围内未发现结构/电气/标准图纸更名后外发或外设拷贝记录。</p>'
    cards = [
        three_d_rename_card_html("预警总数", total, f"标准图纸更名后发现外发/外设，本周期新增 {current_period} 条", links.get("all"), "red"),
        three_d_rename_card_html("结构", len(structure), "结构标准方案更名后外发/外设", links.get("structure"), "violet"),
        three_d_rename_card_html("电气", len(electrical), "电气标准方案更名后外发/外设", links.get("electrical"), "amber"),
        three_d_rename_card_html("油变", len(yb_standard), "3YB/5YB/8YB 油变标准方案更名后外发/外设", links.get("yb_standard"), "blue"),
        three_d_rename_card_html("主要去向", f"{top_channel} · {top_channel_count}", "按最终可观测去向聚合", links.get("top_channel"), "slate"),
    ]
    return f"""
    <section id="standard-design-rename-alert" class="section-block rename-tracking-shell standard-design-alert-shell">
      <div class="section-title-row">
        <div>
          <span class="section-eyebrow">Critical Drawing Rename Alert</span>
          <h2>标准图纸更名外发预警</h2>
          <p>结构/电气/标准图纸仅更名不示警；一旦更名后追踪到邮件、IM、外部站点上传或外设拷贝，即作为严重违规单独预警。</p>
        </div>
      </div>
      <div class="rename-card-grid rename-card-grid-compact">{"".join(cards)}</div>
      {empty_text}
    </section>
"""


def three_d_rename_detail_rows(findings: list[ThreeDRenameFinding], tz: timezone) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for finding in sorted(
        findings,
        key=lambda item: (
            0 if item.tracking_status == "未发现后续去向" else 1,
            item.rename_ts or datetime.min.replace(tzinfo=tz),
        ),
        reverse=True,
    ):
        destination_text = finding.destination_channel or "未发现后续去向"
        if finding.destination_target:
            destination_text += " / " + finding.destination_target
        rows.append(
            [
                format_ts(finding.rename_ts, tz),
                finding.company or "-",
                finding.department or "-",
                finding.person or "-",
                finding.client_ip or "-",
                finding.client_mac or "-",
                three_d_rename_type_label(finding),
                tooltip_cell(finding.old_name or "-", finding.old_path or finding.old_name or "-"),
                tooltip_cell(finding.new_name or "-", finding.new_path or finding.new_name or "-"),
                three_d_rename_change_label(finding),
                three_d_rename_chain_cell(finding),
                finding.process_name or "-",
                finding.tracking_status,
                tooltip_cell(finding.destination_channel or "未发现后续去向", destination_text),
                finding.destination_confidence or "-",
                format_ts(finding.destination_ts, tz) if finding.destination_ts else "-",
                tooltip_cell(finding.destination_target or "-", destination_text),
            ]
        )
    return rows


def build_three_d_rename_detail_page(
    title: str,
    findings: list[ThreeDRenameFinding],
    tz: timezone,
    report_period: str,
    source_label: str,
    note: str,
    context_label: str = "图纸更名追踪",
    section_title: str = "图纸更名追踪清单",
    primary_metric_note: str = "本页展示三维后缀伪装，以及标准图纸更名后外发/外设记录",
) -> str:
    confirmed = sum(1 for finding in findings if three_d_rename_is_confirmed(finding))
    unresolved = sum(1 for finding in findings if finding.tracking_status == "未发现后续去向")
    outbound = sum(1 for finding in findings if three_d_rename_is_outbound_or_copy(finding))
    current_period = sum(1 for finding in findings if finding.in_report_period)
    metrics = detail_metric_chips(
        [
            ("记录数", len(findings), primary_metric_note),
            ("本周期新增", current_period, "改名动作发生在当前报告周期内"),
            ("已发现去向", confirmed, "强匹配或可信匹配的后续去向"),
            ("未发现去向", unresolved, "尚未从日志中发现后续去向"),
            ("已外发/外设", outbound, "后续去向为外发、上传或外设拷贝"),
        ]
    )
    body = f"""
    {detail_hero_html(title, context_label, report_period, source_label + " + ClickHouse:tianqing.raw_syslog", note, "记录数", len(findings))}
    {metrics}
    <section class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Rename Tracking</span>
          <h2>{esc(section_title)}</h2>
        </div>
        <span class="section-count">共 {len(findings)} 条</span>
      </div>
      {html_table(["时间", "公司", "部门", "使用人", "IP地址", "MAC地址", "类型", "原文件", "改名后文件", "后缀链路", "改名链路", "进程", "追踪状态", "最终去向", "匹配可信度", "去向时间", "目标/通道"], three_d_rename_detail_rows(findings, tz), "events three-d-rename", page_size=20)}
      <p class="note">最终去向按可观测日志判断；未发现后续去向不代表文件没有其他未记录流转。低可信记录只用于人工复核，不计入首页已确认去向。</p>
    </section>
"""
    return html_detail_document(title, body)


def build_tianqing_rename_tracking_result(
    args: argparse.Namespace,
    findings: list[ThreeDRenameFinding],
    tz: timezone,
    report_period: str,
    source_label: str,
) -> TianqingRenameTrackingResult:
    three_d_suffix_findings = [
        finding for finding in findings if three_d_rename_is_suffix_mask(finding)
    ]
    standard_rename_findings = [
        finding for finding in findings if standard_design_rename_outbound(finding)
    ]
    three_d_rename_confirmed = [
        finding for finding in three_d_suffix_findings if three_d_rename_is_confirmed(finding)
    ]
    three_d_rename_unresolved = [
        finding for finding in three_d_suffix_findings if finding.tracking_status == "未发现后续去向"
    ]
    three_d_rename_outbound = [
        finding for finding in three_d_suffix_findings if three_d_rename_is_outbound_or_copy(finding)
    ]
    change_counts = Counter(three_d_rename_change_label(finding) for finding in three_d_suffix_findings)
    top_change_label = change_counts.most_common(1)[0][0] if change_counts else ""
    three_d_rename_top_change = [
        finding for finding in three_d_suffix_findings if top_change_label and three_d_rename_change_label(finding) == top_change_label
    ]
    standard_rename_structure = [
        finding for finding in standard_rename_findings if finding.critical_design_label == CRITICAL_STRUCTURE_LABEL
    ]
    standard_rename_electrical = [
        finding for finding in standard_rename_findings if finding.critical_design_label == CRITICAL_ELECTRICAL_LABEL
    ]
    standard_rename_yb = [
        finding for finding in standard_rename_findings if finding.critical_design_label == CRITICAL_YB_STANDARD_LABEL
    ]
    standard_channel_counts = Counter((finding.destination_channel or "未知去向").split("/", 1)[0] for finding in standard_rename_findings)
    standard_top_channel = standard_channel_counts.most_common(1)[0][0] if standard_channel_counts else ""
    standard_rename_top_channel = [
        finding for finding in standard_rename_findings if standard_top_channel and (finding.destination_channel or "未知去向").split("/", 1)[0] == standard_top_channel
    ]

    three_d_links = {
        "all": sidecar_page_filename(args, "rename-3d", "all"),
        "confirmed": sidecar_page_filename(args, "rename-3d", "confirmed"),
        "unresolved": sidecar_page_filename(args, "rename-3d", "unresolved"),
        "outbound": sidecar_page_filename(args, "rename-3d", "outbound"),
        "top_change": sidecar_page_filename(args, "rename-3d", "top-change"),
    }
    standard_links = {
        "all": sidecar_page_filename(args, "rename-standard", "all"),
        "structure": sidecar_page_filename(args, "rename-standard", "structure"),
        "electrical": sidecar_page_filename(args, "rename-standard", "electrical"),
        "yb_standard": sidecar_page_filename(args, "rename-standard", "yb-standard"),
        "top_channel": sidecar_page_filename(args, "rename-standard", "top-channel"),
    }
    sidecar_pages = {
        three_d_links["all"]: build_three_d_rename_detail_page(
            "三维图纸后缀伪装追踪",
            three_d_suffix_findings,
            tz,
            report_period,
            source_label,
            "三维模型后缀被改成非三维后缀的高风险伪装行为，含跨周期未闭环追踪。",
            context_label="三维伪装追踪",
            section_title="三维图纸后缀伪装追踪清单",
            primary_metric_note="本页仅展示三维图纸后缀伪装记录",
        ),
        three_d_links["confirmed"]: build_three_d_rename_detail_page(
            "三维伪装已发现后续去向",
            three_d_rename_confirmed,
            tz,
            report_period,
            source_label,
            "仅展示强匹配或可信匹配到后续动作的三维后缀伪装记录。",
            context_label="三维伪装追踪",
            section_title="三维图纸后缀伪装追踪清单",
            primary_metric_note="本页仅展示已发现后续去向的三维后缀伪装记录",
        ),
        three_d_links["unresolved"]: build_three_d_rename_detail_page(
            "三维伪装未发现后续去向",
            three_d_rename_unresolved,
            tz,
            report_period,
            source_label,
            "尚未从日志中发现后续去向的三维后缀伪装记录，后续周期会继续滚动追踪。",
            context_label="三维伪装追踪",
            section_title="三维图纸后缀伪装追踪清单",
            primary_metric_note="本页仅展示未发现后续去向的三维后缀伪装记录",
        ),
        three_d_links["outbound"]: build_three_d_rename_detail_page(
            "三维伪装已外发/外设",
            three_d_rename_outbound,
            tz,
            report_period,
            source_label,
            "最终去向为邮件、IM、外部站点上传或外设拷贝的三维后缀伪装记录。",
            context_label="三维伪装追踪",
            section_title="三维图纸后缀伪装追踪清单",
            primary_metric_note="本页仅展示已外发或外设拷贝的三维后缀伪装记录",
        ),
        three_d_links["top_change"]: build_three_d_rename_detail_page(
            f"最高频后缀变化：{top_change_label or '-'}",
            three_d_rename_top_change,
            tz,
            report_period,
            source_label,
            "按本次追踪结果中最高频的三维后缀伪装变化组合过滤。",
            context_label="三维伪装追踪",
            section_title="三维图纸后缀伪装追踪清单",
            primary_metric_note="本页按最高频三维后缀伪装变化过滤",
        ),
        standard_links["all"]: build_three_d_rename_detail_page(
            "油变标准方案更名外发预警",
            standard_rename_findings,
            tz,
            report_period,
            source_label,
            "结构/电气/标准图纸仅更名不示警；更名后追踪到外发、上传或外设拷贝才进入本预警。",
            context_label="标准图纸更名外发",
            section_title="标准图纸更名外发预警清单",
            primary_metric_note="本页仅展示结构/电气/标准图纸更名后外发或外设拷贝记录",
        ),
        standard_links["structure"]: build_three_d_rename_detail_page(
            "结构标准图纸更名外发预警",
            standard_rename_structure,
            tz,
            report_period,
            source_label,
            "结构标准方案图纸更名后追踪到外发、上传或外设拷贝的记录。",
            context_label="结构更名外发",
            section_title="结构标准图纸更名外发预警清单",
            primary_metric_note="本页仅展示结构标准图纸更名后外发或外设拷贝记录",
        ),
        standard_links["electrical"]: build_three_d_rename_detail_page(
            "电气标准图纸更名外发预警",
            standard_rename_electrical,
            tz,
            report_period,
            source_label,
            "电气标准方案图纸更名后追踪到外发、上传或外设拷贝的记录。",
            context_label="电气更名外发",
            section_title="电气标准图纸更名外发预警清单",
            primary_metric_note="本页仅展示电气标准图纸更名后外发或外设拷贝记录",
        ),
        standard_links["yb_standard"]: build_three_d_rename_detail_page(
            "标准图纸更名外发预警",
            standard_rename_yb,
            tz,
            report_period,
            source_label,
            "3YB/5YB/8YB 油变标准方案更名后追踪到外发、上传或外设拷贝的记录。",
            context_label="标准更名外发",
            section_title="油变标准方案更名外发预警清单",
            primary_metric_note="本页仅展示 3YB/5YB/8YB 油变标准方案更名后外发或外设拷贝记录",
        ),
        standard_links["top_channel"]: build_three_d_rename_detail_page(
            f"标准图纸更名外发主要去向：{standard_top_channel or '-'}",
            standard_rename_top_channel,
            tz,
            report_period,
            source_label,
            "按本次标准图纸更名外发预警中最高频的最终去向过滤。",
            context_label="标准图纸更名外发",
            section_title="标准图纸更名外发预警清单",
            primary_metric_note="本页按标准图纸更名外发最高频去向过滤",
        ),
    }
    return TianqingRenameTrackingResult(
        three_d_block_html=three_d_rename_home_html(three_d_suffix_findings, three_d_links),
        standard_block_html=standard_design_rename_home_html(standard_rename_findings, standard_links),
        sidecar_pages=sidecar_pages,
        three_d_links=three_d_links,
        standard_links=standard_links,
    )
