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


def build_tianqing_evidence_detail_result(
    args: argparse.Namespace,
    events: list[AuditEvent],
    procurement_muted_events: list[AuditEvent],
    false_positive_events: list[AuditEvent],
    false_positive_reasons: dict[str, str],
    behavior_rows: dict[str, list[list[Any]]],
    keyword_counts: Counter,
    keyword_event_map: dict[str, list[AuditEvent]],
    asset_analysis: AssetAnalysis,
    asset_as_of: datetime,
    channel_focus_metrics: str,
    internal_domains: set[str],
    tz: timezone,
    report_period: str,
    source_label: str,
) -> TianqingEvidenceDetailResult:
    events = [event for event in events if is_leadership_focus_event(event, internal_domains)]
    sidecar_pages: dict[str, str] = {}
    kpi_pages = {
        "focus": sidecar_page_filename(args, "kpi", "focus"),
        "design": sidecar_page_filename(args, "kpi", "design"),
        "design_send": sidecar_page_filename(args, "kpi", "design-send"),
        "external": sidecar_page_filename(args, "kpi", "external"),
        "mail": sidecar_page_filename(args, "kpi", "mail"),
        "external_sender": sidecar_page_filename(args, "kpi", "external-sender"),
        "im": sidecar_page_filename(args, "kpi", "im"),
        "web_upload": sidecar_page_filename(args, "kpi", "web-upload"),
        "unclear_target": sidecar_page_filename(args, "kpi", "unclear-target"),
        "lookup": sidecar_page_filename(args, "kpi", "lookup"),
        "sensitive": sidecar_page_filename(args, "kpi", "sensitive"),
        "archive": sidecar_page_filename(args, "kpi", "archive"),
        "behavior": sidecar_page_filename(args, "kpi", "behavior"),
        "3d_model": sidecar_page_filename(args, "kpi", "3d-model"),
        "2d_cad": sidecar_page_filename(args, "kpi", "2d-cad"),
        "copyout": sidecar_page_filename(args, "kpi", "copyout"),
        "procurement_muted": sidecar_page_filename(args, "kpi", "procurement-muted"),
        "false_positive": sidecar_page_filename(args, "kpi", "false-positive"),
    }
    asset_pages = {
        "old_device": sidecar_page_filename(args, "asset", "old-device"),
        "unknown_manufacture_date": sidecar_page_filename(args, "asset", "unknown-manufacture-date"),
        "old_os": sidecar_page_filename(args, "asset", "old-os"),
        "lagging_version": sidecar_page_filename(args, "asset", "lagging-version"),
        "offline": sidecar_page_filename(args, "asset", "offline"),
        "offline_7d": sidecar_page_filename(args, "asset", "offline-7d"),
        "missing_7d": sidecar_page_filename(args, "asset", "missing-7d"),
        "missing_risk": sidecar_page_filename(args, "asset", "missing-risk"),
        "suspected_uninstall": sidecar_page_filename(args, "asset", "suspected-uninstall"),
        "reinstall_excluded": sidecar_page_filename(args, "asset", "reinstall-excluded"),
    }
    keyword_links = {
        keyword: detail_page_filename(args, keyword)
        for keyword, count in keyword_counts.most_common(10)
        if count > 0
    }

    design_focus_events = [event for event in events if any(extension(name) in DESIGN_EXTS for name in leadership_file_names(event))]
    design_send_focus_events = [event for event in events if is_design_send_event(event)]
    peripheral_copy_focus_events = [event for event in events if is_peripheral_copy_event(event) and is_design_event(event)]
    three_d_focus_events = [event for event in events if is_three_d_model_event(event)]
    two_d_focus_events = [event for event in events if is_two_d_cad_event(event)]
    sensitive_focus_events = [event for event in events if event_leadership_keyword_hits(event)]
    archive_focus_events = [event for event in events if audit_matrix_bucket(event) == "压缩包"]
    external_events = [event for event in events if is_confirmed_external_event(event)]
    mail_focus_events = [event for event in events if event.topic == "mail_audit"]
    external_sender_events = [event for event in events if is_external_sender_mailbox(event)]
    im_focus_events = [
        event
        for event in events
        if audit_channel_group(event, internal_domains) == "IM附件"
    ]
    web_upload_events = [
        event
        for event in events
        if audit_channel_group(event, internal_domains) == "外部站点上传"
    ]
    unclear_target_events = [
        event
        for event in events
        if not is_confirmed_external_event(event) and not is_peripheral_copy_event(event) and not is_external_sender_mailbox(event)
    ]
    lookup_events = [event for event in events if any(key.startswith(("search_id=", "download_file_key=", "file_id=")) for key in event.lookup_keys)]

    sidecar_pages[kpi_pages["focus"]] = build_event_detail_page(
        "重点事件明细",
        events,
        args,
        tz,
        report_period,
        source_label,
        "设计资料发送/上传、外设拷贝和敏感关键词命中事件的完整明细。",
        metrics_html=channel_focus_metrics,
    )
    sidecar_pages[kpi_pages["design"]] = build_event_detail_page("设计资料总览", design_focus_events, args, tz, report_period, source_label, "设计资料总览页，已区分设计资料发送/上传与外设拷贝。")
    sidecar_pages[kpi_pages["design_send"]] = build_event_detail_page("设计资料发送/上传明细", design_send_focus_events, args, tz, report_period, source_label, "仅展示设计资料通过邮件、IM、站点上传等方式发送/上传的事件。")
    sidecar_pages[kpi_pages["copyout"]] = build_event_detail_page("外设拷贝明细", peripheral_copy_focus_events, args, tz, report_period, source_label, "仅展示设计资料拷贝到外设/介质的高敏感事件，不与对外发送/上传混淆。")
    sidecar_pages[kpi_pages["3d_model"]] = build_event_detail_page("三维模型重点明细", three_d_focus_events, args, tz, report_period, source_label, "仅包含 PRT/ASM/SLDASM/SLDPRT/STEP 三维模型强管控事件，已区分发送/上传与外设拷贝。")
    sidecar_pages[kpi_pages["2d_cad"]] = build_event_detail_page("DWG二维图纸明细", two_d_focus_events, args, tz, report_period, source_label, "仅包含 DWG 二维图纸强管控事件，已区分发送/上传与外设拷贝。")
    sidecar_pages[kpi_pages["sensitive"]] = build_event_detail_page("敏感名称事件明细", sensitive_focus_events, args, tz, report_period, source_label, "邮件主题或附件名称命中敏感词策略的外发重点事件。")
    sidecar_pages[kpi_pages["archive"]] = build_event_detail_page("压缩包事件明细", archive_focus_events, args, tz, report_period, source_label, "仅展示矩阵对象归类为压缩包的外发、上传和外设拷贝重点事件。")
    sidecar_pages[kpi_pages["external"]] = build_event_detail_page("明确外发/上传事件明细", external_events, args, tz, report_period, source_label, "日志包含外部邮箱、外部域名、高风险外联目标或外部上传地址的事件。")
    sidecar_pages[kpi_pages["mail"]] = build_event_detail_page("邮件外发事件明细", mail_focus_events, args, tz, report_period, source_label, "邮件通道事件，重点看发件箱、发件箱类型、收件邮箱、域名、主题和附件。")
    sidecar_pages[kpi_pages["external_sender"]] = build_event_detail_page("外部发件箱邮件明细", external_sender_events, args, tz, report_period, source_label, "使用非 daqo.com 发件箱发送带附件邮件的事件，需确认是否绕开公司邮箱管控。")
    sidecar_pages[kpi_pages["im"]] = build_event_detail_page("IM附件外发事件明细", im_focus_events, args, tz, report_period, source_label, "IM通道附件发送事件；具体IM渠道在明细“通道”列展示，接收方未匹配时需回查确认内外部关系。")
    sidecar_pages[kpi_pages["web_upload"]] = build_event_detail_page("外部站点上传明细", web_upload_events, args, tz, report_period, source_label, "明确外部站点上传的重点事件，内部系统上传和软件同步噪音不进入本页。")
    sidecar_pages[kpi_pages["unclear_target"]] = build_event_detail_page("接收方未取到/待判定明细", unclear_target_events, args, tz, report_period, source_label, "当前日志未提供明确外部接收方或目标的事件，只作为疑似外发/待回查线索，不等同于明确外发。")
    sidecar_pages[kpi_pages["lookup"]] = build_event_detail_page("可回查线索事件明细", lookup_events, args, tz, report_period, source_label, "包含 search_id、download_file_key 或 file_id 的可回查事件。")
    sidecar_pages[kpi_pages["procurement_muted"]] = build_event_detail_page(
        "已降噪正常采购询价明细",
        procurement_muted_events,
        args,
        tz,
        report_period,
        source_label,
        "命中采购询价正常业务场景，且不含设计图纸、高风险外联目标、外设拷贝、超大文件、数据库/源码或非采购敏感关键词；仅从首页和普通异常噪音中降噪，审计底稿仍保留。",
    )
    sidecar_pages[kpi_pages["false_positive"]] = build_false_positive_detail_page(
        "已判定误判/低置信噪音明细",
        false_positive_events,
        false_positive_reasons,
        args,
        tz,
        report_period,
        source_label,
        "包含 FILEASSIST 自传、应用发送伴随重复记录，以及无接收方且非硬管控对象的低置信应用发送记录；不计入首页矩阵和终端排行。",
    )
    sidecar_pages[kpi_pages["behavior"]] = build_behavior_detail_page(behavior_rows, report_period, source_label)

    if asset_analysis.available:
        sidecar_pages[asset_pages["old_device"]] = build_asset_detail_page(
            "5年以上设备明细",
            asset_analysis.old_device_assets,
            args,
            tz,
            report_period,
            source_label,
            "按 board_bios 末尾日期解析设备出厂日期，筛选 5 年以上设备。",
            asset_as_of,
        )
        sidecar_pages[asset_pages["unknown_manufacture_date"]] = build_asset_detail_page(
            "未知出厂日期终端",
            asset_analysis.unknown_manufacture_assets,
            args,
            tz,
            report_period,
            source_label,
            "board_bios 未包含可解析出厂日期的终端，需结合天擎资产详情或厂商信息补齐。",
            asset_as_of,
        )
        sidecar_pages[asset_pages["old_os"]] = build_asset_detail_page(
            "老旧操作系统终端",
            asset_analysis.old_os_assets,
            args,
            tz,
            report_period,
            source_label,
            "Windows 7/8/XP/Server 以及 Windows 10 21H1 及更早版本按老旧系统提示。",
            asset_as_of,
        )
        sidecar_pages[asset_pages["lagging_version"]] = build_asset_detail_page(
            "版本落后或未知终端",
            asset_analysis.lagging_version_assets,
            args,
            tz,
            report_period,
            source_label,
            "病毒库、补丁或主程序低于当前最高版本，或关键版本字段为空的终端。",
            asset_as_of,
        )
        sidecar_pages[asset_pages["offline"]] = build_asset_detail_page(
            "当前离线终端",
            asset_analysis.offline_assets,
            args,
            tz,
            report_period,
            source_label,
            "天擎最新资产状态显示 is_online=false 的终端；离线时长按 online_info.last_time 计算。",
            asset_as_of,
        )
        sidecar_pages[asset_pages["offline_7d"]] = build_asset_detail_page(
            "天擎离线超7天终端",
            asset_analysis.long_offline_assets,
            args,
            tz,
            report_period,
            source_label,
            "天擎最新资产状态显示离线，且最后在线时间距统计截止超过 7 天；last_time 缺失的离线终端也进入本页待核对。",
            asset_as_of,
        )
        sidecar_pages[asset_pages["missing_7d"]] = build_asset_detail_page(
            "7天未观察到终端",
            asset_analysis.missing_assets,
            args,
            tz,
            report_period,
            source_label,
            "连续 7 天没有资产概况或审计日志观察到的终端，仅代表长期未观察到，不等同确认卸载。",
            asset_as_of,
        )
        sidecar_pages[asset_pages["missing_risk"]] = build_asset_detail_page(
            "消失前有风险行为终端",
            asset_analysis.high_attention_missing_assets,
            args,
            tz,
            report_period,
            source_label,
            "长期未观察到，且近 30 天存在设计图纸、外设拷贝、个人邮箱或高风险外发线索的终端。",
            asset_as_of,
        )
        sidecar_pages[asset_pages["suspected_uninstall"]] = build_asset_detail_page(
            "疑似已卸载终端",
            asset_analysis.suspected_uninstalled_assets,
            args,
            tz,
            report_period,
            source_label,
            "30 天未观察到该 client_id，且未发现同一主板序列号/MAC/MID 以新 client_id 重装上线；当前无显式卸载事件时按此口径提示。",
            asset_as_of,
        )
        sidecar_pages[asset_pages["reinstall_excluded"]] = build_asset_detail_page(
            "卸载重装排除清单",
            asset_analysis.reinstall_excluded_assets,
            args,
            tz,
            report_period,
            source_label,
            "旧 client_id 长期未观察，但同一主板序列号/MAC/MID 后续以其他 client_id 出现，视为卸载重装或重新纳管，不计入疑似已卸载。",
            asset_as_of,
        )

    for keyword, count in keyword_counts.most_common(10):
        if count <= 0:
            continue
        detail_events = sorted(keyword_event_map[keyword], key=event_priority_sort_key)
        detail_metrics = detail_metric_chips(
            [
                ("命中次数", count, "该敏感词在重点事件中的命中次数"),
                ("事件数", len(detail_events), "命中该敏感词的重点事件数"),
                ("设计资料", sum(1 for event in detail_events if is_design_event(event)), "同时包含设计资料后缀的事件"),
                ("明确外部", sum(1 for event in detail_events if event.recipient_relation in EXTERNAL_RELATIONS), "接收方为外部/客户/供应商/合作方"),
            ]
        )
        detail_body = f"""
    {detail_hero_html(f"敏感命中详情：{keyword}", "敏感名称明细", report_period, source_label, "仅展示命中该词的外发重点事件，不展示原始消息正文。", "命中次数", count)}
    {detail_metrics}
    <section class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Keyword Evidence</span>
          <h2>命中事件清单</h2>
        </div>
        <span class="section-count">共 {len(detail_events)} 条</span>
      </div>
      {event_detail_table_html(detail_events, tz, keyword=keyword, page_size=10, asset_by_terminal=getattr(args, "asset_by_terminal", {}), recipient_map=getattr(args, "recipient_map_loaded", {}) or {})}
    </section>
"""
        sidecar_pages[keyword_links[keyword]] = html_detail_document(f"敏感命中详情：{keyword}", detail_body)

    return TianqingEvidenceDetailResult(
        sidecar_pages=sidecar_pages,
        kpi_pages=kpi_pages,
        asset_pages=asset_pages,
        keyword_links=keyword_links,
    )
