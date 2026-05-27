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
from typing import Any, Callable


def bind_runtime_dependencies(namespace: dict[str, Any]) -> None:
    for key, value in namespace.items():
        if key.startswith("__"):
            continue
        globals()[key] = value


DECRYPT_OBJECT_ORDER = ["结构", "电气", "三维模型", "DWG图纸", "压缩包", "其他"]
DECRYPT_TREND_OBJECTS = ["结构", "电气", "三维模型", "DWG图纸"]
DECRYPT_TREND_COLORS = {
    "结构": "#7c3aed",
    "电气": "#b45309",
    "三维模型": "#be123c",
    "DWG图纸": "#2563eb",
}
DECRYPT_MATRIX_COLUMNS = DECRYPT_OBJECT_ORDER


def decrypt_has_followup(record: DecryptRiskRecord) -> bool:
    return bool(record.followup_confidence)


def decrypt_standard_records(records: list[DecryptRiskRecord]) -> list[DecryptRiskRecord]:
    return [record for record in records if record.object_bucket in {"结构", "电气", "标准"}]


def decrypt_card_html(label: str, value: Any, note: str, href: str | None, tone: str = "blue") -> str:
    inner = f"""
        <div class="decrypt-mini-card-main">
          <span>{esc(label)}</span>
          <strong>{esc(value)}</strong>
        </div>
        <em>{esc(note)}</em>
    """
    if href:
        return f'<a class="decrypt-mini-card decrypt-mini-card-{esc(tone)}" href="{esc(href)}" title="{esc(note)}">{inner}</a>'
    return f'<div class="decrypt-mini-card decrypt-mini-card-{esc(tone)}" title="{esc(note)}">{inner}</div>'


def decrypt_company_label(record: DecryptRiskRecord) -> str:
    return str(record.company or record.raw_company or UNMATCHED_COMPANY_LABEL).strip() or UNMATCHED_COMPANY_LABEL


def decrypt_department_label(record: DecryptRiskRecord) -> str:
    return str(record.department or record.raw_department or UNMATCHED_DEPARTMENT_LABEL).strip() or UNMATCHED_DEPARTMENT_LABEL


def decrypt_top_labels(records: list[DecryptRiskRecord], label_fn: Callable[[DecryptRiskRecord], str], limit: int = 5) -> list[str]:
    counts: Counter = Counter()
    for record in records:
        if not record.org_matched:
            continue
        label = label_fn(record)
        if identity_value_unmatched(label):
            continue
        counts[label] += 1
    return [label for label, _count in counts.most_common(limit)]


def decrypt_counter_for(
    records: list[DecryptRiskRecord],
    label_fn: Callable[[DecryptRiskRecord], str],
    *,
    skip_unmatched: bool = True,
) -> Counter:
    counts: Counter = Counter()
    for record in records:
        label = str(label_fn(record) or "").strip()
        if not label:
            continue
        if skip_unmatched and (not record.org_matched or identity_value_unmatched(label)):
            continue
        counts[label] += 1
    return counts


def decrypt_object_short_label(bucket: str) -> str:
    return {"三维模型": "三维", "DWG图纸": "DWG", "压缩包": "压缩"}.get(bucket, bucket)


def decrypt_rule_risk_overview_html(
    analysis: DecryptRiskAnalysis,
    links: dict[str, str],
) -> str:
    records = analysis.records
    total = len(records)
    object_counts: Counter = Counter(record.object_bucket for record in records)
    structure_count = int(object_counts.get("结构", 0) or 0)
    electrical_count = int(object_counts.get("电气", 0) or 0)
    standard_count = structure_count + electrical_count
    three_d_count = int(object_counts.get("三维模型", 0) or 0)
    dwg_count = int(object_counts.get("DWG图纸", 0) or 0)
    archive_count = int(object_counts.get("压缩包", 0) or 0)
    linked_records = [record for record in records if decrypt_has_followup(record)]
    linked_count = len(linked_records)
    unmatched_count = sum(1 for record in records if not record.org_matched)
    top_object, top_object_count = risk_overview_top_label(object_counts)
    company_counts = decrypt_counter_for(records, decrypt_company_label)
    department_counts = decrypt_counter_for(records, decrypt_department_label)
    top_company, top_company_count = risk_overview_top_label(company_counts)
    top_department, top_department_count = risk_overview_top_label(department_counts)
    followup_counts = Counter(record.followup_channel or "未发现后续外发/拷贝线索" for record in linked_records)
    top_followup, top_followup_count = risk_overview_top_label(followup_counts)
    trend_total = len(analysis.trend_records)
    trend_company_counts = decrypt_counter_for(analysis.trend_records, decrypt_company_label)
    trend_company, trend_company_count = risk_overview_top_label(trend_company_counts)

    if analysis.error and not total:
        conclusions = [f"解密记录分析暂不可用：{analysis.error}。"]
    elif total:
        conclusions = [
            (
                f"本期加密软件解密审计记录 {total} 条，其中标准图纸 {standard_count} 条"
                f"（结构 {structure_count} / 电气 {electrical_count}）；标准图纸解密按最高关注对象复核。"
            ),
            (
                f"对象结构为三维模型 {three_d_count} 条、DWG图纸 {dwg_count} 条、压缩包 {archive_count} 条；"
                f"最高频对象为 {decrypt_object_short_label(top_object)} {top_object_count} 条。"
            ),
            (
                f"组织侧优先看 {top_company} {top_company_count} 条、{top_department} {top_department_count} 条；"
                f"未完成组织映射 {unmatched_count} 条，不参与公司解密风险矩阵比较。"
            ),
            (
                f"解密后 30 天内发现同名文件后续流转线索 {linked_count} 条，"
                f"主要后续通道为 {top_followup} {top_followup_count} 条；该线索为疑似关联，需结合审批单和天擎附件复核。"
            ),
            (
                f"近30天解密趋势累计 {trend_total} 条，趋势组织侧 Top 为 {trend_company} {trend_company_count} 条；"
                "管理动作建议先复核标准图纸，再复核三维/DWG与后续流转链路。"
            ),
        ]
    else:
        conclusions = [
            "本期暂无解密记录进入报告，仍保留近30天趋势和公司矩阵入口用于后续导入后复核。",
            "标准图纸、三维模型和 DWG 图纸解密仍按独立审计源追踪，不与天擎外发通道矩阵混算。",
        ]

    conclusion_html = "".join(f"<li>{esc(item)}</li>" for item in conclusions)
    return f"""
    <section id="decrypt-risk-overview" class="section-block risk-overview-shell decrypt-overview-shell">
      <div class="section-title-row">
        <div>
          <span class="section-eyebrow">Rule Overview</span>
          <h2>加密软件解密规则风险概览</h2>
          <p>基于解密记录、标准图纸识别、组织别名映射和同名文件后续流转线索生成管理结论；不使用 AI 推断。</p>
        </div>
      </div>
      <div class="risk-overview-hero">
        <div class="risk-overview-conclusions">
          <span>管理结论</span>
          <ul>{conclusion_html}</ul>
        </div>
      </div>
    </section>
"""


def decrypt_trend_series_for_labels(
    records: list[DecryptRiskRecord],
    days: list[date],
    labels: list[str],
    label_fn: Callable[[DecryptRiskRecord], str],
    tz: timezone,
    colors: list[str] | None = None,
) -> list[dict[str, Any]]:
    counts: dict[str, Counter] = {label: Counter() for label in labels}
    for record in records:
        if not record.apply_time:
            continue
        label = label_fn(record)
        if label not in counts:
            continue
        counts[label][record.apply_time.astimezone(tz).date()] += 1
    color_values = colors or TREND_COLORS
    return [
        {
            "label": label,
            "current": [counts[label][day] for day in days],
            "current_total": sum(counts[label].values()),
            "color": color_values[idx % len(color_values)],
        }
        for idx, label in enumerate(labels)
    ]


def decrypt_trend_script() -> str:
    return """
      <script>
        (function () {
          var scope = document.querySelector("#decrypt-risk-tracking");
          if (!scope || scope.getAttribute("data-decrypt-trend-ready") === "1") {
            return;
          }
          scope.setAttribute("data-decrypt-trend-ready", "1");
          function parseJsonArray(raw) {
            try {
              var parsed = JSON.parse(raw || "[]");
              return Array.isArray(parsed) ? parsed : [];
            } catch (err) {
              return [];
            }
          }
          function ensureTip() {
            var tip = document.querySelector(".trend-hover-tip");
            if (!tip) {
              tip = document.createElement("div");
              tip.className = "trend-hover-tip";
              document.body.appendChild(tip);
            }
            return tip;
          }
          function translateX(group) {
            var line = group.querySelector(".trend-line");
            var transform = line ? (line.getAttribute("transform") || "") : "";
            var match = transform.match(/translate\\(([-\\d.]+)/);
            return match ? Number(match[1]) || 0 : 0;
          }
          function pathPoints(group) {
            var path = group.querySelector(".trend-line");
            var raw = path ? (path.getAttribute("d") || "") : "";
            var points = [];
            raw.replace(/(-?\\d+(?:\\.\\d+)?),(-?\\d+(?:\\.\\d+)?)/g, function (_, x, y) {
              points.push({x: Number(x), y: Number(y)});
              return "";
            });
            return points;
          }
          function trendText(group, evt) {
            var direct = evt && evt.target && evt.target.getAttribute && evt.target.getAttribute("data-trend-tip");
            if (direct) {
              return direct;
            }
            var label = group.getAttribute("data-trend-label") || "";
            var values = parseJsonArray(group.getAttribute("data-trend-values")).map(function (value) { return Number(value) || 0; });
            var buckets = parseJsonArray(group.getAttribute("data-trend-buckets"));
            var total = Number(group.getAttribute("data-trend-total") || 0);
            var points = pathPoints(group);
            if (!points.length) {
              return label ? (label + " 合计 " + total + " 条") : "";
            }
            var idx = 0;
            if (evt && isFinite(evt.clientX)) {
              var svg = group.closest("svg");
              var rect = svg.getBoundingClientRect();
              var viewW = svg.viewBox && svg.viewBox.baseVal ? svg.viewBox.baseVal.width : rect.width;
              var localX = (evt.clientX - rect.left) * viewW / Math.max(rect.width, 1) - translateX(group);
              var best = Infinity;
              points.forEach(function (point, pointIdx) {
                var distance = Math.abs(point.x - localX);
                if (distance < best) {
                  best = distance;
                  idx = pointIdx;
                }
              });
            }
            return (label || "趋势") + " " + (buckets[idx] || ("第" + (idx + 1) + "点")) + "：" + (values[idx] || 0) + " 条 / 合计 " + total + " 条";
          }
          function showTip(group, evt) {
            var tip = ensureTip();
            if (!group || group.classList.contains("is-hidden")) {
              tip.style.display = "none";
              return;
            }
            var text = trendText(group, evt);
            if (!text) {
              return;
            }
            tip.textContent = text;
            tip.style.display = "block";
            var x = evt && isFinite(evt.clientX) ? evt.clientX + 12 : 24;
            var y = evt && isFinite(evt.clientY) ? evt.clientY + 12 : 24;
            tip.style.left = Math.min(x, window.innerWidth - tip.offsetWidth - 12) + "px";
            tip.style.top = Math.min(y, window.innerHeight - tip.offsetHeight - 12) + "px";
          }
          Array.prototype.forEach.call(scope.querySelectorAll("[data-trend-toggle]"), function (toggle) {
            toggle.addEventListener("click", function () {
              var key = toggle.getAttribute("data-trend-toggle");
              var hidden = !toggle.classList.contains("is-muted");
              toggle.classList.toggle("is-muted", hidden);
              toggle.setAttribute("aria-pressed", hidden ? "false" : "true");
              Array.prototype.forEach.call(scope.querySelectorAll('[data-trend-line="' + key + '"]'), function (line) {
                line.classList.toggle("is-hidden", hidden);
              });
            });
          });
          Array.prototype.forEach.call(scope.querySelectorAll(".trend-line-group"), function (group) {
            group.addEventListener("mousemove", function (evt) { showTip(group, evt); });
            group.addEventListener("click", function (evt) { showTip(group, evt); });
            group.addEventListener("focus", function (evt) { showTip(group, evt); });
            group.addEventListener("mouseleave", function () { ensureTip().style.display = "none"; });
            group.addEventListener("blur", function () { ensureTip().style.display = "none"; });
          });
        })();
      </script>
"""


def decrypt_trend_svg(
    current_records: list[DecryptRiskRecord],
    trend_records: list[DecryptRiskRecord],
    tz: timezone,
    end: datetime | None,
) -> str:
    trend_end = (end or datetime.now(tz)).astimezone(tz).date()
    days = [trend_end - timedelta(days=offset) for offset in range(29, -1, -1)]
    counts: dict[str, Counter] = {name: Counter() for name in DECRYPT_TREND_OBJECTS}
    for record in trend_records:
        if record.object_bucket not in counts or not record.apply_time:
            continue
        counts[record.object_bucket][record.apply_time.astimezone(tz).date()] += 1
    labels = [day.strftime("%m-%d") for day in days]
    series = [
        {
            "label": name,
            "current": [counts[name][day] for day in days],
            "current_total": sum(counts[name].values()),
            "color": DECRYPT_TREND_COLORS[name],
        }
        for name in DECRYPT_TREND_OBJECTS
    ]
    top_basis = trend_records or current_records
    company_labels = decrypt_top_labels(top_basis, decrypt_company_label, 5)
    company_series = decrypt_trend_series_for_labels(trend_records, days, company_labels, decrypt_company_label, tz)
    empty = ""
    if not any(int(item["current_total"] or 0) for item in series):
        empty = '<p class="rename-empty">近30天暂无结构、电气、三维模型或 DWG 解密记录。</p>'
    object_chart = trend_chart_html("解密对象趋势", series, labels, "近30天", "按天", include_small_multiples=False).replace(
        'class="trend-chart-card"', 'class="trend-chart-card decrypt-trend-card"', 1
    )
    organization_chart = trend_chart_html("解密组织 Top5 趋势", company_series, labels, "近30天", "按近30天公司 Top5", include_small_multiples=False).replace(
        'class="trend-chart-card"', 'class="trend-chart-card decrypt-trend-card"', 1
    )
    return f"""
      <div class="decrypt-trend-panel">
        <style>
          #decrypt-risk-tracking .decrypt-trend-row {{
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
            align-items: stretch;
          }}
          #decrypt-risk-tracking .decrypt-trend-card {{
            min-width: 0;
          }}
          #decrypt-risk-tracking .decrypt-trend-card .trend-svg {{
            height: 220px;
          }}
          @media (max-width: 900px) {{
            #decrypt-risk-tracking .decrypt-trend-row {{
              grid-template-columns: 1fr;
            }}
          }}
        </style>
        <div class="decrypt-trend-row" style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;align-items:stretch;">
          {object_chart}
          {organization_chart}
        </div>
        {empty}
      </div>
      {decrypt_trend_script()}
    """


def decrypt_company_matrix_records(records: list[DecryptRiskRecord]) -> list[DecryptRiskRecord]:
    return [
        record
        for record in records
        if record.org_matched and not identity_value_unmatched(decrypt_company_label(record))
    ]


def decrypt_company_matrix_detail_key(company: str, bucket: str) -> tuple[str, str]:
    return (company or "", bucket or "")


def decrypt_company_groups(records: list[DecryptRiskRecord]) -> dict[str, list[DecryptRiskRecord]]:
    groups: dict[str, list[DecryptRiskRecord]] = defaultdict(list)
    for record in decrypt_company_matrix_records(records):
        groups[decrypt_company_label(record)].append(record)
    return groups


def decrypt_company_matrix_html(
    records: list[DecryptRiskRecord],
    detail_links: dict[tuple[str, str], str],
    limit: int | None = 10,
) -> str:
    groups = decrypt_company_groups(records)
    ordered = sorted(
        groups.items(),
        key=lambda item: (
            -len(item[1]),
            -sum(1 for record in item[1] if record.object_bucket in {"结构", "电气"}),
            item[0],
        ),
    )
    visible = ordered if limit is None else ordered[:limit]
    if not visible:
        return '<p class="empty">暂无已映射公司的解密记录。</p>'
    all_cell_counts: list[int] = []
    all_total_counts: list[int] = []
    for _company, company_records in ordered:
        counts = Counter(record.object_bucket for record in company_records)
        all_cell_counts.extend(int(counts.get(column, 0) or 0) for column in DECRYPT_MATRIX_COLUMNS)
        all_total_counts.append(len(company_records))
    cell_thresholds = heat_thresholds_from_counts(all_cell_counts)
    total_thresholds = heat_thresholds_from_counts(all_total_counts)
    headers = "".join(
        f'<th title="{esc(column)}">{esc({"三维模型": "三维", "DWG图纸": "DWG", "压缩包": "压缩"}.get(column, column))}</th>'
        for column in DECRYPT_MATRIX_COLUMNS
    )
    rows: list[str] = []
    for company, company_records in visible:
        counts = Counter(record.object_bucket for record in company_records)
        applicant_count = len({normalize_key(record.applicant_name or record.applicant_account) for record in company_records if normalize_key(record.applicant_name or record.applicant_account)})
        label_inner = f"""
          <div class="org-matrix-label">
            <strong title="{esc(company)}">{esc(company)}</strong>
            <small>{esc(applicant_count)} 名申请人</small>
          </div>
"""
        total_href = detail_links.get(decrypt_company_matrix_detail_key(company, "__all__"), "")
        if total_href:
            row_label = f'<a class="org-matrix-label-link" href="{esc(total_href)}" title="查看{esc(company)}解密记录">{label_inner}</a>'
        else:
            row_label = label_inner
        cells = [f'<th class="channel-name org-matrix-name" scope="row">{row_label}</th>']
        for column in DECRYPT_MATRIX_COLUMNS:
            count = int(counts.get(column, 0) or 0)
            href = detail_links.get(decrypt_company_matrix_detail_key(company, column), "")
            cells.append(
                f"<td>{matrix_number_html(count, href, f'查看{company} / {column} 解密记录', cell_thresholds)}</td>"
            )
        cells.append(
            f"<td>{matrix_number_html(len(company_records), total_href, f'查看{company}全部解密记录', total_thresholds, total=True)}</td>"
        )
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return f"""
      <div class="channel-matrix-wrap organization-matrix-wrap decrypt-company-matrix-wrap">
        <table class="channel-matrix organization-matrix decrypt-company-matrix">
          <thead><tr><th>公司</th>{headers}<th>合计</th></tr></thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
      </div>
"""


def decrypt_risk_home_html(
    analysis: DecryptRiskAnalysis,
    links: dict[str, str],
    company_detail_links: dict[tuple[str, str], str],
    tz: timezone,
    end: datetime | None,
) -> str:
    records = analysis.records
    standard = decrypt_standard_records(records)
    structure = [record for record in records if record.object_bucket == "结构"]
    electrical = [record for record in records if record.object_bucket == "电气"]
    three_d = [record for record in records if record.object_bucket == "三维模型"]
    dwg = [record for record in records if record.object_bucket == "DWG图纸"]
    linked = [record for record in records if decrypt_has_followup(record)]
    cards = [
        decrypt_card_html("标准图纸解密总数", len(standard), "结构/电气/标准图纸解密，原则上不应发生", links.get("standard"), "red"),
        decrypt_card_html("结构", len(structure), "结构标准方案解密记录", links.get("structure"), "violet"),
        decrypt_card_html("电气", len(electrical), "电气标准方案解密记录", links.get("electrical"), "amber"),
        decrypt_card_html("三维模型", len(three_d), "PRT/ASM/SLDASM/SLDPRT/STEP 解密记录", links.get("three_d"), "blue"),
        decrypt_card_html("DWG图纸", len(dwg), "DWG 图纸解密记录", links.get("dwg"), "slate"),
        decrypt_card_html("发现后续流转", len(linked), "解密后30天内按同名文件发现邮件/IM/上传/外设线索", links.get("linked"), "red"),
    ]
    error_html = f'<p class="rename-empty">解密记录追踪暂不可用：{esc(analysis.error)}</p>' if analysis.error else ""
    overview_html = decrypt_rule_risk_overview_html(analysis, links)
    return f"""
    {overview_html}
    <section id="decrypt-risk-tracking" class="section-block rename-tracking-shell decrypt-risk-shell">
      <div class="section-title-row">
        <div>
          <span class="section-eyebrow">Decrypt Drawing Risk</span>
          <h2>解密图纸风险追踪</h2>
          <p>来自加密软件解密/外发申请 Excel，独立追踪结构、电气、三维模型和 DWG 图纸解密；与天擎外发通道矩阵分开统计。</p>
        </div>
      </div>
      <div class="decrypt-card-grid">{"".join(cards)}</div>
      {decrypt_trend_svg(analysis.records, analysis.trend_records, tz, end)}
      <section class="decrypt-company-panel">
        <div class="org-panel-head">
          <span>Company Decrypt Risk</span>
          <a href="{esc(links.get('all', ''))}">查看全部解密记录</a>
        </div>
        <h3>公司解密风险矩阵 Top10</h3>
        {decrypt_company_matrix_html(records, company_detail_links, limit=10)}
      </section>
      {error_html}
    </section>
"""


def decrypt_record_company_cell(record: DecryptRiskRecord) -> HtmlCell:
    display = record.company or record.raw_company or "未确认公司"
    title = f"原始所属部门：{record.raw_org_path or '-'}；原始公司：{record.raw_company or '-'}；映射状态：{'已确认' if record.org_matched else '待完善'}"
    return tooltip_cell(display, title)


def decrypt_record_department_cell(record: DecryptRiskRecord) -> HtmlCell:
    display = record.department or record.raw_department or "未确认部门"
    title = f"原始所属部门：{record.raw_org_path or '-'}；原始部门：{record.raw_department or '-'}；映射状态：{'已确认' if record.org_matched else '待完善'}"
    return tooltip_cell(display, title)


def decrypt_flow_chain_cell(record: DecryptRiskRecord, tz: timezone) -> HtmlCell:
    if not record.followup_chain:
        return tooltip_cell("未发现", "申请后30天内未从天擎审计底稿发现同名文件外发、上传或外设拷贝线索。")
    segments: list[str] = []
    title_lines: list[str] = []
    for idx, item in enumerate(record.followup_chain, 1):
        ts_text = format_ts(item.ts, tz) or "-"
        target = item.target or "未取到目标"
        label = item.channel or "后续文件流转"
        segments.append(f"{idx}.{label}")
        title_lines.append(
            f"{idx}. {ts_text} | {label} | {target} | {item.confidence or '-'} | event_id={item.event_id or '-'}"
        )
    display = " → ".join(segments[:4])
    if len(segments) > 4:
        display += f" → +{len(segments) - 4}"
    return tooltip_cell(compact_id(display, 70), "\n".join(title_lines))


def decrypt_final_destination_cell(record: DecryptRiskRecord) -> HtmlCell:
    if not record.followup_confidence:
        return tooltip_cell("未发现后续流转", "未发现同名文件后续外发、上传或外设拷贝线索。")
    title = " / ".join(
        value
        for value in [
            record.followup_channel,
            record.followup_target,
            record.followup_confidence,
            f"event_id={record.followup_event_id}" if record.followup_event_id else "",
        ]
        if value
    )
    return tooltip_cell(record.followup_channel or "疑似后续流转", title)


def decrypt_detail_rows(records: list[DecryptRiskRecord], tz: timezone) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for record in sorted(records, key=lambda item: item.apply_time or datetime.min.replace(tzinfo=tz), reverse=True):
        followup_title = " / ".join(value for value in [record.followup_channel, record.followup_target, record.followup_confidence] if value)
        rows.append(
            [
                format_ts(record.apply_time, tz),
                decrypt_record_company_cell(record),
                decrypt_record_department_cell(record),
                record.applicant_name or "-",
                record.applicant_account or "-",
                tooltip_cell(record.file_name or "-", record.file_name or "-"),
                record.object_bucket,
                size_label(record.file_size),
                tooltip_cell(compact_id(record.request_reason or "-", 42), record.request_reason or "-"),
                tooltip_cell(record.recipient_unit or "-", record.recipient_unit or "-"),
                record.approver_name or record.approver or "-",
                format_ts(record.approve_time, tz),
                record.status or "-",
                decrypt_final_destination_cell(record),
                format_ts(record.followup_time, tz) if record.followup_time else "-",
                record.followup_confidence or "-",
                tooltip_cell(record.followup_target or "-", followup_title),
                decrypt_flow_chain_cell(record, tz),
            ]
        )
    return rows



def build_decrypt_risk_detail_page(
    title: str,
    records: list[DecryptRiskRecord],
    tz: timezone,
    report_period: str,
    source_label: str,
    note: str,
) -> str:
    linked = sum(1 for record in records if decrypt_has_followup(record))
    unmatched = sum(1 for record in records if not record.org_matched)
    metrics = detail_metric_chips(
        [
            ("记录数", len(records), "当前筛选下的解密记录数"),
            ("标准图纸", len(decrypt_standard_records(records)), "结构/电气标准图纸解密记录"),
            ("发现后续流转", linked, "申请后30天内同名文件关联到后续事件"),
            ("组织映射待完善", unmatched, "未命中组织别名关联表"),
        ]
    )
    body = f"""
    {detail_hero_html(title, "解密图纸风险", report_period, source_label + " + ClickHouse:tianqing.decrypt_records", note, "记录数", len(records))}
    {metrics}
    <section class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Decrypt Records</span>
          <h2>{esc(title)}清单</h2>
        </div>
        <span class="section-count">共 {len(records)} 条</span>
      </div>
      {html_table(["申请时间", "公司", "部门", "申请人", "申请人账号", "文件名", "资料类型", "文件大小", "申请原因", "接受单位", "审批人", "审批时间", "状态", "最终可观测去向", "最终时间", "匹配可信度", "最终目标", "流转链路"], decrypt_detail_rows(records, tz), "events decrypt-records", page_size=50)}
      <p class="note">流转链路按同名文件、人员和组织线索关联；最终可观测去向取申请后30天内可信/组织匹配的最后一次后续事件，只有低可信记录时标记待人工复核。未发现后续线索不代表文件没有其他未记录流转。</p>
    </section>
"""
    return html_detail_document(title, body)


def build_decrypt_audit_module_result(
    args: argparse.Namespace,
    analysis: DecryptRiskAnalysis,
    tz: timezone,
    report_period: str,
    source_label: str,
    end: datetime | None,
) -> ReportModuleResult:
    records = analysis.records
    standard_records = decrypt_standard_records(records)
    structure_records = [record for record in records if record.object_bucket == "结构"]
    electrical_records = [record for record in records if record.object_bucket == "电气"]
    three_d_records = [record for record in records if record.object_bucket == "三维模型"]
    dwg_records = [record for record in records if record.object_bucket == "DWG图纸"]
    linked_records = [record for record in records if decrypt_has_followup(record)]
    unmatched_records = [record for record in records if not record.org_matched]
    page_names = {
        "all": sidecar_page_filename(args, "decrypt-risk", "all"),
        "standard": sidecar_page_filename(args, "decrypt-risk", "standard"),
        "structure": sidecar_page_filename(args, "decrypt-risk", "structure"),
        "electrical": sidecar_page_filename(args, "decrypt-risk", "electrical"),
        "three_d": sidecar_page_filename(args, "decrypt-risk", "three-d"),
        "dwg": sidecar_page_filename(args, "decrypt-risk", "dwg"),
        "linked": sidecar_page_filename(args, "decrypt-risk", "linked"),
        "unmatched": sidecar_page_filename(args, "decrypt-risk", "unmatched-org"),
    }
    sidecar_pages = {
        page_names["all"]: build_decrypt_risk_detail_page(
            "解密图纸风险追踪",
            records,
            tz,
            report_period,
            source_label,
            "加密软件解密/外发申请记录独立追踪页；不并入天擎外发通道矩阵。",
        ),
        page_names["standard"]: build_decrypt_risk_detail_page(
            "标准图纸解密明细",
            standard_records,
            tz,
            report_period,
            source_label,
            "仅展示结构/电气标准图纸解密记录；3YB/5YB/8YB 油变标准方案按后缀并入结构或电气，原则上不允许发生。",
        ),
        page_names["structure"]: build_decrypt_risk_detail_page(
            "结构解密明细",
            structure_records,
            tz,
            report_period,
            source_label,
            "结构标准方案解密记录；三维后缀的 3YB/5YB/8YB 油变标准方案并入本页。",
        ),
        page_names["electrical"]: build_decrypt_risk_detail_page(
            "电气解密明细",
            electrical_records,
            tz,
            report_period,
            source_label,
            "电气标准方案解密记录；DWG 后缀的 3YB/5YB/8YB 油变标准方案并入本页。",
        ),
        page_names["three_d"]: build_decrypt_risk_detail_page(
            "三维模型解密明细",
            three_d_records,
            tz,
            report_period,
            source_label,
            "PRT/ASM/SLDASM/SLDPRT/STEP 三维模型解密记录。",
        ),
        page_names["dwg"]: build_decrypt_risk_detail_page(
            "DWG图纸解密明细",
            dwg_records,
            tz,
            report_period,
            source_label,
            "DWG 图纸解密记录。",
        ),
        page_names["linked"]: build_decrypt_risk_detail_page(
            "解密文件流转链路明细",
            linked_records,
            tz,
            report_period,
            source_label,
            "解密申请后30天内，同名文件在天擎邮件、IM、上传或外设拷贝底稿中出现的流转链路线索。",
        ),
        page_names["unmatched"]: build_decrypt_risk_detail_page(
            "组织映射待完善明细",
            unmatched_records,
            tz,
            report_period,
            source_label,
            "原始组织尚未通过策略中心确认到标准公司/部门的解密记录。",
        ),
    }
    company_detail_links: dict[tuple[str, str], str] = {}
    for company, company_records in decrypt_company_groups(records).items():
        if not company_records:
            continue
        page = sidecar_page_filename(args, "decrypt-company", company)
        company_detail_links[decrypt_company_matrix_detail_key(company, "__all__")] = page
        sidecar_pages[page] = build_decrypt_risk_detail_page(
            f"公司解密风险明细：{company}",
            company_records,
            tz,
            report_period,
            source_label,
            f"{company} 本周期进入解密审计的全部结构、电气、三维、DWG、压缩包及其他解密记录。",
        )
        for bucket in DECRYPT_MATRIX_COLUMNS:
            bucket_records = [record for record in company_records if record.object_bucket == bucket]
            if not bucket_records:
                continue
            cell_page = sidecar_page_filename(args, "decrypt-company-cell", f"{company}|{bucket}")
            company_detail_links[decrypt_company_matrix_detail_key(company, bucket)] = cell_page
            sidecar_pages[cell_page] = build_decrypt_risk_detail_page(
                f"公司解密风险明细：{company} / {bucket}",
                bucket_records,
                tz,
                report_period,
                source_label,
                f"{company} 本周期资料类型为 {bucket} 的解密记录。",
            )

    home_html = decrypt_risk_home_html(analysis, page_names, company_detail_links, tz, end)
    return ReportModuleResult(
        home_module=build_decrypt_audit_home_module(home_html),
        sidecar_pages=sidecar_pages,
        metrics={
            "records": len(records),
            "standard": len(standard_records),
            "linked": len(linked_records),
            "unmatched_org": len(unmatched_records),
            "company_count": len(decrypt_company_groups(records)),
        },
        status="ready" if analysis.available else "error",
    )
