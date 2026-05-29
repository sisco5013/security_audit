#!/usr/bin/env python3
"""Runtime-bound report submodule extracted from tianqing_external_audit_report.

The extracted functions keep the mature report logic intact. The main generator
binds its runtime namespace before calling these functions so shared policy,
HTML, ClickHouse, and classification helpers remain single-sourced during this
phase of modularization.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from typing import Any


def bind_runtime_dependencies(namespace: dict[str, Any]) -> None:
    for key, value in namespace.items():
        if key.startswith("__"):
            continue
        globals()[key] = value


def risk_overview_number(value: float | int | None) -> str:
    if value is None:
        return "-"
    numeric = float(value)
    if abs(numeric) >= 10 or numeric.is_integer():
        return f"{numeric:.0f}"
    return f"{numeric:.1f}"


def pct_text(part: int, total: int) -> str:
    if total <= 0:
        return "0%"
    return f"{part / total * 100:.0f}%"


def risk_overview_period_days(
    events: list[AuditEvent],
    start: datetime | None,
    end: datetime | None,
    tz: timezone,
) -> tuple[datetime | None, datetime | None, float]:
    period_start, period_end = trend_period_bounds(events, start, end, tz)
    if not period_start or not period_end or period_end <= period_start:
        return period_start, period_end, 0.0
    return period_start, period_end, max((period_end - period_start).total_seconds() / 86400, 1 / 24)


def risk_overview_empty_counts() -> dict[str, Any]:
    return {
        "events": [],
        "total": 0,
        "objects": Counter(),
        "channels": Counter(),
        "companies": Counter(),
        "departments": Counter(),
        "company_departments": Counter(),
        "object_channels": defaultdict(Counter),
        "object_companies": defaultdict(Counter),
        "object_departments": defaultdict(Counter),
    }


def risk_overview_add_count(
    counts: dict[str, Any],
    bucket: str,
    channel: str,
    company: str,
    department: str,
    count: int,
) -> None:
    if not bucket or not channel or count <= 0:
        return
    company = company or UNMATCHED_COMPANY_LABEL
    department = department or UNMATCHED_DEPARTMENT_LABEL
    counts["total"] += count
    counts["objects"][bucket] += count
    counts["channels"][channel] += count
    counts["companies"][company] += count
    counts["departments"][department] += count
    counts["company_departments"][(company, department)] += count
    counts["object_channels"][bucket][channel] += count
    counts["object_companies"][bucket][company] += count
    counts["object_departments"][bucket][department] += count


def risk_overview_pack_counts(events: list[AuditEvent], internal_domains: set[str]) -> dict[str, Any]:
    matrix_events = trend_matrix_events(events, internal_domains)
    counts = risk_overview_empty_counts()
    counts["events"] = matrix_events
    for event in matrix_events:
        channel = audit_channel_group(event, internal_domains)
        bucket = audit_matrix_bucket(event)
        if not channel or not bucket:
            continue
        risk_overview_add_count(
            counts,
            bucket,
            channel,
            event_company_label(event),
            event_department_label(event),
            1,
        )
    return counts


def risk_overview_history_counts_from_clickhouse(
    args: argparse.Namespace,
    history_start: datetime,
    period_start: datetime,
    tz: timezone,
    internal_domains: set[str],
) -> dict[int, dict[str, Any]]:
    cutoff_by_days = {days: period_start - timedelta(days=days) for days in RISK_OVERVIEW_HISTORY_DAYS}
    event_where = clickhouse_event_filter(history_start, period_start)
    object_expr, channel_expr, focus_expr = clickhouse_matrix_classification_exprs(internal_domains)
    count_columns = ", ".join(
        f"countIf(ts >= parseDateTime64BestEffort({clickhouse_literal(cutoff.isoformat())}, 3)) AS count_{days}"
        for days, cutoff in sorted(cutoff_by_days.items())
    )
    query = f"""
SELECT object, channel_group, company_label, department_label, {count_columns}
FROM
(
    SELECT
        ts,
        {object_expr} AS object,
        {channel_expr} AS channel_group,
        if(company = '' OR company = 'unknown', {clickhouse_literal(UNMATCHED_COMPANY_LABEL)}, company) AS company_label,
        if(department = '' OR department = 'unknown', {clickhouse_literal(UNMATCHED_DEPARTMENT_LABEL)}, department) AS department_label,
        {focus_expr} AS focus_signal
    FROM audit_events
    WHERE {event_where}
)
WHERE object != '' AND channel_group != '' AND focus_signal
GROUP BY object, channel_group, company_label, department_label
FORMAT JSONEachRow
"""
    text = clickhouse_query(args, query)
    counts_by_days = {days: risk_overview_empty_counts() for days in RISK_OVERVIEW_HISTORY_DAYS}
    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        bucket = str(row.get("object") or "")
        channel = str(row.get("channel_group") or "")
        company = str(row.get("company_label") or UNMATCHED_COMPANY_LABEL)
        department = str(row.get("department_label") or UNMATCHED_DEPARTMENT_LABEL)
        for days in RISK_OVERVIEW_HISTORY_DAYS:
            risk_overview_add_count(
                counts_by_days[days],
                bucket,
                channel,
                company,
                department,
                int(row.get(f"count_{days}") or 0),
            )
    return counts_by_days


def load_risk_overview_history(
    args: argparse.Namespace,
    current_events: list[AuditEvent],
    start: datetime | None,
    end: datetime | None,
    tz: timezone,
    internal_domains: set[str],
) -> dict[str, Any]:
    period_start, period_end, period_days = risk_overview_period_days(current_events, start, end, tz)
    result: dict[str, Any] = {
        "available": False,
        "period_start": period_start,
        "period_end": period_end,
        "period_days": period_days,
        "windows": {},
        "note": "",
    }
    if not period_start or not period_end or period_days <= 0:
        result["note"] = "当前报告周期不足，无法计算历史同周期均值。"
        return result
    if not getattr(args, "use_clickhouse", False):
        result["note"] = "非 ClickHouse 数据源，首页仅展示本期规则概览，历史同周期均值不可用。"
        return result
    max_days = max(RISK_OVERVIEW_HISTORY_DAYS)
    history_start = period_start - timedelta(days=max_days)
    try:
        counts_by_days = risk_overview_history_counts_from_clickhouse(args, history_start, period_start, tz, internal_domains)
    except Exception as exc:
        result["note"] = f"历史均值查询失败，已降级为本期概览：{type(exc).__name__}: {str(exc)[:160]}"
        return result

    for days in RISK_OVERVIEW_HISTORY_DAYS:
        window_start = period_start - timedelta(days=days)
        history_days = max((period_start - window_start).total_seconds() / 86400, 1 / 24)
        result["windows"][days] = {
            "available": True,
            "days": days,
            "start": window_start,
            "end": period_start,
            "history_days": history_days,
            "scale": period_days / history_days,
            "counts": counts_by_days.get(days, risk_overview_empty_counts()),
        }
    result["available"] = True
    return result


def risk_overview_comparisons(
    current_count: int,
    history: dict[str, Any],
    count_func: Any,
) -> list[dict[str, Any]]:
    comparisons: list[dict[str, Any]] = []
    for days in RISK_OVERVIEW_HISTORY_DAYS:
        payload = (history.get("windows") or {}).get(days) if isinstance(history, dict) else None
        if not isinstance(payload, dict) or not payload.get("available"):
            comparisons.append({"available": False, "days": days, "current": current_count})
            continue
        counts = payload.get("counts") or {}
        try:
            history_count = int(count_func(counts) or 0)
        except Exception:
            history_count = 0
        baseline = history_count * float(payload.get("scale") or 0)
        delta = current_count - baseline
        if baseline <= 0:
            ratio = None
        else:
            ratio = delta / baseline
        if baseline <= 0 and current_count <= 0:
            level = "flat"
        elif baseline <= 0:
            level = "up"
        elif abs(delta) <= max(1.0, baseline * 0.08):
            level = "flat"
        elif delta > 0:
            level = "up"
        else:
            level = "down"
        comparisons.append(
            {
                "available": True,
                "days": days,
                "current": current_count,
                "history_count": history_count,
                "baseline": baseline,
                "delta": delta,
                "ratio": ratio,
                "level": level,
            }
        )
    return comparisons


def risk_overview_primary_comparison(comparisons: list[dict[str, Any]]) -> dict[str, Any]:
    return next((item for item in comparisons if item.get("available")), comparisons[0] if comparisons else {"available": False})


def risk_overview_compare_text(comparison: dict[str, Any], compact: bool = False) -> str:
    days = int(comparison.get("days") or 0)
    if not comparison.get("available"):
        return f"{days}天均值不可用" if days else "历史均值不可用"
    baseline = float(comparison.get("baseline") or 0)
    delta = float(comparison.get("delta") or 0)
    current = float(comparison.get("current") or 0)
    level = str(comparison.get("level") or "flat")
    baseline_text = risk_overview_number(baseline)
    if level == "flat":
        return f"{days}天持平（均值{baseline_text}）"
    if baseline <= 0:
        if delta > 0:
            return f"{days}天由0增至{risk_overview_number(current)}"
        return f"{days}天仍为0"
    ratio = comparison.get("ratio")
    direction = "高于" if level == "up" else "低于"
    if abs(float(ratio or 0)) >= 5 or baseline < 5:
        delta_text = risk_overview_number(abs(delta))
        if compact:
            return f"{days}天{direction}{delta_text}条"
        return f"{direction}{days}天同周期均值{delta_text}条（均值{baseline_text}）"
    ratio_text = f"{abs(float(ratio or 0)) * 100:.0f}%"
    if compact:
        return f"{days}天{direction}{ratio_text}"
    return f"{direction}{days}天同周期均值{ratio_text}（均值{baseline_text}）"


def risk_overview_top_label(counter: Counter) -> tuple[str, int]:
    for label, count in counter.most_common():
        text = str(label or "").strip()
        if text and int(count or 0) > 0:
            return text, int(count)
    return "-", 0


def risk_overview_finding_matrix_count(finding: OrganizationRiskFinding, internal_domains: set[str]) -> int:
    return len(organization_channel_events(finding, internal_domains))


def risk_overview_finding_history_getter(finding: OrganizationRiskFinding) -> Any:
    if finding.scope == "company":
        key = finding.company or UNMATCHED_COMPANY_LABEL
        return lambda counts: (counts.get("companies") or Counter()).get(key, 0)
    if finding.scope == "department_type":
        key = finding.department or UNMATCHED_DEPARTMENT_LABEL
        return lambda counts: (counts.get("departments") or Counter()).get(key, 0)
    key = (finding.company or UNMATCHED_COMPANY_LABEL, finding.department or UNMATCHED_DEPARTMENT_LABEL)
    return lambda counts: (counts.get("company_departments") or Counter()).get(key, 0)


def risk_overview_org_item(
    finding: OrganizationRiskFinding,
    history: dict[str, Any],
    org_links: dict[tuple[str, str, str], str],
    internal_domains: set[str],
    scope_label: str,
) -> dict[str, Any]:
    current_count = risk_overview_finding_matrix_count(finding, internal_domains)
    cell_counts = organization_channel_object_counts(finding, internal_domains)
    object_counts: Counter = Counter()
    channel_counts: Counter = Counter()
    for (channel, bucket), count in cell_counts.items():
        object_counts[bucket] += count
        channel_counts[channel] += count
    top_object, top_object_count = risk_overview_top_label(object_counts)
    top_channel, top_channel_count = risk_overview_top_label(channel_counts)
    return {
        "label": finding.label,
        "scope_label": scope_label,
        "current": current_count,
        "share_base": 0,
        "risk_terminals": finding.risk_terminal_count,
        "top_object": top_object,
        "top_object_count": top_object_count,
        "top_channel": top_channel,
        "top_channel_count": top_channel_count,
        "tags": finding.issue_tags[:3],
        "href": org_links.get(organization_key(finding), ""),
        "comparisons": risk_overview_comparisons(current_count, history, risk_overview_finding_history_getter(finding)),
    }


def risk_overview_object_items(
    current_counts: dict[str, Any],
    history: dict[str, Any],
    object_links: dict[str, str],
    total_count: int,
) -> list[dict[str, Any]]:
    object_counts: Counter = current_counts.get("objects") or Counter()
    object_channels: dict[str, Counter] = current_counts.get("object_channels") or {}
    object_companies: dict[str, Counter] = current_counts.get("object_companies") or {}
    object_departments: dict[str, Counter] = current_counts.get("object_departments") or {}
    items: list[dict[str, Any]] = []
    for bucket in RISK_OVERVIEW_OBJECT_ORDER:
        current_count = int(object_counts.get(bucket, 0) or 0)
        top_channel, top_channel_count = risk_overview_top_label(object_channels.get(bucket, Counter()))
        top_company, top_company_count = risk_overview_top_label(object_companies.get(bucket, Counter()))
        top_department, top_department_count = risk_overview_top_label(object_departments.get(bucket, Counter()))
        items.append(
            {
                "label": bucket,
                "importance": RISK_OVERVIEW_OBJECT_IMPORTANCE.get(bucket, "关注"),
                "current": current_count,
                "share": pct_text(current_count, total_count),
                "top_channel": top_channel,
                "top_channel_count": top_channel_count,
                "top_company": top_company,
                "top_company_count": top_company_count,
                "top_department": top_department,
                "top_department_count": top_department_count,
                "href": object_links.get(bucket, ""),
                "comparisons": risk_overview_comparisons(
                    current_count,
                    history,
                    lambda counts, object_name=bucket: (counts.get("objects") or Counter()).get(object_name, 0),
                ),
            }
        )
    return items


def build_rule_risk_overview_html(
    events: list[AuditEvent],
    args: argparse.Namespace,
    start: datetime | None,
    end: datetime | None,
    tz: timezone,
    internal_domains: set[str],
    organization_analysis: OrganizationRiskAnalysis,
    org_links: dict[tuple[str, str, str], str],
    object_links: dict[str, str],
) -> str:
    current_counts = risk_overview_pack_counts(events, internal_domains)
    total_count = int(current_counts.get("total") or 0)
    history = load_risk_overview_history(args, events, start, end, tz, internal_domains)
    overall_comparisons = risk_overview_comparisons(total_count, history, lambda counts: counts.get("total", 0))
    overall_primary = risk_overview_primary_comparison(overall_comparisons)
    object_items = risk_overview_object_items(current_counts, history, object_links, total_count)
    three_d_item = next((item for item in object_items if item.get("label") == "三维模型"), object_items[0] if object_items else {})

    company_items = [
        risk_overview_org_item(finding, history, org_links, internal_domains, "公司")
        for finding in organization_analysis.companies
        if risk_overview_finding_matrix_count(finding, internal_domains) > 0
    ][:3]
    department_candidates = [
        risk_overview_org_item(finding, history, org_links, internal_domains, "跨公司部门")
        for finding in organization_analysis.department_types
        if risk_overview_finding_matrix_count(finding, internal_domains) > 0
    ] + [
        risk_overview_org_item(finding, history, org_links, internal_domains, "公司内部门")
        for finding in organization_analysis.company_departments
        if risk_overview_finding_matrix_count(finding, internal_domains) > 0
    ]
    department_items = sorted(
        department_candidates,
        key=lambda item: (-int(item.get("current") or 0), str(item.get("scope_label") or ""), str(item.get("label") or "")),
    )[:3]
    top_company = company_items[0] if company_items else {}
    top_department = department_items[0] if department_items else {}
    top_channel, top_channel_count = risk_overview_top_label(current_counts.get("channels") or Counter())
    three_d_primary = risk_overview_primary_comparison(three_d_item.get("comparisons") or [])
    company_primary = risk_overview_primary_comparison(top_company.get("comparisons") or [])
    department_primary = risk_overview_primary_comparison(top_department.get("comparisons") or [])
    object_by_count = sorted(object_items, key=lambda item: int(item.get("current") or 0), reverse=True)
    object_parts = [
        f"{item.get('label', '-')} {item.get('current', 0)} 条（占{item.get('share', '0%')}）"
        for item in object_by_count
        if int(item.get("current") or 0) > 0
    ][:3]

    if total_count:
        overall_sentence = (
            f"本期进入通道×对象矩阵的重点事件 {total_count} 条，"
            f"{risk_overview_compare_text(overall_primary)}；最高频通道为 {top_channel} {top_channel_count} 条。"
        )
    else:
        overall_sentence = "本期暂无进入通道×对象矩阵的重点事件，首页保留组织和趋势入口用于复核。"
    matrix_events = list(current_counts.get("events") or [])
    structure_critical = sum(
        1 for event in matrix_events if CRITICAL_STRUCTURE_LABEL in critical_design_labels_for_event(event)
    )
    electrical_critical = sum(
        1
        for event in matrix_events
        if CRITICAL_ELECTRICAL_LABEL in critical_design_labels_for_event(event)
        and CRITICAL_STRUCTURE_LABEL not in critical_design_labels_for_event(event)
    )
    standard_critical = structure_critical + electrical_critical
    large_archive_critical = sum(1 for event in matrix_events if is_large_archive_event(event))
    level_one_sentence = (
        f"一级风险对象：标准图纸外发/拷贝 {standard_critical} 条"
        f"（结构 {structure_critical} 条、电气 {electrical_critical} 条），"
        f"大于100MB压缩包 {large_archive_critical} 条；顶部汇总只展示分项，不再合并成一个总数。"
    )
    three_d_sentence = (
        f"三维模型作为最高关注对象，本期 {three_d_item.get('current', 0)} 条，"
        f"{risk_overview_compare_text(three_d_primary)}；主要集中在 {three_d_item.get('top_company') or '-'} / {three_d_item.get('top_department') or '-'}，"
        f"主要通道为 {three_d_item.get('top_channel') or '-'} {three_d_item.get('top_channel_count', 0)} 条，需要按项目、客户/供应商和审批依据逐条闭环。"
    )
    object_sentence = (
        "对象结构上，" + "、".join(object_parts) + "；三维模型即使不是数量最高，也按核心技术资产单独复核。"
        if object_parts
        else "对象结构暂无明显集中项，后续以新增事件和趋势迁移为主。"
    )
    if top_company or top_department:
        org_sentence = (
            f"组织侧优先看 {top_company.get('label', '-')}（{top_company.get('current', 0)} 条、{top_company.get('risk_terminals', 0)} 台风险终端）"
            f"和 {top_department.get('label', '-')}（{top_department.get('current', 0)} 条、{top_department.get('risk_terminals', 0)} 台风险终端）；"
            f"公司侧{risk_overview_compare_text(company_primary)}，部门侧{risk_overview_compare_text(department_primary)}。"
        )
    else:
        org_sentence = "公司和部门侧暂无可聚合的矩阵风险，后续以趋势和新增事件为主。"
    action_sentence = (
        f"建议复核顺序：先看三维模型和 {top_channel}，再按 {top_company.get('label', '公司矩阵')} / {top_department.get('label', '部门矩阵')} 下钻；"
        "结论区只给管理判断，详细对象、公司、部门和终端数字继续在下方矩阵中核对。"
    )
    history_note = str(history.get("note") or "")
    history_note_html = f'<p class="note risk-overview-note">{esc(history_note)}</p>' if history_note else ""

    return f"""
    <section id="risk-overview" class="section-block risk-overview-shell">
      <div class="section-title-row">
        <div>
          <span class="section-eyebrow">Rule Overview</span>
          <h2>天擎外发规则风险概览</h2>
          <p>基于天擎外发、上传、外设拷贝审计底稿汇总矩阵事实和历史均值；详细数字继续在下方矩阵和组织洞察中核对。</p>
        </div>
      </div>
      <div class="risk-overview-hero">
        <div class="risk-overview-conclusions">
          <span>管理结论</span>
          <ul>
            <li>{esc(level_one_sentence)}</li>
            <li>{esc(overall_sentence)}</li>
            <li>{esc(three_d_sentence)}</li>
            <li>{esc(object_sentence)}</li>
            <li>{esc(org_sentence)}</li>
            <li>{esc(action_sentence)}</li>
          </ul>
        </div>
      </div>
      {history_note_html}
    </section>
"""
