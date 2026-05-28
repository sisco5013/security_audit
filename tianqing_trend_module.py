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


def trend_period_bounds(
    events: list[AuditEvent],
    start: datetime | None,
    end: datetime | None,
    tz: timezone,
) -> tuple[datetime | None, datetime | None]:
    if start and end and end > start:
        return start.astimezone(tz), end.astimezone(tz)
    event_times = sorted(event.ts.astimezone(tz) for event in events if event.ts)
    if not event_times:
        return start, end
    period_start = start.astimezone(tz) if start else event_times[0].replace(minute=0, second=0, microsecond=0)
    period_end = end.astimezone(tz) if end else event_times[-1] + timedelta(minutes=1)
    if period_end <= period_start:
        period_end = period_start + timedelta(hours=1)
    return period_start, period_end


def trend_granularity(start: datetime | None, end: datetime | None) -> str:
    if not start or not end or end <= start:
        return "day"
    hours = (end - start).total_seconds() / 3600
    if hours <= 45 * 24:
        return "day"
    if hours <= 180 * 24:
        return "week"
    return "month"


def start_of_trend_bucket(value: datetime, granularity: str, tz: timezone) -> datetime:
    local = value.astimezone(tz)
    if granularity == "hour":
        return local.replace(minute=0, second=0, microsecond=0)
    if granularity == "day":
        return local.replace(hour=0, minute=0, second=0, microsecond=0)
    if granularity == "week":
        day_start = local.replace(hour=0, minute=0, second=0, microsecond=0)
        return day_start - timedelta(days=day_start.weekday())
    return local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def add_trend_bucket(value: datetime, granularity: str) -> datetime:
    if granularity == "hour":
        return value + timedelta(hours=1)
    if granularity == "day":
        return value + timedelta(days=1)
    if granularity == "week":
        return value + timedelta(days=7)
    year = value.year + (1 if value.month == 12 else 0)
    month = 1 if value.month == 12 else value.month + 1
    return value.replace(year=year, month=month, day=1)


def trend_bucket_label(value: datetime, granularity: str) -> str:
    if granularity == "hour":
        return value.strftime("%m-%d %H:00")
    if granularity == "day":
        return value.strftime("%m-%d")
    if granularity == "week":
        return value.strftime("%m-%d周")
    return value.strftime("%Y-%m")


def trend_buckets(start: datetime, end: datetime, granularity: str, tz: timezone) -> tuple[list[datetime], list[str]]:
    first = start_of_trend_bucket(start, granularity, tz)
    buckets: list[datetime] = []
    current = first
    guard = 0
    while current < end and guard < 400:
        buckets.append(current)
        current = add_trend_bucket(current, granularity)
        guard += 1
    if not buckets:
        buckets = [first]
    return buckets, [trend_bucket_label(bucket, granularity) for bucket in buckets]


def trend_matrix_events(events: list[AuditEvent], internal_domains: set[str]) -> list[AuditEvent]:
    return [
        event
        for event in events
        if event.ts and audit_channel_group(event, internal_domains) and audit_matrix_bucket(event)
    ]


def trend_counts_by_bucket(
    events: list[AuditEvent],
    buckets: list[datetime],
    granularity: str,
    tz: timezone,
    label_func: Any,
) -> dict[str, list[int]]:
    index = {bucket: idx for idx, bucket in enumerate(buckets)}
    counts: dict[str, list[int]] = defaultdict(lambda: [0 for _ in buckets])
    for event in events:
        if not event.ts:
            continue
        bucket = start_of_trend_bucket(event.ts, granularity, tz)
        idx = index.get(bucket)
        if idx is None:
            continue
        label = str(label_func(event) or "").strip()
        if not label:
            continue
        counts[label][idx] += 1
    return counts


def build_trend_series(
    labels: list[str],
    current_counts: dict[str, list[int]],
    links: dict[str, str],
) -> list[dict[str, Any]]:
    series: list[dict[str, Any]] = []
    default_len = len(next(iter(current_counts.values()), [])) if current_counts else 0
    for idx, label in enumerate(labels):
        current_values = current_counts.get(label, [0] * default_len)
        current_total = sum(current_values)
        if current_total <= 0:
            continue
        series.append(
            {
                "label": label,
                "current": current_values,
                "current_total": current_total,
                "href": links.get(label, ""),
                "color": TREND_COLORS[idx % len(TREND_COLORS)],
            }
        )
    return series


def top_trend_count_labels(
    counts: dict[str, list[int]],
    limit: int = 5,
    exclude_unmatched: bool = True,
) -> list[str]:
    ranked: list[tuple[str, int]] = []
    for label, values in counts.items():
        text = str(label or "").strip()
        if not text:
            continue
        if exclude_unmatched and text.startswith("未匹配"):
            continue
        total = sum(int(value or 0) for value in values)
        if total > 0:
            ranked.append((text, total))
    ranked.sort(key=lambda item: (-item[1], item[0]))
    return [label for label, _total in ranked[:limit]]


def top_trend_labels(
    events: list[AuditEvent],
    label_func: Any,
    limit: int = 5,
    exclude_unmatched: bool = True,
) -> list[str]:
    counts: Counter = Counter()
    for event in events:
        label = str(label_func(event) or "").strip()
        if not label:
            continue
        if exclude_unmatched and label.startswith("未匹配"):
            continue
        counts[label] += 1
    return [label for label, count in counts.most_common(limit) if count > 0]


def trend_reference_end(
    args: argparse.Namespace,
    events: list[AuditEvent],
    start: datetime | None,
    end: datetime | None,
    tz: timezone,
) -> datetime:
    if end:
        return end.astimezone(tz)
    event_times = [event.ts.astimezone(tz) for event in events if event.ts]
    if event_times:
        return max(event_times)
    return datetime.now(tz)


def prepare_trend_source_events(
    args: argparse.Namespace,
    events: list[AuditEvent],
    start: datetime | None,
    end: datetime | None,
    tz: timezone,
    internal_domains: set[str],
) -> list[AuditEvent]:
    raw_file_audit_map = raw_file_audit_map_from_clickhouse(args, start, end)
    apply_report_policies(events, raw_file_audit_map, internal_domains)
    wecom_people_map = getattr(args, "wecom_people_map_loaded", {}) or {}
    terminal_identity_history = load_terminal_identity_history(
        args,
        [],
        tz,
        start,
        end,
        wecom_people_map,
    )
    enrich_events(
        events,
        getattr(args, "people_map_loaded", {}) or {},
        wecom_people_map,
        {},
        {},
        terminal_identity_history=terminal_identity_history,
        terminal_identity_max_age_days=getattr(args, "terminal_identity_max_age_days", 30),
    )
    return events


def clickhouse_matrix_classification_exprs(internal_domains: set[str] | None = None) -> tuple[str, str, str]:
    internal_domains = {
        str(domain or "").lower().strip(".")
        for domain in (internal_domains or DEFAULT_INTERNAL_DOMAINS)
        if str(domain or "").strip()
    }
    three_d_exts = clickhouse_array_literal(sorted(CONTROLLED_3D_EXTS))
    two_d_exts = clickhouse_array_literal(sorted(CONTROLLED_2D_CAD_EXTS))
    archive_exts = clickhouse_array_literal(sorted(ARCHIVE_EXTS))
    design_exts = clickhouse_array_literal(sorted(DESIGN_EXTS))
    external_relations = clickhouse_array_literal(sorted(EXTERNAL_RELATIONS))
    external_reasons = clickhouse_array_literal(["个人邮箱域名", "网盘/高风险外联目标", "外部收件域名", "外部上传/下载地址"])
    upload_reasons = clickhouse_array_literal(["外部站点上传", "外部上传/下载地址"])
    internal_domain_array = clickhouse_array_literal(sorted(internal_domains))
    upload_noise_hints = clickhouse_array_literal(sorted(UPLOAD_NOISE_HINTS))
    target_domains_lower = "arrayMap(x -> lowerUTF8(x), target_domains)"
    upload_noise_expr = (
        "topic = 'file_audit' "
        f"AND (hasAny(reasons, {upload_reasons}) OR channel = '文件上传/外发') "
        "AND ("
        f"arrayExists(d -> has({internal_domain_array}, d) OR arrayExists(i -> d = i OR endsWith(d, concat('.', i)), {internal_domain_array}), {target_domains_lower}) "
        "OR arrayExists(value -> arrayExists(hint -> positionCaseInsensitiveUTF8(value, hint) > 0, "
        f"{upload_noise_hints}), arrayConcat(target_domains, targets))"
        ")"
    )
    rename_expr = "topic = 'file_audit' AND (channel = '文件重命名' OR has(reasons, '文件重命名'))"
    critical_object_clauses = "".join(
        f"has(reasons, {clickhouse_literal(CRITICAL_DESIGN_REASON_PREFIX + label)}), {clickhouse_literal(label)}, "
        for label in CRITICAL_DESIGN_LABELS
    )
    object_expr = (
        "multiIf("
        f"{critical_object_clauses}"
        f"hasAny(file_exts, {three_d_exts}), '三维模型', "
        f"hasAny(file_exts, {two_d_exts}), 'DWG二维图纸', "
        f"hasAny(file_exts, {archive_exts}), '压缩包', "
        "arrayExists(reason -> startsWith(reason, '敏感关键词:'), reasons), '敏感名称', "
        "''"
        ")"
    )
    channel_expr = (
        "multiIf("
        "topic = 'mail_audit', '邮件外发', "
        "topic = 'im_audit' OR (topic = 'file_audit' AND channel = '应用发送/传输'), 'IM附件', "
        "topic = 'file_audit' AND (channel = '外设拷贝' OR has(reasons, '外设拷贝')), '外设拷贝', "
        "has(reasons, '网盘/高风险外联目标'), '外部站点上传', "
        f"topic = 'file_audit' AND (hasAny(reasons, {upload_reasons}) OR channel = '文件上传/外发'), '外部站点上传', "
        "''"
        ")"
    )
    focus_expr = (
        "("
        "NOT ("
        "recipient_relation = 'internal' "
        "AND ("
        "topic = 'mail_audit' "
        "OR (topic = 'im_audit' AND lowerUTF8(process_name) IN ('wxwork.exe','wxwork','wecom.exe','wecom')) "
        "OR (topic = 'file_audit' AND channel = '应用发送/传输' AND lowerUTF8(process_name) IN ('wxwork.exe','wxwork','wecom.exe','wecom'))"
        ")"
        ") "
        f"AND NOT ({rename_expr}) "
        f"AND NOT ({upload_noise_expr}) "
        "AND NOT ("
        "topic = 'file_audit' "
        "AND channel = '应用发送/传输' "
        "AND lowerUTF8(process_name) IN ('wxwork.exe', 'dingtalk.exe') "
        "AND recipient_relation = 'unknown' "
        "AND length(recipients) = 1 "
        "AND match(recipients[1], '^[A-Za-z0-9_-]{5,64}$')"
        ") "
        ") AND ("
        f"hasAny(file_exts, {design_exts}) "
        f"OR hasAny(file_exts, {archive_exts}) "
        "OR arrayExists(reason -> startsWith(reason, '敏感关键词:'), reasons)"
        ") AND ("
        f"recipient_relation IN {external_relations} "
        f"OR hasAny(reasons, {external_reasons}) "
        "OR (topic IN ('mail_audit', 'im_audit') AND recipient_relation = 'unknown') "
        "OR (topic = 'file_audit' AND recipient_relation = 'unknown' AND ("
        f"hasAny(file_exts, {three_d_exts}) "
        "OR lowerUTF8(process_name) NOT IN ('explorer', 'explorer.exe') "
        f"OR (level = 'HIGH' AND (hasAny(file_exts, {archive_exts}) OR arrayExists(reason -> startsWith(reason, '敏感关键词:'), reasons)))"
        "))"
        ")"
    )
    return object_expr, channel_expr, focus_expr


def clickhouse_trend_bucket_expr(granularity: str, tz: timezone) -> str:
    tz_name = getattr(tz, "key", None) or "Asia/Shanghai"
    local_ts = f"toTimeZone(ts, {clickhouse_literal(tz_name)})"
    if granularity == "hour":
        return f"toUnixTimestamp(toStartOfHour({local_ts}))"
    if granularity == "day":
        return f"toUnixTimestamp(toStartOfDay({local_ts}))"
    if granularity == "week":
        return f"toUnixTimestamp(toStartOfWeek({local_ts}, 1))"
    return f"toUnixTimestamp(toStartOfMonth({local_ts}))"


def load_trend_window_counts_from_clickhouse(
    args: argparse.Namespace,
    period_start: datetime,
    period_end: datetime,
    granularity: str,
    buckets: list[datetime],
    tz: timezone,
    internal_domains: set[str],
) -> dict[str, dict[str, list[int]]]:
    event_where = clickhouse_event_filter(period_start, period_end)
    object_expr, channel_expr, focus_expr = clickhouse_matrix_classification_exprs(internal_domains)
    bucket_expr = clickhouse_trend_bucket_expr(granularity, tz)
    query = f"""
SELECT bucket_ts, object, channel_group, company_label, department_label, count() AS count
FROM
(
    SELECT
        {bucket_expr} AS bucket_ts,
        {object_expr} AS object,
        {channel_expr} AS channel_group,
        if(company = '' OR company = 'unknown', {clickhouse_literal(UNMATCHED_COMPANY_LABEL)}, company) AS company_label,
        if(department = '' OR department = 'unknown', {clickhouse_literal(UNMATCHED_DEPARTMENT_LABEL)}, department) AS department_label,
        {focus_expr} AS focus_signal
    FROM audit_events
    WHERE {event_where}
)
WHERE object != '' AND channel_group != '' AND focus_signal
GROUP BY bucket_ts, object, channel_group, company_label, department_label
FORMAT JSONEachRow
"""
    index = {bucket: idx for idx, bucket in enumerate(buckets)}
    counts: dict[str, dict[str, list[int]]] = {
        "channels": defaultdict(lambda: [0 for _ in buckets]),
        "objects": defaultdict(lambda: [0 for _ in buckets]),
        "companies": defaultdict(lambda: [0 for _ in buckets]),
        "departments": defaultdict(lambda: [0 for _ in buckets]),
    }
    for line in clickhouse_query(args, query).splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        try:
            bucket = datetime.fromtimestamp(int(row.get("bucket_ts") or 0), tz)
        except (TypeError, ValueError, OSError):
            continue
        bucket = start_of_trend_bucket(bucket, granularity, tz)
        idx = index.get(bucket)
        if idx is None:
            continue
        count = int(row.get("count") or 0)
        if count <= 0:
            continue
        channel = str(row.get("channel_group") or "").strip()
        bucket_name = str(row.get("object") or "").strip()
        company = str(row.get("company_label") or UNMATCHED_COMPANY_LABEL).strip() or UNMATCHED_COMPANY_LABEL
        department = str(row.get("department_label") or UNMATCHED_DEPARTMENT_LABEL).strip() or UNMATCHED_DEPARTMENT_LABEL
        if channel:
            counts["channels"][channel][idx] += count
        if bucket_name:
            counts["objects"][bucket_name][idx] += count
        counts["companies"][company][idx] += count
        counts["departments"][department][idx] += count
    return {group: dict(group_counts) for group, group_counts in counts.items()}


def load_trend_window_event_sets(
    args: argparse.Namespace,
    fallback_events: list[AuditEvent],
    reference_end: datetime,
    tz: timezone,
    internal_domains: set[str],
    report_start: datetime | None = None,
    report_end: datetime | None = None,
    windows: list[int] | None = None,
) -> dict[int, dict[str, Any]]:
    window_days = sorted(set(windows or TREND_WINDOW_DAYS))
    reference_end = reference_end.astimezone(tz)
    result: dict[int, dict[str, Any]] = {}
    for days in window_days:
        period_start = reference_end - timedelta(days=days)
        granularity = trend_granularity(period_start, reference_end)
        buckets, labels = trend_buckets(period_start, reference_end, granularity, tz)
        payload: dict[str, Any] = {
            "days": days,
            "start": period_start,
            "end": reference_end,
            "granularity": granularity,
            "granularity_label": TREND_GRANULARITY_LABELS.get(granularity, granularity),
            "labels": labels,
            "events": fallback_events if not getattr(args, "use_clickhouse", False) else [],
            "note": "",
        }
        if getattr(args, "use_clickhouse", False):
            try:
                payload["counts"] = load_trend_window_counts_from_clickhouse(args, period_start, reference_end, granularity, buckets, tz, internal_domains)
                payload["available"] = True
            except Exception as exc:
                payload["available"] = False
                payload["note"] = f"趋势聚合查询失败，已跳过该窗口：{type(exc).__name__}: {str(exc)[:160]}"
        else:
            payload["available"] = True
            payload["note"] = "非 ClickHouse 数据源，趋势仅基于当前报告已载入数据。"
        result[days] = payload
    return result


def build_trend_range_summary(
    current_events: list[AuditEvent],
    start: datetime | None,
    end: datetime | None,
    days: int,
    note: str,
    tz: timezone,
    internal_domains: set[str],
    channel_links: dict[str, str],
    object_links: dict[str, str],
    org_links: dict[tuple[str, str, str], str],
    company_labels: list[str] | None = None,
    department_labels: list[str] | None = None,
    top_source_events: list[AuditEvent] | None = None,
    report_start: datetime | None = None,
    report_end: datetime | None = None,
    available: bool = True,
    precomputed_counts: dict[str, dict[str, list[int]]] | None = None,
    precomputed_labels: list[str] | None = None,
    precomputed_granularity: str | None = None,
    precomputed_granularity_label: str | None = None,
) -> dict[str, Any]:
    if not available:
        return {"available": False, "days": days, "label": f"近{days}天", "note": note or "趋势历史已降级为当前周期聚合。"}
    if precomputed_counts is not None:
        labels = precomputed_labels or []
        granularity = precomputed_granularity or trend_granularity(start, end)
        channel_counts = precomputed_counts.get("channels") or {}
        object_counts = precomputed_counts.get("objects") or {}
        company_counts = precomputed_counts.get("companies") or {}
        department_counts = precomputed_counts.get("departments") or {}
        company_labels = company_labels or top_trend_count_labels(company_counts, 5)
        department_labels = department_labels or top_trend_count_labels(department_counts, 5)
        company_links = {label: org_links.get(("company", label, ""), "") for label in company_labels}
        department_links = {label: org_links.get(("department_type", "", label), "") for label in department_labels}
        return {
            "available": True,
            "days": days,
            "label": f"近{days}天",
            "granularity": granularity,
            "granularity_label": precomputed_granularity_label or TREND_GRANULARITY_LABELS.get(granularity, granularity),
            "labels": labels,
            "period": {
                "start": start.isoformat() if start else "",
                "end": end.isoformat() if end else "",
            },
            "note": note,
            "channel_series": build_trend_series(CHANNEL_MATRIX_BASE_ROWS, channel_counts, channel_links),
            "object_series": build_trend_series(CHANNEL_MATRIX_COLUMNS, object_counts, object_links),
            "company_series": build_trend_series(company_labels, company_counts, company_links),
            "department_series": build_trend_series(department_labels, department_counts, department_links),
        }
    period_start, period_end = trend_period_bounds(current_events, start, end, tz)
    if not period_start or not period_end:
        return {"available": False, "days": days, "label": f"近{days}天", "note": "没有可用于趋势分析的时间窗口。"}
    granularity = trend_granularity(period_start, period_end)
    current_buckets, labels = trend_buckets(period_start, period_end, granularity, tz)

    current_matrix_events = trend_matrix_events(current_events, internal_domains)
    current_channel_counts = trend_counts_by_bucket(current_matrix_events, current_buckets, granularity, tz, lambda event: audit_channel_group(event, internal_domains))
    current_object_counts = trend_counts_by_bucket(current_matrix_events, current_buckets, granularity, tz, lambda event: audit_matrix_bucket(event))

    company_labels = company_labels or top_trend_labels(current_matrix_events, event_company_label, 5)
    department_labels = department_labels or top_trend_labels(current_matrix_events, event_department_label, 5)
    current_company_counts = trend_counts_by_bucket(current_matrix_events, current_buckets, granularity, tz, event_company_label)
    current_department_counts = trend_counts_by_bucket(current_matrix_events, current_buckets, granularity, tz, event_department_label)

    if top_source_events and report_start and report_end:
        report_start_local = report_start.astimezone(tz)
        report_end_local = report_end.astimezone(tz)
        overlay_indices = [
            idx
            for idx, bucket in enumerate(current_buckets)
            if bucket < report_end_local and add_trend_bucket(bucket, granularity) > report_start_local
        ]
        if overlay_indices:
            report_matrix_events = trend_matrix_events(top_source_events, internal_domains)
            overlay_channel_counts = trend_counts_by_bucket(report_matrix_events, current_buckets, granularity, tz, lambda event: audit_channel_group(event, internal_domains))
            overlay_object_counts = trend_counts_by_bucket(report_matrix_events, current_buckets, granularity, tz, lambda event: audit_matrix_bucket(event))
            overlay_company_counts = trend_counts_by_bucket(report_matrix_events, current_buckets, granularity, tz, event_company_label)
            overlay_department_counts = trend_counts_by_bucket(report_matrix_events, current_buckets, granularity, tz, event_department_label)

            def apply_overlay(target: dict[str, list[int]], overlay: dict[str, list[int]]) -> None:
                width = len(current_buckets)
                for label, values in overlay.items():
                    target_values = target.setdefault(label, [0 for _ in range(width)])
                    for idx in overlay_indices:
                        target_values[idx] = values[idx] if idx < len(values) else 0

            apply_overlay(current_channel_counts, overlay_channel_counts)
            apply_overlay(current_object_counts, overlay_object_counts)
            apply_overlay(current_company_counts, overlay_company_counts)
            apply_overlay(current_department_counts, overlay_department_counts)

    company_links = {label: org_links.get(("company", label, ""), "") for label in company_labels}
    department_links = {label: org_links.get(("department_type", "", label), "") for label in department_labels}
    return {
        "available": True,
        "days": days,
        "label": f"近{days}天",
        "granularity": granularity,
        "granularity_label": TREND_GRANULARITY_LABELS.get(granularity, granularity),
        "labels": labels,
        "period": {
            "start": period_start.isoformat(),
            "end": period_end.isoformat(),
        },
        "note": note,
        "channel_series": build_trend_series(CHANNEL_MATRIX_BASE_ROWS, current_channel_counts, channel_links),
        "object_series": build_trend_series(CHANNEL_MATRIX_COLUMNS, current_object_counts, object_links),
        "company_series": build_trend_series(company_labels, current_company_counts, company_links),
        "department_series": build_trend_series(department_labels, current_department_counts, department_links),
    }


def build_trend_summary(
    trend_windows: dict[int, dict[str, Any]],
    tz: timezone,
    internal_domains: set[str],
    channel_links: dict[str, str],
    object_links: dict[str, str],
    org_links: dict[tuple[str, str, str], str],
    top_source_events: list[AuditEvent] | None = None,
    report_start: datetime | None = None,
    report_end: datetime | None = None,
) -> dict[str, Any]:
    ranges: list[dict[str, Any]] = []
    top_matrix_events = trend_matrix_events(top_source_events or [], internal_domains)
    company_labels = top_trend_labels(top_matrix_events, event_company_label, 5) if top_matrix_events else []
    department_labels = top_trend_labels(top_matrix_events, event_department_label, 5) if top_matrix_events else []
    for days in TREND_WINDOW_DAYS:
        payload = trend_windows.get(days) or {}
        period_start = payload.get("start")
        period_end = payload.get("end")
        current_events = payload.get("events") or []
        ranges.append(
            build_trend_range_summary(
                current_events,
                period_start,
                period_end,
                days,
                str(payload.get("note") or ""),
                tz,
                internal_domains,
                channel_links,
                object_links,
                org_links,
                company_labels,
                department_labels,
                top_source_events,
                report_start,
                report_end,
                bool(payload.get("available", True)),
                payload.get("counts"),
                payload.get("labels"),
                payload.get("granularity"),
                payload.get("granularity_label"),
            )
            )
    return {
        "available": any(bool(item.get("available")) for item in ranges),
        "default_days": DEFAULT_TREND_WINDOW_DAYS,
        "ranges": ranges,
        "note": "趋势观察窗口独立于本报告统计周期，默认近30天；公司/部门 Top5 按本报告统计周期确定。",
    }


def trend_point_path(values: list[int], chart_w: int, chart_h: int, max_value: int) -> str:
    if not values:
        return ""
    if len(values) == 1:
        x_values = [chart_w / 2]
    else:
        x_values = [idx * chart_w / (len(values) - 1) for idx in range(len(values))]
    points = []
    for idx, value in enumerate(values):
        y = chart_h - (value / max(max_value, 1) * chart_h)
        points.append(f"{x_values[idx]:.1f},{y:.1f}")
    return "M " + " L ".join(points)


def trend_label_indices(count: int, max_ticks: int = 8) -> list[int]:
    if count <= 0:
        return []
    if count <= max_ticks:
        return list(range(count))
    return sorted({round(idx * (count - 1) / (max_ticks - 1)) for idx in range(max_ticks)})


def trend_series_key(title: str, range_label: str, label: str) -> str:
    return slug_id("trend-series", f"{title}|{range_label}|{label}")


def trend_series_values(item: dict[str, Any]) -> list[int]:
    return [int(value or 0) for value in (item.get("current") or [])]


def trend_peak(item: dict[str, Any]) -> int:
    values = trend_series_values(item)
    return max(values) if values else 0


def median_number(values: list[int]) -> float:
    if not values:
        return 0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2


def trend_needs_small_multiples(series: list[dict[str, Any]]) -> bool:
    peaks = [trend_peak(item) for item in series if trend_peak(item) > 0]
    if len(peaks) < 3:
        return False
    max_peak = max(peaks)
    other_peaks = [peak for peak in peaks if peak < max_peak]
    if not other_peaks:
        return False
    low_count = sum(1 for peak in other_peaks if max_peak / max(peak, 1) >= 8)
    return low_count >= 2 and max_peak / max(median_number(other_peaks), 1) >= 8


def trend_small_multiples_html(
    title: str,
    series: list[dict[str, Any]],
    labels: list[str],
    range_label: str,
    granularity_label: str,
) -> str:
    if not trend_needs_small_multiples(series):
        return ""
    width = 360
    height = 168
    left = 34
    top = 20
    chart_w = 306
    chart_h = 92
    label_indices = trend_label_indices(len(labels), 4)
    cards = []
    for item in series:
        label = str(item.get("label") or "")
        values = trend_series_values(item)
        if not label or not values or sum(values) <= 0:
            continue
        peak = max(values)
        axis_max = max(peak, 1)
        color = item.get("color") or "#2563eb"
        path = trend_point_path(values, chart_w, chart_h, axis_max)
        series_key = trend_series_key(title, range_label, label)
        data_values = esc(json.dumps(values, ensure_ascii=False, separators=(",", ":")))
        data_buckets = esc(json.dumps(labels, ensure_ascii=False, separators=(",", ":")))
        total = int(item.get("current_total") or sum(values))
        x_labels = []
        for idx in label_indices:
            if idx < 0 or idx >= len(labels):
                continue
            x = left + (chart_w / 2 if len(labels) == 1 else idx * chart_w / max(len(labels) - 1, 1))
            x_labels.append(f'<text x="{x:.1f}" y="{top + chart_h + 24}" class="trend-axis-label trend-axis-label-x" text-anchor="middle">{esc(labels[idx])}</text>')
        grid = (
            f'<line x1="{left}" y1="{top:.1f}" x2="{left + chart_w}" y2="{top:.1f}" class="trend-grid-line"/>'
            f'<line x1="{left}" y1="{top + chart_h:.1f}" x2="{left + chart_w}" y2="{top + chart_h:.1f}" class="trend-grid-line"/>'
            f'<text x="{left - 10}" y="{top + 4:.1f}" class="trend-axis-label" text-anchor="end">{esc(axis_max)}</text>'
            f'<text x="{left - 10}" y="{top + chart_h + 4:.1f}" class="trend-axis-label" text-anchor="end">0</text>'
        )
        line = ""
        if path:
            line = (
                f'<g class="trend-line-group" data-trend-line="{esc(series_key)}" data-trend-label="{esc(label)}" data-trend-values="{data_values}" data-trend-buckets="{data_buckets}" data-trend-total="{esc(total)}" tabindex="0" role="img" aria-label="{esc(label)} 小尺度趋势">'
                f'<path class="trend-hit-line" d="{path}" transform="translate({left},{top})"/>'
                f'<title>{esc(label)} 合计 {total} 条，峰值 {axis_max} 条</title>'
                f'<path class="trend-line-shadow trend-mini-line-shadow" d="{path}" transform="translate({left},{top})" fill="none" stroke="{esc(color)}" stroke-width="7.2" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>'
                f'<path class="trend-line trend-mini-line" d="{path}" transform="translate({left},{top})" fill="none" stroke="{esc(color)}" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>'
                f'</g>'
            )
        cards.append(
            f"""
            <div class="trend-mini-card">
              <div class="trend-mini-title">
                <span title="{esc(label)}">{esc(label)}</span>
                <strong>合计 {esc(total)} / 峰值 {esc(axis_max)}</strong>
              </div>
              <svg class="trend-mini-svg" viewBox="0 0 {width} {height}" preserveAspectRatio="none" role="img" aria-label="{esc(label)}小尺度趋势">
                <rect x="0" y="0" width="{width}" height="{height}" rx="12" class="trend-svg-bg"/>
                {grid}
                {line}
                {"".join(x_labels)}
              </svg>
            </div>
"""
        )
    if not cards:
        return ""
    return f"""
        <div class="trend-small-multiples">
          <div class="trend-small-head">
            <strong>{esc(title.replace("趋势", "小尺度趋势"))}</strong>
            <span>{esc(range_label)}，{esc(granularity_label)}；独立纵轴，仅看走势，不比较绝对数量。</span>
          </div>
          <div class="trend-mini-grid">{"".join(cards)}</div>
        </div>
"""


def trend_chart_html(
    title: str,
    series: list[dict[str, Any]],
    labels: list[str],
    range_label: str,
    granularity_label: str,
    include_small_multiples: bool = True,
) -> str:
    if not series:
        return f'<div class="trend-chart-card"><h3>{esc(title)}</h3><p class="empty">暂无趋势数据。</p></div>'
    width = 760
    height = 296
    left = 38
    top = 13
    chart_w = 694
    chart_h = 222
    max_value = max(
        [value for item in series for value in (item.get("current") or [])] or [1]
    )
    axis_max = max(max_value, 3)
    grid_lines = []
    for step in range(4):
        y = top + chart_h - (chart_h * step / 3)
        label = round(axis_max * step / 3)
        grid_lines.append(
            f'<line x1="{left}" y1="{y:.1f}" x2="{left + chart_w}" y2="{y:.1f}" class="trend-grid-line"/>'
            f'<text x="{left - 12}" y="{y + 4:.1f}" class="trend-axis-label" text-anchor="end">{esc(label)}</text>'
        )
    label_items = []
    if labels:
        label_indices = trend_label_indices(len(labels))
        for idx in label_indices:
            if idx < 0 or idx >= len(labels):
                continue
            x = left + (chart_w / 2 if len(labels) == 1 else idx * chart_w / (len(labels) - 1))
            label_items.append(f'<text x="{x:.1f}" y="{top + chart_h + 22}" class="trend-axis-label trend-axis-label-x" text-anchor="middle">{esc(labels[idx])}</text>')

    paths = []
    for item in series:
        color = item.get("color") or "#2563eb"
        label = str(item.get("label") or "")
        total = int(item.get("current_total") or 0)
        series_key = trend_series_key(title, range_label, label)
        current_values = trend_series_values(item)
        current_path = trend_point_path(current_values, chart_w, chart_h, axis_max)
        if current_path:
            data_values = esc(json.dumps(current_values, ensure_ascii=False, separators=(",", ":")))
            data_buckets = esc(json.dumps(labels, ensure_ascii=False, separators=(",", ":")))
            line_title = f"{label} 合计 {total} 条"
            point_items = []
            for idx, value in enumerate(current_values):
                x = chart_w / 2 if len(current_values) == 1 else idx * chart_w / max(len(current_values) - 1, 1)
                y = chart_h - (value / max(axis_max, 1) * chart_h)
                bucket = labels[idx] if idx < len(labels) else f"第{idx + 1}点"
                tip = f"{label} {bucket}：{value} 条 / 合计 {total} 条"
                point_items.append(
                    f'<circle class="trend-point-hit" cx="{x:.1f}" cy="{y:.1f}" r="7" transform="translate({left},{top})" data-trend-tip="{esc(tip)}"><title>{esc(tip)}</title></circle>'
                )
            paths.append(
                f'<g class="trend-line-group" data-trend-line="{esc(series_key)}" data-trend-label="{esc(label)}" data-trend-values="{data_values}" data-trend-buckets="{data_buckets}" data-trend-total="{esc(total)}" tabindex="0" role="img" aria-label="{esc(line_title)}">'
                f'<path class="trend-hit-line" d="{current_path}" transform="translate({left},{top})"/>'
                f'<title>{esc(line_title)}</title>'
                f'<path class="trend-line-shadow" d="{current_path}" transform="translate({left},{top})" fill="none" stroke="{esc(color)}" stroke-width="6.6" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>'
                f'<path class="trend-line" d="{current_path}" transform="translate({left},{top})" fill="none" stroke="{esc(color)}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>'
                f'{"".join(point_items)}'
                f'</g>'
            )
    legend = []
    for item in series:
        label = str(item.get("label") or "")
        series_key = trend_series_key(title, range_label, label)
        body = (
            f'<span class="trend-line-swatch" style="--trend-color:{esc(item.get("color") or "#2563eb")}"></span>'
            f'<span class="trend-legend-label" title="{esc(label)}">{esc(label)}</span>'
            f'<strong>{esc(item.get("current_total", 0))}</strong>'
        )
        legend_title = f"{label} 合计 {int(item.get('current_total') or 0)} 条"
        legend.append(
            f'<button type="button" class="trend-legend-item" data-trend-toggle="{esc(series_key)}" aria-pressed="true" title="{esc(legend_title)}">{body}</button>'
        )
    compare_note = f"{range_label}，{granularity_label}展示。"
    small_multiples = trend_small_multiples_html(title, series, labels, range_label, granularity_label) if include_small_multiples else ""
    return f"""
      <div class="trend-chart-card">
        <div class="trend-chart-head">
          <h3>{esc(title)}</h3>
          <span>{esc(compare_note)}</span>
        </div>
        <svg class="trend-svg" viewBox="0 0 {width} {height}" preserveAspectRatio="none" role="img" aria-label="{esc(title)}趋势曲线">
          <rect x="0" y="0" width="{width}" height="{height}" rx="14" class="trend-svg-bg"/>
          {"".join(grid_lines)}
          {"".join(paths)}
          {"".join(label_items)}
        </svg>
        <div class="trend-legend">{"".join(legend)}</div>
        {small_multiples}
      </div>
"""



def trend_comparison_html(trend_summary: dict[str, Any]) -> str:
    if not trend_summary.get("available"):
        return f"""
    <section id="risk-trend" class="section-block trend-shell">
      <div class="section-title-row">
        <div>
          <span class="section-eyebrow">Trend Compare</span>
          <h2>天擎外发风险趋势</h2>
          <p>{esc(trend_summary.get("note") or "暂无趋势数据。")}</p>
        </div>
      </div>
    </section>
"""
    ranges = [item for item in trend_summary.get("ranges") or [] if isinstance(item, dict)]
    default_days = int(trend_summary.get("default_days") or DEFAULT_TREND_WINDOW_DAYS)
    if not any(int(item.get("days") or 0) == default_days for item in ranges) and ranges:
        default_days = int(ranges[0].get("days") or DEFAULT_TREND_WINDOW_DAYS)
    range_buttons = []
    range_panels = []
    for item in ranges:
        days = int(item.get("days") or 0)
        if days <= 0:
            continue
        active = " active" if days == default_days else ""
        label = str(item.get("label") or f"近{days}天")
        labels = [str(label_item) for label_item in item.get("labels") or []]
        granularity_label = str(item.get("granularity_label") or "自动粒度")
        note = str(item.get("note") or "")
        note_html = f'<p class="note trend-range-note">{esc(note)}</p>' if note else ""
        channel_panel = trend_chart_html("通道趋势", item.get("channel_series") or [], labels, label, granularity_label)
        object_panel = trend_chart_html("对象趋势", item.get("object_series") or [], labels, label, granularity_label)
        company_panel = trend_chart_html("公司 Top5 趋势", item.get("company_series") or [], labels, label, granularity_label)
        department_panel = trend_chart_html("部门 Top5 趋势", item.get("department_series") or [], labels, label, granularity_label)
        range_buttons.append(f'<button type="button" class="{active.strip()}" data-trend-range="{days}">{esc(label)}</button>')
        range_panels.append(
            f"""
      <div class="trend-range-panel{active}" data-trend-range-panel="{days}">
        {note_html}
        <div class="trend-panel trend-channel-grid active" data-trend-panel="channel">{channel_panel}{object_panel}</div>
        <div class="trend-panel trend-org-grid" data-trend-panel="organization">{company_panel}{department_panel}</div>
      </div>
"""
        )
    return f"""
    <section id="risk-trend" class="section-block trend-shell">
      <div class="section-title-row">
        <div>
          <span class="section-eyebrow">Trend Window</span>
          <h2>天擎外发风险趋势</h2>
          <p>{esc(trend_summary.get("note") or "趋势观察窗口默认近30天；公司/部门 Top5 按本报告统计周期确定。")}</p>
        </div>
      </div>
      <div class="trend-control-row">
        <div class="trend-range-tabs" role="tablist" aria-label="趋势时间窗口">
          {"".join(range_buttons)}
        </div>
        <div class="trend-tabs" role="tablist" aria-label="趋势维度">
          <button type="button" class="active" data-trend-tab="channel">通道/对象</button>
          <button type="button" data-trend-tab="organization">组织趋势</button>
        </div>
      </div>
      {"".join(range_panels)}
    </section>
    <script>
      (function () {{
        var rangeTabs = Array.prototype.slice.call(document.querySelectorAll("#risk-trend [data-trend-range]"));
        var rangePanels = Array.prototype.slice.call(document.querySelectorAll("#risk-trend [data-trend-range-panel]"));
        var tabs = Array.prototype.slice.call(document.querySelectorAll("#risk-trend [data-trend-tab]"));
        var panels = Array.prototype.slice.call(document.querySelectorAll("#risk-trend [data-trend-panel]"));
        var legendToggles = Array.prototype.slice.call(document.querySelectorAll("#risk-trend [data-trend-toggle]"));
        var activeTab = "channel";
        function activateTab(name) {{
          activeTab = name;
          tabs.forEach(function (item) {{ item.classList.toggle("active", item.getAttribute("data-trend-tab") === name); }});
          panels.forEach(function (panel) {{ panel.classList.toggle("active", panel.getAttribute("data-trend-panel") === name); }});
        }}
        function activateRange(days) {{
          rangeTabs.forEach(function (item) {{ item.classList.toggle("active", item.getAttribute("data-trend-range") === days); }});
          rangePanels.forEach(function (panel) {{ panel.classList.toggle("active", panel.getAttribute("data-trend-range-panel") === days); }});
          activateTab(activeTab);
        }}
        rangeTabs.forEach(function (tab) {{
          tab.addEventListener("click", function () {{
            activateRange(tab.getAttribute("data-trend-range"));
          }});
        }});
        tabs.forEach(function (tab) {{
          tab.addEventListener("click", function () {{
            activateTab(tab.getAttribute("data-trend-tab"));
          }});
        }});
        legendToggles.forEach(function (toggle) {{
          toggle.addEventListener("click", function () {{
            var key = toggle.getAttribute("data-trend-toggle");
            var hidden = !toggle.classList.contains("is-muted");
            toggle.classList.toggle("is-muted", hidden);
            toggle.setAttribute("aria-pressed", hidden ? "false" : "true");
            Array.prototype.forEach.call(document.querySelectorAll('#risk-trend [data-trend-line="' + key + '"]'), function (line) {{
              line.classList.toggle("is-hidden", hidden);
            }});
          }});
        }});
        var trendTip = document.createElement("div");
        trendTip.className = "trend-hover-tip";
        document.body.appendChild(trendTip);
        function parseJsonArray(raw) {{
          try {{
            var parsed = JSON.parse(raw || "[]");
            return Array.isArray(parsed) ? parsed : [];
          }} catch (err) {{
            return [];
          }}
        }}
        function pathPoints(group) {{
          var path = group.querySelector(".trend-line");
          var raw = path ? (path.getAttribute("d") || "") : "";
          var points = [];
          raw.replace(/(-?\\d+(?:\\.\\d+)?),(-?\\d+(?:\\.\\d+)?)/g, function (_, x, y) {{
            points.push({{x: Number(x), y: Number(y)}});
            return "";
          }});
          return points;
        }}
        function fallbackBuckets(group, count) {{
          var card = group.closest(".trend-chart-card");
          var labels = card ? Array.prototype.map.call(card.querySelectorAll(".trend-axis-label-x"), function (node) {{ return (node.textContent || "").trim(); }}) : [];
          if (labels.length === count) {{
            return labels;
          }}
          var result = [];
          for (var i = 0; i < count; i += 1) {{
            result.push(labels[i] || ("第" + (i + 1) + "点"));
          }}
          return result;
        }}
        function fallbackAxisMax(group) {{
          var card = group.closest(".trend-chart-card");
          var values = card ? Array.prototype.map.call(card.querySelectorAll(".trend-axis-label:not(.trend-axis-label-x)"), function (node) {{ return Number((node.textContent || "").trim()); }}) : [];
          values = values.filter(function (value) {{ return isFinite(value); }});
          return values.length ? Math.max.apply(Math, values) : 1;
        }}
        function trendText(group, evt) {{
          var direct = evt && evt.target && evt.target.getAttribute && evt.target.getAttribute("data-trend-tip");
          if (direct) {{
            return direct;
          }}
          var label = group.getAttribute("data-trend-label") || "";
          var values = parseJsonArray(group.getAttribute("data-trend-values")).map(function (value) {{ return Number(value) || 0; }});
          var buckets = parseJsonArray(group.getAttribute("data-trend-buckets"));
          var total = Number(group.getAttribute("data-trend-total") || 0);
          var points = pathPoints(group);
          if (!points.length) {{
            return label ? (label + " 合计 " + total + " 条") : "";
          }}
          if (!values.length) {{
            var chartH = Math.max.apply(Math, points.map(function (point) {{ return point.y; }})) || 1;
            var axisMax = fallbackAxisMax(group);
            values = points.map(function (point) {{ return Math.max(0, Math.round((chartH - point.y) / chartH * axisMax)); }});
          }}
          if (!buckets.length) {{
            buckets = fallbackBuckets(group, points.length);
          }}
          if (!total) {{
            total = values.reduce(function (sum, value) {{ return sum + value; }}, 0);
          }}
          var idx = 0;
          if (evt && isFinite(evt.clientX)) {{
            var svg = group.closest("svg");
            var rect = svg.getBoundingClientRect();
            var viewW = svg.viewBox && svg.viewBox.baseVal ? svg.viewBox.baseVal.width : rect.width;
            var localX = (evt.clientX - rect.left) * viewW / Math.max(rect.width, 1) - 30;
            var best = Infinity;
            points.forEach(function (point, pointIdx) {{
              var distance = Math.abs(point.x - localX);
              if (distance < best) {{
                best = distance;
                idx = pointIdx;
              }}
            }});
          }}
          return (label || "趋势") + " " + (buckets[idx] || ("第" + (idx + 1) + "点")) + "：" + (values[idx] || 0) + " 条 / 合计 " + total + " 条";
        }}
        function showTrendTip(group, evt) {{
          if (!group || group.classList.contains("is-hidden")) {{
            trendTip.style.display = "none";
            return;
          }}
          var text = trendText(group, evt);
          if (!text) {{
            return;
          }}
          trendTip.textContent = text;
          trendTip.style.display = "block";
          var x = evt && isFinite(evt.clientX) ? evt.clientX + 12 : 24;
          var y = evt && isFinite(evt.clientY) ? evt.clientY + 12 : 24;
          trendTip.style.left = Math.min(x, window.innerWidth - trendTip.offsetWidth - 12) + "px";
          trendTip.style.top = Math.min(y, window.innerHeight - trendTip.offsetHeight - 12) + "px";
        }}
        Array.prototype.forEach.call(document.querySelectorAll("#risk-trend .trend-line-group"), function (group) {{
          group.addEventListener("mousemove", function (evt) {{ showTrendTip(group, evt); }});
          group.addEventListener("click", function (evt) {{ showTrendTip(group, evt); }});
          group.addEventListener("focus", function (evt) {{ showTrendTip(group, evt); }});
          group.addEventListener("mouseleave", function () {{ trendTip.style.display = "none"; }});
          group.addEventListener("blur", function () {{ trendTip.style.display = "none"; }});
        }});
      }})();
    </script>
"""
