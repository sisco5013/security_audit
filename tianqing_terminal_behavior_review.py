#!/usr/bin/env python3
"""Manual review workflow for abnormal terminal behavior candidates."""

from __future__ import annotations

import hashlib
import html
import json
import re
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable

import tianqing_external_audit_report as report_gen


TERMINAL_BEHAVIOR_REVIEW_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS terminal_behavior_reviews
(
    event_date Date,
    event_start DateTime64(3, 'Asia/Shanghai'),
    event_end DateTime64(3, 'Asia/Shanghai'),
    review_id String,
    candidate_id String,
    anomaly_type LowCardinality(String),
    status LowCardinality(String),
    include_in_report UInt8,
    reviewer_userid String,
    reviewer_name String,
    review_time DateTime64(3, 'Asia/Shanghai'),
    updated_at DateTime64(3, 'Asia/Shanghai'),
    company String,
    department String,
    person String,
    client_name String,
    client_ip String,
    client_mac String,
    event_count UInt32,
    structure_count UInt32,
    electrical_count UInt32,
    three_d_count UInt32,
    dwg_count UInt32,
    archive_count UInt32,
    channels Array(String),
    targets Array(String),
    sample_files Array(String),
    event_ids Array(String),
    conclusion String,
    notes String,
    owner_department String,
    due_date Nullable(Date),
    evidence_json String
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, review_id)
TTL event_date + INTERVAL 3 YEAR
SETTINGS index_granularity = 8192
"""


REVIEW_STATUSES = ["待核查", "异常待整改", "正常业务", "误报", "继续观察", "已闭环", "不纳入报告"]
REPORT_EXCLUDED_STATUSES = {"不纳入报告"}
DEFAULT_REVIEW_POLICY: dict[str, Any] = {
    "enabled": True,
    "peripheral_design_daily": 300,
    "peripheral_total_daily": 1000,
    "core_design_daily": 50,
    "burst_window_minutes": 30,
    "burst_min_events": 30,
    "multi_channel_min_channels": 2,
    "multi_channel_min_events": 20,
    "multi_target_min_targets": 8,
    "multi_target_min_events": 15,
    "unknown_target_min_events": 10,
    "external_mailbox_min_events": 1,
    "baseline_days": 90,
    "baseline_multiplier": 5,
    "baseline_min_events": 30,
    "other_drawing_min_events": 100,
    "sensitive_name_min_events": 1000,
    "candidate_limit": 300,
}
DEFAULT_THREE_D_EXTS = {"prt", "asm", "sldasm", "sldprt", "step"}
DEFAULT_TWO_D_EXTS = {"dwg"}
DEFAULT_ARCHIVE_EXTS = {"zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "zst", "zipx", "001"}


@dataclass
class TerminalBehaviorCandidate:
    candidate_id: str
    event_date: date
    event_start: datetime
    event_end: datetime
    anomaly_type: str
    company: str
    department: str
    person: str
    client_name: str
    client_ip: str
    client_mac: str
    event_count: int = 0
    structure_count: int = 0
    electrical_count: int = 0
    three_d_count: int = 0
    dwg_count: int = 0
    archive_count: int = 0
    channels: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    sample_files: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    matrix_counts: dict[str, int] = field(default_factory=dict)
    evidence_events: list[dict[str, Any]] = field(default_factory=list)
    basis: str = ""
    existing_status: str = ""
    existing_review_time: str = ""
    existing_conclusion: str = ""
    existing_notes: str = ""
    existing_owner_department: str = ""
    existing_due_date: str = ""


@dataclass
class TerminalBehaviorReview:
    review_id: str
    candidate_id: str
    event_date: str
    event_start: str
    event_end: str
    anomaly_type: str
    status: str
    include_in_report: int
    reviewer_userid: str
    reviewer_name: str
    review_time: str
    company: str
    department: str
    person: str
    client_name: str
    client_ip: str
    client_mac: str
    event_count: int
    structure_count: int
    electrical_count: int
    three_d_count: int
    dwg_count: int
    archive_count: int
    channels: list[str]
    targets: list[str]
    sample_files: list[str]
    event_ids: list[str]
    conclusion: str = ""
    notes: str = ""
    owner_department: str = ""
    due_date: str = ""


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def normalize_text(value: Any) -> str:
    return " ".join(str(value if value is not None else "").replace("\u3000", " ").strip().split())


def normalize_key(value: Any) -> str:
    return normalize_text(value).lower()


def ch_quote(value: Any) -> str:
    return "'" + str(value if value is not None else "").replace("\\", "\\\\").replace("'", "\\'") + "'"


def ch_array(values: Iterable[str]) -> str:
    return "[" + ",".join(ch_quote(value) for value in values) + "]"


def ch_tuple(values: Iterable[str]) -> str:
    return "(" + ",".join(ch_quote(value) for value in values) + ")"


def clickhouse_headers(config: Any) -> dict[str, str]:
    headers: dict[str, str] = {}
    user = str(getattr(config, "clickhouse_user", "") or "").strip()
    password = str(getattr(config, "clickhouse_password", "") or "").strip()
    if user:
        headers["X-ClickHouse-User"] = user
    if password:
        headers["X-ClickHouse-Key"] = password
    return headers


def clickhouse_query(config: Any, query: str, data: bytes | None = None) -> str:
    params = {"database": getattr(config, "clickhouse_database", "tianqing"), "query": query}
    url = str(getattr(config, "clickhouse_url", "http://127.0.0.1:8123")).rstrip("/") + "/?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, data=data, headers=clickhouse_headers(config), method="POST")
    with urllib.request.urlopen(request, timeout=int(getattr(config, "clickhouse_timeout", 120) or 120)) as response:
        return response.read().decode("utf-8", errors="replace")


def clickhouse_query_body(config: Any, query: str) -> str:
    params = {"database": getattr(config, "clickhouse_database", "tianqing")}
    url = str(getattr(config, "clickhouse_url", "http://127.0.0.1:8123")).rstrip("/") + "/?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, data=query.encode("utf-8"), headers=clickhouse_headers(config), method="POST")
    with urllib.request.urlopen(request, timeout=int(getattr(config, "clickhouse_timeout", 120) or 120)) as response:
        return response.read().decode("utf-8", errors="replace")


def ensure_review_table(config: Any) -> None:
    clickhouse_query(config, f"CREATE DATABASE IF NOT EXISTS {getattr(config, 'clickhouse_database', 'tianqing')}")
    clickhouse_query(config, TERMINAL_BEHAVIOR_REVIEW_TABLE_SQL)


def policy_int(policy: dict[str, Any], key: str) -> int:
    default = int(DEFAULT_REVIEW_POLICY[key])
    try:
        return max(0, int(policy.get(key, default)))
    except (TypeError, ValueError):
        return default


def normalized_review_policy(policy_doc: dict[str, Any] | None) -> dict[str, Any]:
    raw = policy_doc.get("terminal_behavior_review") if isinstance(policy_doc, dict) else {}
    raw = raw if isinstance(raw, dict) else {}
    result = dict(DEFAULT_REVIEW_POLICY)
    for key in DEFAULT_REVIEW_POLICY:
        if key == "enabled":
            result[key] = bool(raw.get(key, DEFAULT_REVIEW_POLICY[key]))
        elif key in raw:
            result[key] = policy_int(raw, key)
    return result


def ext_from_name(name: str) -> str:
    base = re.split(r"[\\/]", normalize_text(name).split("?", 1)[0])[-1]
    if "." not in base:
        return ""
    ext = base.rsplit(".", 1)[-1].strip().lower()
    return ext if re.fullmatch(r"[a-z0-9_]{1,16}", ext) else ""


def policy_exts(policy_doc: dict[str, Any] | None) -> tuple[set[str], set[str], set[str], list[tuple[str, re.Pattern[str]]]]:
    policy_doc = policy_doc if isinstance(policy_doc, dict) else {}
    design = policy_doc.get("design_suffixes") if isinstance(policy_doc.get("design_suffixes"), dict) else {}
    three_d = {normalize_key(item).lstrip(".") for item in design.get("three_d", []) if normalize_key(item)} or set(DEFAULT_THREE_D_EXTS)
    two_d = {normalize_key(item).lstrip(".") for item in design.get("two_d", []) if normalize_key(item)} or set(DEFAULT_TWO_D_EXTS)
    archives = {normalize_key(item).lstrip(".") for item in policy_doc.get("archive_suffixes", []) if normalize_key(item)} or set(DEFAULT_ARCHIVE_EXTS)
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for item in policy_doc.get("critical_design_patterns", []) if isinstance(policy_doc.get("critical_design_patterns"), list) else []:
        if not isinstance(item, dict) or item.get("enabled", True) is False:
            continue
        try:
            label = str(item.get("label") or item.get("key") or "")
            patterns.append((label, re.compile(str(item.get("regex") or ""), re.IGNORECASE)))
        except re.error:
            continue
    return three_d, two_d, archives, patterns


def parse_ts(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace(" ", "T"))
    except ValueError:
        return None


def display_channel(event: dict[str, Any]) -> str:
    topic = str(event.get("topic") or "")
    channel = str(event.get("channel") or "")
    if "外设拷贝" in channel or "外设拷贝" in event.get("reasons", []):
        return "外设拷贝"
    if topic == "mail_audit":
        return "邮件外发"
    if topic == "im_audit":
        return "IM附件"
    if "外部站点上传" in channel or "外部站点上传" in event.get("reasons", []):
        return "外部站点上传"
    return channel or topic or "未知通道"


def event_targets(event: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("recipients", "targets", "target_domains"):
        raw = event.get(key) or []
        if isinstance(raw, list):
            values.extend(str(item) for item in raw if str(item or "").strip())
    return list(dict.fromkeys(values))[:30]


def is_external_mailbox(mailbox: str) -> bool:
    domain = mailbox.rsplit("@", 1)[-1].lower() if "@" in mailbox else ""
    return bool(domain and domain != "daqo.com")


def is_wecom_process_name(process_name: Any) -> bool:
    return normalize_key(process_name) in {"wxwork.exe", "wxwork", "wecom.exe", "wecom"}


def trusted_internal_sql() -> str:
    wecom_processes = "('wxwork.exe','wxwork','wecom.exe','wecom')"
    return (
        "(recipient_relation = 'internal' AND ("
        "topic = 'mail_audit' "
        f"OR (topic = 'im_audit' AND lowerUTF8(process_name) IN {wecom_processes}) "
        f"OR (topic = 'file_audit' AND channel = '应用发送/传输' AND lowerUTF8(process_name) IN {wecom_processes})"
        "))"
    )


def is_im_file_send_row(event: dict[str, Any]) -> bool:
    return (
        str(event.get("topic") or "") == "file_audit"
        and str(event.get("channel") or "") == "应用发送/传输"
        and is_wecom_process_name(event.get("process_name"))
    )


def trusted_internal_row(event: dict[str, Any]) -> bool:
    if str(event.get("recipient_relation") or "").strip().lower() != "internal":
        return False
    topic = str(event.get("topic") or "")
    if topic == "mail_audit":
        return True
    if topic == "im_audit":
        return is_wecom_process_name(event.get("process_name"))
    return is_im_file_send_row(event)


def candidate_scope_event(event: dict[str, Any]) -> bool:
    channel = display_channel(event)
    reasons = {str(reason) for reason in event.get("reasons") or []}
    if channel == "内部系统上传" or "内部系统上传" in reasons:
        return False
    if channel == "文件重命名" or "文件重命名" in reasons:
        return False
    if trusted_internal_row(event):
        return False
    return True


def event_object_counts(event: dict[str, Any], three_d: set[str], two_d: set[str], archives: set[str], patterns: list[tuple[str, re.Pattern[str]]]) -> Counter:
    counts: Counter = Counter()
    names = [str(item) for item in event.get("file_names") or []]
    exts = {normalize_key(item).lstrip(".") for item in event.get("file_exts") or [] if normalize_key(item)}
    if not exts:
        exts = {ext_from_name(name) for name in names if ext_from_name(name)}
    for label, pattern in patterns:
        if not any(pattern.search(re.split(r"[\\/]", name)[-1]) for name in names):
            continue
        if "电气" in label or "electrical" in label.lower():
            counts["electrical"] += 1
        else:
            counts["structure"] += 1
    if exts & three_d:
        counts["three_d"] += 1
    if exts & two_d:
        counts["dwg"] += 1
    if exts & archives:
        counts["archive"] += 1
    if any("敏感" in str(reason) for reason in event.get("reasons") or []):
        counts["sensitive"] += 1
    return counts


def event_matrix_bucket(event: dict[str, Any], three_d: set[str], two_d: set[str], archives: set[str], patterns: list[tuple[str, re.Pattern[str]]]) -> str:
    names = [str(item) for item in event.get("file_names") or []]
    exts = {normalize_key(item).lstrip(".") for item in event.get("file_exts") or [] if normalize_key(item)}
    if not exts:
        exts = {ext_from_name(name) for name in names if ext_from_name(name)}
    reasons = [str(reason) for reason in event.get("reasons") or []]
    for label, pattern in patterns:
        if any(pattern.search(re.split(r"[\\/]", name)[-1]) for name in names):
            return label
        if f"{report_gen.CRITICAL_DESIGN_REASON_PREFIX}{label}" in reasons:
            return label
    if exts & three_d or "三维模型" in reasons:
        return "三维模型"
    if exts & two_d or "DWG二维图纸" in reasons:
        return "DWG二维图纸"
    if any(reason.startswith("敏感") for reason in reasons):
        return "敏感名称"
    if exts & archives or "压缩包" in reasons:
        return "压缩包"
    return ""


def significant_event(event: dict[str, Any], three_d: set[str], two_d: set[str], archives: set[str], patterns: list[tuple[str, re.Pattern[str]]]) -> bool:
    counts = event_object_counts(event, three_d, two_d, archives, patterns)
    return bool(counts["structure"] or counts["electrical"] or counts["three_d"] or counts["dwg"] or counts["archive"] or counts["sensitive"])


def primary_risk_event(event: dict[str, Any], three_d: set[str], two_d: set[str], archives: set[str], patterns: list[tuple[str, re.Pattern[str]]]) -> bool:
    counts = event_object_counts(event, three_d, two_d, archives, patterns)
    return bool(counts["structure"] or counts["electrical"])


def standard_drawing_event(event: dict[str, Any], three_d: set[str], two_d: set[str], archives: set[str], patterns: list[tuple[str, re.Pattern[str]]]) -> bool:
    return event_matrix_bucket(event, three_d, two_d, archives, patterns) in report_gen.CRITICAL_DESIGN_LABELS


def ordinary_drawing_event(event: dict[str, Any], three_d: set[str], two_d: set[str], archives: set[str], patterns: list[tuple[str, re.Pattern[str]]]) -> bool:
    if standard_drawing_event(event, three_d, two_d, archives, patterns):
        return False
    bucket = event_matrix_bucket(event, three_d, two_d, archives, patterns)
    return bucket in {"三维模型", "DWG二维图纸"}


def sensitive_name_event(event: dict[str, Any], three_d: set[str], two_d: set[str], archives: set[str], patterns: list[tuple[str, re.Pattern[str]]]) -> bool:
    return event_matrix_bucket(event, three_d, two_d, archives, patterns) == "敏感名称"


def report_arg_namespace(config: Any) -> SimpleNamespace:
    app_dir = Path(getattr(config, "app_dir", "."))
    return SimpleNamespace(
        use_clickhouse=True,
        clickhouse_url=getattr(config, "clickhouse_url", "http://127.0.0.1:8123"),
        clickhouse_database=getattr(config, "clickhouse_database", "tianqing"),
        clickhouse_user=getattr(config, "clickhouse_user", ""),
        clickhouse_password=getattr(config, "clickhouse_password", ""),
        clickhouse_timeout=int(getattr(config, "clickhouse_timeout", 120) or 120),
        audit_policy_file=str(getattr(config, "policy_file", app_dir / "audit_policy.json")),
        sensitive_keywords_file=str(getattr(config, "keywords_file", app_dir / "sensitive_keywords.json")),
        exclusion_file=str(getattr(config, "exclusions_file", app_dir / "audit_exclusions.json")),
        people_map=str(app_dir / "people_mapping.csv"),
        recipient_map=str(app_dir / "recipient_mapping.csv"),
        disable_wecom_directory=False,
        wecom_directory_host=getattr(config, "ai_host", ""),
        wecom_directory_container=getattr(config, "ai_container", ""),
        wecom_directory_cache=str(app_dir / "wecom_directory_cache.json"),
        wecom_directory_cache_hours=24 * 365 * 20,
        wecom_directory_refresh=False,
        wecom_directory_min_users=100,
        wecom_directory_authoritative=False,
        terminal_identity_max_age_days=30,
    )


def load_cached_wecom_items(config: Any) -> list[dict[str, Any]]:
    cache_path = Path(getattr(config, "app_dir", ".")) / "wecom_directory_cache.json"
    try:
        data = json.loads(cache_path.read_text("utf-8"))
    except Exception:
        return []
    items = data.get("items") if isinstance(data, dict) else data
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def configure_report_policy_context(config: Any, policy_doc: dict[str, Any]) -> tuple[SimpleNamespace, set[str]]:
    args = report_arg_namespace(config)
    report_gen.configure_audit_policy(policy_doc if isinstance(policy_doc, dict) else {})
    try:
        report_gen.configure_sensitive_keyword_rules(report_gen.load_sensitive_keyword_rules(args.sensitive_keywords_file))
    except Exception:
        report_gen.configure_sensitive_keyword_rules([])
    internal_domains = set(report_gen.DEFAULT_INTERNAL_DOMAINS)
    internal_domains.update(report_gen.policy_internal_domains(policy_doc if isinstance(policy_doc, dict) else {}))
    people_map = report_gen.load_people_map(args.people_map)
    wecom_items = load_cached_wecom_items(config)
    args.people_map_loaded = people_map
    args.wecom_people_map_loaded = report_gen.build_wecom_people_map(wecom_items)
    args.wecom_directory_meta = {"source": "cache", "ok": bool(wecom_items), "count": len(wecom_items)}
    return args, internal_domains


def report_detail_row(event: Any, internal_domains: set[str]) -> dict[str, Any]:
    channel = report_gen.audit_channel_group(event, internal_domains) or str(getattr(event, "channel", "") or "")
    return {
        "event_id": str(getattr(event, "event_id", "") or ""),
        "event_date": (getattr(event, "ts", None).date().isoformat() if getattr(event, "ts", None) else ""),
        "ts": getattr(event, "ts", None).isoformat() if getattr(event, "ts", None) else "",
        "topic": str(getattr(event, "topic", "") or ""),
        "channel": channel,
        "level": str(getattr(event, "level", "") or ""),
        "company": report_gen.event_company_label(event),
        "department": report_gen.event_department_label(event),
        "resolved_person": str(getattr(event, "resolved_person", "") or getattr(event, "person", "") or ""),
        "person": str(getattr(event, "person", "") or ""),
        "client_name": str(getattr(event, "client_name", "") or ""),
        "client_ip": str(getattr(event, "client_ip", "") or ""),
        "process_name": str(getattr(event, "process_name", "") or ""),
        "mail_subject": str(getattr(event, "mail_subject", "") or ""),
        "sender_mailbox": str(getattr(event, "sender_mailbox", "") or ""),
        "recipient_relation": str(getattr(event, "recipient_relation", "") or ""),
        "targets": [str(item) for item in getattr(event, "targets", []) or []],
        "target_domains": [str(item) for item in getattr(event, "target_domains", []) or []],
        "recipients": [str(item) for item in getattr(event, "recipients", []) or []],
        "file_names": [str(item) for item in getattr(event, "file_names", []) or []],
        "file_exts": [str(item) for item in getattr(event, "file_exts", []) or []],
        "file_size": getattr(event, "file_size", None),
        "lookup_keys": [str(item) for item in getattr(event, "lookup_keys", []) or []],
        "reasons": [str(item) for item in getattr(event, "reasons", []) or []],
        "parsed_ts": getattr(event, "ts", None),
    }


def limited_terminal_identity_history(
    config: Any,
    args: SimpleNamespace,
    events: list[Any],
    tz: Any,
    start: datetime,
    end: datetime,
) -> dict[tuple[str, str], list[Any]]:
    wecom_people_map = getattr(args, "wecom_people_map_loaded", {}) or {}
    if not wecom_people_map or not events:
        return {}
    max_age_days = int(getattr(args, "terminal_identity_max_age_days", 30) or 0)
    identity_start = start - timedelta(days=max_age_days) if max_age_days > 0 else start
    names = sorted({str(getattr(event, "client_name", "") or "").strip() for event in events if str(getattr(event, "client_name", "") or "").strip()})
    ips = sorted({str(getattr(event, "client_ip", "") or "").strip() for event in events if str(getattr(event, "client_ip", "") or "").strip()})
    filters: list[str] = []
    if names:
        filters.append(f"JSONExtractString(raw_json, 'client_name') IN {ch_tuple(names[:1000])}")
    if ips:
        filters.append(f"JSONExtractString(raw_json, 'client_ip') IN {ch_tuple(ips[:1000])}")
    if not filters:
        return {}
    query = f"""
SELECT ts,
  JSONExtractString(raw_json, 'process_name') AS process_name,
  JSONExtractString(raw_json, 'client_name') AS client_name,
  JSONExtractString(raw_json, 'client_ip') AS client_ip,
  JSONExtractString(raw_json, 'client_login_account') AS login_account,
  JSONExtractString(raw_json, 'local_account') AS local_account,
  JSONExtractString(raw_json, 'local_nickname') AS local_nickname
FROM raw_syslog
WHERE ts >= parseDateTime64BestEffort({ch_quote(identity_start.isoformat())}, 3)
  AND ts < parseDateTime64BestEffort({ch_quote(end.isoformat())}, 3)
  AND topic = 'im_audit'
  AND lower(JSONExtractString(raw_json, 'process_name')) = 'wxwork.exe'
  AND (length(JSONExtractString(raw_json, 'client_login_account')) > 0 OR length(JSONExtractString(raw_json, 'local_nickname')) > 0)
  AND ({' OR '.join(filters)})
FORMAT JSONEachRow
"""
    rows = (json.loads(line) for line in clickhouse_query_body(config, query).splitlines() if line.strip())
    return report_gen.build_terminal_identity_history_from_rows(rows, tz, wecom_people_map)


def fetch_report_detail_events(config: Any, start: datetime, end: datetime, policy_doc: dict[str, Any]) -> list[dict[str, Any]]:
    args, internal_domains = configure_report_policy_context(config, policy_doc)
    tz = report_gen.get_tz(getattr(config, "timezone", "Asia/Shanghai"))
    three_d, two_d, archives, _patterns = policy_exts(policy_doc)
    signal_exts = sorted(three_d | two_d | archives)
    query = f"""
SELECT {report_gen.CLICKHOUSE_AUDIT_EVENT_SELECT}
FROM audit_events
WHERE ts >= parseDateTime64BestEffort({ch_quote(start.isoformat())}, 3)
  AND ts < parseDateTime64BestEffort({ch_quote(end.isoformat())}, 3)
  AND topic IN ('mail_audit','im_audit','file_audit')
  AND length(file_names) > 0
  AND channel != '内部系统上传'
  AND channel != '文件重命名'
  AND NOT has(reasons, '内部系统上传')
  AND NOT has(reasons, '文件重命名')
  AND (
      hasAny(file_exts, {ch_array(signal_exts)})
      OR hasAny(reasons, ['外设拷贝','外部站点上传','外部上传/下载地址','个人邮箱域名','外部收件域名','网盘/高风险外联目标','三维模型','DWG二维图纸','压缩包'])
      OR arrayExists(reason -> startsWith(reason, '敏感'), reasons)
      OR arrayExists(reason -> startsWith(reason, '{report_gen.CRITICAL_DESIGN_REASON_PREFIX}'), reasons)
      OR level = 'HIGH'
      OR ifNull(file_size, 0) >= 10485760
  )
FORMAT JSONEachRow
"""
    audit_events = [
        report_gen.audit_event_from_clickhouse_row(json.loads(line), tz)
        for line in clickhouse_query(config, query).splitlines()
        if line.strip()
    ]
    if not audit_events:
        return []
    terminal_identity_history = limited_terminal_identity_history(config, args, audit_events, tz, start, end)
    report_gen.apply_report_policies(audit_events, {}, internal_domains)
    report_gen.enrich_events(
        audit_events,
        getattr(args, "people_map_loaded", {}) or {},
        getattr(args, "wecom_people_map_loaded", {}) or {},
        {},
        {},
        terminal_identity_history=terminal_identity_history,
        terminal_identity_max_age_days=getattr(args, "terminal_identity_max_age_days", 30),
    )
    report_gen.apply_terminal_majority_identity(audit_events, terminal_identity_history)
    detail_events, _false_positive_reasons = report_gen.report_focus_events(audit_events, internal_domains)
    rows = [report_detail_row(event, internal_domains) for event in detail_events]
    return [row for row in rows if row.get("parsed_ts") and candidate_scope_event(row)]


def fetch_audit_events_from_table(config: Any, start: datetime, end: datetime, policy_doc: dict[str, Any]) -> list[dict[str, Any]]:
    three_d, two_d, archives, _patterns = policy_exts(policy_doc)
    signal_exts = sorted(three_d | two_d | archives)
    query = f"""
SELECT
    event_id, event_date, ts, topic, channel, level, company, department,
    resolved_person, person, client_name, client_ip, process_name, sender_mailbox,
    recipient_relation, targets, target_domains, recipients, file_names, file_exts,
    file_size, reasons
FROM audit_events
WHERE ts >= parseDateTime64BestEffort({ch_quote(start.isoformat())}, 3)
  AND ts < parseDateTime64BestEffort({ch_quote(end.isoformat())}, 3)
  AND topic IN ('mail_audit','im_audit','file_audit')
  AND length(file_names) > 0
  AND NOT {trusted_internal_sql()}
  AND channel != '内部系统上传'
  AND channel != '文件重命名'
  AND NOT has(reasons, '内部系统上传')
  AND NOT has(reasons, '文件重命名')
  AND (
      hasAny(file_exts, {ch_array(signal_exts)})
      OR hasAny(reasons, ['外设拷贝','外部站点上传','外部上传/下载地址','个人邮箱域名','外部收件域名','网盘/高风险外联目标'])
      OR level = 'HIGH'
      OR ifNull(file_size, 0) >= 10485760
  )
FORMAT JSONEachRow
"""
    events: list[dict[str, Any]] = []
    for line in clickhouse_query(config, query).splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        row["parsed_ts"] = parse_ts(row.get("ts"))
        if candidate_scope_event(row):
            events.append(row)
    return events


def fetch_audit_events(config: Any, start: datetime, end: datetime, policy_doc: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        return fetch_report_detail_events(config, start, end, policy_doc)
    except Exception:
        return fetch_audit_events_from_table(config, start, end, policy_doc)


def fetch_mac_map(config: Any) -> dict[tuple[str, str], str]:
    query = """
SELECT client_name, client_ip, argMax(client_mac, observed_at) AS client_mac
FROM asset_latest
GROUP BY client_name, client_ip
FORMAT JSONEachRow
"""
    result: dict[tuple[str, str], str] = {}
    try:
        text = clickhouse_query(config, query)
    except Exception:
        return result
    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        key = (str(row.get("client_name") or ""), str(row.get("client_ip") or ""))
        value = normalize_text(row.get("client_mac"))
        if value:
            result[key] = value
    return result


def baseline_counts(config: Any, start: datetime, policy_doc: dict[str, Any], policy: dict[str, Any]) -> dict[tuple[str, str], float]:
    days = max(1, policy_int(policy, "baseline_days"))
    baseline_start = start - timedelta(days=days)
    three_d, two_d, archives, _patterns = policy_exts(policy_doc)
    signal_exts = sorted(three_d | two_d | archives)
    query = f"""
SELECT client_name, client_ip, count() / {days} AS avg_day
FROM audit_events
WHERE ts >= parseDateTime64BestEffort({ch_quote(baseline_start.isoformat())}, 3)
  AND ts < parseDateTime64BestEffort({ch_quote(start.isoformat())}, 3)
  AND topic IN ('mail_audit','im_audit','file_audit')
  AND length(file_names) > 0
  AND NOT {trusted_internal_sql()}
  AND channel != '内部系统上传'
  AND channel != '文件重命名'
  AND NOT has(reasons, '内部系统上传')
  AND NOT has(reasons, '文件重命名')
  AND (hasAny(file_exts, {ch_array(signal_exts)}) OR hasAny(reasons, ['外设拷贝','外部站点上传','外部上传/下载地址','个人邮箱域名','外部收件域名','网盘/高风险外联目标']) OR level = 'HIGH')
GROUP BY client_name, client_ip
FORMAT JSONEachRow
"""
    result: dict[tuple[str, str], float] = {}
    try:
        text = clickhouse_query(config, query)
    except Exception:
        return result
    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        result[(str(row.get("client_name") or ""), str(row.get("client_ip") or ""))] = float(row.get("avg_day") or 0)
    return result


def candidate_hash(parts: Iterable[Any]) -> str:
    text = "|".join(normalize_text(part) for part in parts)
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:24]


def top_counter(values: Iterable[str], fallback: str) -> str:
    counter = Counter(value for value in values if normalize_text(value))
    return counter.most_common(1)[0][0] if counter else fallback


def build_candidate(
    anomaly_type: str,
    events: list[dict[str, Any]],
    policy_doc: dict[str, Any],
    mac_map: dict[tuple[str, str], str],
    basis: str,
) -> TerminalBehaviorCandidate:
    three_d, two_d, archives, patterns = policy_exts(policy_doc)
    ordered = sorted(events, key=lambda item: item.get("parsed_ts") or datetime.min)
    first = ordered[0]
    last = ordered[-1]
    event_date_value = (first.get("parsed_ts") or datetime.now()).date()
    client_name = str(first.get("client_name") or "")
    client_ip = str(first.get("client_ip") or "")
    counts: Counter = Counter()
    channels: list[str] = []
    targets: list[str] = []
    files: list[str] = []
    event_ids: list[str] = []
    matrix_counts: Counter = Counter()
    for event in ordered:
        counts.update(event_object_counts(event, three_d, two_d, archives, patterns))
        channel = display_channel(event)
        channels.append(channel)
        bucket = event_matrix_bucket(event, three_d, two_d, archives, patterns)
        if channel and bucket:
            matrix_counts[f"{channel}\u241f{bucket}"] += 1
        targets.extend(event_targets(event))
        files.extend(str(name) for name in event.get("file_names") or [] if normalize_text(name))
        event_ids.append(str(event.get("event_id") or ""))
    person = top_counter((str(event.get("resolved_person") or event.get("person") or "") for event in ordered), "未匹配使用人")
    company = top_counter((str(event.get("company") or "") for event in ordered), "未匹配公司")
    department = top_counter((str(event.get("department") or "") for event in ordered), "未匹配部门")
    candidate_id = candidate_hash([event_date_value.isoformat(), client_name, client_ip, person, anomaly_type])
    return TerminalBehaviorCandidate(
        candidate_id=candidate_id,
        event_date=event_date_value,
        event_start=first.get("parsed_ts") or datetime.now(),
        event_end=last.get("parsed_ts") or first.get("parsed_ts") or datetime.now(),
        anomaly_type=anomaly_type,
        company=company,
        department=department,
        person=person,
        client_name=client_name,
        client_ip=client_ip,
        client_mac=mac_map.get((client_name, client_ip), "-"),
        event_count=len(ordered),
        structure_count=int(counts["structure"]),
        electrical_count=int(counts["electrical"]),
        three_d_count=int(counts["three_d"]),
        dwg_count=int(counts["dwg"]),
        archive_count=int(counts["archive"]),
        channels=list(dict.fromkeys(channels))[:8],
        targets=list(dict.fromkeys(targets))[:12],
        sample_files=list(dict.fromkeys(files))[:8],
        event_ids=[item for item in dict.fromkeys(event_ids) if item],
        matrix_counts=dict(matrix_counts),
        evidence_events=ordered,
        basis=basis,
    )


def burst_window(events: list[dict[str, Any]], minutes: int, min_events: int) -> list[dict[str, Any]]:
    ordered = sorted([event for event in events if event.get("parsed_ts")], key=lambda item: item["parsed_ts"])
    left = 0
    best: list[dict[str, Any]] = []
    for right, event in enumerate(ordered):
        while left <= right and event["parsed_ts"] - ordered[left]["parsed_ts"] > timedelta(minutes=minutes):
            left += 1
        window = ordered[left : right + 1]
        if len(window) >= min_events and len(window) > len(best):
            best = window
    return best


def generate_candidates(config: Any, policy_doc: dict[str, Any], start: datetime, end: datetime) -> list[TerminalBehaviorCandidate]:
    policy = normalized_review_policy(policy_doc)
    if not policy.get("enabled", True):
        return []
    ensure_review_table(config)
    events = fetch_audit_events(config, start, end, policy_doc)
    three_d, two_d, archives, patterns = policy_exts(policy_doc)
    mac_map = fetch_mac_map(config)
    other_drawing_min = max(1, policy_int(policy, "other_drawing_min_events") or 100)
    sensitive_min = max(1, policy_int(policy, "sensitive_name_min_events") or 1000)
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        ts = event.get("parsed_ts")
        if not ts:
            continue
        key = (str(event.get("client_name") or ""), str(event.get("client_ip") or ""), str(event.get("resolved_person") or event.get("person") or ""))
        groups[key].append(event)
    candidates: dict[str, TerminalBehaviorCandidate] = {}
    for key, group in groups.items():
        significant = [event for event in group if significant_event(event, three_d, two_d, archives, patterns)]
        if not significant:
            continue
        selected_events: dict[str, dict[str, Any]] = {}
        reason_labels: list[str] = []
        reason_basis: list[str] = []

        standard_events = [event for event in significant if standard_drawing_event(event, three_d, two_d, archives, patterns)]
        if standard_events:
            reason_labels.append("一级风险：标准图纸流转")
            reason_basis.append("标准图纸经邮件、IM、外部站点上传或外设拷贝等通道流转。")
            for event in standard_events:
                selected_events[str(event.get("event_id") or id(event))] = event

        ordinary_drawing_events = [event for event in significant if ordinary_drawing_event(event, three_d, two_d, archives, patterns)]
        if len(ordinary_drawing_events) >= other_drawing_min:
            reason_labels.append("普通图纸高频流转")
            reason_basis.append(f"非标准三维模型或 DWG 图纸流转达到 {other_drawing_min} 条阈值。")
            for event in ordinary_drawing_events:
                selected_events[str(event.get("event_id") or id(event))] = event

        sensitive_events = [event for event in significant if sensitive_name_event(event, three_d, two_d, archives, patterns)]
        if len(sensitive_events) >= sensitive_min:
            reason_labels.append("敏感文件高频流转")
            reason_basis.append(f"敏感名称文件流转达到 {sensitive_min} 条阈值。")
            for event in sensitive_events:
                selected_events[str(event.get("event_id") or id(event))] = event

        if selected_events:
            candidate = build_candidate("；".join(reason_labels), list(selected_events.values()), policy_doc, mac_map, "；".join(reason_basis))
            candidates[candidate.candidate_id] = candidate
    result = sorted(
        candidates.values(),
        key=lambda item: (
            0 if item.anomaly_type.startswith("一级风险") else 1,
            1 if item.anomaly_type.startswith("普通图纸") else 2 if item.anomaly_type.startswith("敏感文件") else 3,
            -item.event_count,
            -(item.structure_count + item.electrical_count),
            -item.three_d_count,
            -item.dwg_count,
            item.company,
            item.department,
        ),
    )
    return result[: policy_int(policy, "candidate_limit")]


def reviews_from_rows(rows: Iterable[dict[str, Any]]) -> list[TerminalBehaviorReview]:
    result: list[TerminalBehaviorReview] = []
    for row in rows:
        result.append(
            TerminalBehaviorReview(
                review_id=str(row.get("review_id") or ""),
                candidate_id=str(row.get("candidate_id") or ""),
                event_date=str(row.get("event_date") or ""),
                event_start=str(row.get("event_start") or ""),
                event_end=str(row.get("event_end") or ""),
                anomaly_type=str(row.get("anomaly_type") or ""),
                status=str(row.get("status") or ""),
                include_in_report=int(row.get("include_in_report") or 0),
                reviewer_userid=str(row.get("reviewer_userid") or ""),
                reviewer_name=str(row.get("reviewer_name") or ""),
                review_time=str(row.get("review_time") or ""),
                company=str(row.get("company") or ""),
                department=str(row.get("department") or ""),
                person=str(row.get("person") or ""),
                client_name=str(row.get("client_name") or ""),
                client_ip=str(row.get("client_ip") or ""),
                client_mac=str(row.get("client_mac") or ""),
                event_count=int(row.get("event_count") or 0),
                structure_count=int(row.get("structure_count") or 0),
                electrical_count=int(row.get("electrical_count") or 0),
                three_d_count=int(row.get("three_d_count") or 0),
                dwg_count=int(row.get("dwg_count") or 0),
                archive_count=int(row.get("archive_count") or 0),
                channels=[str(item) for item in row.get("channels") or []],
                targets=[str(item) for item in row.get("targets") or []],
                sample_files=[str(item) for item in row.get("sample_files") or []],
                event_ids=[str(item) for item in row.get("event_ids") or []],
                conclusion=str(row.get("conclusion") or ""),
                notes=str(row.get("notes") or ""),
                owner_department=str(row.get("owner_department") or ""),
                due_date=str(row.get("due_date") or ""),
            )
        )
    return result


def fetch_reviews(config: Any, start: datetime, end: datetime, include_all_status: bool = True) -> list[TerminalBehaviorReview]:
    ensure_review_table(config)
    include_filter = "" if include_all_status else "AND include_in_report = 1"
    query = f"""
SELECT *
FROM terminal_behavior_reviews FINAL
WHERE event_start >= parseDateTime64BestEffort({ch_quote(start.isoformat())}, 3)
  AND event_start < parseDateTime64BestEffort({ch_quote(end.isoformat())}, 3)
  {include_filter}
ORDER BY event_start DESC, event_count DESC
FORMAT JSONEachRow
"""
    rows = [json.loads(line) for line in clickhouse_query(config, query).splitlines() if line.strip()]
    return reviews_from_rows(rows)


def fetch_reviews_by_candidate(config: Any, start: datetime, end: datetime) -> dict[str, TerminalBehaviorReview]:
    return {review.candidate_id: review for review in fetch_reviews(config, start, end, include_all_status=True)}


def insert_reviews(config: Any, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    ensure_review_table(config)
    payload = "\n".join(json.dumps(row, ensure_ascii=False) for row in rows).encode("utf-8")
    clickhouse_query(config, "INSERT INTO terminal_behavior_reviews FORMAT JSONEachRow", data=payload)


def report_summary_html(config: Any, start: datetime, end: datetime) -> str:
    try:
        reviews = fetch_reviews(config, start, end, include_all_status=False)
    except Exception as exc:
        return f"""
    <section id="terminal-behavior-review-summary" class="section-block terminal-review-summary">
      <div class="section-title-row">
        <div><span class="section-eyebrow">Manual Review</span><h2>风险终端复核</h2><p>复核记录暂不可用：{esc(exc)}</p></div>
      </div>
    </section>
"""
    if not reviews:
        return """
    <section id="terminal-behavior-review-summary" class="section-block terminal-review-summary">
      <div class="section-title-row">
        <div><span class="section-eyebrow">Manual Review</span><h2>风险终端复核</h2><p>本周期暂无人工确认进入报告的风险终端复核记录；候选线索请进入复核工作台处理。</p></div>
        <a class="section-action" href="/terminal-check">进入复核工作台</a>
      </div>
    </section>
"""
    status_counts = Counter(review.status for review in reviews)
    company_counts = Counter(review.company for review in reviews if review.company)
    terminal_counts = Counter(f"{review.client_ip} / {review.client_mac or '-'}" for review in reviews)
    chips = [
        ("核查记录", len(reviews), "人工确认进入本周期报告的记录数"),
        ("异常待整改", status_counts.get("异常待整改", 0), "需责任部门整改确认"),
        ("正常业务", status_counts.get("正常业务", 0), "已确认属于正常业务"),
        ("已闭环", status_counts.get("已闭环", 0), "已完成整改或复核闭环"),
    ]
    chip_html = "".join(f'<a class="terminal-review-chip" href="/terminal-check"><span>{esc(label)}</span><strong>{value}</strong><em>{esc(title)}</em></a>' for label, value, title in chips)
    top_company = company_counts.most_common(1)[0][0] if company_counts else "-"
    top_terminal = terminal_counts.most_common(1)[0][0] if terminal_counts else "-"
    return f"""
    <section id="terminal-behavior-review-summary" class="section-block terminal-review-summary">
      <div class="section-title-row">
        <div>
          <span class="section-eyebrow">Manual Review</span>
          <h2>风险终端复核</h2>
          <p>仅展示审核员人工确认进入报告的复核记录；周报按事件发生时间自动汇总日报复核结果。</p>
        </div>
        <a class="section-action" href="/terminal-check">进入复核工作台</a>
      </div>
      <div class="terminal-review-chip-grid">{chip_html}</div>
      <p class="note">本周期核查集中公司：{esc(top_company)}；高频终端：{esc(top_terminal)}。候选未人工确认前不进入正式报告。</p>
    </section>
"""


def report_summary_style() -> str:
    return """
<style id="terminal-review-summary-style">
  .terminal-review-summary {
    border-color: rgba(23, 92, 211, 0.16);
    background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
  }
  .terminal-review-chip-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
  }
  .terminal-review-chip {
    display: grid;
    gap: 5px;
    min-height: 94px;
    border: 1px solid #dbe6f3;
    border-radius: 12px;
    padding: 13px 14px;
    background: #fff;
    color: #122033;
    text-decoration: none;
  }
  .terminal-review-chip span { color: #175cd3; font-size: 12px; font-weight: 850; }
  .terminal-review-chip strong { font-size: 26px; line-height: 1; font-weight: 920; }
  .terminal-review-chip em { color: #667085; font-size: 12px; font-style: normal; font-weight: 720; }
  @media (max-width: 900px) { .terminal-review-chip-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
  @media (max-width: 620px) { .terminal-review-chip-grid { grid-template-columns: 1fr; } }
</style>
"""
