#!/usr/bin/env python3
"""Incrementally index Tianqing syslog into ClickHouse.

Raw syslog remains the audit evidence. ClickHouse is an analysis index used by
weekly/monthly reports and ad-hoc queries.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import tianqing_external_audit_report as report
import tianqing_decrypt_records as decrypt_records
import tianqing_encryption_terminals as encryption_terminals
import tianqing_terminal_behavior_review as terminal_behavior_review


DEFAULT_LOG_FILE = "/data/tianqing-audit/raw-log/tianqing.log"
DEFAULT_STATE_FILE = "/data/tianqing-audit/ingest/state.json"
DEFAULT_CH_URL = "http://127.0.0.1:8123"
DEFAULT_CH_DATABASE = "tianqing"
DEFAULT_APP_DIR = "/opt/tianqing-report-app"


RAW_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS raw_syslog
(
    event_date Date,
    ts DateTime64(3, 'Asia/Shanghai'),
    ingest_time DateTime64(3, 'Asia/Shanghai'),
    source_file String,
    byte_offset UInt64,
    raw_hash String,
    topic LowCardinality(String),
    raw_json String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, topic, ts, raw_hash)
TTL event_date + INTERVAL 180 DAY
SETTINGS index_granularity = 8192
"""


EVENT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_events
(
    event_date Date,
    ts DateTime64(3, 'Asia/Shanghai'),
    ingest_time DateTime64(3, 'Asia/Shanghai'),
    event_id String,
    raw_hash String,
    topic LowCardinality(String),
    channel LowCardinality(String),
    level LowCardinality(String),
    score UInt16,
    person String,
    account String,
    resolved_person String,
    company String,
    department String,
    client_name String,
    client_ip String,
    process_name String,
    mail_subject String,
    sender_mailbox String,
    recipient_relation LowCardinality(String),
    targets Array(String),
    target_domains Array(String),
    recipients Array(String),
    file_names Array(String),
    file_exts Array(String),
    file_size Nullable(UInt64),
    lookup_keys Array(String),
    search_id String,
    reasons Array(String),
    disposition_status String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, level, company, department, resolved_person, ts, event_id)
TTL event_date + INTERVAL 180 DAY
SETTINGS index_granularity = 8192
"""


EVENT_TABLE_MIGRATIONS = [
    "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS sender_mailbox String AFTER mail_subject",
]


ASSET_OBSERVATION_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS asset_observations
(
    event_date Date,
    observed_hour DateTime('Asia/Shanghai'),
    observed_at DateTime64(3, 'Asia/Shanghai'),
    ingest_time DateTime64(3, 'Asia/Shanghai'),
    raw_hash String,
    topic LowCardinality(String),
    client_id String,
    client_name String,
    client_ip String,
    client_mac String,
    client_mid String,
    login_account String,
    company String,
    department String,
    org_path String,
    board_serial_number String,
    brand_model String,
    board_model String,
    board_bios String,
    manufacture_date Nullable(Date),
    os_main String,
    os_release_id String,
    os_build_version String,
    os_describe String,
    memory_mb Nullable(UInt64),
    core_number Nullable(UInt16),
    sys_space_mb Nullable(UInt64),
    main_program_version String,
    patch_version String,
    virus_version String,
    virus_bd_version String,
    peripheral_devices_version String,
    software_library_version String,
    activation UInt8,
    is_online UInt8,
    online_state Int16,
    last_online_time Nullable(DateTime64(3, 'Asia/Shanghai')),
    client_create_time Nullable(DateTime64(3, 'Asia/Shanghai')),
    client_update_time Nullable(DateTime64(3, 'Asia/Shanghai'))
)
ENGINE = ReplacingMergeTree(observed_at)
PARTITION BY toYYYYMM(event_date)
ORDER BY (client_id, observed_hour)
TTL event_date + INTERVAL 3 YEAR
SETTINGS index_granularity = 8192
"""


ASSET_LATEST_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS asset_latest
(
    event_date Date,
    observed_at DateTime64(3, 'Asia/Shanghai'),
    ingest_time DateTime64(3, 'Asia/Shanghai'),
    raw_hash String,
    topic LowCardinality(String),
    client_id String,
    client_name String,
    client_ip String,
    client_mac String,
    client_mid String,
    login_account String,
    company String,
    department String,
    org_path String,
    board_serial_number String,
    brand_model String,
    board_model String,
    board_bios String,
    manufacture_date Nullable(Date),
    os_main String,
    os_release_id String,
    os_build_version String,
    os_describe String,
    memory_mb Nullable(UInt64),
    core_number Nullable(UInt16),
    sys_space_mb Nullable(UInt64),
    main_program_version String,
    patch_version String,
    virus_version String,
    virus_bd_version String,
    peripheral_devices_version String,
    software_library_version String,
    activation UInt8,
    is_online UInt8,
    online_state Int16,
    last_online_time Nullable(DateTime64(3, 'Asia/Shanghai')),
    client_create_time Nullable(DateTime64(3, 'Asia/Shanghai')),
    client_update_time Nullable(DateTime64(3, 'Asia/Shanghai'))
)
ENGINE = ReplacingMergeTree(observed_at)
PARTITION BY toYYYYMM(event_date)
ORDER BY client_id
TTL event_date + INTERVAL 3 YEAR
SETTINGS index_granularity = 8192
"""


def load_state(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o640)
    except OSError:
        pass


def clickhouse_request(args: argparse.Namespace, query: str, data: bytes | None = None) -> bytes:
    params = {"database": args.clickhouse_database, "query": query}
    url = args.clickhouse_url.rstrip("/") + "/?" + urllib.parse.urlencode(params)
    headers = {}
    if args.clickhouse_user:
        headers["X-ClickHouse-User"] = args.clickhouse_user
    if args.clickhouse_password:
        headers["X-ClickHouse-Key"] = args.clickhouse_password
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"ClickHouse HTTP {exc.code}: {detail}") from exc


def init_db(args: argparse.Namespace) -> None:
    clickhouse_request(args, f"CREATE DATABASE IF NOT EXISTS {args.clickhouse_database}")
    clickhouse_request(args, RAW_TABLE_SQL)
    clickhouse_request(args, EVENT_TABLE_SQL)
    for migration in EVENT_TABLE_MIGRATIONS:
        clickhouse_request(args, migration)
    clickhouse_request(args, ASSET_OBSERVATION_TABLE_SQL)
    clickhouse_request(args, ASSET_LATEST_TABLE_SQL)
    clickhouse_request(args, decrypt_records.DECRYPT_TABLE_SQL)
    clickhouse_request(args, encryption_terminals.TERMINAL_TABLE_SQL)
    clickhouse_request(args, terminal_behavior_review.TERMINAL_BEHAVIOR_REVIEW_TABLE_SQL)


def open_log(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def ts_or_epoch(ts: datetime | None) -> datetime:
    if ts is None:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


def ch_dt(ts: datetime | None) -> str:
    value = ts_or_epoch(ts)
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")[:23]


def ch_date(ts: datetime | None) -> str:
    return ts_or_epoch(ts).date().isoformat()


def ch_dt_nullable(ts: datetime | None) -> str | None:
    if ts is None:
        return None
    return ch_dt(ts)


def raw_hash(raw_json: str) -> str:
    return hashlib.sha256(raw_json.encode("utf-8", errors="replace")).hexdigest()


def json_each_row(rows: list[dict[str, Any]]) -> bytes:
    return ("\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in rows) + "\n").encode("utf-8")


def insert_rows(args: argparse.Namespace, table: str, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    clickhouse_request(args, f"INSERT INTO {table} FORMAT JSONEachRow", json_each_row(rows))


def clickhouse_stream_rows(args: argparse.Namespace, query: str) -> Iterable[dict[str, Any]]:
    params = {"database": args.clickhouse_database, "query": query}
    url = args.clickhouse_url.rstrip("/") + "/?" + urllib.parse.urlencode(params)
    headers = {}
    if args.clickhouse_user:
        headers["X-ClickHouse-User"] = args.clickhouse_user
    if args.clickhouse_password:
        headers["X-ClickHouse-Key"] = args.clickhouse_password
    request = urllib.request.Request(url, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            for line in response:
                if not line.strip():
                    continue
                yield json.loads(line.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"ClickHouse HTTP {exc.code}: {detail}") from exc


def file_digest(path: str) -> str:
    source = Path(path)
    if not source.exists():
        return "missing"
    digest = hashlib.sha256()
    digest.update(source.read_bytes())
    return digest.hexdigest()


def strategy_fingerprint(args: argparse.Namespace) -> str:
    payload = {
        "sensitive_keywords": file_digest(args.sensitive_keywords_file),
        "audit_policy": file_digest(args.audit_policy_file),
        "exclusions": file_digest(args.exclusion_file),
        "recipient_map": file_digest(args.recipient_map),
        "schema": 6,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def event_row(event: report.AuditEvent, raw_record_hash: str, ingest_time: str) -> dict[str, Any]:
    return {
        "event_date": ch_date(event.ts),
        "ts": ch_dt(event.ts),
        "ingest_time": ingest_time,
        "event_id": event.event_id,
        "raw_hash": raw_record_hash,
        "topic": event.topic,
        "channel": event.channel,
        "level": event.level,
        "score": int(event.score or 0),
        "person": event.person or "",
        "account": event.account or "",
        "resolved_person": event.resolved_person or "",
        "company": report.event_company_label(event),
        "department": report.event_department_label(event),
        "client_name": event.client_name or "",
        "client_ip": event.client_ip or "",
        "process_name": event.process_name or "",
        "mail_subject": event.mail_subject or "",
        "sender_mailbox": event.sender_mailbox or "",
        "recipient_relation": event.recipient_relation or "unknown",
        "targets": event.targets or [],
        "target_domains": event.target_domains or [],
        "recipients": event.recipients or [],
        "file_names": event.file_names or [],
        "file_exts": event.file_exts or [],
        "file_size": event.file_size,
        "lookup_keys": event.lookup_keys or [],
        "search_id": event.search_id or "",
        "reasons": event.reasons or [],
        "disposition_status": event.disposition_status or "",
    }


def nested_dict(obj: dict[str, Any], key: str) -> dict[str, Any]:
    value = obj.get(key)
    return value if isinstance(value, dict) else {}


def first_value(*values: Any) -> str:
    for value in values:
        if value not in (None, "", [], {}, "[]"):
            return str(value)
    return ""


def bool_int(value: Any) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    text = str(value if value is not None else "").strip().lower()
    return 1 if text in {"1", "true", "yes", "y", "on", "启用", "是"} else 0


def nullable_uint(value: Any) -> int | None:
    try:
        number = int(float(str(value).strip()))
    except Exception:
        return None
    return number if number >= 0 else None


def nullable_int(value: Any) -> int | None:
    try:
        return int(float(str(value).strip()))
    except Exception:
        return None


def parse_iso_datetime(value: Any) -> datetime | None:
    text = str(value if value is not None else "").strip()
    if not text or text.startswith("1970-01-01"):
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def parse_clickhouse_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text or text.startswith("1970-01-01"):
        return None
    try:
        parsed = datetime.fromisoformat(text.replace(" ", "T"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone(timedelta(hours=8)))
    return parsed


def parse_manufacture_date(board_bios: str) -> str | None:
    match = re.search(r":\s*(\d{1,2})/(\d{1,2})/(\d{4})\s*$", board_bios or "")
    if not match:
        return None
    month, day, year = (int(part) for part in match.groups())
    try:
        return datetime(year, month, day).date().isoformat()
    except ValueError:
        return None


def asset_row(record: report.RawRecord, raw_record_hash: str, ingest_time: str) -> dict[str, Any] | None:
    obj = record.obj
    client_info = nested_dict(obj, "client_info")
    if not client_info:
        return None
    client_id = first_value(obj.get("client_id"), client_info.get("id"))
    if not client_id:
        return None
    asset_computer = nested_dict(client_info, "asset_computer")
    asset_version = nested_dict(client_info, "asset_version")
    os_version = nested_dict(client_info, "os_version")
    online_info = nested_dict(client_info, "online_info")
    observed_at = report.ts_or_epoch(record.ts) if hasattr(report, "ts_or_epoch") else ts_or_epoch(record.ts)
    observed_hour = observed_at.replace(minute=0, second=0, microsecond=0)
    board_bios = first_value(asset_computer.get("board_bios"))
    org_path = report.organization_path(obj)
    company, department = report.normalize_org_fields(
        first_value(obj.get("path_level3"), obj.get("group_node_name")),
        first_value(obj.get("path_level4"), obj.get("path_level5")),
    )
    return {
        "event_date": ch_date(record.ts),
        "observed_hour": ch_dt(observed_hour)[:19],
        "observed_at": ch_dt(record.ts),
        "ingest_time": ingest_time,
        "raw_hash": raw_record_hash,
        "topic": str(obj.get("syslog_topic") or "unknown"),
        "client_id": client_id,
        "client_name": first_value(obj.get("client_name"), client_info.get("name")),
        "client_ip": first_value(obj.get("client_ip"), obj.get("client_report_ip"), client_info.get("ip"), client_info.get("report_ip")),
        "client_mac": first_value(obj.get("client_mac"), client_info.get("mac")),
        "client_mid": first_value(obj.get("client_mid"), client_info.get("mid")),
        "login_account": first_value(obj.get("client_login_account"), obj.get("login_user"), client_info.get("login_account")),
        "company": company,
        "department": department,
        "org_path": org_path,
        "board_serial_number": first_value(asset_computer.get("board_serial_number")),
        "brand_model": first_value(asset_computer.get("brand_model")),
        "board_model": first_value(asset_computer.get("board_model")),
        "board_bios": board_bios,
        "manufacture_date": parse_manufacture_date(board_bios),
        "os_main": first_value(obj.get("client_os_version_main"), os_version.get("main")),
        "os_release_id": first_value(obj.get("client_os_version_release_id"), os_version.get("release_id")),
        "os_build_version": first_value(obj.get("client_os_version_build_version"), os_version.get("build_version")),
        "os_describe": first_value(obj.get("client_os_version_describe"), os_version.get("describe")),
        "memory_mb": nullable_uint(first_value(obj.get("client_memory_size"), client_info.get("memory_size"))),
        "core_number": nullable_uint(first_value(obj.get("client_core_number"), client_info.get("core_number"))),
        "sys_space_mb": nullable_uint(first_value(obj.get("client_sys_space"), client_info.get("sys_space"))),
        "main_program_version": first_value(asset_version.get("main_program_version")),
        "patch_version": first_value(asset_version.get("patch_version")),
        "virus_version": first_value(asset_version.get("virus_version")),
        "virus_bd_version": first_value(asset_version.get("virus_bd_version")),
        "peripheral_devices_version": first_value(asset_version.get("peripheral_devices_version")),
        "software_library_version": first_value(asset_version.get("software_library_version")),
        "activation": bool_int(first_value(obj.get("client_activation"), client_info.get("activation"))),
        "is_online": bool_int(online_info.get("is_online")),
        "online_state": nullable_int(first_value(obj.get("client_state"), client_info.get("state"), online_info.get("state"))) or 0,
        "last_online_time": ch_dt_nullable(parse_iso_datetime(online_info.get("last_time"))),
        "client_create_time": ch_dt_nullable(parse_iso_datetime(first_value(obj.get("client_create_time"), client_info.get("create_time")))),
        "client_update_time": ch_dt_nullable(parse_iso_datetime(first_value(obj.get("client_update_time"), client_info.get("update_time")))),
    }


def load_context(args: argparse.Namespace):
    report.configure_audit_policy(report.load_audit_policy(args.audit_policy_file))
    keyword_rules = report.load_sensitive_keyword_rules(args.sensitive_keywords_file)
    report.configure_sensitive_keyword_rules(keyword_rules)
    exclusion_rules = report.load_exclusion_rules(args.exclusion_file)
    people_map = report.load_people_map(args.people_map)
    wecom_items: list[dict[str, Any]] = []
    try:
        cached = json.loads(Path(args.wecom_directory_cache).read_text(encoding="utf-8"))
        items = cached.get("items") if isinstance(cached, dict) else []
        if isinstance(items, list):
            wecom_items = [item for item in items if isinstance(item, dict)]
    except Exception:
        wecom_items = []
    wecom_people_map = report.build_wecom_people_map(wecom_items)
    recipient_map = report.build_wecom_recipient_map(wecom_items)
    recipient_map.update(report.load_observed_wecom_account_recipient_map(args, wecom_people_map))
    recipient_map.update(report.load_recipient_map(args.recipient_map))
    disposition_by_event_id, disposition_by_search_id = report.load_dispositions(args.disposition_file)
    return exclusion_rules, people_map, wecom_people_map, recipient_map, disposition_by_event_id, disposition_by_search_id


def iter_new_lines(path: Path, state: dict[str, Any], from_beginning: bool) -> Iterable[tuple[int, str]]:
    stat = path.stat()
    state_key = str(path)
    previous = state.get(state_key) if isinstance(state.get(state_key), dict) else {}
    offset = 0 if from_beginning else int(previous.get("offset") or 0)
    if previous.get("inode") and int(previous.get("inode")) != int(stat.st_ino):
        offset = 0
    if offset > stat.st_size:
        offset = 0
    with path.open("rb") as handle:
        handle.seek(offset)
        while True:
            pos = handle.tell()
            raw = handle.readline()
            if not raw:
                break
            yield pos, raw.decode("utf-8", errors="replace")
        state[state_key] = {"inode": int(stat.st_ino), "offset": int(handle.tell()), "size": int(stat.st_size), "updated_at": datetime.now().isoformat(timespec="seconds")}


def ingest(args: argparse.Namespace) -> tuple[int, int]:
    init_db(args)
    state_path = Path(args.state_file)
    state = {} if args.from_beginning else load_state(state_path)
    log_path = Path(args.log_file)
    if not log_path.exists():
        raise FileNotFoundError(str(log_path))
    exclusion_rules, people_map, wecom_people_map, recipient_map, disposition_by_event_id, disposition_by_search_id = load_context(args)
    internal_domains = set(report.DEFAULT_INTERNAL_DOMAINS)
    current_policy_hash = strategy_fingerprint(args)
    previous_policy_hash = str(state.get("__policy_hash") or "")
    if (
        not args.no_auto_rebuild_on_policy_change
        and not args.from_beginning
        and current_policy_hash != previous_policy_hash
    ):
        args.rebuilt_event_count = rebuild_events_from_raw(
            args,
            (
                exclusion_rules,
                people_map,
                wecom_people_map,
                recipient_map,
                disposition_by_event_id,
                disposition_by_search_id,
            ),
            reset_event_table=True,
        )
        state["__policy_hash"] = current_policy_hash
    raw_rows: list[dict[str, Any]] = []
    event_rows: list[dict[str, Any]] = []
    asset_observation_rows: dict[tuple[str, str], dict[str, Any]] = {}
    asset_latest_rows: dict[str, dict[str, Any]] = {}
    pending_events: list[report.AuditEvent] = []
    pending_hashes: list[str] = []
    raw_count = 0
    event_count = 0
    asset_count = 0
    ingest_time = ch_dt(datetime.now(timezone.utc))

    def flush() -> None:
        nonlocal raw_count, event_count, asset_count
        report.apply_report_policies(pending_events, {}, internal_domains)
        report.enrich_events(pending_events, people_map, wecom_people_map, disposition_by_event_id, disposition_by_search_id)
        event_rows.extend(event_row(event, digest, ingest_time) for event, digest in zip(pending_events, pending_hashes))
        insert_rows(args, "raw_syslog", raw_rows)
        insert_rows(args, "audit_events", event_rows)
        observation_rows = list(asset_observation_rows.values())
        latest_rows = list(asset_latest_rows.values())
        insert_rows(args, "asset_observations", observation_rows)
        insert_rows(args, "asset_latest", latest_rows)
        raw_count += len(raw_rows)
        event_count += len(event_rows)
        asset_count += len(observation_rows)
        raw_rows.clear()
        event_rows.clear()
        asset_observation_rows.clear()
        asset_latest_rows.clear()
        pending_events.clear()
        pending_hashes.clear()

    for byte_offset, line in iter_new_lines(log_path, state, args.from_beginning):
        record = report.parse_syslog_json(line)
        if not record:
            continue
        raw_json = json.dumps(record.obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        digest = raw_hash(raw_json)
        raw_rows.append(
            {
                "event_date": ch_date(record.ts),
                "ts": ch_dt(record.ts),
                "ingest_time": ingest_time,
                "source_file": str(log_path),
                "byte_offset": int(byte_offset),
                "raw_hash": digest,
                "topic": str(record.obj.get("syslog_topic") or "unknown"),
                "raw_json": raw_json,
            }
        )
        row = asset_row(record, digest, ingest_time)
        if row:
            asset_observation_rows[(row["client_id"], row["observed_hour"])] = row
            asset_latest_rows[row["client_id"]] = {key: value for key, value in row.items() if key != "observed_hour"}
        event = report.build_event(
            record,
            internal_domains,
            recipient_map,
            exclusion_rules=exclusion_rules,
            include_firewall=True,
            include_unknown_im=True,
            include_untargeted_file=True,
            wecom_directory_authoritative=False,
        )
        if event:
            pending_events.append(event)
            pending_hashes.append(digest)
        if len(raw_rows) >= args.batch_size:
            flush()
    if raw_rows or pending_events or asset_observation_rows:
        flush()
    state["__policy_hash"] = current_policy_hash
    save_state(state_path, state)
    args.asset_count = asset_count
    return raw_count, event_count


def rebuild_events_from_raw(
    args: argparse.Namespace,
    context: tuple[Any, ...] | None = None,
    reset_event_table: bool = True,
) -> int:
    init_db(args)
    if context is None:
        context = load_context(args)
    exclusion_rules, people_map, wecom_people_map, recipient_map, disposition_by_event_id, disposition_by_search_id = context
    if reset_event_table:
        clickhouse_request(args, "TRUNCATE TABLE audit_events")
    internal_domains = set(report.DEFAULT_INTERNAL_DOMAINS)
    ingest_time = ch_dt(datetime.now(timezone.utc))
    pending_events: list[report.AuditEvent] = []
    pending_hashes: list[str] = []
    event_count = 0
    scanned = 0

    def flush_events() -> None:
        nonlocal event_count
        if not pending_events:
            return
        report.apply_report_policies(pending_events, {}, internal_domains)
        report.enrich_events(pending_events, people_map, wecom_people_map, disposition_by_event_id, disposition_by_search_id)
        rows = [event_row(event, digest, ingest_time) for event, digest in zip(pending_events, pending_hashes)]
        insert_rows(args, "audit_events", rows)
        event_count += len(rows)
        pending_events.clear()
        pending_hashes.clear()

    query = "SELECT ts, raw_hash, raw_json FROM raw_syslog FORMAT JSONEachRow"
    for row in clickhouse_stream_rows(args, query):
        scanned += 1
        try:
            obj = json.loads(str(row.get("raw_json") or ""))
        except json.JSONDecodeError:
            continue
        record = report.RawRecord(ts=parse_clickhouse_datetime(row.get("ts")), obj=obj)
        event = report.build_event(
            record,
            internal_domains,
            recipient_map,
            exclusion_rules=exclusion_rules,
            include_firewall=True,
            include_unknown_im=True,
            include_untargeted_file=True,
            wecom_directory_authoritative=False,
        )
        if event:
            pending_events.append(event)
            pending_hashes.append(str(row.get("raw_hash") or ""))
        if len(pending_events) >= args.batch_size:
            flush_events()
    flush_events()
    args.rebuild_scanned = scanned
    return event_count


def backfill_assets_from_raw(args: argparse.Namespace) -> int:
    init_db(args)
    if args.reset_asset_tables:
        clickhouse_request(args, "TRUNCATE TABLE asset_observations")
        clickhouse_request(args, "TRUNCATE TABLE asset_latest")
    query = (
        "SELECT ts, raw_hash, raw_json "
        "FROM raw_syslog "
        "WHERE raw_json LIKE '%\"client_info\"%' "
        "ORDER BY ts FORMAT JSONEachRow"
    )
    text = clickhouse_request(args, query).decode("utf-8", errors="replace")
    ingest_time = ch_dt(datetime.now(timezone.utc))
    observation_rows: dict[tuple[str, str], dict[str, Any]] = {}
    latest_rows: dict[str, dict[str, Any]] = {}
    scanned = 0
    inserted = 0

    def flush_assets() -> None:
        nonlocal inserted
        rows = list(observation_rows.values())
        latest = list(latest_rows.values())
        insert_rows(args, "asset_observations", rows)
        insert_rows(args, "asset_latest", latest)
        inserted += len(rows)
        observation_rows.clear()
        latest_rows.clear()

    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        try:
            obj = json.loads(str(row.get("raw_json") or ""))
        except json.JSONDecodeError:
            continue
        record = report.RawRecord(ts=parse_clickhouse_datetime(row.get("ts")), obj=obj)
        asset = asset_row(record, str(row.get("raw_hash") or ""), ingest_time)
        scanned += 1
        if not asset:
            continue
        observation_rows[(asset["client_id"], asset["observed_hour"])] = asset
        latest_rows[asset["client_id"]] = {key: value for key, value in asset.items() if key != "observed_hour"}
        if scanned % args.batch_size == 0:
            flush_assets()
    if observation_rows:
        flush_assets()
    args.backfill_scanned = scanned
    return inserted


def parse_args() -> argparse.Namespace:
    app_dir = Path(os.getenv("TIANQING_APP_DIR", DEFAULT_APP_DIR))
    parser = argparse.ArgumentParser(description="Index Tianqing syslog into ClickHouse.")
    parser.add_argument("--log-file", default=os.getenv("TIANQING_LOG_FILE", DEFAULT_LOG_FILE))
    parser.add_argument("--state-file", default=os.getenv("TIANQING_INGEST_STATE", DEFAULT_STATE_FILE))
    parser.add_argument("--clickhouse-url", default=os.getenv("CLICKHOUSE_URL", DEFAULT_CH_URL))
    parser.add_argument("--clickhouse-database", default=os.getenv("CLICKHOUSE_DB", DEFAULT_CH_DATABASE))
    parser.add_argument("--clickhouse-user", default=os.getenv("CLICKHOUSE_USER", ""))
    parser.add_argument("--clickhouse-password", default=os.getenv("CLICKHOUSE_PASSWORD", ""))
    parser.add_argument("--people-map", default=str(app_dir / "people_mapping.csv"))
    parser.add_argument("--recipient-map", default=str(app_dir / "recipient_mapping.csv"))
    parser.add_argument("--disposition-file", default=str(app_dir / "audit_dispositions.csv"))
    parser.add_argument("--sensitive-keywords-file", default=os.getenv("TIANQING_SENSITIVE_KEYWORDS_FILE", str(app_dir / "sensitive_keywords.json")))
    parser.add_argument("--audit-policy-file", default=os.getenv("TIANQING_AUDIT_POLICY_FILE", str(app_dir / "audit_policy.json")))
    parser.add_argument("--exclusion-file", default=os.getenv("TIANQING_AUDIT_EXCLUSION_FILE", str(app_dir / "audit_exclusions.json")))
    parser.add_argument("--wecom-directory-cache", default=str(app_dir / "wecom_directory_cache.json"))
    parser.add_argument("--batch-size", type=int, default=10000)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--from-beginning", action="store_true", help="Ignore existing offset state and read the current log from the beginning.")
    parser.add_argument("--backfill-assets-from-raw", action="store_true", help="Rebuild asset analysis tables from existing raw_syslog rows without touching raw/event tables.")
    parser.add_argument("--reset-asset-tables", action="store_true", help="Truncate asset analysis tables before --backfill-assets-from-raw.")
    parser.add_argument("--rebuild-events-from-raw", action="store_true", help="Rebuild audit_events from raw_syslog using the current strategy files; raw_syslog is not changed.")
    parser.add_argument("--no-auto-rebuild-on-policy-change", action="store_true", help="Disable automatic audit_events rebuild when strategy file hash changes.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started = time.time()
    if args.backfill_assets_from_raw:
        asset_count = backfill_assets_from_raw(args)
        elapsed = time.time() - started
        print(f"backfilled assets={asset_count} scanned_raw={getattr(args, 'backfill_scanned', 0)} elapsed={elapsed:.1f}s")
        return 0
    if args.rebuild_events_from_raw:
        event_count = rebuild_events_from_raw(args, reset_event_table=True)
        state_path = Path(args.state_file)
        state = load_state(state_path)
        state["__policy_hash"] = strategy_fingerprint(args)
        save_state(state_path, state)
        elapsed = time.time() - started
        print(f"rebuilt events={event_count} scanned_raw={getattr(args, 'rebuild_scanned', 0)} elapsed={elapsed:.1f}s")
        return 0
    raw_count, event_count = ingest(args)
    elapsed = time.time() - started
    rebuilt = getattr(args, "rebuilt_event_count", 0)
    rebuild_note = f" rebuilt_events={rebuilt}" if rebuilt else ""
    print(f"indexed raw={raw_count} events={event_count} assets={getattr(args, 'asset_count', 0)}{rebuild_note} elapsed={elapsed:.1f}s log={args.log_file}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
