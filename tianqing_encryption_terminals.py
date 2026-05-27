#!/usr/bin/env python3
"""Import encryption-software terminal inventory into ClickHouse.

The latest imported inventory batch can be used as a compliance IP pool for
systems such as PLM login auditing. The raw row is retained so new header
aliases can be added later without losing the evidence trail.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import tianqing_decrypt_records as xlsx


TERMINAL_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS encryption_terminal_inventory
(
    event_date Date,
    import_time DateTime64(3, 'Asia/Shanghai'),
    import_batch String,
    source_file String,
    row_number UInt32,
    terminal_fingerprint String,
    ip_address String,
    mac_address String,
    computer_name String,
    user_account String,
    user_name String,
    company String,
    department String,
    os_version String,
    client_version String,
    encryption_status String,
    last_seen Nullable(DateTime64(3, 'Asia/Shanghai')),
    raw_json String
)
ENGINE = ReplacingMergeTree(import_time)
PARTITION BY toYYYYMM(event_date)
ORDER BY terminal_fingerprint
TTL event_date + INTERVAL 3 YEAR
SETTINGS index_granularity = 8192
"""

FIELD_ALIASES = {
    "ip_address": ["IP", "IP地址", "终端IP", "客户端IP", "设备IP", "主机IP", "登录IP", "IP Address"],
    "mac_address": ["MAC", "MAC地址", "物理地址", "网卡地址", "终端MAC", "MAC Address"],
    "computer_name": ["计算机名", "电脑名", "主机名", "终端名称", "设备名称", "机器名", "主机名称", "Computer Name"],
    "user_account": ["账号", "用户账号", "登录账号", "域账号", "员工账号", "使用人账号", "资产责任者账号", "User Account"],
    "user_name": ["使用人", "用户名", "姓名", "用户姓名", "员工姓名", "终端使用人", "资产责任者", "User Name"],
    "company": ["公司", "所属公司", "单位", "所属单位", "组织", "组织名称", "Company"],
    "department": ["部门", "所属部门", "用户部门", "Department"],
    "os_version": ["操作系统", "操作系统版本", "操作系统类型", "OS", "系统版本", "OS Version"],
    "client_version": ["客户端版本", "加密软件版本", "软件版本", "版本号", "Agent版本", "终端版本", "Client Version"],
    "encryption_status": ["状态", "加密状态", "客户端状态", "在线状态", "管控状态", "Status"],
    "last_seen": ["最后在线时间", "最近在线时间", "最后登录时间", "更新时间", "最近通讯时间", "在线时间", "Last Seen"],
}


@dataclass
class TerminalImportSummary:
    batch_id: str
    source_file: str
    total_rows: int = 0
    inserted_rows: int = 0
    duplicate_rows: int = 0
    valid_ip_rows: int = 0
    unique_ips: int = 0
    unique_terminal_keys: int = 0
    missing_ip_rows: int = 0
    errors: list[str] = field(default_factory=list)


def normalize_header(value: Any) -> str:
    return re.sub(r"[\s_：:（）()\\/-]+", "", xlsx.normalize_text(value).lower())


def header_mapping(headers: list[str]) -> dict[int, str]:
    alias_to_field: dict[str, str] = {}
    for field, aliases in FIELD_ALIASES.items():
        alias_to_field[normalize_header(field)] = field
        for alias in aliases:
            alias_to_field[normalize_header(alias)] = field
    mapping: dict[int, str] = {}
    for idx, header in enumerate(headers):
        field = alias_to_field.get(normalize_header(header))
        if field:
            mapping[idx] = field
    return mapping


def normalize_ip(value: Any) -> str:
    text = xlsx.normalize_text(value)
    if not text:
        return ""
    candidates = re.findall(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", text)
    for candidate in candidates or [text]:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return ""


def normalize_mac(value: Any) -> str:
    text = xlsx.normalize_text(value)
    if not text:
        return ""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(cleaned) < 12:
        return text.upper()
    cleaned = cleaned[:12].upper()
    return "-".join(cleaned[index : index + 2] for index in range(0, 12, 2))


def parse_terminal_dt(value: Any) -> datetime | None:
    parsed = xlsx.parse_dt(value)
    if parsed:
        return parsed
    text = xlsx.normalize_text(value)
    if not text:
        return None
    try:
        serial = float(text)
    except ValueError:
        return None
    if not 20000 <= serial <= 80000:
        return None
    return datetime(1899, 12, 30) + timedelta(days=serial)


def split_terminal_org_path(value: Any) -> tuple[str, str]:
    text = xlsx.normalize_text(value)
    if not text:
        return "", ""
    parts = [part.strip() for part in text.split("/") if part.strip()]
    if len(parts) >= 3 and parts[0] == "大全集团":
        return parts[1], parts[-1]
    if len(parts) >= 2 and parts[0] == "大全集团":
        return parts[0], parts[-1]
    if len(parts) >= 2:
        return parts[0], parts[-1]
    return "", text


def parse_terminal_workbook(path: Path) -> tuple[list[str], list[dict[str, Any]]]:
    iterator = iter(xlsx.iter_xlsx_rows(path))
    try:
        headers = [xlsx.normalize_text(item) for item in next(iterator)]
    except StopIteration as exc:
        raise ValueError("Excel 文件为空。") from exc
    mapping = header_mapping(headers)
    if "ip_address" not in set(mapping.values()):
        raise ValueError("Excel 表头缺少可识别的 IP 地址字段。")
    rows: list[dict[str, Any]] = []
    for row_number, values in enumerate(iterator, 2):
        raw = {header: values[idx] if idx < len(values) else "" for idx, header in enumerate(headers)}
        if not any(xlsx.normalize_text(value) for value in raw.values()):
            continue
        item: dict[str, Any] = {"row_number": row_number, "raw": raw}
        for idx, field in mapping.items():
            item[field] = values[idx] if idx < len(values) else ""
        item["ip_address"] = normalize_ip(item.get("ip_address"))
        item["mac_address"] = normalize_mac(item.get("mac_address"))
        item["last_seen"] = parse_terminal_dt(item.get("last_seen"))
        if not xlsx.normalize_text(item.get("company")):
            company, department = split_terminal_org_path(item.get("department"))
            if company:
                item["company"] = company
            if department:
                item["department"] = department
        rows.append(item)
    return headers, rows


def terminal_fingerprint(record: dict[str, Any]) -> str:
    values = [
        xlsx.normalize_text(record.get("ip_address")),
        xlsx.normalize_text(record.get("mac_address")),
        xlsx.normalize_text(record.get("computer_name")),
        xlsx.normalize_text(record.get("user_account")),
        xlsx.normalize_text(record.get("user_name")),
        xlsx.normalize_text(record.get("company")),
        xlsx.normalize_text(record.get("department")),
        xlsx.normalize_text(record.get("os_version")),
        xlsx.normalize_text(record.get("client_version")),
        xlsx.normalize_text(record.get("encryption_status")),
        xlsx.normalize_text(xlsx.ch_dt(record.get("last_seen"))),
    ]
    return hashlib.sha256("|".join(values).encode("utf-8", errors="replace")).hexdigest()


def ensure_terminal_table(args: argparse.Namespace) -> None:
    xlsx.clickhouse_request(args, f"CREATE DATABASE IF NOT EXISTS {args.clickhouse_database}")
    xlsx.clickhouse_request(args, TERMINAL_TABLE_SQL)


def existing_terminal_fingerprints(args: argparse.Namespace, fingerprints: list[str], chunk_size: int = 500) -> set[str]:
    found: set[str] = set()
    for start in range(0, len(fingerprints), chunk_size):
        chunk = fingerprints[start : start + chunk_size]
        if not chunk:
            continue
        query = (
            "SELECT terminal_fingerprint FROM encryption_terminal_inventory FINAL "
            f"WHERE terminal_fingerprint IN ({','.join(xlsx.clickhouse_quote(item) for item in chunk)}) "
            "FORMAT TabSeparated"
        )
        text = xlsx.clickhouse_request(args, query).decode("utf-8", errors="replace")
        found.update(line.strip() for line in text.splitlines() if line.strip())
    return found


def insert_terminal_rows(args: argparse.Namespace, rows: list[dict[str, Any]]) -> None:
    if rows:
        xlsx.clickhouse_request(args, "INSERT INTO encryption_terminal_inventory FORMAT JSONEachRow", xlsx.json_each_row(rows))


def import_terminal_workbook(
    args: argparse.Namespace,
    path: Path,
    original_filename: str,
    batch_id: str,
) -> TerminalImportSummary:
    ensure_terminal_table(args)
    _headers, parsed_rows = parse_terminal_workbook(path)
    now = datetime.now()
    import_time = xlsx.ch_dt(now) or now.strftime("%Y-%m-%d %H:%M:%S.000")
    summary = TerminalImportSummary(batch_id=batch_id, source_file=original_filename, total_rows=len(parsed_rows))
    fingerprints = [terminal_fingerprint(row) for row in parsed_rows]
    existing = existing_terminal_fingerprints(args, fingerprints)
    seen_in_file: set[str] = set()
    unique_ips: set[str] = set()
    unique_terminal_keys: set[tuple[str, str]] = set()
    payload: list[dict[str, Any]] = []
    for row, fingerprint in zip(parsed_rows, fingerprints):
        ip = xlsx.normalize_text(row.get("ip_address"))
        computer_name = xlsx.normalize_text(row.get("computer_name"))
        if ip:
            summary.valid_ip_rows += 1
            unique_ips.add(ip)
            if computer_name:
                unique_terminal_keys.add((ip, computer_name))
        else:
            summary.missing_ip_rows += 1
        if fingerprint in existing or fingerprint in seen_in_file:
            summary.duplicate_rows += 1
            continue
        seen_in_file.add(fingerprint)
        last_seen = row.get("last_seen")
        payload.append(
            {
                "event_date": xlsx.ch_date(last_seen, now),
                "import_time": import_time,
                "import_batch": batch_id,
                "source_file": original_filename,
                "row_number": int(row.get("row_number") or 0),
                "terminal_fingerprint": fingerprint,
                "ip_address": ip,
                "mac_address": xlsx.normalize_text(row.get("mac_address")),
                "computer_name": computer_name,
                "user_account": xlsx.normalize_text(row.get("user_account")),
                "user_name": xlsx.normalize_text(row.get("user_name")),
                "company": xlsx.normalize_text(row.get("company")),
                "department": xlsx.normalize_text(row.get("department")),
                "os_version": xlsx.normalize_text(row.get("os_version")),
                "client_version": xlsx.normalize_text(row.get("client_version")),
                "encryption_status": xlsx.normalize_text(row.get("encryption_status")),
                "last_seen": xlsx.ch_dt(last_seen),
                "raw_json": json.dumps(row.get("raw") or {}, ensure_ascii=False, separators=(",", ":")),
            }
        )
    insert_terminal_rows(args, payload)
    summary.inserted_rows = len(payload)
    summary.unique_ips = len(unique_ips)
    summary.unique_terminal_keys = len(unique_terminal_keys)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import encryption terminal inventory xlsx.")
    parser.add_argument("xlsx")
    parser.add_argument("--source-file", default="")
    parser.add_argument("--batch-id", default="")
    parser.add_argument("--clickhouse-url", default="http://127.0.0.1:8123")
    parser.add_argument("--clickhouse-database", default="tianqing")
    parser.add_argument("--clickhouse-user", default="")
    parser.add_argument("--clickhouse-password", default="")
    parser.add_argument("--timeout", type=int, default=120)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    batch_id = args.batch_id or datetime.now().strftime("%Y%m%d%H%M%S")
    started = time.time()
    summary = import_terminal_workbook(args, Path(args.xlsx), args.source_file or Path(args.xlsx).name, batch_id)
    print(json.dumps({**summary.__dict__, "elapsed": round(time.time() - started, 2)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
