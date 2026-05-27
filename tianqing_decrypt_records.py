#!/usr/bin/env python3
"""Import encryption-software decrypt/export records into ClickHouse."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree as ET
from zipfile import BadZipFile, ZipFile


DECRYPT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS decrypt_records
(
    event_date Date,
    apply_time Nullable(DateTime64(3, 'Asia/Shanghai')),
    import_time DateTime64(3, 'Asia/Shanghai'),
    import_batch String,
    source_file String,
    row_number UInt32,
    business_fingerprint String,
    request_reason String,
    request_level String,
    applicant_account String,
    applicant_name String,
    approver String,
    approve_reason String,
    approve_time Nullable(DateTime64(3, 'Asia/Shanghai')),
    recipient_unit String,
    raw_org_path String,
    raw_company String,
    raw_department String,
    security_level String,
    sender String,
    recipients String,
    cc_recipients String,
    mail_subject String,
    mail_content String,
    file_name String,
    file_ext String,
    file_size Nullable(UInt64),
    status String,
    approver_account String,
    approver_name String,
    approver_department String,
    mail_fail_reason String
)
ENGINE = ReplacingMergeTree(import_time)
PARTITION BY toYYYYMM(event_date)
ORDER BY business_fingerprint
TTL event_date + INTERVAL 3 YEAR
SETTINGS index_granularity = 8192
"""

EXPECTED_HEADERS = [
    "申请原因",
    "申请时间",
    "申请等级",
    "申请人账号",
    "申请人名称",
    "审批人",
    "审批原因",
    "审批时间",
    "接受单位",
    "所属部门",
    "外发密级",
    "发件人",
    "接收人",
    "抄送人",
    "邮件主题",
    "邮件内容",
    "文件名",
    "文件大小",
    "状态",
    "审批人账户",
    "审批人名称",
    "审批人所属部门",
    "外发邮件失败原因",
]

FIELD_BY_HEADER = {
    "申请原因": "request_reason",
    "申请时间": "apply_time",
    "申请等级": "request_level",
    "申请人账号": "applicant_account",
    "申请人名称": "applicant_name",
    "审批人": "approver",
    "审批原因": "approve_reason",
    "审批时间": "approve_time",
    "接受单位": "recipient_unit",
    "所属部门": "raw_org_path",
    "外发密级": "security_level",
    "发件人": "sender",
    "接收人": "recipients",
    "抄送人": "cc_recipients",
    "邮件主题": "mail_subject",
    "邮件内容": "mail_content",
    "文件名": "file_name",
    "文件大小": "file_size",
    "状态": "status",
    "审批人账户": "approver_account",
    "审批人名称": "approver_name",
    "审批人所属部门": "approver_department",
    "外发邮件失败原因": "mail_fail_reason",
}


@dataclass
class ImportSummary:
    batch_id: str
    source_file: str
    total_rows: int = 0
    inserted_rows: int = 0
    duplicate_rows: int = 0
    critical_design_rows: int = 0
    unmatched_org_rows: int = 0
    errors: list[str] = field(default_factory=list)


def normalize_text(value: Any) -> str:
    text = str(value if value is not None else "").replace("\u3000", " ").strip()
    return " ".join(text.split())


def path_basename(value: Any) -> str:
    text = normalize_text(value).split("?", 1)[0]
    return re.split(r"[\\/]", text)[-1].strip()


def extension(value: Any) -> str:
    base = path_basename(value)
    if "." not in base:
        return ""
    ext = base.rsplit(".", 1)[-1].strip().lower()
    return ext if re.fullmatch(r"[a-z0-9_]{1,16}", ext) else ""


def parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    text = normalize_text(value)
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def ch_dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")[:23]


def ch_date(value: datetime | None, fallback: datetime) -> str:
    return (value or fallback).date().isoformat()


def file_size_int(value: Any) -> int | None:
    text = normalize_text(value)
    if not text:
        return None
    try:
        return max(0, int(float(text)))
    except ValueError:
        return None


def split_org_path(path: Any) -> tuple[str, str]:
    parts = [part.strip() for part in normalize_text(path).split("/") if part.strip()]
    if not parts:
        return "", ""
    if parts[0] == "大全集团" and len(parts) >= 2:
        company = parts[1]
        department = " / ".join(parts[2:]) if len(parts) > 2 else ""
        return company, department
    company = parts[0]
    department = " / ".join(parts[1:]) if len(parts) > 1 else ""
    return company, department


def normalize_alias_key(value: Any) -> str:
    return normalize_text(value).lower()


def normalize_aliases(policy: dict[str, Any]) -> list[dict[str, str]]:
    raw = policy.get("organization_aliases") if isinstance(policy, dict) else []
    if not isinstance(raw, list):
        return []
    rows: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        if item.get("enabled", True) is False:
            continue
        canonical_company = normalize_text(item.get("canonical_company"))
        canonical_department = normalize_text(item.get("canonical_department"))
        if not canonical_company:
            continue
        rows.append(
            {
                "raw_org_path": normalize_text(item.get("raw_org_path") or item.get("alias_path")),
                "raw_company": normalize_text(item.get("raw_company") or item.get("alias_company")),
                "raw_department": normalize_text(item.get("raw_department") or item.get("alias_department")),
                "canonical_company": canonical_company,
                "canonical_department": canonical_department,
            }
        )
    return rows


def resolve_org_alias(raw_org_path: str, raw_company: str, raw_department: str, aliases: list[dict[str, str]]) -> tuple[str, str, bool]:
    raw_path_key = normalize_alias_key(raw_org_path)
    raw_company_key = normalize_alias_key(raw_company)
    raw_department_key = normalize_alias_key(raw_department)
    for item in aliases:
        if normalize_alias_key(item.get("raw_org_path")) and normalize_alias_key(item.get("raw_org_path")) == raw_path_key:
            return item["canonical_company"], item.get("canonical_department") or raw_department, True
    for item in aliases:
        if (
            normalize_alias_key(item.get("raw_company")) == raw_company_key
            and normalize_alias_key(item.get("raw_department")) == raw_department_key
        ):
            return item["canonical_company"], item.get("canonical_department") or raw_department, True
    return raw_company, raw_department, False


def critical_design_labels(file_name: str, policy: dict[str, Any]) -> list[str]:
    base = path_basename(file_name)
    rows = policy.get("critical_design_patterns") if isinstance(policy, dict) else []
    if not isinstance(rows, list):
        return []
    labels: list[str] = []
    for item in rows:
        if not isinstance(item, dict) or item.get("enabled", True) is False:
            continue
        regex = normalize_text(item.get("regex"))
        label = normalize_text(item.get("label"))
        if not regex or not label:
            continue
        try:
            if re.fullmatch(regex, base, re.IGNORECASE):
                labels.append(label)
        except re.error:
            continue
    return labels


def column_index(cell_ref: str) -> int:
    letters = "".join(ch for ch in cell_ref if ch.isalpha())
    value = 0
    for ch in letters.upper():
        value = value * 26 + ord(ch) - 64
    return value


def shared_strings(workbook: ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in workbook.namelist():
        return []
    ns = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    root = ET.fromstring(workbook.read("xl/sharedStrings.xml"))
    result: list[str] = []
    for si in root.findall("a:si", ns):
        result.append("".join((text.text or "") for text in si.findall(".//a:t", ns)))
    return result


def workbook_first_sheet_path(workbook: ZipFile) -> str:
    names = workbook.namelist()
    for name in names:
        if name.startswith("xl/worksheets/sheet") and name.endswith(".xml"):
            return name
    raise ValueError("Excel 文件中没有工作表。")


def iter_xlsx_rows(path: Path) -> Iterable[list[str]]:
    ns = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    try:
        with ZipFile(path) as workbook:
            strings = shared_strings(workbook)
            sheet_path = workbook_first_sheet_path(workbook)
            for event, elem in ET.iterparse(workbook.open(sheet_path), events=("end",)):
                tag = elem.tag.rsplit("}", 1)[-1]
                if tag != "row":
                    continue
                row: dict[int, str] = {}
                for cell in elem.findall("a:c", ns):
                    ref = cell.attrib.get("r", "")
                    idx = column_index(ref)
                    cell_type = cell.attrib.get("t")
                    value = ""
                    if cell_type == "inlineStr":
                        value = "".join((text.text or "") for text in cell.findall(".//a:t", ns))
                    else:
                        node = cell.find("a:v", ns)
                        value = "" if node is None or node.text is None else node.text
                        if cell_type == "s" and value:
                            try:
                                value = strings[int(value)]
                            except (ValueError, IndexError):
                                pass
                    row[idx] = normalize_text(value)
                if row:
                    yield [row.get(i, "") for i in range(1, max(row) + 1)]
                elem.clear()
    except BadZipFile as exc:
        raise ValueError("上传文件不是有效的 .xlsx 文件。") from exc


def parse_xlsx_records(path: Path) -> tuple[list[str], list[dict[str, Any]]]:
    iterator = iter(iter_xlsx_rows(path))
    try:
        headers = [normalize_text(item) for item in next(iterator)]
    except StopIteration as exc:
        raise ValueError("Excel 文件为空。") from exc
    if "申请时间" not in headers or "文件名" not in headers:
        raise ValueError("Excel 表头缺少必要字段：申请时间、文件名。")
    rows: list[dict[str, Any]] = []
    for row_number, values in enumerate(iterator, 2):
        item: dict[str, Any] = {"row_number": row_number}
        empty = True
        for idx, header in enumerate(headers):
            value = values[idx] if idx < len(values) else ""
            if value:
                empty = False
            field = FIELD_BY_HEADER.get(header)
            if field:
                item[field] = value
        if not empty:
            rows.append(item)
    return headers, rows


def business_fingerprint(record: dict[str, Any]) -> str:
    values = [
        normalize_text(record.get("apply_time")),
        normalize_text(record.get("applicant_account")),
        normalize_text(record.get("file_name")),
        normalize_text(record.get("file_size")),
        normalize_text(record.get("status")),
        normalize_text(record.get("approve_time")),
    ]
    return hashlib.sha256("|".join(values).encode("utf-8", errors="replace")).hexdigest()


def clickhouse_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def clickhouse_request(args: argparse.Namespace, query: str, data: bytes | None = None) -> bytes:
    params = {"database": args.clickhouse_database, "query": query}
    url = args.clickhouse_url.rstrip("/") + "/?" + urllib.parse.urlencode(params)
    headers = {}
    if getattr(args, "clickhouse_user", ""):
        headers["X-ClickHouse-User"] = args.clickhouse_user
    if getattr(args, "clickhouse_password", ""):
        headers["X-ClickHouse-Key"] = args.clickhouse_password
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=int(getattr(args, "timeout", 120))) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"ClickHouse HTTP {exc.code}: {detail}") from exc


def ensure_decrypt_table(args: argparse.Namespace) -> None:
    clickhouse_request(args, f"CREATE DATABASE IF NOT EXISTS {args.clickhouse_database}")
    clickhouse_request(args, DECRYPT_TABLE_SQL)


def existing_fingerprints(args: argparse.Namespace, fingerprints: list[str], chunk_size: int = 500) -> set[str]:
    found: set[str] = set()
    for start in range(0, len(fingerprints), chunk_size):
        chunk = fingerprints[start : start + chunk_size]
        if not chunk:
            continue
        query = (
            "SELECT business_fingerprint FROM decrypt_records FINAL "
            f"WHERE business_fingerprint IN ({','.join(clickhouse_quote(item) for item in chunk)}) "
            "FORMAT TabSeparated"
        )
        text = clickhouse_request(args, query).decode("utf-8", errors="replace")
        found.update(line.strip() for line in text.splitlines() if line.strip())
    return found


def json_each_row(rows: list[dict[str, Any]]) -> bytes:
    return ("\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in rows) + "\n").encode("utf-8")


def insert_rows(args: argparse.Namespace, rows: list[dict[str, Any]]) -> None:
    if rows:
        clickhouse_request(args, "INSERT INTO decrypt_records FORMAT JSONEachRow", json_each_row(rows))


def import_decrypt_workbook(
    args: argparse.Namespace,
    path: Path,
    original_filename: str,
    batch_id: str,
    policy: dict[str, Any],
) -> ImportSummary:
    ensure_decrypt_table(args)
    _headers, parsed_rows = parse_xlsx_records(path)
    now = datetime.now()
    import_time = ch_dt(now) or now.strftime("%Y-%m-%d %H:%M:%S.000")
    aliases = normalize_aliases(policy)
    summary = ImportSummary(batch_id=batch_id, source_file=original_filename, total_rows=len(parsed_rows))
    fingerprints = [business_fingerprint(row) for row in parsed_rows]
    existing = existing_fingerprints(args, fingerprints)
    insert_payload: list[dict[str, Any]] = []
    seen_in_file: set[str] = set()
    for row, fingerprint in zip(parsed_rows, fingerprints):
        raw_org_path = normalize_text(row.get("raw_org_path"))
        raw_company, raw_department = split_org_path(raw_org_path)
        _company, _department, alias_matched = resolve_org_alias(raw_org_path, raw_company, raw_department, aliases)
        if not alias_matched:
            summary.unmatched_org_rows += 1
        file_name = normalize_text(row.get("file_name"))
        if critical_design_labels(file_name, policy):
            summary.critical_design_rows += 1
        if fingerprint in existing or fingerprint in seen_in_file:
            summary.duplicate_rows += 1
            continue
        seen_in_file.add(fingerprint)
        apply_time = parse_dt(row.get("apply_time"))
        approve_time = parse_dt(row.get("approve_time"))
        insert_payload.append(
            {
                "event_date": ch_date(apply_time, now),
                "apply_time": ch_dt(apply_time),
                "import_time": import_time,
                "import_batch": batch_id,
                "source_file": original_filename,
                "row_number": int(row.get("row_number") or 0),
                "business_fingerprint": fingerprint,
                "request_reason": normalize_text(row.get("request_reason")),
                "request_level": normalize_text(row.get("request_level")),
                "applicant_account": normalize_text(row.get("applicant_account")),
                "applicant_name": normalize_text(row.get("applicant_name")),
                "approver": normalize_text(row.get("approver")),
                "approve_reason": normalize_text(row.get("approve_reason")),
                "approve_time": ch_dt(approve_time),
                "recipient_unit": normalize_text(row.get("recipient_unit")),
                "raw_org_path": raw_org_path,
                "raw_company": raw_company,
                "raw_department": raw_department,
                "security_level": normalize_text(row.get("security_level")),
                "sender": normalize_text(row.get("sender")),
                "recipients": normalize_text(row.get("recipients")),
                "cc_recipients": normalize_text(row.get("cc_recipients")),
                "mail_subject": normalize_text(row.get("mail_subject")),
                "mail_content": normalize_text(row.get("mail_content")),
                "file_name": file_name,
                "file_ext": extension(file_name),
                "file_size": file_size_int(row.get("file_size")),
                "status": normalize_text(row.get("status")),
                "approver_account": normalize_text(row.get("approver_account")),
                "approver_name": normalize_text(row.get("approver_name")),
                "approver_department": normalize_text(row.get("approver_department")),
                "mail_fail_reason": normalize_text(row.get("mail_fail_reason")),
            }
        )
    insert_rows(args, insert_payload)
    summary.inserted_rows = len(insert_payload)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import decrypt/export records from xlsx.")
    parser.add_argument("xlsx")
    parser.add_argument("--source-file", default="")
    parser.add_argument("--batch-id", default="")
    parser.add_argument("--policy-file", default=os.getenv("TIANQING_AUDIT_POLICY_FILE", "audit_policy.json"))
    parser.add_argument("--clickhouse-url", default="http://127.0.0.1:8123")
    parser.add_argument("--clickhouse-database", default="tianqing")
    parser.add_argument("--clickhouse-user", default="")
    parser.add_argument("--clickhouse-password", default="")
    parser.add_argument("--timeout", type=int, default=120)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy_path = Path(args.policy_file)
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except Exception:
        policy = {}
    batch_id = args.batch_id or datetime.now().strftime("%Y%m%d%H%M%S")
    started = time.time()
    summary = import_decrypt_workbook(args, Path(args.xlsx), args.source_file or Path(args.xlsx).name, batch_id, policy)
    print(json.dumps({**summary.__dict__, "elapsed": round(time.time() - started, 2)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
