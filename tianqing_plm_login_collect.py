#!/usr/bin/env python3
"""Collect and validate PLM login records for constrained departments.

The SAP/PLM login interface is intentionally queried only for employee ids
from constrained departments such as 技术部、研发部、工艺部.  The returned
login terminal is resolved through Tianqing asset observations to a MAC, then
validated against the imported encryption terminal inventory.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
import uuid
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import tianqing_plm_login_audit as plm_audit


DEFAULT_POLICY = "audit_policy.json"
DEFAULT_WECOM_CACHE = "wecom_directory_cache.json"
DEFAULT_SAP_QUERY_SCRIPT = "plm_sm20_query.mjs"


def normalize_text(value: Any) -> str:
    return " ".join(str(value if value is not None else "").replace("\u3000", " ").strip().split())


def load_json(path: str | Path, default: Any) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    return json.loads(p.read_text(encoding="utf-8"))


def active_wecom_items(cache_doc: Any) -> list[dict[str, Any]]:
    items = cache_doc.get("items") if isinstance(cache_doc, dict) else []
    if not isinstance(items, list):
        return []
    result: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "").strip()
        if status and status != "1":
            continue
        result.append(item)
    return result


def item_matches_department(item: dict[str, Any], departments: list[str]) -> bool:
    haystack = " / ".join(
        normalize_text(item.get(key))
        for key in ["company", "department", "department_path", "position"]
        if normalize_text(item.get(key))
    )
    return any(department and department in haystack for department in departments)


def constrained_plm_users(
    wecom_cache_path: str | Path,
    policy: plm_audit.PlmAuditPolicy,
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    cache_doc = load_json(wecom_cache_path, {})
    users: list[str] = []
    identity: dict[str, dict[str, Any]] = {}
    for item in active_wecom_items(cache_doc):
        userid = normalize_text(item.get("userid"))
        if not userid:
            continue
        if not item_matches_department(item, policy.constrained_departments):
            continue
        if userid not in identity:
            users.append(userid)
            identity[userid] = {
                "userid": userid,
                "name": normalize_text(item.get("name")),
                "company": normalize_text(item.get("company")),
                "department": normalize_text(item.get("department")),
                "department_path": normalize_text(item.get("department_path")),
                "position": normalize_text(item.get("position")),
            }
    users.sort(key=lambda value: (len(value), value))
    return users, identity


def chunks(values: list[str], size: int) -> list[list[str]]:
    size = max(1, size)
    return [values[index : index + size] for index in range(0, len(values), size)]


def sap_query_args(args: argparse.Namespace, users_file: str) -> list[str]:
    command = [
        "node",
        str(args.sap_query_script),
        "--users-file",
        users_file,
        "--time-from",
        args.time_from,
        "--time-to",
        args.time_to,
    ]
    if args.date:
        command.extend(["--date", args.date])
    else:
        command.extend(["--date-from", args.date_from, "--date-to", args.date_to])
    if args.sap_url:
        command.extend(["--url", args.sap_url])
    return command


def sap_credentials(args: argparse.Namespace) -> tuple[str, str]:
    user = args.sap_user or os.environ.get("SAP_USER", "")
    password = args.sap_password or os.environ.get("SAP_PASSWORD", "")
    if not user or not password:
        raise RuntimeError("SAP_USER/SAP_PASSWORD environment variables are required, or use --sap-user/--sap-password.")
    return user, password


def query_sap_chunk_http(args: argparse.Namespace, user_chunk: list[str]) -> list[dict[str, Any]]:
    sap_user, sap_password = sap_credentials(args)
    query_date = str(args.date or "").replace("-", "")
    date_from = str(args.date_from or "").replace("-", "") or query_date
    date_to = str(args.date_to or "").replace("-", "") or query_date
    data_in: dict[str, Any] = {
        "DATEFROM": date_from,
        "TIMEFROM": args.time_from.replace(":", ""),
        "DATETO": date_to,
        "TIMETO": args.time_to.replace(":", ""),
    }
    if user_chunk:
        data_in["USERS"] = [{"USERID": userid} for userid in user_chunk]

    boundary = "----formdata-undici-" + uuid.uuid4().hex[:12]
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="data_in"\r\n'
        "\r\n"
        + json.dumps(data_in, ensure_ascii=False, separators=(",", ":"))
        + f"\r\n--{boundary}--"
    ).encode("utf-8")
    auth = base64.b64encode(f"{sap_user}:{sap_password}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        args.sap_url or "http://s4devapp.daqo.com:8000/sap/zplm_userdata?sap-client=302",
        data=body,
        method="POST",
        headers={
            "Authorization": "Basic " + auth,
            "Content-Type": "multipart/form-data; boundary=" + boundary,
            "Accept": "application/json, text/plain",
            "User-Agent": "node",
            "Content-Length": str(len(body)),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=args.sap_timeout) as response:
            response_text = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"SAP API failed: HTTP {exc.code}: {body_text[:1000]}") from exc
    if not response_text.strip():
        return []
    parsed = json.loads(response_text)
    return parsed if isinstance(parsed, list) else parsed.get("data", []) if isinstance(parsed, dict) else []


def query_sap_chunk_node(args: argparse.Namespace, user_chunk: list[str]) -> list[dict[str, Any]]:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as tmp:
        json.dump(user_chunk, tmp, ensure_ascii=False)
        tmp_path = tmp.name
    try:
        env = os.environ.copy()
        if args.sap_user:
            env["SAP_USER"] = args.sap_user
        if args.sap_password:
            env["SAP_PASSWORD"] = args.sap_password
        completed = subprocess.run(
            sap_query_args(args, tmp_path),
            cwd=str(Path(args.sap_query_script).resolve().parent),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.sap_timeout,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip()[:1000])
        parsed = json.loads(completed.stdout or "[]")
        return parsed if isinstance(parsed, list) else parsed.get("data", []) if isinstance(parsed, dict) else []
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def query_sap_for_users(args: argparse.Namespace, users: list[str]) -> list[dict[str, Any]]:
    all_rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, user_chunk in enumerate(chunks(users, args.chunk_size), start=1):
        try:
            rows = query_sap_chunk_node(args, user_chunk) if args.sap_query_mode == "node" else query_sap_chunk_http(args, user_chunk)
            for row in rows:
                if not isinstance(row, dict):
                    continue
                fingerprint = json.dumps(row, ensure_ascii=False, sort_keys=True)
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                all_rows.append(row)
        except Exception as exc:
            raise RuntimeError(f"SAP query chunk {index} failed: {str(exc)[:1000]}") from exc
    return all_rows


def parse_sap_time(value: Any) -> datetime | None:
    text = re.sub(r"\D", "", str(value or ""))
    if len(text) < 14:
        return None
    try:
        return datetime.strptime(text[:14], "%Y%m%d%H%M%S")
    except ValueError:
        return None


def split_terminal(value: Any) -> tuple[str, str]:
    text = normalize_text(value)
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
        return text, ""
    return "", text


def clickhouse_config(args: argparse.Namespace) -> SimpleNamespace:
    return SimpleNamespace(
        clickhouse_url=args.clickhouse_url,
        clickhouse_database=args.clickhouse_database,
        clickhouse_user=args.clickhouse_user,
        clickhouse_password=args.clickhouse_password,
        clickhouse_timeout=args.clickhouse_timeout,
    )


def validate_rows(
    args: argparse.Namespace,
    rows: list[dict[str, Any]],
    identity: dict[str, dict[str, Any]],
    policy_doc: dict[str, Any],
) -> list[dict[str, Any]]:
    config = clickhouse_config(args)
    validated: list[dict[str, Any]] = []
    for row in rows:
        userid = normalize_text(row.get("slguser"))
        if userid not in identity:
            continue
        login_time = parse_sap_time(row.get("slgdattim") or row.get("slgdatim"))
        if not login_time:
            continue
        login_ip, computer_name = split_terminal(row.get("slgltrm2") or row.get("termIPv6") or row.get("termIpv6"))
        resolution = plm_audit.resolve_plm_login_device_from_policy_doc(
            config,
            login_time,
            login_ip,
            computer_name,
            policy_doc,
        )
        person = identity.get(userid) or {}
        validated.append(
            {
                "time": login_time.isoformat(sep=" "),
                "userid": userid,
                "name": person.get("name", ""),
                "company": person.get("company", ""),
                "department": person.get("department", ""),
                "department_path": person.get("department_path", ""),
                "terminal": normalize_text(row.get("slgltrm2") or row.get("termIPv6") or row.get("termIpv6")),
                "tcode": normalize_text(row.get("slgtc")),
                "program": normalize_text(row.get("slgrepna") or row.get("slgrepsna")),
                "data": normalize_text(row.get("salData")),
                "decision": resolution.decision,
                "reason": resolution.reason,
                "resolution": asdict(resolution),
            }
        )
    return validated


def output_summary(args: argparse.Namespace, users: list[str], rows: list[dict[str, Any]], validated: list[dict[str, Any]]) -> dict[str, Any]:
    decisions = Counter(item["decision"] for item in validated)
    companies = Counter(item["company"] or "未匹配公司" for item in validated if item["decision"] == "一级风险")
    users_counter = Counter(
        f"{item['name'] or item['userid']}({item['userid']})" for item in validated if item["decision"] == "一级风险"
    )
    summary = {
        "date": args.date or f"{args.date_from}..{args.date_to}",
        "time_from": args.time_from,
        "time_to": args.time_to,
        "target_user_count": len(users),
        "sap_row_count": len(rows),
        "validated_row_count": len(validated),
        "decision_counts": dict(decisions),
        "risk_count": decisions.get("一级风险", 0),
        "top_risk_companies": companies.most_common(10),
        "top_risk_users": users_counter.most_common(10),
        "risk_samples": [item for item in validated if item["decision"] == "一级风险"][:50],
        "review_samples": [item for item in validated if item["decision"] == "待复核"][:30],
    }
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect PLM login audit rows for constrained departments and validate encryption-terminal MAC trust.")
    parser.add_argument("--date", default="", help="Single date, YYYYMMDD or YYYY-MM-DD.")
    parser.add_argument("--date-from", default="", help="Start date if --date is not used.")
    parser.add_argument("--date-to", default="", help="End date if --date is not used.")
    parser.add_argument("--time-from", default="000000")
    parser.add_argument("--time-to", default="235959")
    parser.add_argument("--policy", default=DEFAULT_POLICY)
    parser.add_argument("--wecom-cache", default=DEFAULT_WECOM_CACHE)
    parser.add_argument("--sap-query-script", default=DEFAULT_SAP_QUERY_SCRIPT)
    parser.add_argument("--sap-query-mode", choices=["python", "node"], default="python")
    parser.add_argument("--sap-url", default="")
    parser.add_argument("--sap-user", default="", help="Optional SAP user. Prefer SAP_USER env.")
    parser.add_argument("--sap-password", default="", help="Optional SAP password. Prefer SAP_PASSWORD env.")
    parser.add_argument("--sap-timeout", type=int, default=240)
    parser.add_argument("--chunk-size", type=int, default=100)
    parser.add_argument("--dry-users", action="store_true", help="Only print constrained PLM user list summary.")
    parser.add_argument("--clickhouse-url", default=os.getenv("CLICKHOUSE_URL", "http://127.0.0.1:8123"))
    parser.add_argument("--clickhouse-database", default=os.getenv("CLICKHOUSE_DB", "tianqing"))
    parser.add_argument("--clickhouse-user", default=os.getenv("CLICKHOUSE_USER", ""))
    parser.add_argument("--clickhouse-password", default=os.getenv("CLICKHOUSE_PASSWORD", ""))
    parser.add_argument("--clickhouse-timeout", type=int, default=int(os.getenv("CLICKHOUSE_TIMEOUT", "120")))
    parser.add_argument("--output", default="", help="Optional JSON output path.")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    policy_doc = load_json(args.policy, {})
    policy = plm_audit.policy_from_doc(policy_doc if isinstance(policy_doc, dict) else {})
    users, identity = constrained_plm_users(args.wecom_cache, policy)
    if args.dry_users:
        by_company = Counter(item.get("company") or "未匹配公司" for item in identity.values())
        result = {
            "target_user_count": len(users),
            "departments": policy.constrained_departments,
            "top_companies": by_company.most_common(20),
            "sample_users": [identity[userid] for userid in users[:30]],
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    if not args.date and not (args.date_from and args.date_to):
        parser.error("Use --date or both --date-from and --date-to.")
    rows = query_sap_for_users(args, users)
    validated = validate_rows(args, rows, identity, policy_doc if isinstance(policy_doc, dict) else {})
    result = output_summary(args, users, rows, validated)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
