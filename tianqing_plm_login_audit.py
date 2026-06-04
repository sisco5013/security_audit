#!/usr/bin/env python3
"""PLM login device compliance helpers.

PLM login records currently expose IP address and computer name, but IP is a
dynamic network attribute. This module resolves the login IP back to the MAC
observed by Tianqing around the login time, then checks that MAC against the
encryption-software terminal inventory.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


DEFAULT_CONSTRAINED_DEPARTMENTS = ["技术部", "研发部", "工艺部"]
DEFAULT_TERMINAL_MATCH_FIELDS = ["ip_address", "computer_name"]
DEFAULT_IP_MAC_LOOKUP_HOURS = 2
DEFAULT_TERMINAL_VALID_DAYS = 7
DEFAULT_SOURCE_WARN_DAYS = 3
DEFAULT_SOURCE_STALE_DAYS = 7


@dataclass
class PlmAuditPolicy:
    constrained_departments: list[str] = field(default_factory=lambda: list(DEFAULT_CONSTRAINED_DEPARTMENTS))
    terminal_match_fields: list[str] = field(default_factory=lambda: list(DEFAULT_TERMINAL_MATCH_FIELDS))
    ip_mac_lookup_hours: int = DEFAULT_IP_MAC_LOOKUP_HOURS
    terminal_valid_days: int = DEFAULT_TERMINAL_VALID_DAYS
    source_warn_days: int = DEFAULT_SOURCE_WARN_DAYS
    source_stale_days: int = DEFAULT_SOURCE_STALE_DAYS


@dataclass
class PlmDeviceResolution:
    decision: str
    reason: str
    lookup_scope: str = ""
    login_time: str = ""
    login_ip: str = ""
    login_computer_name: str = ""
    resolved_mac: str = ""
    asset_observed_at: str = ""
    encryption_batch: str = ""
    encryption_import_time: str = ""
    encryption_last_seen: str = ""
    encryption_computer_name: str = ""
    encryption_ip: str = ""
    warning: str = ""


def normalize_text(value: Any) -> str:
    return " ".join(str(value if value is not None else "").replace("\u3000", " ").strip().split())


def normalize_key(value: Any) -> str:
    return normalize_text(value).lower()


def normalize_mac_key(value: Any) -> str:
    text = normalize_text(value)
    return re.sub(r"[^0-9a-f]", "", text.lower())[:12]


def ch_quote(value: Any) -> str:
    return "'" + str(value if value is not None else "").replace("\\", "\\\\").replace("'", "\\'") + "'"


def ch_dt(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")[:23]


def ch_datetime(value: datetime) -> str:
    return f"parseDateTime64BestEffort({ch_quote(ch_dt(value))}, 3, 'Asia/Shanghai')"


def mac_key_sql(column: str) -> str:
    return f"lowerUTF8(replaceAll(replaceAll(replaceAll({column}, '-', ''), ':', ''), ' ', ''))"


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return min(maximum, max(minimum, parsed))


def normalize_text_list(value: Any) -> list[str]:
    if isinstance(value, str):
        parts = re.split(r"[,，\n\r;；]+", value)
    elif isinstance(value, list):
        parts = [str(item) for item in value]
    else:
        parts = []
    result: list[str] = []
    for item in parts:
        text = normalize_text(item)
        if text and text not in result:
            result.append(text)
    return result


def policy_from_doc(policy_doc: dict[str, Any] | None) -> PlmAuditPolicy:
    raw = {}
    if isinstance(policy_doc, dict) and isinstance(policy_doc.get("plm_login_audit"), dict):
        raw = policy_doc.get("plm_login_audit") or {}
    departments = normalize_text_list(raw.get("constrained_departments")) or list(DEFAULT_CONSTRAINED_DEPARTMENTS)
    fields = [item for item in normalize_text_list(raw.get("terminal_match_fields")) if item in DEFAULT_TERMINAL_MATCH_FIELDS]
    return PlmAuditPolicy(
        constrained_departments=departments,
        terminal_match_fields=fields or list(DEFAULT_TERMINAL_MATCH_FIELDS),
        ip_mac_lookup_hours=bounded_int(raw.get("ip_mac_lookup_hours"), DEFAULT_IP_MAC_LOOKUP_HOURS, 1, 24),
        terminal_valid_days=bounded_int(raw.get("terminal_valid_days"), DEFAULT_TERMINAL_VALID_DAYS, 1, 30),
        source_warn_days=bounded_int(raw.get("source_warn_days"), DEFAULT_SOURCE_WARN_DAYS, 1, 30),
        source_stale_days=bounded_int(raw.get("source_stale_days"), DEFAULT_SOURCE_STALE_DAYS, 1, 60),
    )


def clickhouse_headers(config: Any) -> dict[str, str]:
    headers: dict[str, str] = {}
    user = str(getattr(config, "clickhouse_user", "") or "").strip()
    password = str(getattr(config, "clickhouse_password", "") or "").strip()
    if user:
        headers["X-ClickHouse-User"] = user
    if password:
        headers["X-ClickHouse-Key"] = password
    return headers


def clickhouse_query(config: Any, query: str) -> list[dict[str, Any]]:
    params = {"database": getattr(config, "clickhouse_database", "tianqing")}
    url = str(getattr(config, "clickhouse_url", "http://127.0.0.1:8123")).rstrip("/") + "/?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, data=query.encode("utf-8"), headers=clickhouse_headers(config), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=int(getattr(config, "clickhouse_timeout", 120) or 120)) as response:
            text = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"ClickHouse query failed: HTTP {exc.code}: {body[:1000]}") from exc
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def latest_encryption_batch(config: Any) -> dict[str, Any] | None:
    rows = clickhouse_query(
        config,
        """
SELECT
  import_batch,
  anyLast(source_file) AS source_file,
  max(import_time) AS import_time
FROM encryption_terminal_inventory FINAL
GROUP BY import_batch
ORDER BY import_time DESC
LIMIT 1
FORMAT JSONEachRow
""",
    )
    return rows[0] if rows else None


def find_asset_mac(
    config: Any,
    login_time: datetime,
    login_ip: str,
    computer_name: str,
    lookup_hours: int,
) -> tuple[str, list[dict[str, Any]]]:
    ip = normalize_text(login_ip)
    name = normalize_text(computer_name)
    if not ip and not name:
        return "missing_login_key", []
    conditions: list[str] = []
    lookup_label_parts: list[str] = []
    if ip:
        conditions.append(f"client_ip = {ch_quote(ip)}")
        lookup_label_parts.append("IP")
    if name:
        conditions.append(f"lowerUTF8(client_name) = lowerUTF8({ch_quote(name)})")
        lookup_label_parts.append("计算机名")
    condition_sql = " AND ".join(conditions)
    lookup_key_label = "+".join(lookup_label_parts)
    windows = [
        (
            f"前后{lookup_hours}小时",
            login_time - timedelta(hours=lookup_hours),
            login_time + timedelta(hours=lookup_hours),
        ),
        (
            "登录当天",
            login_time.replace(hour=0, minute=0, second=0, microsecond=0),
            login_time.replace(hour=23, minute=59, second=59, microsecond=999000),
        ),
    ]
    key_expr = mac_key_sql("client_mac")
    for label, start, end in windows:
        rows = clickhouse_query(
            config,
            f"""
SELECT
  {key_expr} AS mac_key,
  anyLast(client_mac) AS asset_client_mac,
  anyLast(client_name) AS asset_client_name,
  anyLast(client_ip) AS asset_client_ip,
  max(observed_at) AS asset_observed_at,
  count() AS observation_count
FROM asset_observations FINAL
WHERE {condition_sql}
  AND notEmpty({key_expr})
  AND observed_at >= {ch_datetime(start)}
  AND observed_at <= {ch_datetime(end)}
GROUP BY mac_key
ORDER BY asset_observed_at DESC
FORMAT JSONEachRow
""",
        )
        if rows:
            return f"{lookup_key_label}/{label}", rows
    return "未找到", []


def find_encryption_terminal_by_mac(config: Any, batch_id: str, mac_key: str) -> list[dict[str, Any]]:
    if not batch_id or not mac_key:
        return []
    key_expr = mac_key_sql("mac_address")
    return clickhouse_query(
        config,
        f"""
SELECT
  ip_address,
  mac_address,
  computer_name,
  user_name,
  user_account,
  company,
  department,
  encryption_status,
  last_seen
FROM encryption_terminal_inventory FINAL
WHERE import_batch = {ch_quote(batch_id)}
  AND {key_expr} = {ch_quote(mac_key)}
ORDER BY last_seen DESC
LIMIT 20
FORMAT JSONEachRow
""",
    )


def parse_ch_dt(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace(" ", "T"))
    except ValueError:
        return None


def days_between_later(later: datetime, earlier: datetime) -> float:
    return max(0.0, (later - earlier).total_seconds() / 86400.0)


def resolve_plm_login_device(
    config: Any,
    login_time: datetime,
    login_ip: str,
    computer_name: str,
    policy: PlmAuditPolicy | None = None,
    now: datetime | None = None,
) -> PlmDeviceResolution:
    policy = policy or PlmAuditPolicy()
    now = now or datetime.now()
    result = PlmDeviceResolution(
        decision="待复核",
        reason="尚未完成设备校验",
        login_time=ch_dt(login_time),
        login_ip=normalize_text(login_ip),
        login_computer_name=normalize_text(computer_name),
    )
    scope, asset_rows = find_asset_mac(config, login_time, login_ip, computer_name, policy.ip_mac_lookup_hours)
    result.lookup_scope = scope
    if scope == "missing_login_key":
        result.reason = "PLM登录记录缺少IP和计算机名，无法反查设备MAC"
        return result
    if not asset_rows:
        result.reason = "未能从天擎资产观测反查到登录设备MAC"
        return result
    if len(asset_rows) > 1:
        result.reason = "同一PLM登录终端线索在反查窗口内对应多个MAC"
        result.resolved_mac = "；".join(str(row.get("asset_client_mac") or row.get("mac_key") or "") for row in asset_rows[:6])
        return result
    asset = asset_rows[0]
    mac_key = str(asset.get("mac_key") or "")
    result.resolved_mac = str(asset.get("asset_client_mac") or "")
    result.asset_observed_at = str(asset.get("asset_observed_at") or "")

    batch = latest_encryption_batch(config)
    if not batch:
        result.reason = "未导入加密终端清单，无法判断授信终端"
        return result
    result.encryption_batch = str(batch.get("import_batch") or "")
    result.encryption_import_time = str(batch.get("import_time") or "")
    import_time = parse_ch_dt(batch.get("import_time"))
    if import_time:
        source_age_days = days_between_later(now, import_time)
        if source_age_days > policy.source_stale_days:
            result.reason = f"加密终端清单已超过{policy.source_stale_days}天未更新，PLM审计降级为待复核"
            return result
        if source_age_days > policy.source_warn_days:
            result.warning = f"加密终端清单超过{policy.source_warn_days}天未更新"

    terminals = find_encryption_terminal_by_mac(config, result.encryption_batch, mac_key)
    if not terminals:
        result.decision = "一级风险"
        result.reason = "登录设备MAC未命中加密终端授信池"
        return result
    computer_key = normalize_key(computer_name)
    matching = [row for row in terminals if normalize_key(row.get("computer_name")) == computer_key]
    if computer_key and not matching:
        result.reason = "登录设备MAC命中加密终端池，但计算机名不一致"
        result.encryption_computer_name = "；".join(str(row.get("computer_name") or "") for row in terminals[:6])
        return result
    terminal = matching[0] if matching else terminals[0]
    result.encryption_computer_name = str(terminal.get("computer_name") or "")
    result.encryption_ip = str(terminal.get("ip_address") or "")
    result.encryption_last_seen = str(terminal.get("last_seen") or "")
    last_seen = parse_ch_dt(terminal.get("last_seen"))
    if not last_seen:
        result.decision = "一级风险"
        result.reason = "加密终端无最后在线时间"
        return result
    if last_seen < login_time - timedelta(days=policy.terminal_valid_days):
        result.decision = "一级风险"
        result.reason = f"加密终端最后在线超过{policy.terminal_valid_days}天"
        return result
    result.decision = "合规"
    result.reason = "PLM登录设备已通过IP反查MAC，并命中有效加密终端"
    return result


def resolve_plm_login_device_from_policy_doc(
    config: Any,
    login_time: datetime,
    login_ip: str,
    computer_name: str,
    policy_doc: dict[str, Any] | None,
) -> PlmDeviceResolution:
    return resolve_plm_login_device(config, login_time, login_ip, computer_name, policy_from_doc(policy_doc))
