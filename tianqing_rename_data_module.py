#!/usr/bin/env python3
"""Three-dimensional and standard drawing rename tracking data module."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable


def bind_runtime_dependencies(namespace: dict[str, Any]) -> None:
    for key, value in namespace.items():
        if key.startswith("__"):
            continue
        globals()[key] = value


def raw_json_from_clickhouse_row(row: dict[str, Any]) -> dict[str, Any]:
    raw_json = row.get("raw_json")
    if isinstance(raw_json, dict):
        return raw_json
    try:
        return json.loads(str(raw_json or ""))
    except json.JSONDecodeError:
        return {}


def raw_client_id(obj: dict[str, Any]) -> str:
    return first_nonempty(obj, ["client_id", "client_mid", "terminal_id", "agent_id"])


def raw_client_mac(obj: dict[str, Any]) -> str:
    return first_nonempty(obj, ["client_mac", "mac", "mac_address", "client_mac_address"])


def raw_file_keys(obj: dict[str, Any]) -> list[str]:
    keys = []
    for key in ["download_file_key", "download_fileid", "file_id", "rename_key"]:
        value = obj.get(key)
        if value not in (None, "", [], {}, "[]"):
            keys.append(str(value).strip())
    return list(dict.fromkeys(keys))


def add_unique_text(values: list[str], value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    key = normalize_key(text)
    if any(normalize_key(item) == key for item in values):
        return False
    values.append(text)
    return True


def add_three_d_rename_alias(
    finding: ThreeDRenameFinding,
    path: str,
    raw_hash: str = "",
) -> bool:
    changed = False
    if path:
        changed = add_unique_text(finding.alias_paths, path) or changed
        name = path_basename(path)
        changed = add_unique_text(finding.alias_names, name) or changed
        if changed:
            add_unique_text(finding.rename_chain_paths, path)
            add_unique_text(finding.rename_chain_names, name)
    if raw_hash:
        add_unique_text(finding.chain_raw_hashes, raw_hash)
    return changed


def add_three_d_rename_keys(finding: ThreeDRenameFinding, keys: Iterable[str]) -> bool:
    changed = False
    for key in keys:
        changed = add_unique_text(finding.alias_keys, key) or changed
    return changed


def is_rename_operation(obj: dict[str, Any]) -> bool:
    return str(obj.get("operation_type") or "").strip() == "7"


def asset_for_terminal_values(
    client_name: str,
    client_ip: str,
    asset_by_terminal: dict[tuple[str, str], AssetSnapshot],
) -> AssetSnapshot | None:
    for key in [
        (normalize_key(client_name), normalize_key(client_ip)),
        (normalize_key(client_name), ""),
        ("", normalize_key(client_ip)),
    ]:
        asset = asset_by_terminal.get(key)
        if asset:
            return asset
    return None


def enrich_three_d_rename_identity(
    finding: ThreeDRenameFinding,
    args: argparse.Namespace,
) -> None:
    observation = terminal_identity_observation_for(
        finding.client_name,
        finding.client_ip,
        finding.rename_ts,
        getattr(args, "terminal_identity_history", {}) or {},
        max_age_days=getattr(args, "terminal_identity_max_age_days", None),
    )
    if observation:
        finding.person = observation.person_name or finding.person
        finding.company = observation.company or finding.company
        finding.department = observation.department or finding.department

    asset = asset_for_terminal_values(
        finding.client_name,
        finding.client_ip,
        getattr(args, "asset_by_terminal", {}) or {},
    )
    if asset:
        finding.client_mac = finding.client_mac or asset.client_mac
        finding.person = finding.person or asset.login_account
        finding.company = finding.company or asset.company
        finding.department = finding.department or asset.department
    finding.person = finding.person or finding.login_account or "-"
    finding.company = finding.company or UNMATCHED_COMPANY_LABEL
    finding.department = finding.department or UNMATCHED_DEPARTMENT_LABEL


def three_d_rename_candidate_from_row(
    row: dict[str, Any],
    tz: timezone,
    start: datetime | None,
    end: datetime | None,
) -> ThreeDRenameFinding | None:
    obj = raw_json_from_clickhouse_row(row)
    if not obj:
        return None
    old_path = first_nonempty(obj, ["local_file_path"])
    new_path = first_nonempty(obj, ["remote_file_path"])
    if not old_path or not new_path:
        return None
    old_name = path_basename(old_path) or first_nonempty(obj, ["file_name"])
    new_name = path_basename(new_path)
    old_ext = path_extension(old_path)
    new_ext = path_extension(new_path)
    critical_label = next(iter(critical_design_labels_for_names([old_path, old_name])), "")
    is_standard_rename = bool(critical_label) and normalize_key(old_name) != normalize_key(new_name)
    is_three_d_suffix_mask = old_ext in CONTROLLED_3D_EXTS and new_ext not in CONTROLLED_3D_EXTS
    if not is_standard_rename and not is_three_d_suffix_mask:
        return None
    ts = parse_clickhouse_ts(row.get("ts"), tz)
    keys = raw_file_keys(obj)
    raw_hash = str(row.get("raw_hash") or "")
    return ThreeDRenameFinding(
        rename_ts=ts,
        raw_hash=raw_hash,
        client_id=raw_client_id(obj),
        client_name=first_nonempty(obj, ["client_name"]),
        client_ip=first_nonempty(obj, ["client_ip"]),
        client_mac=raw_client_mac(obj),
        login_account=first_nonempty(obj, ["client_login_account", "login_account", "local_account"]),
        old_path=old_path,
        new_path=new_path,
        old_name=old_name,
        new_name=new_name,
        old_ext=old_ext,
        new_ext=new_ext,
        critical_design_label=critical_label,
        process_name=first_nonempty(obj, ["process_name"]),
        file_key=keys[0] if keys else "",
        file_id=first_nonempty(obj, ["file_id", "download_fileid"]),
        alias_paths=[new_path],
        alias_names=[new_name] if new_name else [],
        alias_keys=keys,
        rename_chain_names=[name for name in [old_name, new_name] if name],
        rename_chain_paths=[path for path in [old_path, new_path] if path],
        chain_raw_hashes=[raw_hash] if raw_hash else [],
        in_report_period=in_period(ts, start, end, tz),
    )


def same_rename_terminal(finding: ThreeDRenameFinding, obj: dict[str, Any]) -> bool:
    row_client_id = raw_client_id(obj)
    if finding.client_id and row_client_id:
        return normalize_key(finding.client_id) == normalize_key(row_client_id)
    row_name = first_nonempty(obj, ["client_name"])
    row_ip = first_nonempty(obj, ["client_ip"])
    if finding.client_name and finding.client_ip and row_name and row_ip:
        return normalize_key(finding.client_name) == normalize_key(row_name) and normalize_key(finding.client_ip) == normalize_key(row_ip)
    if finding.client_name and row_name:
        return normalize_key(finding.client_name) == normalize_key(row_name)
    if finding.client_ip and row_ip:
        return normalize_key(finding.client_ip) == normalize_key(row_ip)
    return False


def row_matches_three_d_rename_alias(
    finding: ThreeDRenameFinding,
    obj: dict[str, Any],
    topic: str,
    require_same_terminal: bool = True,
) -> tuple[str, str]:
    same_terminal = same_rename_terminal(finding, obj)
    if require_same_terminal and not same_terminal:
        return "", ""
    alias_path_keys = {path_match_key(path) for path in finding.alias_paths if path}
    alias_name_keys = {report_file_name_key(name) for name in finding.alias_names if name}
    alias_keys = {normalize_key(key) for key in finding.alias_keys if key}
    row_paths = [first_nonempty(obj, ["local_file_path"]), first_nonempty(obj, ["remote_file_path"])]
    for path in row_paths:
        if path and path_match_key(path) in alias_path_keys:
            return "path", "完整路径匹配"
        name = path_basename(path)
        if name and report_file_name_key(name) in alias_name_keys:
            return "name", "文件名匹配"
    for name in file_names_for(obj, topic):
        if report_file_name_key(name) in alias_name_keys:
            return "name", "文件名匹配"
    row_keys = {normalize_key(key) for key in raw_file_keys(obj) if key}
    if alias_keys and row_keys & alias_keys:
        return "key", "文件键匹配"
    raw_text = normalize_key(str(obj))
    for name_key in alias_name_keys:
        if name_key and name_key in raw_text:
            return "name", "消息/附件文本包含文件名"
    return "", ""


def expand_three_d_rename_chains(
    findings: list[ThreeDRenameFinding],
    rename_rows: list[dict[str, Any]],
    tz: timezone,
) -> None:
    ordered_rows = sorted(
        rename_rows,
        key=lambda row: parse_clickhouse_ts(row.get("ts"), tz) or datetime.min.replace(tzinfo=tz),
    )
    for finding in findings:
        for row in ordered_rows:
            ts = parse_clickhouse_ts(row.get("ts"), tz)
            if not ts or (finding.rename_ts and ts <= finding.rename_ts):
                continue
            raw_hash = str(row.get("raw_hash") or "")
            if raw_hash and raw_hash in finding.chain_raw_hashes:
                continue
            obj = raw_json_from_clickhouse_row(row)
            if not obj or not is_rename_operation(obj):
                continue
            match_kind, _basis = row_matches_three_d_rename_alias(finding, obj, "file_audit", require_same_terminal=True)
            if not match_kind:
                continue
            next_path = first_nonempty(obj, ["remote_file_path"])
            if not next_path:
                continue
            add_three_d_rename_alias(finding, next_path, raw_hash=raw_hash)
            add_three_d_rename_keys(finding, raw_file_keys(obj))


def destination_channel_for_raw(
    topic: str,
    obj: dict[str, Any],
    internal_domains: set[str],
) -> tuple[str, str]:
    if topic == "mail_audit":
        targets, _domains = targets_for(obj, topic)
        return "邮件外发", "; ".join(targets[:8])
    if topic == "im_audit":
        targets, _domains = targets_for(obj, topic)
        process = first_nonempty(obj, ["process_name"])
        channel = "IM附件"
        if normalize_key(process) in {"wxwork.exe", "wxwork", "wecom.exe", "wecom"}:
            channel = "IM附件/企业微信"
        elif normalize_key(process) in {"dingtalk.exe", "dingtalk"}:
            channel = "IM附件/钉钉"
        elif normalize_key(process) in {"feishu.exe", "lark.exe"}:
            channel = "IM附件/飞书"
        return channel, "; ".join(targets[:8])
    if topic != "file_audit":
        return topic or "后续动作", ""

    method = file_audit_transfer_method(obj)
    targets, domains = targets_for(obj, topic)
    target_text = "; ".join(targets[:8]) or first_nonempty(obj, ["remote_file_path", "local_file_path"])
    if method == "copyout":
        return "外设拷贝", target_text
    if method == "send":
        return "IM附件", target_text
    if method == "upload_to_site":
        if any(text_matches_hints(value, CLOUD_DEST_HINTS) for value in domains + targets):
            return "外部站点上传", target_text
        if any(domain and not domain_is_internal(domain, internal_domains) for domain in domains):
            return "外部站点上传", target_text
        return "内部系统上传", target_text
    if str(obj.get("operation_type") or "") == "7":
        return "再次重命名", target_text
    return "后续文件操作", target_text


def destination_match_for_rename(
    finding: ThreeDRenameFinding,
    row: dict[str, Any],
    internal_domains: set[str],
    tz: timezone,
) -> tuple[str, str, str, str] | None:
    obj = raw_json_from_clickhouse_row(row)
    if not obj:
        return None
    topic = str(row.get("topic") or obj.get("syslog_topic") or "")
    row_hash = str(row.get("raw_hash") or "")
    if row_hash and row_hash == finding.raw_hash:
        return None
    if row_hash and row_hash in finding.chain_raw_hashes:
        return None
    ts = parse_clickhouse_ts(row.get("ts"), tz)
    if finding.rename_ts and ts and ts <= finding.rename_ts:
        return None
    if topic == "file_audit" and is_rename_operation(obj):
        return None
    same_terminal = same_rename_terminal(finding, obj)
    match_kind, match_basis = row_matches_three_d_rename_alias(finding, obj, topic, require_same_terminal=False)

    confidence = ""
    basis = ""
    if same_terminal and match_kind == "path":
        confidence = "强匹配"
        basis = f"同一终端 + 链路别名{match_basis}"
    elif same_terminal and match_kind == "key":
        confidence = "强匹配"
        basis = "同一终端 + 链路文件键一致"
    elif same_terminal and match_kind == "name":
        confidence = "可信匹配"
        basis = f"同一终端 + 链路别名{match_basis}"
    elif match_kind == "name":
        confidence = "低可信"
        basis = "仅链路文件名相同，终端未确认一致"

    if not confidence:
        return None
    channel, target = destination_channel_for_raw(topic, obj, internal_domains)
    return channel, target, confidence, basis


def update_three_d_rename_destination(
    findings: list[ThreeDRenameFinding],
    destination_rows: list[dict[str, Any]],
    internal_domains: set[str],
    tz: timezone,
) -> None:
    for finding in findings:
        best: tuple[datetime, dict[str, Any], tuple[str, str, str, str]] | None = None
        for row in destination_rows:
            ts = parse_clickhouse_ts(row.get("ts"), tz)
            if not ts or (finding.rename_ts and ts <= finding.rename_ts):
                continue
            matched = destination_match_for_rename(finding, row, internal_domains, tz)
            if not matched:
                continue
            if best is None or ts > best[0]:
                best = (ts, row, matched)
        if not best:
            continue
        ts, row, (channel, target, confidence, basis) = best
        finding.destination_ts = ts
        finding.destination_channel = channel
        finding.destination_target = target
        finding.destination_confidence = confidence
        finding.destination_basis = basis
        finding.destination_topic = str(row.get("topic") or "")
        finding.destination_raw_hash = str(row.get("raw_hash") or "")
        finding.tracking_status = "已发现后续去向" if confidence in THREE_D_RENAME_CONFIRMED_CONFIDENCES else "待确认"


def load_three_d_rename_findings(
    args: argparse.Namespace,
    start: datetime | None,
    end: datetime | None,
    tz: timezone,
    internal_domains: set[str],
) -> list[ThreeDRenameFinding]:
    if not getattr(args, "use_clickhouse", False):
        return []
    report_end = end or datetime.now(tz)
    report_start = start or (report_end - timedelta(days=1))
    lookback_start = report_end - timedelta(days=THREE_D_RENAME_TRACK_DAYS)
    where = clickhouse_time_filter(lookback_start, report_end)
    query = (
        "SELECT ts, topic, raw_hash, raw_json "
        f"FROM raw_syslog WHERE {where} AND topic = 'file_audit' "
        "AND (JSONExtractString(raw_json, 'operation_type') = '7' OR JSONExtractInt(raw_json, 'operation_type') = 7) "
        "FORMAT JSONEachRow"
    )
    try:
        text = clickhouse_query(args, query)
    except Exception as exc:
        debug_timing(f"three_d_rename query failed {type(exc).__name__}: {exc}")
        return []

    rename_rows: list[dict[str, Any]] = []
    findings: list[ThreeDRenameFinding] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        rename_rows.append(row)
        finding = three_d_rename_candidate_from_row(row, tz, report_start, report_end)
        if not finding:
            continue
        enrich_three_d_rename_identity(finding, args)
        findings.append(finding)

    if not findings:
        return []
    expand_three_d_rename_chains(findings, rename_rows, tz)

    min_rename_ts = min((finding.rename_ts for finding in findings if finding.rename_ts), default=lookback_start)
    new_paths = sorted({path for finding in findings for path in finding.alias_paths if path})
    new_names = sorted({name for finding in findings for name in finding.alias_names if name})
    file_keys = sorted({value for finding in findings for value in finding.alias_keys if value})
    path_array = clickhouse_array_literal(new_paths)
    name_array = clickhouse_array_literal(new_names)
    key_match_expr = ""
    if file_keys:
        key_array = clickhouse_array_literal(file_keys)
        key_match_expr = (
            f" OR has({key_array}, JSONExtractString(raw_json, 'download_file_key')) "
            f"OR has({key_array}, JSONExtractString(raw_json, 'download_fileid')) "
            f"OR has({key_array}, JSONExtractString(raw_json, 'file_id'))"
        )
    dest_where = clickhouse_time_filter(min_rename_ts, report_end)
    match_expr = (
        "("
        "topic = 'file_audit' AND ("
        f"has({path_array}, JSONExtractString(raw_json, 'local_file_path')) "
        f"OR has({path_array}, JSONExtractString(raw_json, 'remote_file_path')) "
        f"OR has({name_array}, JSONExtractString(raw_json, 'file_name'))"
        f"{key_match_expr}"
        ")"
        ") OR (topic IN ('mail_audit','im_audit') "
        f"AND arrayExists(x -> positionCaseInsensitiveUTF8(raw_json, x) > 0, {name_array}))"
    )
    dest_query = (
        "SELECT ts, topic, raw_hash, raw_json "
        f"FROM raw_syslog WHERE {dest_where} AND topic IN ('file_audit','mail_audit','im_audit') "
        f"AND ({match_expr}) "
        "FORMAT JSONEachRow"
    )
    destination_rows: list[dict[str, Any]] = []
    try:
        dest_text = clickhouse_query(args, dest_query)
        for line in dest_text.splitlines():
            if not line.strip():
                continue
            try:
                destination_rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except Exception as exc:
        debug_timing(f"three_d_rename destination query failed {type(exc).__name__}: {exc}")

    update_three_d_rename_destination(findings, destination_rows, internal_domains, tz)
    active = [
        finding
        for finding in findings
        if three_d_rename_is_report_visible(finding)
        if (
            finding.in_report_period
            or finding.tracking_status == "未发现后续去向"
            or in_period(finding.destination_ts, start, end, tz)
        )
    ]
    return sorted(
        active,
        key=lambda item: (
            0 if item.tracking_status != "已发现后续去向" else 1,
            item.rename_ts or datetime.min.replace(tzinfo=tz),
        ),
        reverse=True,
    )


def three_d_rename_is_suffix_mask(finding: ThreeDRenameFinding) -> bool:
    return finding.old_ext in CONTROLLED_3D_EXTS and finding.new_ext not in CONTROLLED_3D_EXTS


def three_d_rename_is_report_visible(finding: ThreeDRenameFinding) -> bool:
    if three_d_rename_is_suffix_mask(finding):
        return True
    if finding.critical_design_label:
        return three_d_rename_is_outbound_or_copy(finding)
    return True
