#!/usr/bin/env python3
"""Decrypt-record data loading and follow-up correlation module.

This module is runtime-bound to the main generator namespace so it can reuse the
existing ClickHouse, policy, classification, and Tianqing event helpers while
keeping decrypt data logic out of the report shell.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


def bind_runtime_dependencies(namespace: dict[str, Any]) -> None:
    for key, value in namespace.items():
        if key.startswith("__"):
            continue
        globals()[key] = value


def decrypt_object_bucket_for(file_name: str, file_ext: str = "") -> tuple[str, list[str]]:
    labels = critical_design_labels_for_name(file_name)
    ext = (file_ext or extension(file_name)).lower()
    if CRITICAL_STRUCTURE_LABEL in labels:
        return "结构", labels
    if CRITICAL_ELECTRICAL_LABEL in labels:
        return "电气", labels
    if CRITICAL_YB_STANDARD_LABEL in labels:
        if ext in CONTROLLED_2D_CAD_EXTS:
            return "电气", labels
        return "结构", labels
    if ext in CONTROLLED_3D_EXTS:
        return "三维模型", labels
    if ext in CONTROLLED_2D_CAD_EXTS:
        return "DWG图纸", labels
    if ext in ARCHIVE_EXTS:
        return "压缩包", labels
    return "其他", labels


def decrypt_record_from_clickhouse_row(row: dict[str, Any], tz: timezone) -> DecryptRiskRecord:
    raw_org_path = str(row.get("raw_org_path") or "")
    raw_company = str(row.get("raw_company") or "")
    raw_department = str(row.get("raw_department") or "")
    company, department, matched = decrypt_imports.resolve_org_alias(raw_org_path, raw_company, raw_department, ORGANIZATION_ALIASES)
    file_name = str(row.get("file_name") or "")
    file_ext = str(row.get("file_ext") or extension(file_name)).lower()
    object_bucket, labels = decrypt_object_bucket_for(file_name, file_ext)
    file_size_value = row.get("file_size")
    try:
        file_size = None if file_size_value is None else int(file_size_value)
    except (TypeError, ValueError):
        file_size = None
    return DecryptRiskRecord(
        apply_time=parse_clickhouse_ts(row.get("apply_time"), tz),
        import_batch=str(row.get("import_batch") or ""),
        source_file=str(row.get("source_file") or ""),
        row_number=int(row.get("row_number") or 0),
        business_fingerprint=str(row.get("business_fingerprint") or ""),
        request_reason=str(row.get("request_reason") or ""),
        request_level=str(row.get("request_level") or ""),
        applicant_account=str(row.get("applicant_account") or ""),
        applicant_name=str(row.get("applicant_name") or ""),
        approver=str(row.get("approver") or ""),
        approve_time=parse_clickhouse_ts(row.get("approve_time"), tz),
        recipient_unit=str(row.get("recipient_unit") or ""),
        raw_org_path=raw_org_path,
        raw_company=raw_company,
        raw_department=raw_department,
        company=company,
        department=department,
        org_matched=matched,
        file_name=file_name,
        file_ext=file_ext,
        file_size=file_size,
        status=str(row.get("status") or ""),
        approver_account=str(row.get("approver_account") or ""),
        approver_name=str(row.get("approver_name") or ""),
        approver_department=str(row.get("approver_department") or ""),
        mail_fail_reason=str(row.get("mail_fail_reason") or ""),
        object_bucket=object_bucket,
        critical_labels=labels,
    )


DECRYPT_RECORD_SELECT = (
    "import_batch, source_file, row_number, business_fingerprint, request_reason, apply_time, request_level, "
    "applicant_account, applicant_name, approver, approve_time, recipient_unit, raw_org_path, raw_company, raw_department, "
    "file_name, file_ext, file_size, status, approver_account, approver_name, approver_department, mail_fail_reason"
)


def decrypt_time_filter(start: datetime | None, end: datetime | None) -> str:
    filters = ["isNotNull(apply_time)"]
    if start:
        filters.append(f"apply_time >= parseDateTime64BestEffort({clickhouse_literal(start.isoformat())}, 3)")
    if end:
        filters.append(f"apply_time < parseDateTime64BestEffort({clickhouse_literal(end.isoformat())}, 3)")
    return " AND ".join(filters)


def query_decrypt_records(args: argparse.Namespace, start: datetime | None, end: datetime | None, tz: timezone) -> list[DecryptRiskRecord]:
    query = (
        f"SELECT {DECRYPT_RECORD_SELECT} "
        f"FROM decrypt_records FINAL WHERE {decrypt_time_filter(start, end)} "
        "ORDER BY apply_time DESC, import_batch DESC, row_number ASC FORMAT JSONEachRow"
    )
    text = clickhouse_query(args, query)
    records: list[DecryptRiskRecord] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        records.append(decrypt_record_from_clickhouse_row(json.loads(line), tz))
    return records


def decrypt_person_match(record: DecryptRiskRecord, event: AuditEvent) -> bool:
    applicants = {
        normalize_key(record.applicant_name),
        normalize_key(record.applicant_account),
    }
    applicants.discard("")
    event_people = {
        normalize_key(event.resolved_person),
        normalize_key(event.person),
        normalize_key(event.account),
        normalize_key(event.sender_mailbox),
    }
    event_people.discard("")
    return bool(applicants & event_people)


def decrypt_org_match(record: DecryptRiskRecord, event: AuditEvent) -> bool:
    record_company = normalize_key(record.company or record.raw_company)
    record_department = normalize_key(record.department or record.raw_department)
    event_company = normalize_key(event_company_label(event))
    event_department = normalize_key(event_department_label(event))
    return bool((record_company and record_company == event_company) or (record_department and record_department == event_department))


def decrypt_followup_confidence(record: DecryptRiskRecord, event: AuditEvent) -> str:
    if decrypt_person_match(record, event):
        return "可信匹配"
    if decrypt_org_match(record, event):
        return "组织匹配"
    return "低可信匹配"


def decrypt_followup_rank(confidence: str) -> int:
    if confidence == "可信匹配":
        return 3
    if confidence == "组织匹配":
        return 2
    if confidence == "低可信匹配":
        return 1
    return 0


def decrypt_followup_channel(event: AuditEvent, internal_domains: set[str]) -> str:
    group = audit_channel_group(event, internal_domains)
    detail = event_channel_label(event)
    if group and detail and detail != group:
        return f"{group}/{detail}"
    return group or detail or "后续文件流转"


def decrypt_rename_person_match(record: DecryptRiskRecord, finding: ThreeDRenameFinding) -> bool:
    applicants = {
        normalize_key(record.applicant_name),
        normalize_key(record.applicant_account),
    }
    applicants.discard("")
    finding_people = {
        normalize_key(finding.person),
        normalize_key(finding.login_account),
    }
    finding_people.discard("")
    return bool(applicants & finding_people)


def decrypt_rename_org_match(record: DecryptRiskRecord, finding: ThreeDRenameFinding) -> bool:
    record_company = normalize_key(record.company or record.raw_company)
    record_department = normalize_key(record.department or record.raw_department)
    finding_company = normalize_key(finding.company)
    finding_department = normalize_key(finding.department)
    return bool(
        (record_company and record_company == finding_company)
        or (record_department and record_department == finding_department)
    )


def decrypt_rename_followup_confidence(record: DecryptRiskRecord, finding: ThreeDRenameFinding) -> str:
    if decrypt_rename_person_match(record, finding):
        return "可信匹配"
    if decrypt_rename_org_match(record, finding):
        return "组织匹配"
    return "低可信匹配"


def decrypt_standard_rename_followup_event(
    record: DecryptRiskRecord,
    finding: ThreeDRenameFinding,
) -> DecryptFollowupEvent | None:
    if record.object_bucket not in {"结构", "电气"} or not record.apply_time:
        return None
    if not standard_design_rename_outbound(finding):
        return None
    rename_ts = finding.rename_ts
    destination_ts = finding.destination_ts
    if not rename_ts or not destination_ts:
        return None
    window_end = record.apply_time + timedelta(days=30)
    if rename_ts < record.apply_time or destination_ts > window_end:
        return None
    if report_file_name_key(record.file_name) != report_file_name_key(finding.old_name):
        return None
    confidence = decrypt_rename_followup_confidence(record, finding)
    channel = finding.destination_channel or "疑似后续外发/拷贝"
    if not channel.startswith("标准图纸更名外发"):
        channel = f"标准图纸更名外发/{channel}"
    target_parts = [
        finding.destination_target,
        f"{finding.old_name or '-'} → {finding.new_name or '-'}",
        finding.destination_basis,
    ]
    return DecryptFollowupEvent(
        ts=destination_ts,
        channel=channel,
        target="；".join(part for part in target_parts if part),
        confidence=confidence,
        event_id=finding.destination_raw_hash or finding.raw_hash,
        topic=finding.destination_topic or "standard_design_rename",
        process_name=finding.process_name,
    )


def enrich_decrypt_standard_rename_followups(
    records: list[DecryptRiskRecord],
    standard_rename_findings: list[ThreeDRenameFinding],
) -> None:
    if not records or not standard_rename_findings:
        return
    rename_index: dict[str, list[ThreeDRenameFinding]] = defaultdict(list)
    for finding in standard_rename_findings:
        if not standard_design_rename_outbound(finding):
            continue
        key = report_file_name_key(finding.old_name)
        if key:
            rename_index[key].append(finding)
    if not rename_index:
        return
    for findings in rename_index.values():
        findings.sort(key=lambda item: item.destination_ts or item.rename_ts or datetime.min.replace(tzinfo=timezone.utc))
    for record in records:
        key = report_file_name_key(record.file_name)
        if not key:
            continue
        for finding in rename_index.get(key, []):
            followup = decrypt_standard_rename_followup_event(record, finding)
            if not followup:
                continue
            record.followup_chain.append(followup)
        if not record.followup_chain:
            continue
        deduped: dict[tuple[str, str, str], DecryptFollowupEvent] = {}
        for item in record.followup_chain:
            deduped[(item.event_id or "", item.channel or "", item.ts.isoformat() if item.ts else "")] = item
        chain = sorted(
            deduped.values(),
            key=lambda item: item.ts or datetime.min.replace(tzinfo=timezone.utc),
        )
        record.followup_chain = chain
        reliable_chain = [item for item in chain if decrypt_followup_rank(item.confidence) >= 2]
        final = max(reliable_chain or chain, key=lambda item: item.ts or datetime.min.replace(tzinfo=timezone.utc))
        record.followup_channel = final.channel or "疑似后续外发/拷贝"
        record.followup_time = final.ts
        record.followup_target = final.target
        record.followup_confidence = final.confidence
        record.followup_event_id = final.event_id


def enrich_decrypt_followups(
    records: list[DecryptRiskRecord],
    candidate_events: list[AuditEvent],
    internal_domains: set[str],
) -> None:
    if not records or not candidate_events:
        return
    index: dict[str, list[AuditEvent]] = defaultdict(list)
    for event in candidate_events:
        channel = audit_channel_group(event, internal_domains)
        if channel not in {"邮件外发", "IM附件", "外部站点上传", "外设拷贝"}:
            continue
        for key in report_event_file_keys(event):
            index[key].append(event)
    for events_for_key in index.values():
        events_for_key.sort(key=lambda item: item.ts or datetime.min.replace(tzinfo=timezone.utc))
    for record in records:
        if not record.apply_time:
            continue
        key = report_file_name_key(record.file_name)
        if not key:
            continue
        window_end = record.apply_time + timedelta(days=30)
        chain: list[DecryptFollowupEvent] = []
        for event in index.get(key, []):
            if not event.ts or event.ts < record.apply_time or event.ts > window_end:
                continue
            confidence = decrypt_followup_confidence(record, event)
            chain.append(
                DecryptFollowupEvent(
                    ts=event.ts,
                    channel=decrypt_followup_channel(event, internal_domains),
                    target=summarize_targets(event, 240),
                    confidence=confidence,
                    event_id=event.event_id,
                    topic=event.topic,
                    process_name=event.process_name,
                )
            )
        if not chain:
            continue
        chain.sort(key=lambda item: item.ts or datetime.min.replace(tzinfo=timezone.utc))
        record.followup_chain = chain
        reliable_chain = [item for item in chain if decrypt_followup_rank(item.confidence) >= 2]
        final = max(reliable_chain or chain, key=lambda item: item.ts or datetime.min.replace(tzinfo=timezone.utc))
        record.followup_channel = final.channel or "疑似后续外发/拷贝"
        record.followup_time = final.ts
        record.followup_target = final.target
        record.followup_confidence = final.confidence
        record.followup_event_id = final.event_id


def load_decrypt_risk_analysis(
    args: argparse.Namespace,
    start: datetime | None,
    end: datetime | None,
    tz: timezone,
    fallback_events: list[AuditEvent],
    internal_domains: set[str],
) -> DecryptRiskAnalysis:
    if not getattr(args, "use_clickhouse", False):
        return DecryptRiskAnalysis(error="未启用 ClickHouse，解密记录追踪暂不可用。")
    trend_end = end or datetime.now(tz)
    trend_start = trend_end - timedelta(days=30)
    try:
        current_records = query_decrypt_records(args, start, end, tz)
        trend_records = query_decrypt_records(args, trend_start, trend_end, tz)
    except Exception as exc:
        return DecryptRiskAnalysis(error=f"解密记录表暂不可用：{type(exc).__name__}: {str(exc)[:180]}")

    followup_start = min((record.apply_time for record in current_records if record.apply_time), default=start or trend_start)
    followup_end = max((record.apply_time + timedelta(days=30) for record in current_records if record.apply_time), default=end or trend_end)
    candidate_events = fallback_events
    if current_records:
        try:
            candidate_events = normalized_audit_events_from_clickhouse_period(
                args,
                followup_start,
                followup_end,
                tz,
                internal_domains,
            )
        except Exception as exc:
            debug_timing(f"decrypt followup event query failed {type(exc).__name__}: {exc}")
    enrich_decrypt_followups(current_records, candidate_events, internal_domains)
    if any(record.object_bucket in {"结构", "电气"} for record in current_records):
        try:
            rename_findings = load_three_d_rename_findings(args, followup_start, followup_end, tz, internal_domains)
            standard_rename_findings = [
                finding for finding in rename_findings if standard_design_rename_outbound(finding)
            ]
            enrich_decrypt_standard_rename_followups(current_records, standard_rename_findings)
        except Exception as exc:
            debug_timing(f"decrypt standard rename followup failed {type(exc).__name__}: {exc}")
    return DecryptRiskAnalysis(available=True, records=current_records, trend_records=trend_records)
