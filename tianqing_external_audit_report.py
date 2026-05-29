#!/usr/bin/env python3
"""Generate a data-security audit report from endpoint and decrypt records.

The report intentionally avoids printing raw mail bodies and chat messages.
It focuses on who/which endpoint sent or attempted to send what kind of file
to what kind of destination, and which events need attachment review.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html as html_lib
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import textwrap
import time as time_module
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import tianqing_decrypt_records as decrypt_imports
from tianqing_channel_matrix_module import (
    bind_runtime_dependencies as bind_channel_matrix_dependencies,
    build_tianqing_channel_matrix_result,
)
from tianqing_decrypt_audit_module import (
    DECRYPT_MATRIX_COLUMNS,
    bind_runtime_dependencies as bind_decrypt_audit_dependencies,
    build_decrypt_audit_module_result,
    build_decrypt_risk_detail_page,
    decrypt_company_groups,
    decrypt_company_label,
    decrypt_company_matrix_detail_key,
    decrypt_has_followup,
    decrypt_risk_home_html,
    decrypt_standard_records,
)
from tianqing_decrypt_data_module import (
    bind_runtime_dependencies as bind_decrypt_data_dependencies,
    load_decrypt_risk_analysis,
)
from tianqing_evidence_detail_module import (
    bind_runtime_dependencies as bind_evidence_detail_dependencies,
    build_tianqing_evidence_detail_result,
)
from tianqing_organization_risk_module import (
    bind_runtime_dependencies as bind_organization_risk_dependencies,
    build_tianqing_organization_risk_result,
)
from tianqing_rename_tracking_module import (
    bind_runtime_dependencies as bind_rename_tracking_dependencies,
    build_tianqing_rename_tracking_result,
    standard_design_rename_outbound,
    three_d_rename_is_outbound_or_copy,
)
from tianqing_rename_data_module import (
    bind_runtime_dependencies as bind_rename_data_dependencies,
    load_three_d_rename_findings,
    three_d_rename_is_suffix_mask,
)
from tianqing_risk_overview_module import (
    bind_runtime_dependencies as bind_risk_overview_dependencies,
    build_rule_risk_overview_html,
    risk_overview_top_label,
)
from tianqing_trend_module import (
    bind_runtime_dependencies as bind_trend_dependencies,
    build_trend_summary,
    clickhouse_matrix_classification_exprs,
    load_trend_window_event_sets,
    trend_chart_html,
    trend_comparison_html,
    trend_matrix_events,
    trend_period_bounds,
    trend_reference_end,
)
from tianqing_report_modules import (
    ReportHomeModule,
    ReportModuleResult,
    TianqingChannelMatrixResult,
    TianqingEvidenceDetailResult,
    TianqingOrganizationRiskResult,
    TianqingOutboundModuleBuilders,
    TianqingRenameTrackingResult,
    build_decrypt_audit_home_module,
    build_global_management_summary_html,
    build_plm_login_audit_home_module,
    build_tianqing_outbound_module_result,
    render_report_home_modules,
)

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - Python < 3.9 fallback.
    ZoneInfo = None


DEFAULT_SSH_HOST = "root@172.88.49.239"
DEFAULT_REMOTE_LOG = "/data/tianqing-audit/raw-log/tianqing.log"
DEFAULT_PUBLIC_BASE_URL = "https://audit.daqo.com"
DEFAULT_CLICKHOUSE_URL = "http://127.0.0.1:8123"
DEFAULT_INTERNAL_DOMAINS = {"daqo.com"}
DEFAULT_INTERNAL_NETWORKS = {"172.88.0.0/16"}
INTERNAL_NETWORKS = set(DEFAULT_INTERNAL_NETWORKS)
UNMATCHED_DIRECTORY_LABEL = "未匹配通讯录"
UNMATCHED_COMPANY_LABEL = "未匹配公司"
UNMATCHED_DEPARTMENT_LABEL = "未匹配部门"
DEEP_NIGHT_START = time(22, 0)
DEEP_NIGHT_END = time(6, 30)
ABNORMAL_BURST_WINDOW_MINUTES = 60
ABNORMAL_BURST_MIN_EVENTS = 3
ABNORMAL_BURST_HIGH_SIGNAL_MIN_EVENTS = 2
RISKY_TARGET_WINDOW_MINUTES = 120
VOLUME_WINDOW_MINUTES = 120
VOLUME_BURST_MIN_BYTES = 100 * 1024 * 1024
SPLIT_TRANSFER_WINDOW_MINUTES = 120
BEHAVIOR_MAX_GROUP_EVENTS = 220
BEHAVIOR_MAX_GROUPS = 450
DEFAULT_PEOPLE_MAP = "people_mapping.csv"
DEFAULT_DISPOSITION_FILE = "audit_dispositions.csv"
DEFAULT_RECIPIENT_MAP = "recipient_mapping.csv"
DEFAULT_WECOM_DIRECTORY_HOST = "root@172.88.49.60"
DEFAULT_WECOM_DIRECTORY_CONTAINER = "wecom-dify-bridge"
DEFAULT_WECOM_DIRECTORY_CACHE = "wecom_directory_cache.json"
DEFAULT_SENSITIVE_KEYWORDS_FILE = os.getenv("TIANQING_SENSITIVE_KEYWORDS_FILE", "sensitive_keywords.json")
DEFAULT_EXCLUSION_FILE = os.getenv("TIANQING_AUDIT_EXCLUSION_FILE", "audit_exclusions.json")
DEFAULT_AUDIT_POLICY_FILE = os.getenv("TIANQING_AUDIT_POLICY_FILE", "audit_policy.json")
EXTERNAL_RELATIONS = {"external", "partner", "customer", "supplier"}
RELATION_LABELS = {
    "external": "外部",
    "partner": "合作方",
    "customer": "客户",
    "supplier": "供应商",
    "unknown": "待判定",
    "internal": "内部",
    "group": "群聊忽略",
}
WECOM_GROUP_TARGET_HINTS = ("群", "团队", "项目组", "工作组", "交流群", "沟通组", "沟通群", "对接群", "访客预约")
PRIORITY_ACTION = "action"
PRIORITY_REVIEW = "review"
PRIORITY_GENERAL = "general"
PRIORITY_WATCH = "watch"
PRIORITY_ORDER = [PRIORITY_ACTION, PRIORITY_REVIEW, PRIORITY_GENERAL, PRIORITY_WATCH]
PRIORITY_LABELS = {
    PRIORITY_ACTION: "重点处置",
    PRIORITY_REVIEW: "优先复核",
    PRIORITY_GENERAL: "一般复核",
    PRIORITY_WATCH: "持续观察",
}
PRIORITY_WEIGHTS = {
    PRIORITY_ACTION: 100,
    PRIORITY_REVIEW: 40,
    PRIORITY_GENERAL: 15,
    PRIORITY_WATCH: 3,
}

PERSONAL_EMAIL_DOMAINS = {
    "126.com",
    "139.com",
    "163.com",
    "189.cn",
    "aliyun.com",
    "foxmail.com",
    "gmail.com",
    "hotmail.com",
    "icloud.com",
    "live.com",
    "msn.com",
    "outlook.com",
    "qq.com",
    "sina.com",
    "sohu.com",
    "yeah.net",
}

DEFAULT_ARCHIVE_EXTS = {"001", "7z", "arj", "bz2", "cab", "gz", "gzip", "iso", "lzh", "rar", "tar", "tbz", "tbz2", "tgz", "txz", "xz", "zip", "zipx", "zst"}
ARCHIVE_EXTS = set(DEFAULT_ARCHIVE_EXTS)
CAD_2D_EXTS = {"dwg"}
MODEL_3D_EXTS = {"asm", "prt", "sldasm", "sldprt", "step"}
PCB_ECAD_EXTS: set[str] = set()
CRITICAL_STRUCTURE_LABEL = "结构标准方案"
CRITICAL_ELECTRICAL_LABEL = "电气标准方案"
CRITICAL_DESIGN_LABELS = [CRITICAL_STRUCTURE_LABEL, CRITICAL_ELECTRICAL_LABEL]
HTML_DISPLAY_LABEL_ALIASES = {
    CRITICAL_STRUCTURE_LABEL: "结构",
    CRITICAL_ELECTRICAL_LABEL: "电气",
    "网盘/高风险外联目标": "高风险外联目标",
}
CRITICAL_DESIGN_REASON_PREFIX = "最高预警:"
DEFAULT_CRITICAL_DESIGN_PATTERNS = [
    {
        "key": "structure_standard",
        "label": CRITICAL_STRUCTURE_LABEL,
        "regex": r"^[3568][^\\/\.]{2}\.[^\\/\.]{3}\.[^\\/\.]{3}\.(?:sldasm|sldprt|step)$",
        "description": "结构方案图号主体为三段点号命名，每段固定三位，第一段以 3/5/6/8 开头，后缀为 SLDASM/SLDPRT/STEP。",
        "match_examples": ["356.123.456.sldprt", "5AB.CD1.999.SLDASM", "8XY.abc.DEF.step"],
        "miss_examples": ["123.456.789.sldprt", "356.1234.456.sldprt", "356.123.456.dwg"],
        "enabled": True,
    },
    {
        "key": "electrical_standard",
        "label": CRITICAL_ELECTRICAL_LABEL,
        "regex": r"^dq[^\\/\-]+-[^\\/\-]+-[^\\/\-]+-[^\\/\-]+\.dwg$",
        "description": "电气方案图号以 DQ 开头，主体正好三个短横线，后缀为 DWG。",
        "match_examples": ["DQ1-22-333-4444.dwg", "DQABC-DEF-G-HI.DWG", "dq低压柜-方案A-一次图-01.dwg"],
        "miss_examples": ["DQ001-002-003.dwg", "DQ001--003-004.dwg", "DQ001-002-003-004.dwg.zip"],
        "enabled": True,
    },
]
CRITICAL_DESIGN_PATTERNS: list[dict[str, Any]] = [dict(item) for item in DEFAULT_CRITICAL_DESIGN_PATTERNS]
ORGANIZATION_ALIASES: list[dict[str, str]] = []
DESIGN_EXTS = CAD_2D_EXTS | MODEL_3D_EXTS | PCB_ECAD_EXTS
CONTROLLED_3D_EXTS = MODEL_3D_EXTS
CONTROLLED_2D_CAD_EXTS = CAD_2D_EXTS
DATABASE_EXTS = {"accdb", "bak", "db", "mdb", "sql"}
TECHNICAL_EXTS = DESIGN_EXTS | DATABASE_EXTS
OFFICE_EXTS = {"csv", "doc", "docx", "pdf", "ppt", "pptx", "xls", "xlsx"}
LOW_VALUE_IMAGE_EXTS = {"bmp", "gif", "jpeg", "jpg", "mpf", "png"}
PROCUREMENT_DEPARTMENT_TERMS = {"采购", "供应链", "物资", "招采"}
PROCUREMENT_INQUIRY_STRONG_TERMS = {"询价", "询价单", "采购询价", "招标资料", "招标文件", "供应商报价"}
PROCUREMENT_INQUIRY_WEAK_TERMS = {"报价", "报价单", "采购", "供应商", "招标"}
PROCUREMENT_FORCE_KEEP_TERMS = {
    "cad",
    "bim",
    "成本",
    "底价",
    "电气图",
    "发票",
    "财务",
    "付款",
    "工资",
    "工程图",
    "回款",
    "合同",
    "客户",
    "客户清单",
    "离职",
    "模型",
    "人事",
    "三维",
    "设计",
    "数据库",
    "图纸",
    "薪资",
    "源码",
    "源代码",
    "账",
}
PROCUREMENT_NORMAL_EXTS = OFFICE_EXTS | ARCHIVE_EXTS | LOW_VALUE_IMAGE_EXTS | {"eml", "htm", "html", "rtf", "txt"}
SOURCE_EXTS = {
    "c",
    "cc",
    "cpp",
    "cs",
    "go",
    "java",
    "js",
    "json",
    "php",
    "py",
    "rs",
    "sh",
    "sql",
    "ts",
    "vue",
    "xml",
    "yaml",
    "yml",
}
SENSITIVE_EXTS = ARCHIVE_EXTS | TECHNICAL_EXTS | OFFICE_EXTS | SOURCE_EXTS
FILENAME_EXTS = SENSITIVE_EXTS | LOW_VALUE_IMAGE_EXTS


def build_filename_re(exts: set[str]) -> re.Pattern[str]:
    return re.compile(
        r"[\w\u4e00-\u9fff（）()【】\[\]《》·._~+\- ]{1,120}\."
        r"(?:" + "|".join(re.escape(ext) for ext in sorted(exts, key=len, reverse=True)) + r")\b",
        re.IGNORECASE,
    )


FILENAME_RE = build_filename_re(FILENAME_EXTS)

SENSITIVE_KEYWORD_RULES: list["KeywordRule"] = []
LEADERSHIP_KEYWORD_RULES: list["KeywordRule"] = []

HIGH_RISK_DEST_HINTS = {
    "1drv.ms",
    "aliyundrive.com",
    "baidu.com",
    "box.com",
    "dbankcloud.com",
    "dropbox.com",
    "drive.google.com",
    "lanzou",
    "live.com",
    "mega.nz",
    "onedrive.live.com",
    "pan.baidu.com",
    "sharepoint.com",
    "wetransfer.com",
}

CLOUD_DEST_HINTS = {
    "1drv.ms",
    "aliyundrive.com",
    "alipan.com",
    "box.com",
    "dbankcloud.com",
    "dropbox.com",
    "drive.google.com",
    "jianguoyun.com",
    "lanzou",
    "mega.nz",
    "onedrive",
    "pan.baidu.com",
    "quark.cn",
    "sharepoint.com",
    "weiyun.com",
}
CLOUD_PROCESS_NAMES = {
    "baidunetdisk.exe",
    "baidunetdiskhost.exe",
    "onedrive.exe",
    "quark.exe",
    "yundetectservice.exe",
}
IM_FILE_SEND_PROCESS_NAMES = {
    "dingtalk.exe",
    "dingtalk",
    "feishu.exe",
    "lark.exe",
    "feishu",
    "lark",
    "wecom.exe",
    "wecom",
    "wxwork.exe",
    "wxwork",
}
WECOM_PROCESS_NAMES = {"wxwork.exe", "wxwork", "wecom.exe", "wecom"}
UPLOAD_NOISE_HINTS = {
    "bugreport",
    "cos.ap-beijing.myqcloud.com",
    "dpr.wps.cn",
    "performance.solidworks.com",
    "pinyin.sogou.com",
    "profile.qqpy.sogou.com",
    "profile.sogou.com",
    "sogou.com",
}
FORBIDDEN_PROCESS_FAMILIES = {
    "weixin.exe": "微信",
    "wechat.exe": "微信",
    "qq.exe": "QQ",
    "ntqq.exe": "QQ",
    "tim.exe": "QQ",
}
FORBIDDEN_PROCESS_ORDER = ["微信", "QQ"]

MESSAGE_BODY_FIELDS = {"message_body", "chat_message"}
REASON_DISPLAY_PRIORITY = [
    "三维模型",
    "DWG二维图纸",
    "外部发件箱",
    "个人邮箱域名",
    "网盘/高风险外联目标",
    "外部收件域名",
    "外部上传/下载地址",
    "IM收件人关系待判定",
]
HIDDEN_LEADERSHIP_REASONS = {"二维/三维设计图纸", "设计图纸后缀"}
DESIGN_CATEGORY_DISPLAY_ORDER = CRITICAL_DESIGN_LABELS + ["三维模型", "DWG二维图纸", "设计资料"]
LARGE_ARCHIVE_RISK_BYTES = 100 * 1024 * 1024


@dataclass
class RawRecord:
    ts: datetime | None
    obj: dict[str, Any]


@dataclass
class AuditEvent:
    event_id: str
    ts: datetime | None
    topic: str
    channel: str
    person: str
    account: str
    client_name: str
    client_ip: str
    department: str
    org_path: str
    process_name: str
    raw_hash: str = ""
    mail_subject: str = ""
    sender_mailbox: str = ""
    targets: list[str] = field(default_factory=list)
    target_domains: list[str] = field(default_factory=list)
    recipients: list[str] = field(default_factory=list)
    recipient_relation: str = "unknown"
    file_names: list[str] = field(default_factory=list)
    file_exts: list[str] = field(default_factory=list)
    file_size: int | None = None
    lookup_keys: list[str] = field(default_factory=list)
    search_id: str = ""
    score: int = 0
    level: str = "LOW"
    priority: str = PRIORITY_WATCH
    priority_score: int = 0
    reasons: list[str] = field(default_factory=list)
    resolved_person: str = ""
    resolved_company: str = ""
    resolved_department: str = ""
    position: str = ""
    sensitive_role: str = ""
    mapping_source: str = ""
    disposition_status: str = ""
    disposition_owner: str = ""
    disposition_result: str = ""
    identity_hints: list[str] = field(default_factory=list)


@dataclass
class KeywordRule:
    keyword: str
    category: str = ""
    scope: str = "both"
    match_type: str = "contains"
    enabled: bool = True
    note: str = ""

    def matches(self, text: str) -> bool:
        if not self.enabled or not self.keyword:
            return False
        if self.match_type == "regex":
            try:
                return bool(re.search(self.keyword, text, re.IGNORECASE))
            except re.error:
                return False
        return self.keyword.lower() in text.lower()

    def in_risk_scope(self) -> bool:
        scopes = normalized_scopes(self.scope)
        return bool(scopes & {"all", "both", "risk", "score", "event"})

    def in_leadership_scope(self) -> bool:
        scopes = normalized_scopes(self.scope)
        return bool(scopes & {"all", "both", "leadership", "leader", "report"})


@dataclass
class ExclusionRule:
    rule_name: str
    topic: str = "*"
    target_contains: list[str] = field(default_factory=list)
    target_regex: list[str] = field(default_factory=list)
    file_contains: list[str] = field(default_factory=list)
    file_regex: list[str] = field(default_factory=list)
    process_contains: list[str] = field(default_factory=list)
    subject_contains: list[str] = field(default_factory=list)
    action: str = "exclude"
    enabled: bool = True
    note: str = ""


@dataclass
class PeopleEntry:
    match_type: str
    match_value: str
    person_name: str
    company: str = ""
    department: str = ""
    position: str = ""
    sensitive_role: str = ""
    status: str = ""
    note: str = ""


@dataclass
class TerminalIdentityObservation:
    ts: datetime | None
    client_name: str
    client_ip: str
    login_account: str = ""
    local_account: str = ""
    local_nickname: str = ""
    person_name: str = ""
    company: str = ""
    department: str = ""
    position: str = ""
    mapping_source: str = ""


@dataclass
class DispositionEntry:
    event_id: str
    search_id: str = ""
    status: str = ""
    owner: str = ""
    reviewer: str = ""
    review_time: str = ""
    attachment_downloaded: str = ""
    conclusion: str = ""
    notes: str = ""


@dataclass
class RecipientEntry:
    match_type: str
    match_value: str
    relation: str
    recipient_name: str = ""
    organization: str = ""
    note: str = ""


@dataclass
class AssetSnapshot:
    client_id: str
    client_name: str = ""
    client_ip: str = ""
    client_mac: str = ""
    client_mid: str = ""
    login_account: str = ""
    company: str = ""
    department: str = ""
    board_serial_number: str = ""
    brand_model: str = ""
    board_bios: str = ""
    manufacture_date: date | None = None
    os_main: str = ""
    os_release_id: str = ""
    os_build_version: str = ""
    os_describe: str = ""
    memory_mb: int | None = None
    core_number: int | None = None
    sys_space_mb: int | None = None
    main_program_version: str = ""
    patch_version: str = ""
    virus_version: str = ""
    activation: bool = False
    is_online: bool = False
    observed_at: datetime | None = None
    last_online_time: datetime | None = None
    client_create_time: datetime | None = None
    recent_risk_events: int = 0


@dataclass
class AssetAnalysis:
    available: bool = False
    error: str = ""
    total_assets: int = 0
    observed_in_period: int = 0
    parsed_manufacture_dates: int = 0
    age_counts: Counter = field(default_factory=Counter)
    os_counts: Counter = field(default_factory=Counter)
    virus_counts: Counter = field(default_factory=Counter)
    patch_counts: Counter = field(default_factory=Counter)
    main_version_counts: Counter = field(default_factory=Counter)
    online_counts: Counter = field(default_factory=Counter)
    risk_counts: Counter = field(default_factory=Counter)
    latest_virus_version: str = ""
    latest_patch_version: str = ""
    latest_main_version: str = ""
    old_device_assets: list[AssetSnapshot] = field(default_factory=list)
    unknown_manufacture_assets: list[AssetSnapshot] = field(default_factory=list)
    old_os_assets: list[AssetSnapshot] = field(default_factory=list)
    lagging_version_assets: list[AssetSnapshot] = field(default_factory=list)
    offline_assets: list[AssetSnapshot] = field(default_factory=list)
    long_offline_assets: list[AssetSnapshot] = field(default_factory=list)
    missing_assets: list[AssetSnapshot] = field(default_factory=list)
    high_attention_missing_assets: list[AssetSnapshot] = field(default_factory=list)
    suspected_uninstalled_assets: list[AssetSnapshot] = field(default_factory=list)
    reinstall_excluded_assets: list[AssetSnapshot] = field(default_factory=list)
    asset_by_terminal: dict[tuple[str, str], AssetSnapshot] = field(default_factory=dict)


@dataclass
class ForbiddenProcessFinding:
    family: str
    process_name: str
    process_md5: str = ""
    client_name: str = ""
    client_ip: str = ""
    login_account: str = ""
    os_version: str = ""
    resolved_person: str = ""
    resolved_company: str = ""
    resolved_department: str = ""
    mapping_source: str = ""
    group_name: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    log_count: int = 0
    search_ids: list[str] = field(default_factory=list)
    identity_hints: list[str] = field(default_factory=list)


@dataclass
class ForbiddenProcessAnalysis:
    available: bool = False
    error: str = ""
    findings: list[ForbiddenProcessFinding] = field(default_factory=list)
    family_counts: Counter = field(default_factory=Counter)
    family_terminal_counts: Counter = field(default_factory=Counter)
    total_terminal_count: int = 0
    total_account_count: int = 0
    matched_person_count: int = 0
    latest_seen: datetime | None = None


@dataclass
class TerminalRiskFinding:
    client_name: str
    client_ip: str
    client_mac: str = ""
    person: str = ""
    company: str = ""
    department: str = ""
    event_count: int = 0
    three_d_count: int = 0
    two_d_cad_count: int = 0
    sensitive_name_count: int = 0
    peripheral_copy_count: int = 0
    action_count: int = 0
    review_count: int = 0
    general_count: int = 0
    watch_count: int = 0
    latest_seen: datetime | None = None
    risk_score: int = 0
    events: list[AuditEvent] = field(default_factory=list)


@dataclass
class OrganizationRiskFinding:
    scope: str
    label: str
    company: str = ""
    department: str = ""
    asset_terminal_count: int = 0
    asset_base_incomplete: bool = False
    risk_terminal_count: int = 0
    event_count: int = 0
    three_d_count: int = 0
    two_d_cad_count: int = 0
    sensitive_name_count: int = 0
    peripheral_copy_count: int = 0
    action_count: int = 0
    review_count: int = 0
    general_count: int = 0
    watch_count: int = 0
    external_sender_count: int = 0
    im_event_count: int = 0
    risk_score: int = 0
    top3_contribution_rate: float = 0.0
    issue_tags: list[str] = field(default_factory=list)
    covered_companies: Counter = field(default_factory=Counter)
    terminal_findings: list[TerminalRiskFinding] = field(default_factory=list)
    events: list[AuditEvent] = field(default_factory=list)
    latest_seen: datetime | None = None


@dataclass
class OrganizationRiskAnalysis:
    companies: list[OrganizationRiskFinding] = field(default_factory=list)
    company_departments: list[OrganizationRiskFinding] = field(default_factory=list)
    department_types: list[OrganizationRiskFinding] = field(default_factory=list)


@dataclass
class ThreeDRenameFinding:
    rename_ts: datetime | None
    raw_hash: str
    client_id: str = ""
    client_name: str = ""
    client_ip: str = ""
    client_mac: str = ""
    login_account: str = ""
    person: str = ""
    company: str = ""
    department: str = ""
    old_path: str = ""
    new_path: str = ""
    old_name: str = ""
    new_name: str = ""
    old_ext: str = ""
    new_ext: str = ""
    critical_design_label: str = ""
    process_name: str = ""
    file_key: str = ""
    file_id: str = ""
    alias_paths: list[str] = field(default_factory=list)
    alias_names: list[str] = field(default_factory=list)
    alias_keys: list[str] = field(default_factory=list)
    rename_chain_names: list[str] = field(default_factory=list)
    rename_chain_paths: list[str] = field(default_factory=list)
    chain_raw_hashes: list[str] = field(default_factory=list)
    in_report_period: bool = False
    destination_in_report_period: bool = False
    tracking_status: str = "未发现后续去向"
    destination_channel: str = "未发现后续去向"
    destination_target: str = ""
    destination_ts: datetime | None = None
    destination_confidence: str = ""
    destination_basis: str = ""
    destination_topic: str = ""
    destination_raw_hash: str = ""


@dataclass
class DecryptFollowupEvent:
    ts: datetime | None
    channel: str
    target: str = ""
    confidence: str = ""
    event_id: str = ""
    topic: str = ""
    process_name: str = ""


@dataclass
class DecryptRiskRecord:
    apply_time: datetime | None
    import_batch: str
    source_file: str
    row_number: int
    business_fingerprint: str
    request_reason: str = ""
    request_level: str = ""
    applicant_account: str = ""
    applicant_name: str = ""
    approver: str = ""
    approve_time: datetime | None = None
    recipient_unit: str = ""
    raw_org_path: str = ""
    raw_company: str = ""
    raw_department: str = ""
    company: str = ""
    department: str = ""
    org_matched: bool = False
    file_name: str = ""
    file_ext: str = ""
    file_size: int | None = None
    status: str = ""
    approver_account: str = ""
    approver_name: str = ""
    approver_department: str = ""
    mail_fail_reason: str = ""
    object_bucket: str = "其他"
    critical_labels: list[str] = field(default_factory=list)
    followup_channel: str = "未发现后续外发/拷贝线索"
    followup_time: datetime | None = None
    followup_target: str = ""
    followup_confidence: str = ""
    followup_event_id: str = ""
    followup_chain: list[DecryptFollowupEvent] = field(default_factory=list)


@dataclass
class DecryptRiskAnalysis:
    available: bool = False
    error: str = ""
    records: list[DecryptRiskRecord] = field(default_factory=list)
    trend_records: list[DecryptRiskRecord] = field(default_factory=list)


@dataclass(frozen=True)
class HtmlCell:
    value: str
    title: str = ""
    raw: bool = False


def sh(args: list[str]) -> str:
    result = subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout


def debug_timing(message: str) -> None:
    if os.getenv("TIANQING_DEBUG_TIMING"):
        print(f"[tianqing-debug] {datetime.now().isoformat(timespec='seconds')} {message}", file=sys.stderr, flush=True)


REPORT_SUBMODULE_BINDERS = (
    bind_channel_matrix_dependencies,
    bind_rename_data_dependencies,
    bind_rename_tracking_dependencies,
    bind_decrypt_data_dependencies,
    bind_decrypt_audit_dependencies,
    bind_organization_risk_dependencies,
    bind_evidence_detail_dependencies,
    bind_trend_dependencies,
    bind_risk_overview_dependencies,
)


def bind_report_submodule_dependencies() -> None:
    namespace = globals()
    for binder in REPORT_SUBMODULE_BINDERS:
        binder(namespace)


def read_lines(args: argparse.Namespace) -> Iterable[str]:
    if args.local_log:
        with open(args.local_log, encoding="utf-8", errors="replace") as handle:
            yield from handle
        return

    command = ["ssh", "-o", "BatchMode=yes", args.ssh_host, "cat", args.remote_log]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    for raw_line in proc.stdout:
        yield raw_line.decode("utf-8", errors="replace")
    stderr_bytes = proc.stderr.read() if proc.stderr else b""
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    code = proc.wait()
    if code:
        raise RuntimeError(f"ssh log read failed with code {code}: {stderr.strip()}")


def parse_syslog_json(line: str) -> RawRecord | None:
    match = re.search(r"^(\S+)\s+\S+\s+(\{.*\})\s*$", line)
    if not match:
        return None
    ts = None
    try:
        ts = datetime.fromisoformat(match.group(1))
    except Exception:
        pass
    try:
        obj = json.loads(match.group(2))
    except Exception:
        return None
    return RawRecord(ts=ts, obj=obj)


def clickhouse_headers(args: argparse.Namespace) -> dict[str, str]:
    headers: dict[str, str] = {}
    user = str(getattr(args, "clickhouse_user", "") or os.getenv("CLICKHOUSE_USER", "")).strip()
    password = str(getattr(args, "clickhouse_password", "") or os.getenv("CLICKHOUSE_PASSWORD", "")).strip()
    if user:
        headers["X-ClickHouse-User"] = user
    if password:
        headers["X-ClickHouse-Key"] = password
    return headers


def clickhouse_query(args: argparse.Namespace, query: str, database: str | None = None) -> str:
    base_url = str(getattr(args, "clickhouse_url", "") or DEFAULT_CLICKHOUSE_URL).rstrip("/")
    db = database if database is not None else str(getattr(args, "clickhouse_database", "") or "tianqing")
    params = {"query": query}
    if db:
        params["database"] = db
    url = base_url + "/?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers=clickhouse_headers(args), method="POST")
    with urllib.request.urlopen(request, timeout=int(getattr(args, "clickhouse_timeout", 120))) as response:
        return response.read().decode("utf-8", errors="replace")


def clickhouse_literal(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def clickhouse_time_filter(start: datetime | None, end: datetime | None) -> str:
    filters = []
    if start:
        filters.append(f"ts >= parseDateTime64BestEffort({clickhouse_literal(start.isoformat())}, 3)")
    if end:
        filters.append(f"ts < parseDateTime64BestEffort({clickhouse_literal(end.isoformat())}, 3)")
    return " AND ".join(filters) if filters else "1"


def clickhouse_array_literal(values: Iterable[str]) -> str:
    return "[" + ",".join(clickhouse_literal(value) for value in values) + "]"


def clickhouse_event_filter(start: datetime | None, end: datetime | None) -> str:
    base = clickhouse_time_filter(start, end)
    signal_exts = sorted(DESIGN_EXTS | ARCHIVE_EXTS)
    return (
        f"{base} AND topic IN ('mail_audit','im_audit','file_audit') "
        "AND length(file_names) > 0 "
        "AND ("
        "level IN ('HIGH','MEDIUM') "
        f"OR hasAny(file_exts, {clickhouse_array_literal(signal_exts)}) "
        "OR ifNull(file_size, 0) >= 10485760 "
        "OR length(reasons) > 0"
        ")"
    )


def parse_clickhouse_ts(value: Any, tz: timezone) -> datetime | None:
    text = str(value or "").strip()
    if not text or text.startswith("1970-01-01"):
        return None
    try:
        parsed = datetime.fromisoformat(text.replace(" ", "T"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz)
    return parsed


CLICKHOUSE_AUDIT_EVENT_SELECT = (
    "event_id, raw_hash, ts, topic, channel, person, account, client_name, client_ip, "
    "department AS resolved_department, process_name, mail_subject, sender_mailbox, "
    "targets, target_domains, recipients, recipient_relation, file_names, file_exts, file_size, lookup_keys, search_id, "
    "score, level, reasons, resolved_person, company, disposition_status"
)


def audit_event_from_clickhouse_row(row: dict[str, Any], tz: timezone) -> "AuditEvent":
    return AuditEvent(
        event_id=str(row.get("event_id") or ""),
        raw_hash=str(row.get("raw_hash") or ""),
        ts=parse_clickhouse_ts(row.get("ts"), tz),
        topic=str(row.get("topic") or ""),
        channel=str(row.get("channel") or ""),
        person=str(row.get("person") or ""),
        account=str(row.get("account") or ""),
        client_name=str(row.get("client_name") or ""),
        client_ip=str(row.get("client_ip") or ""),
        department=str(row.get("resolved_department") or ""),
        org_path="",
        process_name=str(row.get("process_name") or ""),
        mail_subject=str(row.get("mail_subject") or ""),
        sender_mailbox=str(row.get("sender_mailbox") or ""),
        targets=[str(item) for item in row.get("targets") or []],
        target_domains=[str(item) for item in row.get("target_domains") or []],
        recipients=[str(item) for item in row.get("recipients") or []],
        recipient_relation=str(row.get("recipient_relation") or "unknown"),
        file_names=[str(item) for item in row.get("file_names") or []],
        file_exts=[str(item) for item in row.get("file_exts") or []],
        file_size=row.get("file_size"),
        lookup_keys=[str(item) for item in row.get("lookup_keys") or []],
        search_id=str(row.get("search_id") or ""),
        score=int(row.get("score") or 0),
        level=str(row.get("level") or "LOW"),
        reasons=[str(item) for item in row.get("reasons") or []],
        resolved_person=str(row.get("resolved_person") or ""),
        resolved_company=str(row.get("company") or ""),
        resolved_department=str(row.get("resolved_department") or ""),
        disposition_status=str(row.get("disposition_status") or ""),
    )


def audit_events_from_clickhouse_period(
    args: argparse.Namespace,
    start: datetime | None,
    end: datetime | None,
    tz: timezone,
) -> list["AuditEvent"]:
    event_where = clickhouse_event_filter(start, end)
    query = f"SELECT {CLICKHOUSE_AUDIT_EVENT_SELECT} FROM audit_events WHERE {event_where} FORMAT JSONEachRow"
    text = clickhouse_query(args, query)
    events: list[AuditEvent] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        events.append(audit_event_from_clickhouse_row(json.loads(line), tz))
    return events


def normalized_audit_events_from_clickhouse_period(
    args: argparse.Namespace,
    start: datetime | None,
    end: datetime | None,
    tz: timezone,
    internal_domains: set[str],
) -> list["AuditEvent"]:
    events = audit_events_from_clickhouse_period(args, start, end, tz)
    if not events:
        return []
    raw_file_audit_map = raw_file_audit_map_from_clickhouse(args, start, end)
    apply_report_policies(events, raw_file_audit_map, internal_domains)
    wecom_people_map = getattr(args, "wecom_people_map_loaded", {}) or {}
    terminal_identity_history = getattr(args, "terminal_identity_history", {}) or {}
    if not terminal_identity_history:
        terminal_identity_history = load_terminal_identity_history(args, [], tz, start, end, wecom_people_map)
    enrich_events(
        events,
        getattr(args, "people_map_loaded", {}) or {},
        wecom_people_map,
        {},
        {},
        recipient_map=getattr(args, "recipient_map_loaded", {}) or {},
        terminal_identity_history=terminal_identity_history,
        terminal_identity_max_age_days=getattr(args, "terminal_identity_max_age_days", 30),
    )
    apply_terminal_majority_identity(events, terminal_identity_history)
    return events


def raw_file_audit_map_from_clickhouse(
    args: argparse.Namespace,
    start: datetime | None,
    end: datetime | None,
) -> dict[str, dict[str, Any]]:
    raw_where = clickhouse_time_filter(start, end)
    event_where = clickhouse_event_filter(start, end)
    raw_map_query = (
        "SELECT raw_hash, raw_json "
        f"FROM raw_syslog WHERE {raw_where} AND topic = 'file_audit' "
        "AND raw_hash IN ("
        f"SELECT raw_hash FROM audit_events WHERE {event_where} AND topic = 'file_audit'"
        ") FORMAT JSONEachRow"
    )
    raw_map_text = clickhouse_query(args, raw_map_query)
    raw_file_audit_map: dict[str, dict[str, Any]] = {}
    for line in raw_map_text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        raw_hash = str(row.get("raw_hash") or "")
        raw_json = str(row.get("raw_json") or "")
        if not raw_hash or not raw_json:
            continue
        try:
            raw_file_audit_map[raw_hash] = json.loads(raw_json)
        except json.JSONDecodeError:
            continue
    return raw_file_audit_map


def records_and_events_from_clickhouse(
    args: argparse.Namespace,
    start: datetime | None,
    end: datetime | None,
    tz: timezone,
) -> tuple[list[RawRecord], list[AuditEvent]]:
    raw_where = clickhouse_time_filter(start, end)
    event_where = clickhouse_event_filter(start, end)
    debug_timing("clickhouse raw count query")
    raw_count_text = clickhouse_query(args, f"SELECT count() FROM raw_syslog WHERE {raw_where} FORMAT TabSeparated").strip()
    try:
        args.raw_record_count_override = int(raw_count_text)
    except ValueError:
        args.raw_record_count_override = 0
    topic_counts = Counter()
    debug_timing("clickhouse topic count query")
    topic_text = clickhouse_query(args, f"SELECT topic, count() AS count FROM raw_syslog WHERE {raw_where} GROUP BY topic FORMAT JSONEachRow")
    for line in topic_text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        topic_counts[str(row.get("topic") or "unknown")] = int(row.get("count") or 0)
    args.topic_counts_override = topic_counts
    query = f"SELECT {CLICKHOUSE_AUDIT_EVENT_SELECT} FROM audit_events WHERE {event_where} FORMAT JSONEachRow"
    debug_timing("clickhouse event query")
    event_text = clickhouse_query(args, query)
    debug_timing("clickhouse raw file_audit query")
    raw_file_audit_map = raw_file_audit_map_from_clickhouse(args, start, end)
    args.file_audit_raw_map = raw_file_audit_map
    debug_timing("clickhouse event parse start")
    events: list[AuditEvent] = []
    for line in event_text.splitlines():
        if not line.strip():
            continue
        events.append(audit_event_from_clickhouse_row(json.loads(line), tz))
    debug_timing(f"clickhouse event parse complete events={len(events)}")
    args.source_label_override = f"ClickHouse:{getattr(args, 'clickhouse_database', 'tianqing')}.audit_events"
    return [], events


def parse_clickhouse_date(value: Any) -> date | None:
    text = str(value or "").strip()
    if not text or text.startswith("1970-01-01"):
        return None
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        try:
            return datetime.strptime(text, "%Y-%m-%d").date()
        except ValueError:
            return None


def int_or_none(value: Any) -> int | None:
    try:
        number = int(float(str(value).strip()))
    except Exception:
        return None
    return number if number >= 0 else None


def bool_from_any(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value if value is not None else "").strip().lower() in {"1", "true", "yes", "y", "on", "是"}


def version_tuple(value: str) -> tuple[int, ...]:
    numbers = [int(part) for part in re.findall(r"\d+", value or "")]
    return tuple(numbers) if numbers else (0,)


def latest_version(counter: Counter) -> str:
    versions = [str(value) for value, count in counter.items() if value and value != "未知" and count > 0]
    return max(versions, key=version_tuple) if versions else ""


def asset_os_label(asset: AssetSnapshot) -> str:
    parts = [asset.os_main, asset.os_release_id]
    label = " ".join(part for part in parts if part).strip()
    return label or "未知系统"


def asset_age_bucket(asset: AssetSnapshot, as_of: datetime) -> str:
    if not asset.manufacture_date:
        return "未知"
    days = (as_of.date() - asset.manufacture_date).days
    if days < 0:
        return "1年内"
    years = days / 365.25
    if years < 1:
        return "1年内"
    if years < 3:
        return "1-3年"
    if years < 5:
        return "3-5年"
    return "5年以上"


def asset_age_label(asset: AssetSnapshot, as_of: datetime | None = None) -> str:
    reference = as_of or datetime.now(timezone.utc)
    if not asset.manufacture_date:
        return "未知"
    return f"{asset_age_bucket(asset, reference)}（{asset.manufacture_date.isoformat()}）"


def offline_days(asset: AssetSnapshot, as_of: datetime) -> int | None:
    if asset.is_online or not asset.last_online_time:
        return None
    reference = as_of if as_of.tzinfo else as_of.replace(tzinfo=timezone.utc)
    last_seen = asset.last_online_time
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=reference.tzinfo)
    delta = reference.astimezone(last_seen.tzinfo) - last_seen
    return max(0, delta.days)


def asset_online_bucket(asset: AssetSnapshot, as_of: datetime) -> str:
    if asset.is_online:
        return "在线"
    days = offline_days(asset, as_of)
    if days is None:
        return "离线-未知时长"
    if days < 1:
        return "离线1天内"
    if days < 3:
        return "离线1-3天"
    if days < 7:
        return "离线3-7天"
    if days < 30:
        return "离线7-30天"
    return "离线30天以上"


def asset_online_label(asset: AssetSnapshot, as_of: datetime) -> str:
    if asset.is_online:
        return "在线"
    bucket = asset_online_bucket(asset, as_of)
    days = offline_days(asset, as_of)
    if days is None:
        return bucket
    return f"{bucket}（最后在线 {asset.last_online_time.strftime('%Y-%m-%d %H:%M:%S')}）"


def is_old_os(asset: AssetSnapshot) -> bool:
    label = asset_os_label(asset).lower()
    if any(token in label for token in ["windows xp", "windows 7", "windows 8", "server"]):
        return True
    if "windows 10" in label:
        old_release_ids = {"1507", "1511", "1607", "1703", "1709", "1803", "1809", "1903", "1909", "2004", "20h2", "21h1"}
        return asset.os_release_id.lower() in old_release_ids
    return False


def asset_terminal_keys(asset: AssetSnapshot) -> list[tuple[str, str]]:
    keys = []
    if asset.client_name or asset.client_ip:
        keys.append((normalize_key(asset.client_name), normalize_key(asset.client_ip)))
    if asset.client_name:
        keys.append((normalize_key(asset.client_name), ""))
    if asset.client_ip:
        keys.append(("", normalize_key(asset.client_ip)))
    return keys


def meaningful_asset_value(value: str) -> bool:
    text = normalize_key(value)
    return bool(text) and text not in {"unknown", "none", "null", "to be filled by o.e.m.", "system serial number", "default string"}


def asset_reinstall_keys(asset: AssetSnapshot) -> list[str]:
    keys = []
    if meaningful_asset_value(asset.board_serial_number):
        keys.append("serial:" + normalize_key(asset.board_serial_number))
    if meaningful_asset_value(asset.client_mac):
        keys.append("mac:" + normalize_key(asset.client_mac))
    if meaningful_asset_value(asset.client_mid):
        keys.append("mid:" + normalize_key(asset.client_mid))
    if not keys and meaningful_asset_value(asset.client_name):
        keys.append("name:" + normalize_key(asset.client_name))
    return keys


def has_reinstall_replacement(asset: AssetSnapshot, assets_by_key: dict[str, list[AssetSnapshot]]) -> bool:
    if not asset.observed_at:
        return False
    for key in asset_reinstall_keys(asset):
        for other in assets_by_key.get(key, []):
            if other.client_id == asset.client_id or not other.observed_at:
                continue
            if other.observed_at > asset.observed_at:
                return True
    return False


def asset_for_event(event: AuditEvent, asset_by_terminal: dict[tuple[str, str], AssetSnapshot]) -> AssetSnapshot | None:
    keys = [
        (normalize_key(event.client_name), normalize_key(event.client_ip)),
        (normalize_key(event.client_name), ""),
        ("", normalize_key(event.client_ip)),
    ]
    for key in keys:
        asset = asset_by_terminal.get(key)
        if asset:
            return asset
    return None


def asset_version_brief(asset: AssetSnapshot | None) -> str:
    if not asset:
        return "-"
    virus = asset.virus_version or "未知病毒库"
    patch = asset.patch_version or "未知补丁"
    return f"{virus} / {patch}"


def parse_asset_row(row: dict[str, Any], tz: timezone) -> AssetSnapshot:
    return AssetSnapshot(
        client_id=str(row.get("client_id") or ""),
        client_name=str(row.get("client_name") or ""),
        client_ip=str(row.get("client_ip") or ""),
        client_mac=str(row.get("client_mac") or ""),
        client_mid=str(row.get("client_mid") or ""),
        login_account=str(row.get("login_account") or ""),
        company=str(row.get("company") or ""),
        department=str(row.get("department") or ""),
        board_serial_number=str(row.get("board_serial_number") or ""),
        brand_model=str(row.get("brand_model") or ""),
        board_bios=str(row.get("board_bios") or ""),
        manufacture_date=parse_clickhouse_date(row.get("manufacture_date")),
        os_main=str(row.get("os_main") or ""),
        os_release_id=str(row.get("os_release_id") or ""),
        os_build_version=str(row.get("os_build_version") or ""),
        os_describe=str(row.get("os_describe") or ""),
        memory_mb=int_or_none(row.get("memory_mb")),
        core_number=int_or_none(row.get("core_number")),
        sys_space_mb=int_or_none(row.get("sys_space_mb")),
        main_program_version=str(row.get("main_program_version") or ""),
        patch_version=str(row.get("patch_version") or ""),
        virus_version=str(row.get("virus_version") or ""),
        activation=bool_from_any(row.get("activation")),
        is_online=bool_from_any(row.get("is_online")),
        observed_at=parse_clickhouse_ts(row.get("observed_at") or row.get("last_observed_at"), tz),
        last_online_time=parse_clickhouse_ts(row.get("last_online_time"), tz),
        client_create_time=parse_clickhouse_ts(row.get("client_create_time"), tz),
    )


def fetch_asset_recent_risk_counts(
    args: argparse.Namespace,
    as_of: datetime,
    internal_domains: set[str],
) -> dict[tuple[str, str], int]:
    start = as_of - timedelta(days=30)
    event_where = clickhouse_time_filter(start, as_of)
    risk_filter = (
        f"{event_where} AND ("
        "level = 'HIGH' "
        f"OR hasAny(file_exts, {clickhouse_array_literal(sorted(DESIGN_EXTS))}) "
        "OR has(reasons, '个人邮箱域名') "
        "OR has(reasons, '网盘/高风险外联目标') "
        "OR has(reasons, '外设拷贝') "
        "OR has(reasons, '外部上传/下载地址') "
        "OR has(reasons, '外部收件域名')"
        ")"
    )
    query = (
        "SELECT client_name, client_ip, count() AS count "
        f"FROM audit_events WHERE {risk_filter} "
        "GROUP BY client_name, client_ip FORMAT JSONEachRow"
    )
    counts: dict[tuple[str, str], int] = {}
    for line in clickhouse_query(args, query).splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        count = int(row.get("count") or 0)
        name = normalize_key(row.get("client_name"))
        ip = normalize_key(row.get("client_ip"))
        for key in [(name, ip), (name, ""), ("", ip)]:
            if key != ("", ""):
                counts[key] = counts.get(key, 0) + count
    return counts


def fetch_asset_analysis(
    args: argparse.Namespace,
    tz: timezone,
    start: datetime | None,
    end: datetime | None,
    internal_domains: set[str],
) -> AssetAnalysis:
    if not getattr(args, "use_clickhouse", False):
        return AssetAnalysis(error="未启用 ClickHouse，资产分析仅在索引模式下生成。")
    as_of = end or datetime.now(tz)
    where = f"observed_at < parseDateTime64BestEffort({clickhouse_literal(as_of.isoformat())}, 3)"
    inner_query = (
        "SELECT "
        "client_id, "
        "argMax(client_name, observed_at) AS client_name, "
        "argMax(client_ip, observed_at) AS client_ip, "
        "argMax(client_mac, observed_at) AS client_mac, "
        "argMax(client_mid, observed_at) AS client_mid, "
        "argMax(login_account, observed_at) AS login_account, "
        "argMax(company, observed_at) AS company, "
        "argMax(department, observed_at) AS department, "
        "argMax(board_serial_number, observed_at) AS board_serial_number, "
        "argMax(brand_model, observed_at) AS brand_model, "
        "argMax(board_bios, observed_at) AS board_bios, "
        "argMax(manufacture_date, observed_at) AS manufacture_date, "
        "argMax(os_main, observed_at) AS os_main, "
        "argMax(os_release_id, observed_at) AS os_release_id, "
        "argMax(os_build_version, observed_at) AS os_build_version, "
        "argMax(os_describe, observed_at) AS os_describe, "
        "argMax(memory_mb, observed_at) AS memory_mb, "
        "argMax(core_number, observed_at) AS core_number, "
        "argMax(sys_space_mb, observed_at) AS sys_space_mb, "
        "argMax(main_program_version, observed_at) AS main_program_version, "
        "argMax(patch_version, observed_at) AS patch_version, "
        "argMax(virus_version, observed_at) AS virus_version, "
        "argMax(activation, observed_at) AS activation, "
        "argMax(is_online, observed_at) AS is_online, "
        "max(observed_at) AS last_observed_at, "
        "argMax(last_online_time, observed_at) AS last_online_time, "
        "argMax(client_create_time, observed_at) AS client_create_time "
        f"FROM asset_observations WHERE {where} AND client_id != '' "
        "GROUP BY client_id"
    )
    query = inner_query + " FORMAT JSONEachRow"
    analysis = AssetAnalysis(available=True)
    try:
        text = clickhouse_query(args, query)
        risk_counts = fetch_asset_recent_risk_counts(args, as_of, internal_domains)
    except Exception as exc:
        return AssetAnalysis(error=f"资产分析表暂不可用：{type(exc).__name__}: {str(exc)[:180]}")

    assets: list[AssetSnapshot] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        asset = parse_asset_row(json.loads(line), tz)
        if not asset.client_id:
            continue
        asset.recent_risk_events = max([risk_counts.get(key, 0) for key in asset_terminal_keys(asset)] or [0])
        assets.append(asset)

    as_of_local = as_of.astimezone(tz) if as_of.tzinfo else as_of.replace(tzinfo=tz)
    missing_cutoff = as_of_local - timedelta(days=7)
    uninstall_cutoff = as_of_local - timedelta(days=30)
    assets_by_reinstall_key: dict[str, list[AssetSnapshot]] = defaultdict(list)
    for asset in assets:
        for key in asset_reinstall_keys(asset):
            assets_by_reinstall_key[key].append(asset)
    analysis.total_assets = len(assets)
    analysis.parsed_manufacture_dates = sum(1 for asset in assets if asset.manufacture_date)
    analysis.observed_in_period = sum(
        1
        for asset in assets
        if asset.observed_at and ((not start) or asset.observed_at >= start) and asset.observed_at < as_of
    )

    for asset in assets:
        age = asset_age_bucket(asset, as_of_local)
        os_label = asset_os_label(asset)
        analysis.age_counts[age] += 1
        analysis.os_counts[os_label] += 1
        analysis.virus_counts[asset.virus_version or "未知"] += 1
        analysis.patch_counts[asset.patch_version or "未知"] += 1
        analysis.main_version_counts[asset.main_program_version or "未知"] += 1
        online_bucket = asset_online_bucket(asset, as_of_local)
        analysis.online_counts[online_bucket] += 1
        if age == "5年以上":
            analysis.old_device_assets.append(asset)
        if age == "未知":
            analysis.unknown_manufacture_assets.append(asset)
        if is_old_os(asset):
            analysis.old_os_assets.append(asset)
        if not asset.is_online:
            analysis.offline_assets.append(asset)
            days = offline_days(asset, as_of_local)
            if days is None or days >= 7:
                analysis.long_offline_assets.append(asset)
        if asset.observed_at and asset.observed_at < missing_cutoff:
            analysis.missing_assets.append(asset)
            if asset.recent_risk_events > 0:
                analysis.high_attention_missing_assets.append(asset)
        if asset.observed_at and asset.observed_at < uninstall_cutoff:
            if has_reinstall_replacement(asset, assets_by_reinstall_key):
                analysis.reinstall_excluded_assets.append(asset)
            else:
                analysis.suspected_uninstalled_assets.append(asset)
        for key in asset_terminal_keys(asset):
            analysis.asset_by_terminal.setdefault(key, asset)

    analysis.latest_virus_version = latest_version(analysis.virus_counts)
    analysis.latest_patch_version = latest_version(analysis.patch_counts)
    analysis.latest_main_version = latest_version(analysis.main_version_counts)
    for asset in assets:
        lagging = False
        if analysis.latest_virus_version and asset.virus_version and version_tuple(asset.virus_version) < version_tuple(analysis.latest_virus_version):
            lagging = True
        if analysis.latest_patch_version and asset.patch_version and version_tuple(asset.patch_version) < version_tuple(analysis.latest_patch_version):
            lagging = True
        if analysis.latest_main_version and asset.main_program_version and version_tuple(asset.main_program_version) < version_tuple(analysis.latest_main_version):
            lagging = True
        if lagging or not (asset.virus_version and asset.patch_version and asset.main_program_version):
            analysis.lagging_version_assets.append(asset)

    analysis.risk_counts["5年以上设备"] = len(analysis.old_device_assets)
    analysis.risk_counts["老旧系统"] = len(analysis.old_os_assets)
    analysis.risk_counts["版本落后/未知"] = len(analysis.lagging_version_assets)
    analysis.risk_counts["当前离线终端"] = len(analysis.offline_assets)
    analysis.risk_counts["天擎离线超7天"] = len(analysis.long_offline_assets)
    analysis.risk_counts["7天未观察到"] = len(analysis.missing_assets)
    analysis.risk_counts["疑似已卸载"] = len(analysis.suspected_uninstalled_assets)
    analysis.risk_counts["卸载重装排除"] = len(analysis.reinstall_excluded_assets)
    analysis.risk_counts["消失前有风险行为"] = len(analysis.high_attention_missing_assets)
    return analysis


def report_raw_record_count(args: argparse.Namespace, records: list[RawRecord]) -> int:
    override = getattr(args, "raw_record_count_override", None)
    if override is None:
        return len(records)
    try:
        return int(override)
    except (TypeError, ValueError):
        return len(records)


def report_topic_counts(args: argparse.Namespace, records: list[RawRecord]) -> Counter:
    override = getattr(args, "topic_counts_override", None)
    if override is not None:
        return Counter(override)
    return Counter(str(record.obj.get("syslog_topic") or "unknown") for record in records)


def report_source_label(args: argparse.Namespace) -> str:
    override = str(getattr(args, "source_label_override", "") or "").strip()
    if override:
        return override
    return args.local_log or args.ssh_host + ":" + args.remote_log


def get_tz(name: str) -> timezone:
    if ZoneInfo:
        return ZoneInfo(name)
    return timezone(timedelta(hours=8))


def period_bounds(period: str, tz: timezone, now: datetime | None = None) -> tuple[datetime | None, datetime | None]:
    now = now or datetime.now(tz)
    today = now.date()
    if period == "all":
        return None, None
    if period == "today":
        return datetime.combine(today, time.min, tz), now
    if period == "previous-day":
        start = today - timedelta(days=1)
        return datetime.combine(start, time.min, tz), datetime.combine(today, time.min, tz)
    if period == "current-week":
        start = today - timedelta(days=today.weekday())
        return datetime.combine(start, time.min, tz), now
    if period == "previous-week":
        this_start = today - timedelta(days=today.weekday())
        start = this_start - timedelta(days=7)
        return datetime.combine(start, time.min, tz), datetime.combine(this_start, time.min, tz)
    if period == "current-month":
        return datetime(now.year, now.month, 1, tzinfo=tz), now
    if period == "previous-month":
        first = datetime(now.year, now.month, 1, tzinfo=tz)
        last_prev = first - timedelta(days=1)
        start = datetime(last_prev.year, last_prev.month, 1, tzinfo=tz)
        return start, first
    raise ValueError(f"unsupported period: {period}")


def parse_custom_datetime(value: str, tz: timezone, end_boundary: bool = False) -> datetime:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("empty datetime")
    date_only = bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw))
    normalized = raw.replace("T", " ")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid datetime: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz)
    else:
        parsed = parsed.astimezone(tz)
    if date_only and end_boundary:
        parsed = parsed + timedelta(days=1)
    return parsed


def in_period(ts: datetime | None, start: datetime | None, end: datetime | None, tz: timezone) -> bool:
    if ts is None:
        return start is None and end is None
    local = ts.astimezone(tz)
    if start and local < start:
        return False
    if end and local >= end:
        return False
    return True


def split_multi(value: Any) -> list[str]:
    if value in (None, "", [], {}, "[]"):
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in re.split(r"[;；,，\n]+", str(value)) if item.strip()]


def email_domain(value: str) -> str:
    match = re.search(r"@([A-Za-z0-9._-]+)", value)
    return match.group(1).lower() if match else ""


def normalize_mailbox(value: Any) -> str:
    for item in split_multi(value):
        match = re.search(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", item)
        if match:
            return match.group(0).lower()
    return ""


def host_domain(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return ""
    value = re.sub(r"^https?://", "", value)
    value = value.split("/", 1)[0].split(":", 1)[0]
    value = value.strip("*. ")
    return value


def internal_networks() -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for value in INTERNAL_NETWORKS:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return networks


def domain_is_internal(domain: str, internal_domains: set[str]) -> bool:
    domain = domain.lower().strip(".")
    try:
        ip = ipaddress.ip_address(domain)
        if ip.is_private or ip.is_loopback or ip.is_link_local or any(ip in network for network in internal_networks()):
            return True
    except ValueError:
        pass
    return any(domain == internal or domain.endswith("." + internal) for internal in internal_domains)


def target_is_internal_network(value: str, internal_domains: set[str]) -> bool:
    domain = host_domain(str(value or ""))
    return bool(domain and domain_is_internal(domain, internal_domains))


def extension(name: str) -> str:
    clean = name.strip().lower().split("?", 1)[0]
    if "." not in clean:
        return ""
    parts = [part.strip() for part in clean.split(".") if part.strip()]
    if not parts:
        return ""
    ext = parts[-1]
    if ext.isdigit() and len(parts) >= 2 and parts[-2] in DESIGN_EXTS:
        ext = parts[-2]
    if not re.fullmatch(r"[a-z0-9_]{1,16}", ext):
        return ""
    return ext


def critical_design_basename(name: Any) -> str:
    return path_basename(str(name or "").split("?", 1)[0]).strip()


def normalize_critical_design_patterns(value: Any) -> list[dict[str, Any]]:
    rows = value if isinstance(value, list) else []
    if not rows:
        rows = DEFAULT_CRITICAL_DESIGN_PATTERNS
    patterns: list[dict[str, Any]] = []
    default_by_key = {str(item["key"]): item for item in DEFAULT_CRITICAL_DESIGN_PATTERNS}
    for item in rows:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        default = default_by_key.get(key, {})
        label = str(item.get("label") or default.get("label") or "").strip()
        if key.lower().startswith("yb_standard"):
            continue
        regex = str(item.get("regex") or default.get("regex") or "").strip()
        if not label or not regex:
            continue
        if not is_enabled_value(item.get("enabled"), default=True):
            continue
        try:
            compiled = re.compile(regex, re.IGNORECASE)
        except re.error:
            continue
        patterns.append(
            {
                "key": key,
                "label": label,
                "regex": regex,
                "description": str(item.get("description") or default.get("description") or "").strip(),
                "compiled": compiled,
            }
        )
    return patterns


def configure_critical_design_patterns(patterns: Any) -> None:
    global CRITICAL_DESIGN_PATTERNS, CRITICAL_DESIGN_LABELS, DESIGN_CATEGORY_DISPLAY_ORDER
    normalized = normalize_critical_design_patterns(patterns)
    CRITICAL_DESIGN_PATTERNS = normalized
    labels = []
    for pattern in normalized:
        label = str(pattern.get("label") or "").strip()
        if label and label not in labels:
            labels.append(label)
    CRITICAL_DESIGN_LABELS = labels
    DESIGN_CATEGORY_DISPLAY_ORDER = CRITICAL_DESIGN_LABELS + ["三维模型", "DWG二维图纸", "设计资料"]


def critical_design_labels_for_name(name: Any) -> list[str]:
    base_name = critical_design_basename(name)
    if not base_name:
        return []
    labels: list[str] = []
    for pattern in CRITICAL_DESIGN_PATTERNS:
        compiled = pattern.get("compiled")
        if not compiled:
            try:
                compiled = re.compile(str(pattern.get("regex") or ""), re.IGNORECASE)
            except re.error:
                continue
        if compiled.fullmatch(base_name):
            label = str(pattern.get("label") or "").strip()
            if label and label not in labels:
                labels.append(label)
    return labels


def critical_design_labels_for_names(names: Iterable[Any]) -> list[str]:
    labels: list[str] = []
    for name in names:
        for label in critical_design_labels_for_name(name):
            if label not in labels:
                labels.append(label)
    return labels


def critical_design_labels_for_event(event: "AuditEvent") -> list[str]:
    return critical_design_labels_for_names(event.file_names)


def is_critical_design_event(event: "AuditEvent") -> bool:
    return bool(critical_design_labels_for_event(event))


def design_category_for_ext(ext: str) -> str:
    if ext in CONTROLLED_3D_EXTS:
        return "三维模型"
    if ext in CONTROLLED_2D_CAD_EXTS:
        return "DWG二维图纸"
    if ext in PCB_ECAD_EXTS:
        return "PCB/电气设计"
    if ext in DESIGN_EXTS:
        return "设计资料"
    return ""


def design_categories_for_event(event: AuditEvent) -> set[str]:
    categories = set(critical_design_labels_for_event(event))
    categories.update(category for ext in event.file_exts for category in [design_category_for_ext(ext)] if category)
    return categories


def ordered_design_categories(event: AuditEvent) -> list[str]:
    categories = design_categories_for_event(event)
    return [category for category in DESIGN_CATEGORY_DISPLAY_ORDER if category in categories]


def design_category_label(event: AuditEvent) -> str:
    categories = ordered_design_categories(event)
    return ";".join(categories) if categories else "-"


def is_design_event(event: AuditEvent) -> bool:
    return bool(set(event.file_exts) & DESIGN_EXTS)


def is_three_d_model_event(event: AuditEvent) -> bool:
    return bool(set(event.file_exts) & CONTROLLED_3D_EXTS)


def is_two_d_cad_event(event: AuditEvent) -> bool:
    return bool(set(event.file_exts) & CONTROLLED_2D_CAD_EXTS)


def is_pcb_ecad_event(event: AuditEvent) -> bool:
    return bool(set(event.file_exts) & PCB_ECAD_EXTS)


def add_unique_reason(reasons: list[str], reason: str) -> None:
    if reason and reason not in reasons:
        reasons.append(reason)


def prioritized_reasons(reasons: Iterable[str]) -> list[str]:
    unique = list(
        dict.fromkeys(
            str(reason)
            for reason in reasons
            if str(reason).strip() and str(reason).strip() not in HIDDEN_LEADERSHIP_REASONS
        )
    )
    priority = {reason: idx for idx, reason in enumerate(REASON_DISPLAY_PRIORITY)}
    return sorted(unique, key=lambda reason: (priority.get(reason, len(priority)), unique.index(reason)))


def reason_cell(event: AuditEvent, limit: int = 5) -> HtmlCell:
    reasons = prioritized_reasons(event.reasons)
    return tooltip_cell(";".join(reasons[:limit]), ";".join(reasons))


def apply_design_control_policy(event: AuditEvent) -> None:
    design_policy_reasons = {"二维/三维设计图纸", "设计图纸后缀", "三维模型", "二维/CAD图纸", "DWG二维图纸", "PCB/电气设计"}
    event.reasons = [
        reason
        for reason in event.reasons
        if reason not in design_policy_reasons and not str(reason).startswith(CRITICAL_DESIGN_REASON_PREFIX)
    ]
    if not is_design_event(event):
        return
    add_unique_reason(event.reasons, "设计图纸后缀")
    for label in critical_design_labels_for_event(event):
        add_unique_reason(event.reasons, CRITICAL_DESIGN_REASON_PREFIX + label)
        event.score = max(int(event.score or 0), 98)
        event.level = "HIGH"
    if is_three_d_model_event(event):
        add_unique_reason(event.reasons, "三维模型")
        event.score = max(int(event.score or 0), 85)
        event.level = "HIGH"
    if is_two_d_cad_event(event):
        add_unique_reason(event.reasons, "DWG二维图纸")
        event.score = max(int(event.score or 0), 60)
        if event.level == "LOW":
            event.level = "MEDIUM"
    if is_pcb_ecad_event(event):
        add_unique_reason(event.reasons, "PCB/电气设计")
        event.score = max(int(event.score or 0), 60)
        if event.level == "LOW":
            event.level = "MEDIUM"


def apply_sensitive_keyword_policy(event: AuditEvent) -> None:
    event.reasons = [
        reason
        for reason in event.reasons
        if not any(str(reason).startswith(prefix) for prefix in SENSITIVE_REASON_PREFIXES)
    ]
    keyword_hits = event_leadership_keyword_hits(event)
    if keyword_hits:
        add_unique_reason(event.reasons, "敏感关键词:" + ",".join(keyword_hits[:4]))


def apply_mail_sender_policy(event: AuditEvent, internal_domains: set[str] | None = None) -> None:
    event.reasons = [reason for reason in event.reasons if reason != "外部发件箱"]
    if not is_external_sender_mailbox(event, internal_domains):
        return
    add_unique_reason(event.reasons, "外部发件箱")
    event.score = max(int(event.score or 0), 75)
    event.level = "HIGH"


def priority_label(priority: str) -> str:
    return PRIORITY_LABELS.get(priority, PRIORITY_LABELS[PRIORITY_WATCH])


def priority_sort_rank(priority: str) -> int:
    try:
        return PRIORITY_ORDER.index(priority)
    except ValueError:
        return len(PRIORITY_ORDER)


def priority_badge(priority: str) -> str:
    label = priority_label(priority)
    return f'<span class="risk risk-{esc(priority)}">{esc(label)}</span>'


def event_priority_counts(events: Iterable[AuditEvent]) -> Counter:
    counter = Counter()
    for event in events:
        counter[event.priority or PRIORITY_WATCH] += 1
    return counter


def event_priority_sort_key(event: AuditEvent) -> tuple[int, int, datetime]:
    return (
        priority_sort_rank(event.priority),
        -int(event.priority_score or event.score or 0),
        event.ts or datetime.min.replace(tzinfo=timezone.utc),
    )


def event_material_score(event: AuditEvent) -> int:
    if is_critical_design_event(event):
        return 70
    if is_three_d_model_event(event):
        return 40
    if is_two_d_cad_event(event):
        return 32
    if event_leadership_keyword_hits(event):
        return 24
    if set(event.file_exts) & (SOURCE_EXTS | DATABASE_EXTS):
        return 20
    if set(event.file_exts) & ARCHIVE_EXTS:
        return 8
    if set(event.file_exts) & OFFICE_EXTS:
        return 5
    return 0


def event_channel_exposure_score(event: AuditEvent, internal_domains: set[str] | None = None) -> int:
    internal_domains = internal_domains or DEFAULT_INTERNAL_DOMAINS
    unknown_im = event.topic == "im_audit" and event.recipient_relation == "unknown"
    if is_external_sender_mailbox(event, internal_domains):
        return 30
    if is_cloud_destination_event(event):
        return 28
    if is_external_site_upload_event(event, set(internal_domains)):
        return 25
    if is_peripheral_copy_event(event):
        return 24
    if unknown_im:
        return 22
    if is_confirmed_external_event(event):
        return 20
    if event.topic == "im_audit":
        return 18
    if event.topic == "mail_audit":
        return 16
    if event.topic == "file_audit":
        return 12
    return 0


def event_behavior_score(event: AuditEvent) -> int:
    score = 0
    domains = event_domain_values(event)
    if any(domain in PERSONAL_EMAIL_DOMAINS for domain in domains):
        score += 6
    if has_high_risk_destination(domains) or "网盘/高风险外联目标" in event.reasons:
        score += 8
    if event.recipient_relation == "unknown":
        score += 4
    if len(event_target_values(event)) >= 3:
        score += 5
    if set(event.file_exts) & ARCHIVE_EXTS:
        score += 5
    if is_large_archive_event(event):
        score += 15
    if event.file_size and event.file_size >= 50 * 1024 * 1024:
        score += 8
    elif event.file_size and event.file_size >= 10 * 1024 * 1024:
        score += 5
    return min(score, 20)


def event_evidence_score(event: AuditEvent) -> int:
    score = 0
    if event.file_names:
        score += 2
    if event_target_values(event):
        score += 2
    if event.mail_subject:
        score += 1
    if event.file_size not in (None, 0):
        score += 2
    if event.lookup_keys:
        score += 2
    if event.sender_mailbox:
        score += 1
    return min(score, 10)


def assign_event_priority(event: AuditEvent, internal_domains: set[str] | None = None) -> None:
    internal_domains = internal_domains or DEFAULT_INTERNAL_DOMAINS
    material = event_material_score(event)
    exposure = event_channel_exposure_score(event, internal_domains)
    behavior = event_behavior_score(event)
    evidence = event_evidence_score(event)
    score = material + exposure + behavior + evidence
    unknown_im = event.topic == "im_audit" and event.recipient_relation == "unknown"
    cloud_or_site = is_cloud_destination_event(event) or is_external_site_upload_event(event, set(internal_domains))
    high_risk_channel = (
        is_external_sender_mailbox(event, internal_domains)
        or cloud_or_site
        or is_peripheral_copy_event(event)
        or unknown_im
        or "网盘/高风险外联目标" in event.reasons
    )
    has_sensitive_name = bool(event_leadership_keyword_hits(event))

    if is_critical_design_event(event):
        score = max(score, 95)
        priority = PRIORITY_ACTION
    elif is_large_archive_event(event):
        score = max(score, 88)
        priority = PRIORITY_ACTION
    elif is_three_d_model_event(event):
        priority = PRIORITY_ACTION
    elif is_two_d_cad_event(event) and high_risk_channel:
        priority = PRIORITY_ACTION
    elif has_sensitive_name and high_risk_channel:
        priority = PRIORITY_ACTION
    elif score >= 75:
        priority = PRIORITY_ACTION
    elif is_two_d_cad_event(event) or has_sensitive_name or unknown_im or is_external_sender_mailbox(event, internal_domains):
        priority = PRIORITY_REVIEW
    elif score >= 45:
        priority = PRIORITY_REVIEW
    elif score >= 20:
        priority = PRIORITY_GENERAL
    else:
        priority = PRIORITY_WATCH

    event.priority = priority
    event.priority_score = score
    if priority == PRIORITY_ACTION:
        event.level = "HIGH"
    elif priority == PRIORITY_REVIEW:
        event.level = "MEDIUM"
    else:
        event.level = "LOW"


def apply_report_policies(
    events: list[AuditEvent],
    raw_file_audit_map: dict[str, dict[str, Any]] | None = None,
    internal_domains: set[str] | None = None,
) -> None:
    raw_file_audit_map = raw_file_audit_map or {}
    internal_domains = internal_domains or DEFAULT_INTERNAL_DOMAINS
    for event in events:
        if event.topic == "file_audit":
            raw_obj = raw_file_audit_map.get(event.raw_hash or "")
            if raw_obj:
                apply_file_audit_context(event, raw_obj, set(internal_domains))
        apply_mail_sender_policy(event, internal_domains)
        apply_design_control_policy(event)
        apply_sensitive_keyword_policy(event)
        normalize_untrusted_internal_im_relation(event)
    enrich_file_audit_im_recipients(events)
    for event in events:
        normalize_untrusted_internal_im_relation(event)
        assign_event_priority(event, internal_domains)


def normalize_untrusted_internal_im_relation(event: AuditEvent) -> None:
    if event.recipient_relation != "internal":
        return
    if event.topic == "im_audit" or is_im_file_audit_event(event):
        if "企业微信本人/文件助手" in event.reasons:
            return
        if is_wecom_process_name(event.process_name):
            return
        has_internal_network_target = any(
            target_is_internal_network(value, DEFAULT_INTERNAL_DOMAINS)
            for value in list(event.targets or []) + list(event.target_domains or []) + list(event.recipients or [])
        )
        if not has_internal_network_target:
            event.recipient_relation = "unknown"
            if "接收端IP未确认" not in event.reasons:
                event.reasons.append("接收端IP未确认")


def is_im_file_audit_event(event: AuditEvent) -> bool:
    return (
        event.topic == "file_audit"
        and event.channel == "应用发送/传输"
        and normalize_key(event.process_name) in IM_FILE_SEND_PROCESS_NAMES
    )


def enrich_file_audit_im_recipients(events: list[AuditEvent], seconds: int = 10) -> None:
    im_by_session: dict[tuple[str, str], list[AuditEvent]] = defaultdict(list)
    for event in events:
        if event.topic != "im_audit" or not event.ts or not event.search_id:
            continue
        if not (event.recipients or event.targets or event.target_domains):
            continue
        im_by_session[(event.client_ip, event.search_id)].append(event)
    for candidates in im_by_session.values():
        candidates.sort(key=lambda item: item.ts or datetime.min.replace(tzinfo=timezone.utc))

    for event in events:
        if not is_im_file_audit_event(event) or not event.ts or not event.search_id:
            continue
        has_only_im_token_recipients = bool(event.recipients) and all(
            looks_like_im_recipient_token(recipient) for recipient in event.recipients
        )
        if event.recipient_relation != "unknown" and event.recipients and not has_only_im_token_recipients:
            continue
        file_keys = report_event_file_keys(event)
        best: tuple[float, AuditEvent] | None = None
        for candidate in im_by_session.get((event.client_ip, event.search_id), []):
            if not candidate.ts:
                continue
            delta = abs((event.ts - candidate.ts).total_seconds())
            if delta > seconds:
                continue
            candidate_keys = report_event_file_keys(candidate)
            if file_keys and candidate_keys and not (file_keys & candidate_keys):
                continue
            if best is None or delta < best[0]:
                best = (delta, candidate)
        if not best:
            continue
        companion = best[1]
        event.recipients = list(companion.recipients)
        event.targets = list(companion.targets)
        event.target_domains = list(companion.target_domains)
        event.recipient_relation = companion.recipient_relation
        if "IM接收方由会话日志补全" not in event.reasons:
            event.reasons.append("IM接收方由会话日志补全")


def parse_size(value: Any) -> int | None:
    try:
        number = int(value)
    except Exception:
        return None
    return number if number >= 0 else None


def size_label(value: int | None) -> str:
    if value is None:
        return "unknown"
    if value <= 0:
        return "0/unknown"
    if value < 1024 * 1024:
        return "<1MB"
    if value < 10 * 1024 * 1024:
        return "1-10MB"
    if value < 50 * 1024 * 1024:
        return "10-50MB"
    return ">=50MB"


def compact_id(value: str, length: int = 24) -> str:
    if not value:
        return ""
    return value if len(value) <= length else value[:length] + "..."


def first_nonempty(obj: dict[str, Any], keys: list[str]) -> str:
    for key in keys:
        value = obj.get(key)
        if value not in (None, "", [], {}, "[]"):
            return str(value)
    return ""


def department(obj: dict[str, Any]) -> str:
    for key in ["path_level3", "group_node_name", "path_level2", "group_node_path"]:
        value = obj.get(key)
        if value not in (None, "", [], {}, "[]"):
            return str(value)
    return "unknown"


def organization_path(obj: dict[str, Any]) -> str:
    raw_path = obj.get("group_node_path")
    parts: list[str] = []
    if isinstance(raw_path, list):
        parts = [str(item).strip() for item in raw_path if str(item).strip()]
    elif isinstance(raw_path, str) and raw_path.strip():
        text = raw_path.strip()
        try:
            loaded = json.loads(text)
            if isinstance(loaded, list):
                parts = [str(item).strip() for item in loaded if str(item).strip()]
        except Exception:
            parts = [item.strip() for item in re.split(r"[/,，;；>]+", text.strip("[]\"'")) if item.strip()]
    if not parts:
        for key in ["path_level3", "path_level4", "path_level5", "group_node_name"]:
            value = str(obj.get(key) or "").strip()
            if value and value not in parts:
                parts.append(value)
    filtered = [
        part
        for part in parts
        if part
        and part not in {"全网终端", "办公终端"}
        and not part.startswith("pf_")
        and part != "unknown"
    ]
    cleaned: list[str] = []
    for part in filtered:
        part = re.sub(r"\(本级\)$", "", part).strip()
        if part and part not in cleaned:
            cleaned.append(part)
    return " / ".join(cleaned) if cleaned else department(obj)


def mail_subject_for(obj: dict[str, Any], topic: str) -> str:
    if topic != "mail_audit":
        return ""
    return first_nonempty(obj, ["mail_title", "subject", "mail_subject", "title"])


def mail_sender_mailbox_for(obj: dict[str, Any], topic: str) -> str:
    if topic != "mail_audit":
        return ""
    return normalize_mailbox(first_nonempty(obj, ["sender_urls", "sender", "from", "mail_from"]))


def mailbox_is_external(mailbox: str, internal_domains: set[str] | None = None) -> bool:
    domain = email_domain(mailbox)
    if not domain:
        return False
    return not domain_is_internal(domain, internal_domains or DEFAULT_INTERNAL_DOMAINS)


def is_external_sender_mailbox(event: AuditEvent, internal_domains: set[str] | None = None) -> bool:
    return event.topic == "mail_audit" and mailbox_is_external(event.sender_mailbox, internal_domains)


def mail_sender_type_label(event: AuditEvent, internal_domains: set[str] | None = None) -> str:
    if event.topic != "mail_audit":
        return "-"
    if not event.sender_mailbox:
        return "未取到发件箱"
    domain = email_domain(event.sender_mailbox)
    if not domain:
        return "未取到域名"
    if domain_is_internal(domain, internal_domains or DEFAULT_INTERNAL_DOMAINS):
        return "daqo.com发件箱"
    return "外部发件箱"


def sender_mailbox_cell(event: AuditEvent) -> HtmlCell:
    if event.topic != "mail_audit":
        return tooltip_cell("-", "-")
    value = event.sender_mailbox or "未取到"
    return tooltip_cell(value, value)


def sender_mailbox_type_cell(event: AuditEvent) -> HtmlCell:
    label = mail_sender_type_label(event)
    if event.topic != "mail_audit":
        return tooltip_cell("-", "-")
    detail = (
        "邮件发件箱后缀只有 daqo.com 按内部处理；其他邮箱作为外部发件箱重点关注。"
        if label == "外部发件箱"
        else "邮件发件箱后缀为 daqo.com，按内部邮箱处理。"
    )
    if "未取到" in label:
        detail = "当前邮件日志未取到 sender_urls 发件箱字段。"
    return tooltip_cell(label, detail)


def mail_signature_name_hints(obj: dict[str, Any]) -> list[str]:
    body = str(obj.get("message_body") or "")
    sender = mail_sender_mailbox_for(obj, "mail_audit")
    if not body:
        return []
    lines = [line.strip() for line in re.split(r"[\r\n]+", body) if line.strip()]
    if not lines:
        return []
    search_lines = lines[-16:]
    sender_domain = email_domain(sender)
    sender_idx = None
    for idx, line in enumerate(search_lines):
        lowered = line.lower()
        if (sender and sender.lower() in lowered) or "mail." in lowered or (sender_domain and sender_domain in lowered):
            sender_idx = idx
            break
    if sender_idx is not None:
        search_lines = search_lines[max(0, sender_idx - 8) : sender_idx]
    stopwords = {"您好", "谢谢", "报价", "采购部", "技术部", "销售部", "财务部", "质量部", "生产部", "客服部"}
    hints: list[str] = []
    for line in reversed(search_lines):
        cleaned = re.sub(r"[\s　:：,，;；.。()（）<>《》【】\\/_-]+", "", line)
        if not cleaned or cleaned in stopwords:
            continue
        if re.search(r"[A-Za-z0-9@]", cleaned):
            continue
        if any(word in cleaned for word in ["公司", "有限", "地址", "电话", "手机", "采购部", "技术部", "销售部", "财务部", "质量部", "生产部"]):
            continue
        if re.fullmatch(r"[\u4e00-\u9fff]{2,4}", cleaned):
            hints.append(cleaned)
    return list(dict.fromkeys(hints))


def identity_hints_for(obj: dict[str, Any], topic: str) -> list[str]:
    hints = split_multi(obj.get("user_real_name"))
    hints.extend(split_multi(obj.get("user_user_name")))
    hints.extend(split_multi(obj.get("user_name")))
    hints.extend(split_multi(obj.get("user_id")))
    hints.extend(split_multi(obj.get("user_email")))
    hints.extend(split_multi(obj.get("user_group_names")))
    hints.extend(split_multi(obj.get("login_user")))
    hints.extend(split_multi(obj.get("staff_name")))
    hints.extend(split_multi(obj.get("local_nickname")))
    hints.extend(split_multi(obj.get("client_login_account")))
    if topic == "mail_audit":
        hints.extend(mail_signature_name_hints(obj))
    return list(dict.fromkeys([hint for hint in hints if hint and hint != "unknown"]))


def person_for(obj: dict[str, Any], topic: str) -> tuple[str, str]:
    if topic == "mail_audit":
        sender = mail_sender_mailbox_for(obj, topic)
        account = first_nonempty(obj, ["client_login_account"])
        return sender or account or "unknown", account
    if topic == "im_audit":
        name = first_nonempty(obj, ["local_nickname", "client_login_account"])
        account = first_nonempty(obj, ["local_account", "client_login_account"])
        return name or account or "unknown", account
    name = first_nonempty(obj, ["staff_name", "client_login_account", "local_nickname"])
    account = first_nonempty(obj, ["client_login_account", "local_account"])
    return name or account or "unknown", account


def file_names_for(obj: dict[str, Any], topic: str) -> list[str]:
    names: list[str] = []
    if topic == "mail_audit":
        names.extend(split_multi(obj.get("enclosure_name")))
    if topic == "im_audit":
        for field_name in ["chat_message", "message_body"]:
            names.extend(extract_file_names_from_text(str(obj.get(field_name) or "")))
    if topic == "file_audit":
        names.extend(split_multi(obj.get("file_name")))
        for key in ["local_file_path", "remote_file_path"]:
            for path in split_multi(obj.get(key)):
                base = re.split(r"[\\/]", path)[-1]
                if base:
                    names.append(base)
    return list(dict.fromkeys(names))


def extract_file_names_from_text(text: str) -> list[str]:
    if not text:
        return []
    found: list[str] = []
    for match in FILENAME_RE.finditer(text):
        name = match.group(0).strip()
        name = re.sub(r"^[\s:：,，;；]+", "", name)
        # Keep the filename part when the regex captured a short lead-in phrase.
        for delimiter in ["：", ":", "，", ",", "；", ";", "\n", "\r", "\t"]:
            if delimiter in name:
                name = name.split(delimiter)[-1].strip()
        if name and extension(name):
            found.append(name)
    return list(dict.fromkeys(found))


def im_targets_for(obj: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    nicknames = split_multi(obj.get("remote_nickname"))
    accounts = split_multi(obj.get("remote_account"))
    for idx in range(max(len(nicknames), len(accounts))):
        nickname = nicknames[idx] if idx < len(nicknames) else ""
        account = accounts[idx] if idx < len(accounts) else ""
        if nickname and account and normalize_key(nickname) != normalize_key(account):
            targets.append(f"{nickname}<{account}>")
        elif nickname or account:
            targets.append(nickname or account)
    return list(dict.fromkeys(targets))


def targets_for(obj: dict[str, Any], topic: str) -> tuple[list[str], list[str]]:
    targets: list[str] = []
    domains: list[str] = []

    if topic == "mail_audit":
        targets.extend(split_multi(obj.get("addressee_urls")))
        for target in targets:
            domain = email_domain(target)
            if domain:
                domains.append(domain)
    elif topic == "im_audit":
        targets.extend(im_targets_for(obj))
    elif topic == "file_audit":
        process_name = normalize_key(first_nonempty(obj, ["process_name"]))
        if process_name in IM_FILE_SEND_PROCESS_NAMES:
            targets.extend(im_targets_for(obj))
        url_targets: list[str] = []
        for key in ["upload_url", "download_url"]:
            url_targets.extend(split_multi(obj.get(key)))
        targets.extend(url_targets)
        for target in url_targets:
            domain = host_domain(target)
            if domain:
                domains.append(domain)
    elif topic == "firewall":
        for key in ["dst_hostname", "dst_ip"]:
            targets.extend(split_multi(obj.get(key)))
        for target in targets:
            domain = host_domain(target)
            if domain and not re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
                domains.append(domain)

    return list(dict.fromkeys(targets)), list(dict.fromkeys(domains))


def lookup_keys_for(obj: dict[str, Any]) -> list[str]:
    keys = []
    for key in ["search_id", "download_file_key", "download_fileid", "file_id"]:
        value = obj.get(key)
        if value not in (None, "", [], {}, "[]"):
            keys.append(f"{key}={compact_id(str(value), 32)}")
    return keys


def stable_event_id(
    ts: datetime | None,
    topic: str,
    person: str,
    client_name: str,
    client_ip: str,
    targets: list[str],
    file_names: list[str],
    search_id: str,
) -> str:
    payload = {
        "ts": ts.isoformat() if ts else "",
        "topic": topic,
        "person": person,
        "client_name": client_name,
        "client_ip": client_ip,
        "targets": targets,
        "file_names": file_names,
        "search_id": search_id,
    }
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


def is_external(domains: Iterable[str], internal_domains: set[str]) -> bool:
    domain_list = [domain for domain in domains if domain]
    if not domain_list:
        return False
    return any(not domain_is_internal(domain, internal_domains) for domain in domain_list)


def has_high_risk_destination(domains: Iterable[str]) -> bool:
    for domain in domains:
        lowered = domain.lower()
        if any(hint in lowered for hint in HIGH_RISK_DEST_HINTS):
            return True
    return False


def is_enabled_value(value: Any, default: bool = True) -> bool:
    text = str(value if value is not None else "").strip().lower()
    if not text:
        return default
    return text in {"1", "true", "yes", "y", "on", "启用", "是"}


def normalized_scopes(value: Any) -> set[str]:
    raw = str(value if value is not None else "").strip().lower()
    if not raw:
        return {"both"}
    return {item.strip() for item in re.split(r"[;；,，/|]+", raw) if item.strip()}


def split_config_list(value: Any) -> list[str]:
    if value in (None, "", [], {}, "[]"):
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in re.split(r"[;；,，\n]+", str(value)) if item.strip()]


def normalize_ext_list(value: Any) -> set[str]:
    exts: set[str] = set()
    for item in split_config_list(value):
        ext = item.strip().lower().lstrip(".")
        if re.fullmatch(r"[a-z0-9_]{1,16}", ext):
            exts.add(ext)
    return exts


def normalize_internal_network_list(value: Any) -> set[str]:
    networks: set[str] = set()
    for item in split_config_list(value):
        raw = item.strip()
        if not raw:
            continue
        if re.fullmatch(r"\d{1,3}\.\d{1,3}", raw):
            raw = f"{raw}.0.0/16"
        elif re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}", raw):
            raw = f"{raw}.0/24"
        elif "/" not in raw and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", raw):
            raw = f"{raw}/32"
        try:
            networks.add(str(ipaddress.ip_network(raw, strict=False)))
        except ValueError:
            continue
    return networks


def normalize_internal_domain_list(value: Any) -> set[str]:
    domains: set[str] = set()
    for item in split_config_list(value):
        domain = host_domain(item)
        if not domain:
            continue
        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass
        domains.add(domain.strip(".").lower())
    return domains


def policy_internal_domains(policy: dict[str, Any]) -> set[str]:
    targets = policy.get("internal_targets") if isinstance(policy, dict) else {}
    if not isinstance(targets, dict):
        return set()
    return normalize_internal_domain_list(targets.get("domains"))


def policy_internal_networks(policy: dict[str, Any]) -> set[str]:
    targets = policy.get("internal_targets") if isinstance(policy, dict) else {}
    if not isinstance(targets, dict):
        return set()
    return normalize_internal_network_list(targets.get("networks"))


def refresh_extension_sets() -> None:
    global TECHNICAL_EXTS, SENSITIVE_EXTS, FILENAME_EXTS, FILENAME_RE, PROCUREMENT_NORMAL_EXTS
    TECHNICAL_EXTS = DESIGN_EXTS | DATABASE_EXTS
    SENSITIVE_EXTS = ARCHIVE_EXTS | TECHNICAL_EXTS | OFFICE_EXTS | SOURCE_EXTS
    FILENAME_EXTS = SENSITIVE_EXTS | LOW_VALUE_IMAGE_EXTS
    PROCUREMENT_NORMAL_EXTS = OFFICE_EXTS | ARCHIVE_EXTS | LOW_VALUE_IMAGE_EXTS | {"eml", "htm", "html", "rtf", "txt"}
    FILENAME_RE = build_filename_re(FILENAME_EXTS)


def configure_archive_suffixes(archive_exts: Iterable[str]) -> None:
    global ARCHIVE_EXTS
    ARCHIVE_EXTS = set(archive_exts)
    refresh_extension_sets()


def configure_design_suffixes(three_d: Iterable[str], two_d: Iterable[str], pcb_ecad: Iterable[str] = ()) -> None:
    global CAD_2D_EXTS, MODEL_3D_EXTS, PCB_ECAD_EXTS, DESIGN_EXTS, CONTROLLED_3D_EXTS, CONTROLLED_2D_CAD_EXTS
    MODEL_3D_EXTS = set(three_d)
    CAD_2D_EXTS = set(two_d)
    PCB_ECAD_EXTS = set(pcb_ecad)
    DESIGN_EXTS = CAD_2D_EXTS | MODEL_3D_EXTS | PCB_ECAD_EXTS
    CONTROLLED_3D_EXTS = MODEL_3D_EXTS
    CONTROLLED_2D_CAD_EXTS = CAD_2D_EXTS
    refresh_extension_sets()


def load_audit_policy(path: str) -> dict[str, Any]:
    source = Path(path)
    if not source.exists():
        return {}
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}



def configure_audit_policy(policy: dict[str, Any]) -> None:
    global INTERNAL_NETWORKS, ORGANIZATION_ALIASES
    design = policy.get("design_suffixes") if isinstance(policy, dict) else {}
    if not isinstance(design, dict):
        design = {}
    archive_exts = normalize_ext_list(policy.get("archive_suffixes")) or set(DEFAULT_ARCHIVE_EXTS)
    configure_archive_suffixes(archive_exts)
    three_d = normalize_ext_list(design.get("three_d")) or {"asm", "prt", "sldasm", "sldprt", "step"}
    two_d = normalize_ext_list(design.get("two_d")) or {"dwg"}
    pcb_ecad = normalize_ext_list(design.get("pcb_ecad"))
    configure_design_suffixes(three_d, two_d, pcb_ecad)
    configure_critical_design_patterns(policy.get("critical_design_patterns") if isinstance(policy, dict) else None)
    INTERNAL_NETWORKS = set(DEFAULT_INTERNAL_NETWORKS) | policy_internal_networks(policy)
    ORGANIZATION_ALIASES = decrypt_imports.normalize_aliases(policy if isinstance(policy, dict) else {})


def csv_rows(path: str) -> list[dict[str, str]]:
    if not path:
        return []
    source = Path(path)
    if not source.exists():
        return []
    with source.open(encoding="utf-8-sig", newline="") as handle:
        lines = [line for line in handle if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        return []
    return list(csv.DictReader(lines))


def json_rule_rows(path: str) -> list[dict[str, Any]]:
    if not path:
        return []
    source = Path(path)
    if not source.exists():
        return []
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("rules") or []
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


def rule_rows(path: str) -> list[dict[str, Any]]:
    if Path(path).suffix.lower() == ".json":
        return json_rule_rows(path)
    return csv_rows(path)


def load_sensitive_keyword_rules(path: str) -> list[KeywordRule]:
    rules: list[KeywordRule] = []
    for row in rule_rows(path):
        keyword = (row.get("keyword") or "").strip()
        if not keyword:
            continue
        match_type = (row.get("match_type") or "contains").strip().lower()
        if match_type not in {"contains", "regex"}:
            match_type = "contains"
        rules.append(
            KeywordRule(
                keyword=keyword,
                category=(row.get("category") or "").strip(),
                scope=(row.get("scope") or "both").strip().lower(),
                match_type=match_type,
                enabled=is_enabled_value(row.get("enabled"), default=True),
                note=(row.get("note") or "").strip(),
            )
        )
    return rules


def configure_sensitive_keyword_rules(rules: list[KeywordRule]) -> None:
    global SENSITIVE_KEYWORD_RULES, LEADERSHIP_KEYWORD_RULES
    enabled = [rule for rule in rules if rule.enabled and rule.keyword]
    SENSITIVE_KEYWORD_RULES = [rule for rule in enabled if rule.in_risk_scope()]
    LEADERSHIP_KEYWORD_RULES = [rule for rule in enabled if rule.in_leadership_scope()]


def sensitive_keywords_summary(args: argparse.Namespace) -> str:
    meta = getattr(args, "sensitive_keyword_meta", {}) or {}
    path = Path(str(meta.get("path") or "")).name or "未配置"
    return f"敏感词：{path}，启用 {meta.get('risk', 0)} 个。"


def audit_policy_summary(args: argparse.Namespace) -> str:
    meta = getattr(args, "audit_policy_meta", {}) or {}
    path = Path(str(meta.get("path") or "")).name or "未配置"
    three_d = "、".join(f".{ext}" for ext in sorted(CONTROLLED_3D_EXTS)) or "未配置"
    two_d = "、".join(f".{ext}" for ext in sorted(CONTROLLED_2D_CAD_EXTS)) or "未配置"
    critical = "、".join(CRITICAL_DESIGN_LABELS) or "未配置"
    return (
        f"审计策略：{path}，三维模型 {three_d}，二维图纸 {two_d}，"
        f"最高预警对象 {critical}，"
        f"压缩包后缀 {meta.get('archive_suffixes', 0)} 个，"
        f"内部域名 {meta.get('internal_domains', 0)} 个，内部网段 {meta.get('internal_networks', 0)} 个，"
        f"组织别名 {meta.get('organization_aliases', 0)} 条。"
    )


def load_exclusion_rules(path: str) -> list[ExclusionRule]:
    rules: list[ExclusionRule] = []
    for row in rule_rows(path):
        rule_name = (row.get("rule_name") or row.get("name") or "").strip()
        if not rule_name:
            continue
        rules.append(
            ExclusionRule(
                rule_name=rule_name,
                topic=(row.get("topic") or "*").strip(),
                target_contains=split_config_list(row.get("target_contains")),
                target_regex=split_config_list(row.get("target_regex")),
                file_contains=split_config_list(row.get("file_contains")),
                file_regex=split_config_list(row.get("file_regex")),
                process_contains=split_config_list(row.get("process_contains")),
                subject_contains=split_config_list(row.get("subject_contains")),
                action=(row.get("action") or "exclude").strip().lower(),
                enabled=is_enabled_value(row.get("enabled"), default=True),
                note=(row.get("note") or "").strip(),
            )
        )
    return rules


def exclusion_summary(args: argparse.Namespace) -> str:
    meta = getattr(args, "exclusion_meta", {}) or {}
    path = Path(str(meta.get("path") or "")).name or "未配置"
    return f"排除策略：{path}，启用 {meta.get('enabled', 0)} 条。"


def contains_any(patterns: list[str], values: Iterable[str]) -> bool:
    lowered_values = [value.lower() for value in values if value]
    for pattern in patterns:
        needle = pattern.lower()
        if any(needle in value for value in lowered_values):
            return True
    return False


def regex_any(patterns: list[str], values: Iterable[str]) -> bool:
    material = [value for value in values if value]
    for pattern in patterns:
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            continue
        if any(compiled.search(value) for value in material):
            return True
    return False


def exclusion_rule_matches(
    rule: ExclusionRule,
    topic: str,
    names: list[str],
    targets: list[str],
    target_domains: list[str],
    process_name: str,
    subject: str,
) -> bool:
    if not rule.enabled or rule.action not in {"exclude", "drop", "ignore"}:
        return False
    topics = {item.strip() for item in re.split(r"[;；,，]+", rule.topic or "*") if item.strip()}
    if topics and "*" not in topics and topic not in topics:
        return False
    target_values = targets + target_domains
    if rule.target_contains and not contains_any(rule.target_contains, target_values):
        return False
    if rule.target_regex and not regex_any(rule.target_regex, target_values):
        return False
    if rule.file_contains and not contains_any(rule.file_contains, names):
        return False
    if rule.file_regex and not regex_any(rule.file_regex, names):
        return False
    if rule.process_contains and not contains_any(rule.process_contains, [process_name]):
        return False
    if rule.subject_contains and not contains_any(rule.subject_contains, [subject]):
        return False
    return True


def exclusion_match_name(
    rules: list[ExclusionRule],
    topic: str,
    names: list[str],
    targets: list[str],
    target_domains: list[str],
    process_name: str,
    subject: str,
) -> str:
    for rule in rules:
        if exclusion_rule_matches(rule, topic, names, targets, target_domains, process_name, subject):
            return rule.rule_name
    return ""


def sensitive_keyword_hits(names: Iterable[str]) -> list[str]:
    joined = " ".join(names).lower()
    return list(dict.fromkeys(rule.keyword for rule in SENSITIVE_KEYWORD_RULES if rule.matches(joined)))


def leadership_keyword_hits(names: Iterable[str]) -> list[str]:
    joined = " ".join(names).lower()
    return list(dict.fromkeys(rule.keyword for rule in LEADERSHIP_KEYWORD_RULES if rule.matches(joined)))


def non_image_file_names(names: Iterable[str]) -> list[str]:
    return [name for name in names if extension(name) not in LOW_VALUE_IMAGE_EXTS]


SENSITIVE_REASON_PREFIXES = ("敏感文件名:", "敏感关键词:")


def event_keyword_match_texts(event: AuditEvent) -> list[str]:
    return [value for value in [event.mail_subject, *non_image_file_names(event.file_names)] if value]


def event_leadership_keyword_hits(event: AuditEvent) -> list[str]:
    return leadership_keyword_hits(event_keyword_match_texts(event))


def leadership_file_names(event: AuditEvent) -> list[str]:
    names = non_image_file_names(event.file_names)
    focused = [
        name
        for name in names
        if extension(name) in DESIGN_EXTS or leadership_keyword_hits([name])
    ]
    if not focused and event_leadership_keyword_hits(event):
        focused = names
    return list(dict.fromkeys(focused))


def contains_procurement_term(text: str, terms: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(str(term).lower() in lowered for term in terms if str(term).strip())


def event_procurement_identity_text(event: AuditEvent) -> str:
    return " ".join(
        str(value)
        for value in [
            event.department,
            event.org_path,
            event.resolved_company,
            event.resolved_department,
            event.position,
        ]
        if str(value).strip()
    ).lower()


def event_subject_file_text(event: AuditEvent) -> str:
    return " ".join([event.mail_subject or "", *event.file_names]).lower()


def procurement_inquiry_keyword_context(event: AuditEvent) -> bool:
    identity_text = event_procurement_identity_text(event)
    subject_file_text = event_subject_file_text(event)
    is_procurement_team = contains_procurement_term(identity_text, PROCUREMENT_DEPARTMENT_TERMS)
    has_strong_context = contains_procurement_term(subject_file_text, PROCUREMENT_INQUIRY_STRONG_TERMS)
    has_weak_context = contains_procurement_term(subject_file_text, PROCUREMENT_INQUIRY_WEAK_TERMS)
    return has_strong_context or (is_procurement_team and has_weak_context)


def event_file_exts(event: AuditEvent) -> set[str]:
    exts = {ext for ext in event.file_exts if ext}
    exts.update(extension(name) for name in event.file_names if extension(name))
    return exts


def has_normal_procurement_file_shape(event: AuditEvent) -> bool:
    exts = event_file_exts(event)
    if not exts:
        return False
    if exts & (DESIGN_EXTS | DATABASE_EXTS | SOURCE_EXTS):
        return False
    return all(ext in PROCUREMENT_NORMAL_EXTS for ext in exts)


def has_non_procurement_sensitive_signal(event: AuditEvent) -> bool:
    keyword_hits = event_leadership_keyword_hits(event)
    normal_terms = PROCUREMENT_INQUIRY_STRONG_TERMS | PROCUREMENT_INQUIRY_WEAK_TERMS
    if any(keyword not in normal_terms for keyword in keyword_hits):
        return True
    return contains_procurement_term(event_subject_file_text(event), PROCUREMENT_FORCE_KEEP_TERMS)


def has_procurement_hard_keep_signal(event: AuditEvent) -> bool:
    exts = event_file_exts(event)
    if is_external_sender_mailbox(event):
        return True
    if exts & (DESIGN_EXTS | DATABASE_EXTS | SOURCE_EXTS):
        return True
    if is_peripheral_copy_event(event):
        return True
    if has_high_risk_destination(event_domain_values(event)):
        return True
    if event.file_size and event.file_size >= VOLUME_BURST_MIN_BYTES:
        return True
    if any(reason in event.reasons for reason in {"网盘/高风险外联目标", "超大文件", "大文件"}):
        return True
    return has_non_procurement_sensitive_signal(event)


def is_normal_procurement_inquiry_event(event: AuditEvent) -> bool:
    if event.topic not in {"mail_audit", "im_audit", "file_audit"}:
        return False
    if not event.file_names:
        return False
    if not procurement_inquiry_keyword_context(event):
        return False
    if has_procurement_hard_keep_signal(event):
        return False
    return has_normal_procurement_file_shape(event)


def is_file_rename_event(event: AuditEvent) -> bool:
    return event.topic == "file_audit" and (event.channel == "文件重命名" or "文件重命名" in event.reasons)


def is_trusted_internal_flow_event(event: AuditEvent) -> bool:
    if event.recipient_relation != "internal":
        return False
    if event.topic == "mail_audit":
        return True
    if event.topic == "im_audit":
        return is_wecom_process_name(event.process_name)
    if is_im_file_audit_event(event):
        return is_wecom_process_name(event.process_name)
    return False


def is_report_flow_event(event: AuditEvent, internal_domains: set[str] | None = None) -> bool:
    internal_domains = internal_domains or DEFAULT_INTERNAL_DOMAINS
    if event.topic == "firewall":
        return False
    if is_file_rename_event(event):
        return False
    if event.recipient_relation == "group" or "企业微信群忽略" in event.reasons:
        return False
    if is_upload_noise_event(event, set(internal_domains)):
        return False
    if is_trusted_internal_flow_event(event) and not is_peripheral_copy_event(event):
        return False
    return True


def is_leadership_focus_event(event: AuditEvent, internal_domains: set[str] | None = None) -> bool:
    internal_domains = internal_domains or DEFAULT_INTERNAL_DOMAINS
    if not is_report_flow_event(event, internal_domains):
        return False
    if is_normal_procurement_inquiry_event(event):
        return False

    names = non_image_file_names(event.file_names)
    has_design = any(extension(name) in DESIGN_EXTS for name in names)
    has_archive = any(extension(name) in ARCHIVE_EXTS for name in names) or is_archive_event(event)
    has_sensitive_name = bool(event_leadership_keyword_hits(event))
    if not (has_design or has_sensitive_name or has_archive):
        return False

    if is_external_sender_mailbox(event):
        return True
    if procurement_inquiry_keyword_context(event) and has_procurement_hard_keep_signal(event):
        return True
    if is_peripheral_copy_event(event):
        return True

    # High-confidence external signals always stay in the leadership view.
    if event.recipient_relation in EXTERNAL_RELATIONS:
        return True
    if any(
        reason in event.reasons
        for reason in {"个人邮箱域名", "网盘/高风险外联目标", "外部收件域名", "外部上传/下载地址"}
    ):
        return True

    # Mail / IM with an unclassified recipient are still worth surfacing.
    if event.topic in {"mail_audit", "im_audit"} and event.recipient_relation == "unknown":
        return True

    # The biggest source of noise is untargeted Explorer-based file audits.
    # Keep only high-signal unknown file transfers in the leadership list;
    # the rest can still surface through aggregated anomaly views.
    if event.topic == "file_audit" and event.recipient_relation == "unknown":
        process_name = normalize_key(event.process_name)
        if is_critical_design_event(event):
            return True
        if is_three_d_model_event(event) or is_pcb_ecad_event(event):
            return True
        if process_name not in {"explorer", "explorer.exe"}:
            return True
        if event.priority == PRIORITY_ACTION and (event_leadership_keyword_hits(event) or has_archive):
            return True
        return False

    return (has_sensitive_name or has_archive) and event.priority != PRIORITY_WATCH


def report_focus_events(
    audit_events: list[AuditEvent],
    internal_domains: set[str] | None = None,
) -> tuple[list[AuditEvent], dict[str, str]]:
    focus_candidates = [event for event in audit_events if is_leadership_focus_event(event, internal_domains)]
    false_positive_reasons = report_false_positive_map(focus_candidates, audit_events)
    focus_events = [event for event in focus_candidates if event.event_id not in false_positive_reasons]
    return focus_events, false_positive_reasons


def file_audit_transfer_method(obj: dict[str, Any]) -> str:
    return normalize_key(obj.get("transfer_method"))


def file_audit_scene(obj: dict[str, Any], event: AuditEvent, internal_domains: set[str]) -> tuple[str, str]:
    method = file_audit_transfer_method(obj)
    external = is_external(event.target_domains, internal_domains) or event.recipient_relation in EXTERNAL_RELATIONS
    if str(obj.get("operation_type") or "").strip() == "7":
        return "文件重命名", "文件重命名"
    if method == "copyout":
        return "外设拷贝", "外设拷贝"
    if method == "upload_to_site":
        if external:
            return "文件上传/外发", "外部站点上传"
        return "内部系统上传", "内部系统上传"
    if method == "send":
        return "应用发送/传输", "应用发送"
    if external:
        return "文件上传/外发", "外部上传/下载地址"
    return event.channel, ""


def apply_file_audit_context(event: AuditEvent, obj: dict[str, Any], internal_domains: set[str]) -> None:
    if event.topic != "file_audit" or not obj:
        return
    event.reasons = [
        reason
        for reason in event.reasons
        if reason not in {"外部上传/下载地址", "外部站点上传", "内部系统上传", "应用发送", "外设拷贝", "文件重命名"}
    ]
    channel, reason = file_audit_scene(obj, event, internal_domains)
    if channel:
        event.channel = channel
    if reason:
        add_unique_reason(event.reasons, reason)


def is_peripheral_copy_event(event: AuditEvent) -> bool:
    return event.topic == "file_audit" and (event.channel == "外设拷贝" or "外设拷贝" in event.reasons)


def is_design_send_event(event: AuditEvent) -> bool:
    return is_design_event(event) and not is_peripheral_copy_event(event)


def is_archive_event(event: AuditEvent) -> bool:
    if set(event.file_exts) & ARCHIVE_EXTS:
        return True
    return any(extension(name) in ARCHIVE_EXTS for name in event.file_names)


def is_large_archive_event(event: AuditEvent) -> bool:
    return is_archive_event(event) and int(event.file_size or 0) > LARGE_ARCHIVE_RISK_BYTES


def is_tianqing_level_one_event(event: AuditEvent, internal_domains: set[str] | None = None) -> bool:
    if not is_leadership_focus_event(event, internal_domains or DEFAULT_INTERNAL_DOMAINS):
        return False
    return is_critical_design_event(event) or is_large_archive_event(event)


def text_matches_hints(value: str, hints: Iterable[str]) -> bool:
    lowered = str(value or "").lower()
    return any(str(hint).lower() in lowered for hint in hints if str(hint).strip())


def is_cloud_destination_event(event: AuditEvent) -> bool:
    process = normalize_key(event.process_name)
    if process in CLOUD_PROCESS_NAMES:
        return True
    values = event.target_domains + event.targets + event.recipients
    return any(text_matches_hints(str(value), CLOUD_DEST_HINTS) for value in values)


def is_upload_noise_event(event: AuditEvent, internal_domains: set[str]) -> bool:
    if event.topic != "file_audit":
        return False
    if not any(reason in event.reasons for reason in {"外部站点上传", "外部上传/下载地址", "内部系统上传"}):
        return False
    if any(domain_is_internal(domain, internal_domains) for domain in event.target_domains):
        return True
    return any(text_matches_hints(value, UPLOAD_NOISE_HINTS) for value in event.target_domains + event.targets)


def is_external_site_upload_event(event: AuditEvent, internal_domains: set[str]) -> bool:
    if event.topic != "file_audit" or is_peripheral_copy_event(event) or is_cloud_destination_event(event):
        return False
    if is_upload_noise_event(event, internal_domains):
        return False
    return any(reason in event.reasons for reason in {"外部站点上传", "外部上传/下载地址"}) or event.channel == "文件上传/外发"


def audit_channel_group(event: AuditEvent, internal_domains: set[str]) -> str:
    if not is_report_flow_event(event, internal_domains):
        return ""
    if event.topic == "mail_audit":
        return "邮件外发"
    if event.topic == "im_audit" or (event.topic == "file_audit" and event.channel == "应用发送/传输"):
        return "IM附件"
    if is_peripheral_copy_event(event):
        return "外设拷贝"
    if is_cloud_destination_event(event):
        return "外部站点上传"
    if is_external_site_upload_event(event, internal_domains):
        return "外部站点上传"
    return ""


def audit_matrix_bucket(event: AuditEvent) -> str | None:
    for label in CRITICAL_DESIGN_LABELS:
        if label in critical_design_labels_for_event(event):
            return label
    if is_three_d_model_event(event):
        return "三维模型"
    if is_two_d_cad_event(event):
        return "DWG二维图纸"
    if is_archive_event(event):
        return "压缩包"
    if event_leadership_keyword_hits(event):
        return "敏感名称"
    return None


def report_file_name_key(name: str) -> str:
    text = str(name or "").replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    return " ".join(text.split())


def report_event_file_keys(event: AuditEvent) -> set[str]:
    return {key for name in event.file_names for key in [report_file_name_key(name)] if key}




def path_basename(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return re.split(r"[\\/]", text)[-1].strip()


def path_extension(value: Any) -> str:
    return extension(path_basename(value))


def path_match_key(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip().lower()
    return " ".join(text.split())




def has_file_assistant_target(event: AuditEvent) -> bool:
    return any(str(value or "").strip().upper() == "FILEASSIST" for value in event.recipients + event.targets + event.target_domains)


def is_app_send_without_recipient(event: AuditEvent) -> bool:
    return (
        event.topic == "file_audit"
        and event.channel == "应用发送/传输"
        and normalize_key(event.process_name) in {"wxwork.exe", "dingtalk.exe"}
        and (
            not (event.recipients or event.targets or event.target_domains)
            or all(looks_like_im_recipient_token(value) for value in event.recipients + event.targets)
        )
    )


def im_companion_index(events: list[AuditEvent]) -> dict[str, list[datetime]]:
    index: dict[str, list[datetime]] = defaultdict(list)
    for event in events:
        if event.topic != "im_audit" or not event.ts:
            continue
        for key in report_event_file_keys(event):
            index[key].append(event.ts)
    return index


def has_nearby_im_companion(event: AuditEvent, index: dict[str, list[datetime]], seconds: int = 180) -> bool:
    if not event.ts:
        return False
    for key in report_event_file_keys(event):
        for ts in index.get(key, []):
            if abs((event.ts - ts).total_seconds()) <= seconds:
                return True
    return False


REPORT_CRITICAL_NAME_TERMS = {
    "成本",
    "底价",
    "发票",
    "财务",
    "付款",
    "工资",
    "回款",
    "客户清单",
    "离职",
    "人事",
    "薪资",
    "账",
}


def low_confidence_app_send_noise(event: AuditEvent) -> bool:
    if not is_app_send_without_recipient(event):
        return False
    exts = event_file_exts(event)
    if exts & (DESIGN_EXTS | DATABASE_EXTS | SOURCE_EXTS | ARCHIVE_EXTS):
        return False
    if is_peripheral_copy_event(event) or event_has_personal_or_cloud_target(event):
        return False
    if event.file_size and event.file_size >= VOLUME_BURST_MIN_BYTES:
        return False
    text = event_subject_file_text(event)
    if contains_procurement_term(text, REPORT_CRITICAL_NAME_TERMS):
        return False
    return True


def report_false_positive_reason(event: AuditEvent, companion_index: dict[str, list[datetime]]) -> str:
    if has_file_assistant_target(event):
        return "FILEASSIST/文件助手自传，不属于外部接收方"
    if is_im_file_audit_event(event) and has_nearby_im_companion(event, companion_index):
        return "应用发送伴随记录，与IM附件外发重复"
    if low_confidence_app_send_noise(event):
        return "应用发送无接收方，非图纸/非高危目标，缺少外发判定证据"
    return ""


def report_false_positive_map(events: list[AuditEvent], all_events: list[AuditEvent]) -> dict[str, str]:
    companion_index = im_companion_index(all_events)
    result: dict[str, str] = {}
    for event in events:
        reason = report_false_positive_reason(event, companion_index)
        if reason:
            result[event.event_id] = reason
    return result


def normalize_key(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


DEPARTMENT_NAME_SUFFIXES = ("部", "中心", "办公室", "科", "处", "组", "室")
ROOT_COMPANY_NAMES = {"大全集团"}
GROUP_FUNCTION_SUFFIXES = ("部", "中心", "办公室", "科", "处", "组", "室", "办")
COMPANY_NAME_MARKERS = ("公司", "集团", "股份", "科技", "电气", "箱变", "母线", "事业部")


def unique_join_text(values: Iterable[Any], sep: str = " / ") -> str:
    cleaned: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in cleaned:
            cleaned.append(text)
    return sep.join(cleaned)


def is_group_function_org(name: str) -> bool:
    text = str(name or "").strip()
    if not text:
        return False
    if any(marker in text for marker in COMPANY_NAME_MARKERS):
        return False
    return text.endswith(GROUP_FUNCTION_SUFFIXES)


def split_wecom_org_path(parts: list[str]) -> tuple[str, str, str]:
    cleaned = [str(part or "").strip() for part in parts if str(part or "").strip()]
    if cleaned and cleaned[0] in ROOT_COMPANY_NAMES and len(cleaned) > 1:
        child = cleaned[1]
        if is_group_function_org(child):
            return cleaned[0], " / ".join(cleaned[1:]), " / ".join(cleaned)
        return child, " / ".join(cleaned[2:]), " / ".join(cleaned)
    if cleaned and is_group_function_org(cleaned[0]):
        return "大全集团", " / ".join(cleaned), " / ".join(cleaned)
    company = cleaned[0] if cleaned else ""
    department = " / ".join(cleaned[1:]) if len(cleaned) > 1 else ""
    return company, department, " / ".join(cleaned)


def wecom_item_org_fields(item: dict[str, Any]) -> tuple[str, str]:
    path_text = str(item.get("department_path") or "").strip()
    if path_text:
        split_items = [
            split_wecom_org_path([part.strip() for part in path.split("/") if part.strip()])
            for path in re.split(r"[;；]", path_text)
            if path.strip()
        ]
        if split_items:
            return (
                unique_join_text((entry[0] for entry in split_items)),
                unique_join_text((entry[1] for entry in split_items), "；"),
            )
    company_name = str(item.get("company") or "").strip()
    department_name = str(item.get("department") or "").strip()
    parts = [company_name] if company_name else []
    if department_name:
        parts.extend(part for part in [str(part or "").strip() for part in department_name.split("/")] if part)
    if parts:
        split_item = split_wecom_org_path(parts)
        return split_item[0], split_item[1]
    return normalize_org_fields(company_name, department_name)


def normalize_org_fields(company: str, department: str) -> tuple[str, str]:
    company = str(company or "").strip()
    department = str(department or "").strip()
    if company and (not department or department == company):
        if company.endswith(DEPARTMENT_NAME_SUFFIXES):
            return "", company
    return company, department


def load_people_map(path: str | None) -> dict[tuple[str, str], PeopleEntry]:
    if not path or not Path(path).exists():
        return {}
    mapping: dict[tuple[str, str], PeopleEntry] = {}
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as handle:
        for row in csv.DictReader(handle):
            match_type = normalize_key(row.get("match_type", ""))
            match_value = normalize_key(row.get("match_value", ""))
            person_name = (row.get("person_name") or "").strip()
            if match_type.startswith("#"):
                continue
            if not match_type or not match_value or not person_name:
                continue
            mapping[(match_type, match_value)] = PeopleEntry(
                match_type=match_type,
                match_value=match_value,
                person_name=person_name,
                company=(row.get("company") or "").strip(),
                department=(row.get("department") or "").strip(),
                position=(row.get("position") or "").strip(),
                sensitive_role=(row.get("sensitive_role") or "").strip(),
                status=(row.get("status") or "").strip(),
                note=(row.get("note") or "").strip(),
            )
    return mapping


def load_dispositions(path: str | None) -> tuple[dict[str, DispositionEntry], dict[str, DispositionEntry]]:
    by_event_id: dict[str, DispositionEntry] = {}
    by_search_id: dict[str, DispositionEntry] = {}
    if not path or not Path(path).exists():
        return by_event_id, by_search_id
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as handle:
        for row in csv.DictReader(handle):
            raw_event_id = (row.get("event_id") or "").strip()
            if raw_event_id.startswith("#"):
                continue
            entry = DispositionEntry(
                event_id=raw_event_id,
                search_id=(row.get("search_id") or "").strip(),
                status=(row.get("status") or "").strip(),
                owner=(row.get("owner") or "").strip(),
                reviewer=(row.get("reviewer") or "").strip(),
                review_time=(row.get("review_time") or "").strip(),
                attachment_downloaded=(row.get("attachment_downloaded") or "").strip(),
                conclusion=(row.get("conclusion") or "").strip(),
                notes=(row.get("notes") or "").strip(),
            )
            if entry.event_id:
                by_event_id[entry.event_id] = entry
            if entry.search_id and entry.search_id not in by_search_id:
                by_search_id[entry.search_id] = entry
    return by_event_id, by_search_id


def load_recipient_map(path: str | None) -> dict[tuple[str, str], RecipientEntry]:
    if not path or not Path(path).exists():
        return {}
    mapping: dict[tuple[str, str], RecipientEntry] = {}
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as handle:
        for row in csv.DictReader(handle):
            match_type = normalize_key(row.get("match_type", ""))
            match_value = normalize_key(row.get("match_value", ""))
            relation = normalize_key(row.get("relation", ""))
            if match_type.startswith("#"):
                continue
            if not match_type or not match_value or relation not in {"internal", "external", "partner", "customer", "supplier"}:
                continue
            mapping[(match_type, match_value)] = RecipientEntry(
                match_type=match_type,
                match_value=match_value,
                relation=relation,
                recipient_name=(row.get("recipient_name") or "").strip(),
                organization=(row.get("organization") or "").strip(),
                note=(row.get("note") or "").strip(),
            )
    return mapping


def _wecom_directory_remote_script() -> str:
    return textwrap.dedent(
        r"""
        import json
        import sys

        import httpx
        from app.config import settings

        result = {"ok": False, "items": [], "error": "", "departments": 0, "schema_version": 2}
        try:
            with httpx.Client(timeout=25) as client:
                token_resp = client.get(
                    "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
                    params={"corpid": settings.wecom_corp_id, "corpsecret": settings.wecom_secret},
                ).json()
                token = token_resp.get("access_token")
                if not token:
                    result["error"] = f"gettoken:{token_resp.get('errcode')}:{token_resp.get('errmsg')}"
                    print(json.dumps(result, ensure_ascii=False))
                    raise SystemExit(0)

                dept_resp = client.get(
                    "https://qyapi.weixin.qq.com/cgi-bin/department/list",
                    params={"access_token": token},
                ).json()
                departments = dept_resp.get("department") or []
                result["departments"] = len(departments)
                if dept_resp.get("errcode") not in (None, 0):
                    result["error"] = f"department/list:{dept_resp.get('errcode')}:{dept_resp.get('errmsg')}"
                    print(json.dumps(result, ensure_ascii=False))
                    raise SystemExit(0)

                dept_by_id = {str(item.get("id")): item for item in departments if str(item.get("id"))}
                dept_names = {dept_id: item.get("name") for dept_id, item in dept_by_id.items()}
                dept_ids = set(dept_names)

                def department_path(dept_id):
                    parts = []
                    seen = set()
                    current = str(dept_id)
                    while current and current not in seen and current in dept_by_id:
                        seen.add(current)
                        item = dept_by_id[current]
                        name = str(item.get("name") or "").strip()
                        if name:
                            parts.append(name)
                        parent = str(item.get("parentid") or "")
                        if not parent or parent == current:
                            break
                        current = parent
                    return list(reversed(parts))

                company_name_markers = ("公司", "集团", "股份", "科技", "电气", "箱变", "母线", "事业部")

                def is_group_function_org(name):
                    text = str(name or "").strip()
                    if not text:
                        return False
                    if any(marker in text for marker in company_name_markers):
                        return False
                    return text.endswith(("部", "中心", "办公室", "科", "处", "组", "室", "办"))

                def company_department_for(dept_id):
                    parts = department_path(dept_id)
                    if parts and parts[0] in {"大全集团"} and len(parts) > 1:
                        child = parts[1]
                        if is_group_function_org(child):
                            return parts[0], " / ".join(parts[1:]), " / ".join(parts)
                        return child, " / ".join(parts[2:]), " / ".join(parts)
                    company = parts[0] if parts else ""
                    department = " / ".join(parts[1:]) if len(parts) > 1 else ""
                    return company, department, " / ".join(parts)

                def unique_join(values, sep=" / "):
                    cleaned = []
                    for value in values:
                        value = str(value or "").strip()
                        if value and value not in cleaned:
                            cleaned.append(value)
                    return sep.join(cleaned)

                query_department_ids = [
                    str(item.get("id"))
                    for item in departments
                    if str(item.get("id")) and str(item.get("parentid")) not in dept_ids
                ]
                if not query_department_ids:
                    query_department_ids = [str(item.get("id")) for item in departments if str(item.get("id"))]
                result["queried_departments"] = len(query_department_ids)
                users = {}
                for dept_id in query_department_ids:
                    data = client.get(
                        "https://qyapi.weixin.qq.com/cgi-bin/user/list",
                        params={"access_token": token, "department_id": dept_id, "fetch_child": 1},
                    ).json()
                    if data.get("errcode") != 0:
                        continue
                    for user in data.get("userlist") or []:
                        userid = str(user.get("userid") or "").strip()
                        name = str(user.get("name") or "").strip()
                        if not userid or not name:
                            continue
                        user_dept_ids = [str(item) for item in (user.get("department") or [])]
                        split_items = [company_department_for(item) for item in user_dept_ids]
                        company_label = unique_join([item[0] for item in split_items])
                        dept_label = unique_join([item[1] for item in split_items], "；")
                        path_label = unique_join([item[2] for item in split_items], "；")
                        if not dept_label:
                            dept_label = unique_join([dept_names.get(item, "") for item in user_dept_ids if dept_names.get(item)])
                        users[userid] = {
                            "userid": userid,
                            "name": name,
                            "company": company_label,
                            "department": dept_label,
                            "department_path": path_label,
                            "position": str(user.get("position") or ""),
                            "status": str(user.get("status") or ""),
                        }

                result["ok"] = True
                result["items"] = list(users.values())
        except Exception as exc:
            result["error"] = repr(exc)

        print(json.dumps(result, ensure_ascii=False))
        """
    ).strip()


def fetch_wecom_directory_items(host: str, container: str) -> dict[str, Any]:
    script = _wecom_directory_remote_script()
    command = f"docker exec -i {container} python -"
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", host, command],
        input=script,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=240,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or f"ssh exited {proc.returncode}").strip())
    output = (proc.stdout or "").strip().splitlines()
    if not output:
        raise RuntimeError("empty wecom directory response")
    return json.loads(output[-1])


def wecom_cache_has_company(items: list[dict[str, Any]]) -> bool:
    if not items:
        return False
    sample = items[: min(len(items), 50)]
    return any("company" in item or "department_path" in item for item in sample)


def load_wecom_directory_items(args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    meta = {
        "enabled": not args.disable_wecom_directory,
        "host": args.wecom_directory_host,
        "container": args.wecom_directory_container,
        "source": "none",
        "ok": False,
        "count": 0,
        "departments": 0,
        "queried_departments": 0,
        "error": "",
    }
    if args.disable_wecom_directory:
        return [], meta

    cache_path = Path(args.wecom_directory_cache) if args.wecom_directory_cache else None
    max_age_seconds = max(args.wecom_directory_cache_hours, 0) * 3600
    if cache_path and cache_path.exists() and max_age_seconds > 0 and not args.wecom_directory_refresh:
        age = datetime.now().timestamp() - cache_path.stat().st_mtime
        if age <= max_age_seconds:
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                items = cached.get("items") if isinstance(cached, dict) else []
                if isinstance(items, list):
                    if wecom_cache_has_company(items):
                        meta.update(cached.get("meta") or {})
                        meta.update({"source": "cache", "ok": True, "count": len(items)})
                        return items, meta
            except Exception:
                pass

    try:
        data = fetch_wecom_directory_items(args.wecom_directory_host, args.wecom_directory_container)
        items = data.get("items") if isinstance(data, dict) else []
        if not isinstance(items, list):
            items = []
        meta.update(
            {
                "source": "remote",
                "ok": bool(data.get("ok")),
                "count": len(items),
                "departments": int(data.get("departments") or 0),
                "queried_departments": int(data.get("queried_departments") or 0),
                "error": str(data.get("error") or ""),
            }
        )
        if cache_path and items:
            cache_path.write_text(json.dumps({"meta": meta, "items": items}, ensure_ascii=False, indent=2), encoding="utf-8")
        return items, meta
    except Exception as exc:
        meta.update({"source": "remote", "ok": False, "error": str(exc)})
        if cache_path and cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                items = cached.get("items") if isinstance(cached, dict) else []
                if isinstance(items, list):
                    meta.update(cached.get("meta") or {})
                    meta.update({"source": "stale-cache", "ok": True, "count": len(items)})
                    return items, meta
            except Exception:
                pass
        return [], meta


def build_wecom_recipient_map(items: list[dict[str, Any]]) -> dict[tuple[str, str], RecipientEntry]:
    mapping: dict[tuple[str, str], RecipientEntry] = {}
    for item in items:
        name = str(item.get("name") or "").strip()
        userid = str(item.get("userid") or "").strip()
        company_name, department_name = wecom_item_org_fields(item)
        org_label = " / ".join([value for value in [company_name, department_name] if value])
        if not name and not userid:
            continue
        entry = RecipientEntry(
            match_type="wecom_directory",
            match_value=name or userid,
            relation="internal",
            recipient_name=name or userid,
            organization=org_label or "企业微信通讯录",
            note="wecom_directory",
        )
        if userid:
            mapping.setdefault(("im_account", normalize_key(userid)), entry)
            mapping.setdefault(("recipient", normalize_key(userid)), entry)
    return mapping


def load_observed_wecom_account_recipient_map(
    args: argparse.Namespace,
    wecom_people_map: dict[tuple[str, str], PeopleEntry],
) -> dict[tuple[str, str], RecipientEntry]:
    if not wecom_people_map or not getattr(args, "use_clickhouse", False):
        return {}
    process_names = clickhouse_array_literal(sorted(WECOM_PROCESS_NAMES))
    query = f"""
SELECT local_account, local_nickname, max(ts) AS last_ts
FROM
(
    SELECT
        JSONExtractString(raw_json, 'local_account') AS local_account,
        JSONExtractString(raw_json, 'local_nickname') AS local_nickname,
        lowerUTF8(JSONExtractString(raw_json, 'process_name')) AS process_name,
        ts
    FROM raw_syslog
    WHERE topic = 'im_audit'
      AND length(JSONExtractString(raw_json, 'local_account')) > 0
      AND length(JSONExtractString(raw_json, 'local_nickname')) > 0
      AND lowerUTF8(JSONExtractString(raw_json, 'process_name')) IN {process_names}
)
GROUP BY local_account, local_nickname
FORMAT JSONEachRow
"""
    try:
        text = clickhouse_query(args, query)
    except Exception:
        return {}
    mapping: dict[tuple[str, str], RecipientEntry] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        account = str(row.get("local_account") or "").strip()
        nickname = str(row.get("local_nickname") or "").strip()
        if not account or not nickname:
            continue
        entry = (
            wecom_people_map.get(("im_nickname", normalize_key(nickname)))
            or wecom_people_map.get(("person", normalize_key(nickname)))
            or wecom_people_map.get(("identity_hint", normalize_key(nickname)))
        )
        if not entry:
            continue
        org_label = " / ".join([value for value in [entry.company, entry.department] if value])
        recipient = RecipientEntry(
            match_type="im_account",
            match_value=account,
            relation="internal",
            recipient_name=entry.person_name or nickname,
            organization=org_label or "企业微信通讯录",
            note="wecom_observed_account",
        )
        mapping.setdefault(("im_account", normalize_key(account)), recipient)
        mapping.setdefault(("recipient", normalize_key(account)), recipient)
    return mapping


def build_wecom_people_map(items: list[dict[str, Any]]) -> dict[tuple[str, str], PeopleEntry]:
    mapping: dict[tuple[str, str], PeopleEntry] = {}
    name_counts = Counter(str(item.get("name") or "").strip() for item in items if str(item.get("name") or "").strip())
    for item in items:
        name = str(item.get("name") or "").strip()
        userid = str(item.get("userid") or "").strip()
        company_name, department_name = wecom_item_org_fields(item)
        position = str(item.get("position") or "").strip()
        status = str(item.get("status") or "").strip()
        if not name and not userid:
            continue
        entry = PeopleEntry(
            match_type="wecom_directory",
            match_value=name or userid,
            person_name=name or userid,
            company=company_name,
            department=department_name,
            position=position,
            status=status,
            note="wecom_directory",
        )
        if userid:
            for match_type in ["im_account", "login_account", "person", "identity_hint"]:
                mapping.setdefault((match_type, normalize_key(userid)), entry)
        if name and name_counts[name] == 1:
            for match_type in ["im_nickname", "person", "identity_hint"]:
                mapping.setdefault((match_type, normalize_key(name)), entry)
    return mapping


def terminal_identity_keys(client_name: str, client_ip: str) -> list[tuple[str, str]]:
    name = normalize_key(client_name)
    ip = normalize_key(client_ip)
    keys: list[tuple[str, str]] = []
    if name or ip:
        keys.append((name, ip))
    if name:
        keys.append((name, ""))
    if ip:
        keys.append(("", ip))
    return keys


def resolve_terminal_wecom_identity(
    row: dict[str, Any],
    wecom_people_map: dict[tuple[str, str], PeopleEntry],
) -> tuple[PeopleEntry | None, str]:
    candidates = [
        ("login_account", str(row.get("login_account") or "").strip()),
        ("im_nickname", str(row.get("local_nickname") or "").strip()),
        ("person", str(row.get("local_nickname") or "").strip()),
    ]
    for match_type, value in candidates:
        if not value:
            continue
        entry = wecom_people_map.get((match_type, normalize_key(value)))
        if entry:
            return entry, f"wecom_terminal:{match_type}:{value}"
    return None, ""


def build_terminal_identity_history_from_rows(
    rows: Iterable[dict[str, Any]],
    tz: timezone,
    wecom_people_map: dict[tuple[str, str], PeopleEntry],
) -> dict[tuple[str, str], list[TerminalIdentityObservation]]:
    history: dict[tuple[str, str], list[TerminalIdentityObservation]] = defaultdict(list)
    for row in rows:
        process_name = normalize_key(row.get("process_name"))
        if process_name != "wxwork.exe":
            continue
        entry, mapping_source = resolve_terminal_wecom_identity(row, wecom_people_map)
        if not entry:
            continue
        client_name = str(row.get("client_name") or "").strip()
        client_ip = str(row.get("client_ip") or "").strip()
        keys = terminal_identity_keys(client_name, client_ip)
        if not keys:
            continue
        ts = row.get("ts")
        if not isinstance(ts, datetime):
            ts = parse_clickhouse_ts(ts, tz)
        observation = TerminalIdentityObservation(
            ts=ts,
            client_name=client_name,
            client_ip=client_ip,
            login_account=str(row.get("login_account") or "").strip(),
            local_account=str(row.get("local_account") or "").strip(),
            local_nickname=str(row.get("local_nickname") or "").strip(),
            person_name=entry.person_name,
            company=entry.company,
            department=entry.department,
            position=entry.position,
            mapping_source=mapping_source,
        )
        for key in keys:
            history[key].append(observation)
    for observations in history.values():
        observations.sort(key=lambda item: item.ts.timestamp() if item.ts else 0, reverse=True)
    return history


def terminal_identity_observation_for(
    client_name: str,
    client_ip: str,
    ts: datetime | None,
    history: dict[tuple[str, str], list[TerminalIdentityObservation]],
    max_age_days: int | None = None,
) -> TerminalIdentityObservation | None:
    max_age = max_age_days if max_age_days and max_age_days > 0 else None
    for key in terminal_identity_keys(client_name, client_ip):
        observations = history.get(key) or []
        if not observations:
            continue
        if ts:
            for item in observations:
                if not item.ts or item.ts > ts:
                    continue
                if max_age is not None and (ts - item.ts).total_seconds() > max_age * 86400:
                    continue
                return item
            return None
        return observations[0]
    return None


def load_terminal_identity_history(
    args: argparse.Namespace,
    records: list[RawRecord],
    tz: timezone,
    start: datetime | None,
    end: datetime | None,
    wecom_people_map: dict[tuple[str, str], PeopleEntry],
) -> dict[tuple[str, str], list[TerminalIdentityObservation]]:
    if not wecom_people_map:
        return {}
    if getattr(args, "use_clickhouse", False):
        identity_start = start
        max_age_days = int(getattr(args, "terminal_identity_max_age_days", 30) or 0)
        if identity_start and max_age_days > 0:
            identity_start = identity_start - timedelta(days=max_age_days)
        where = clickhouse_time_filter(identity_start, end)
        query = (
            "SELECT ts, "
            "JSONExtractString(raw_json, 'process_name') AS process_name, "
            "JSONExtractString(raw_json, 'client_name') AS client_name, "
            "JSONExtractString(raw_json, 'client_ip') AS client_ip, "
            "JSONExtractString(raw_json, 'client_login_account') AS login_account, "
            "JSONExtractString(raw_json, 'local_account') AS local_account, "
            "JSONExtractString(raw_json, 'local_nickname') AS local_nickname "
            f"FROM raw_syslog WHERE {where} AND topic = 'im_audit' "
            "AND lower(JSONExtractString(raw_json, 'process_name')) = 'wxwork.exe' "
            "AND (length(JSONExtractString(raw_json, 'client_login_account')) > 0 "
            "OR length(JSONExtractString(raw_json, 'local_nickname')) > 0) "
            "FORMAT JSONEachRow"
        )
        rows = (
            json.loads(line)
            for line in clickhouse_query(args, query).splitlines()
            if line.strip()
        )
        return build_terminal_identity_history_from_rows(rows, tz, wecom_people_map)

    rows: list[dict[str, Any]] = []
    for record in records:
        obj = record.obj
        if str(obj.get("syslog_topic") or "") != "im_audit":
            continue
        rows.append(
            {
                "ts": record.ts,
                "process_name": obj.get("process_name"),
                "client_name": obj.get("client_name"),
                "client_ip": obj.get("client_ip"),
                "login_account": obj.get("client_login_account"),
                "local_account": obj.get("local_account"),
                "local_nickname": obj.get("local_nickname"),
            }
        )
    return build_terminal_identity_history_from_rows(rows, tz, wecom_people_map)


def recipient_entry_for(
    match_type: str,
    value: str,
    recipient_map: dict[tuple[str, str], RecipientEntry],
) -> RecipientEntry | None:
    if not value:
        return None
    return recipient_map.get((match_type, normalize_key(value)))


def display_recipient(raw: str, entry: RecipientEntry | None = None) -> str:
    if entry and entry.recipient_name:
        if entry.organization:
            return f"{entry.recipient_name}({entry.organization})"
        return entry.recipient_name
    return raw


def split_im_target(target: str) -> tuple[str, str]:
    match = re.fullmatch(r"\s*(.*?)\s*<([^<>]+)>\s*", target)
    if match:
        return match.group(1).strip(), match.group(2).strip()
    match = re.fullmatch(r"\s*(.*?)\s*[（(]([^()（）<>]+)[）)]\s*", target)
    if match:
        nickname = match.group(1).strip()
        account = match.group(2).strip()
        if re.fullmatch(r"[A-Za-z0-9_-]{5,64}", account):
            return nickname, account
    return target.strip(), target.strip()


def looks_like_wecom_group_target(nickname: str, account: str, target: str) -> bool:
    label = str(nickname or target or "").strip()
    if not label:
        return False
    if normalize_key(label) == normalize_key(account):
        return False
    return any(hint in label for hint in WECOM_GROUP_TARGET_HINTS)


def looks_like_im_recipient_token(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if "<" in text and ">" in text:
        return True
    if re.fullmatch(r"\s*.*?\s*[（(][A-Za-z0-9_-]{5,64}[）)]\s*", text):
        return True
    if any(marker in text for marker in ("://", "/", "\\", "@")):
        return False
    if "." in text:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{5,64}", text))


def is_wecom_process_name(process_name: Any) -> bool:
    return normalize_key(process_name) in WECOM_PROCESS_NAMES


def recipient_entry_trusted_for_im(entry: RecipientEntry, trust_wecom_directory: bool) -> bool:
    if trust_wecom_directory:
        return True
    if entry.note in {"wecom_directory", "wecom_observed_account"}:
        return False
    if entry.relation == "internal":
        return False
    return True


def im_recipient_entry_for_target(
    nickname: str,
    account: str,
    target: str,
    recipient_map: dict[tuple[str, str], RecipientEntry],
    trust_wecom_directory: bool,
) -> RecipientEntry | None:
    account_entry = recipient_entry_for("im_account", account, recipient_map)
    if account_entry:
        if recipient_entry_trusted_for_im(account_entry, trust_wecom_directory):
            return account_entry
    if account:
        exact_entry = recipient_entry_for("recipient", target, recipient_map)
        if exact_entry and exact_entry.note not in {"wecom_directory", "wecom_observed_account"}:
            if recipient_entry_trusted_for_im(exact_entry, trust_wecom_directory):
                return exact_entry
        nickname_entry = recipient_entry_for("im_nickname", nickname, recipient_map)
        for entry in (nickname_entry,):
            if (
                entry
                and entry.note not in {"wecom_directory", "wecom_observed_account"}
                and entry.relation != "internal"
                and recipient_entry_trusted_for_im(entry, trust_wecom_directory)
            ):
                return entry
        return None
    for entry in (recipient_entry_for("im_nickname", nickname, recipient_map), recipient_entry_for("recipient", target, recipient_map)):
        if not entry:
            continue
        if entry.note in {"wecom_directory", "wecom_observed_account"}:
            continue
        if recipient_entry_trusted_for_im(entry, trust_wecom_directory):
            return entry
    return None


def active_wecom_people_entry(entry: PeopleEntry | None) -> PeopleEntry | None:
    if not entry:
        return None
    status = str(entry.status or "").strip()
    if status and status != "1":
        return None
    return entry


def wecom_internal_entry_for_recipient_label(
    target: str,
    wecom_people_map: dict[tuple[str, str], PeopleEntry],
) -> PeopleEntry | None:
    nickname, account = split_im_target(target)
    if account:
        entry = active_wecom_people_entry(wecom_people_map.get(("im_account", normalize_key(account))))
        if entry:
            return entry
        if normalize_key(account) != normalize_key(nickname):
            return None
    if not nickname:
        return None
    return active_wecom_people_entry(wecom_people_map.get(("im_nickname", normalize_key(nickname))))


def wecom_internal_recipient_label(entry: PeopleEntry) -> str:
    org_label = " / ".join([value for value in [entry.company, entry.department] if value])
    if org_label:
        return f"{entry.person_name}({org_label})"
    return entry.person_name


def manual_internal_recipient_label_for_target(
    target: str,
    recipient_map: dict[tuple[str, str], RecipientEntry],
) -> str:
    if not recipient_map:
        return ""
    nickname, account = split_im_target(target)
    candidates: list[tuple[str, str]] = []
    if account:
        candidates.append(("im_account", account))
        candidates.append(("recipient", target))
        if normalize_key(account) == normalize_key(nickname):
            candidates.append(("im_nickname", nickname))
    else:
        candidates.append(("im_nickname", nickname))
        candidates.append(("recipient", target))
    for match_type, value in candidates:
        entry = recipient_entry_for(match_type, value, recipient_map)
        if entry and entry.relation == "internal":
            return display_recipient(target, entry)
    return ""


def im_recipient_labels_need_wecom_repair(values: Iterable[str]) -> bool:
    labels = [str(value or "").strip() for value in values if str(value or "").strip()]
    if not labels:
        return False
    return all(looks_like_im_recipient_token(label) for label in labels)


def wecom_event_recipient_values(event: AuditEvent) -> list[str]:
    values: list[str] = []
    for items in (event.recipients, event.targets, event.target_domains):
        values.extend(str(item or "").strip() for item in items if str(item or "").strip())
    return list(dict.fromkeys(values))


def readable_internal_recipient_labels(event: AuditEvent) -> list[str]:
    if event.recipient_relation != "internal":
        return []
    labels: list[str] = []
    for value in event.recipients:
        text = str(value or "").strip()
        if text and not looks_like_im_recipient_token(text):
            labels.append(text)
    return list(dict.fromkeys(labels))


def repair_wecom_internal_recipient_relations(
    events: list[AuditEvent],
    wecom_people_map: dict[tuple[str, str], PeopleEntry],
    recipient_map: dict[tuple[str, str], RecipientEntry] | None = None,
) -> None:
    recipient_map = recipient_map or {}
    if not wecom_people_map and not recipient_map:
        return
    for event in events:
        if event.topic == "im_audit":
            if not is_wecom_process_name(event.process_name):
                continue
        elif is_im_file_audit_event(event):
            if not is_wecom_process_name(event.process_name):
                continue
        else:
            continue
        raw_targets = [item for item in (event.recipients or event.targets) if str(item or "").strip()]
        if not raw_targets:
            continue
        needs_repair = event.recipient_relation == "unknown" or (
            event.recipient_relation == "internal"
            and im_recipient_labels_need_wecom_repair(raw_targets)
        )
        if not needs_repair:
            continue
        labels: list[str] = []
        unmatched = False
        for target in raw_targets:
            entry = wecom_internal_entry_for_recipient_label(target, wecom_people_map)
            if entry:
                labels.append(wecom_internal_recipient_label(entry))
                continue
            manual_label = manual_internal_recipient_label_for_target(target, recipient_map)
            if manual_label:
                labels.append(manual_label)
                continue
            if not entry:
                unmatched = True
                break
        if unmatched or not labels:
            continue
        labels = list(dict.fromkeys(label for label in labels if label))
        if not labels:
            continue
        event.recipient_relation = "internal"
        event.recipients = labels
        event.targets = labels
        event.reasons = [reason for reason in event.reasons if reason != "IM收件人关系待判定"]
        if "企业微信内部接收方" not in event.reasons:
            event.reasons.append("企业微信内部接收方")


def repair_wecom_recipients_from_event_context(
    events: list[AuditEvent],
    wecom_people_map: dict[tuple[str, str], PeopleEntry],
    recipient_map: dict[tuple[str, str], RecipientEntry] | None = None,
) -> None:
    recipient_map = recipient_map or {}
    internal_labels_by_account: dict[str, list[str]] = defaultdict(list)
    display_labels_by_account: dict[str, list[str]] = defaultdict(list)
    for event in events:
        if event.topic == "im_audit":
            if not is_wecom_process_name(event.process_name):
                continue
        elif is_im_file_audit_event(event):
            if not is_wecom_process_name(event.process_name):
                continue
        else:
            continue
        readable_internal = readable_internal_recipient_labels(event)
        for raw_target in wecom_event_recipient_values(event):
            nickname, account = split_im_target(raw_target)
            if not re.fullmatch(r"[A-Za-z0-9_-]{5,64}", account or ""):
                continue
            normalized_account = normalize_key(account)
            entry = wecom_internal_entry_for_recipient_label(raw_target, wecom_people_map)
            if entry:
                internal_labels_by_account[normalized_account].append(wecom_internal_recipient_label(entry))
                continue
            manual_label = manual_internal_recipient_label_for_target(raw_target, recipient_map)
            if manual_label:
                internal_labels_by_account[normalized_account].append(manual_label)
                continue
            if readable_internal:
                internal_labels_by_account[normalized_account].extend(readable_internal)
                continue
            if nickname and normalize_key(nickname) != normalize_key(account):
                display_labels_by_account[normalized_account].append(raw_target)

    if not internal_labels_by_account and not display_labels_by_account:
        return

    for event in events:
        if event.topic == "im_audit":
            if not is_wecom_process_name(event.process_name):
                continue
        elif is_im_file_audit_event(event):
            if not is_wecom_process_name(event.process_name):
                continue
        else:
            continue
        raw_targets = wecom_event_recipient_values(event)
        if not raw_targets:
            continue
        labels: list[str] = []
        account_count = 0
        internal_count = 0
        changed = False
        for raw_target in raw_targets:
            nickname, account = split_im_target(raw_target)
            if not re.fullmatch(r"[A-Za-z0-9_-]{5,64}", account or ""):
                labels.append(raw_target)
                continue
            account_count += 1
            normalized_account = normalize_key(account)
            internal_labels = list(dict.fromkeys(internal_labels_by_account.get(normalized_account, [])))
            if internal_labels:
                labels.extend(internal_labels)
                internal_count += 1
                changed = True
                continue
            display_labels = list(dict.fromkeys(display_labels_by_account.get(normalized_account, [])))
            if display_labels:
                labels.extend(display_labels)
                changed = True
                continue
            labels.append(raw_target)
        labels = list(dict.fromkeys(label for label in labels if label))
        if not labels or not changed:
            continue
        event.recipients = labels
        event.targets = labels
        event.target_domains = []
        if account_count and internal_count == account_count:
            event.recipient_relation = "internal"
            event.reasons = [reason for reason in event.reasons if reason != "IM收件人关系待判定"]
            if "企业微信内部接收方" not in event.reasons:
                event.reasons.append("企业微信内部接收方")
        elif event.recipient_relation == "unknown" and "企业微信接收方名称补全" not in event.reasons:
            event.reasons.append("企业微信接收方名称补全")


def repair_wecom_self_recipient_relations(events: list[AuditEvent]) -> None:
    for event in events:
        if event.topic == "im_audit":
            if not is_wecom_process_name(event.process_name):
                continue
        elif is_im_file_audit_event(event):
            if not is_wecom_process_name(event.process_name):
                continue
        else:
            continue
        account = normalize_key(event.account)
        if not account:
            continue
        target_accounts: set[str] = set()
        for raw_target in wecom_event_recipient_values(event):
            _nickname, target_account = split_im_target(raw_target)
            if re.fullmatch(r"[A-Za-z0-9_-]{5,64}", target_account or ""):
                target_accounts.add(normalize_key(target_account))
        if account not in target_accounts:
            continue
        label_name = event.resolved_person or event.person or event.account
        label = f"{label_name}(本人/文件助手)" if label_name else "本人/文件助手"
        event.recipient_relation = "internal"
        event.recipients = [label]
        event.targets = [label]
        event.target_domains = []
        event.reasons = [
            reason
            for reason in event.reasons
            if reason not in {"IM收件人关系待判定", "企业微信接收方名称补全"}
        ]
        if "企业微信本人/文件助手" not in event.reasons:
            event.reasons.append("企业微信本人/文件助手")


def classify_recipients(
    topic: str,
    targets: list[str],
    target_domains: list[str],
    internal_domains: set[str],
    recipient_map: dict[tuple[str, str], RecipientEntry],
    wecom_directory_authoritative: bool = False,
    trust_wecom_directory: bool = True,
) -> tuple[list[str], str]:
    external_like: list[str] = []
    internal_like: list[str] = []
    relations: list[str] = []
    has_internal = False
    has_unknown = False
    group_like: list[str] = []

    if topic == "mail_audit":
        for target in targets:
            domain = email_domain(target)
            entry = recipient_entry_for("email", target, recipient_map) or recipient_entry_for("domain", domain, recipient_map)
            if entry:
                if entry.relation == "internal":
                    has_internal = True
                    internal_like.append(display_recipient(target, entry))
                    continue
                external_like.append(display_recipient(target, entry))
                relations.append(entry.relation)
                continue
            if domain and domain_is_internal(domain, internal_domains):
                has_internal = True
                internal_like.append(target)
            elif domain:
                external_like.append(target)
                relations.append("external")
            else:
                has_unknown = True

    elif topic == "im_audit":
        for target in targets:
            if target_is_internal_network(target, internal_domains):
                has_internal = True
                internal_like.append(target)
                continue
            nickname, account = split_im_target(target)
            entry = im_recipient_entry_for_target(nickname, account, target, recipient_map, trust_wecom_directory)
            if entry:
                display = display_recipient(target, entry)
                if entry.relation == "internal":
                    has_internal = True
                    internal_like.append(display)
                    continue
                external_like.append(display)
                relations.append(entry.relation)
            else:
                if trust_wecom_directory and looks_like_wecom_group_target(nickname, account, target):
                    group_like.append(target)
                elif wecom_directory_authoritative or trust_wecom_directory:
                    external_like.append(target)
                    relations.append("external")
                else:
                    external_like.append(target)
                    has_unknown = True

    else:
        for target in targets:
            if target_is_internal_network(target, internal_domains):
                has_internal = True
                internal_like.append(target)
                continue
            nickname, account = split_im_target(target)
            im_entry = im_recipient_entry_for_target(nickname, account, target, recipient_map, trust_wecom_directory)
            if im_entry:
                display = display_recipient(target, im_entry)
                if im_entry.relation == "internal":
                    has_internal = True
                    internal_like.append(display)
                    continue
                external_like.append(display)
                relations.append(im_entry.relation)
                continue
            if trust_wecom_directory and looks_like_wecom_group_target(nickname, account, target):
                group_like.append(target)
                continue
            if topic == "file_audit" and looks_like_im_recipient_token(target):
                external_like.append(target)
                if trust_wecom_directory:
                    relations.append("external")
                else:
                    has_unknown = True
                continue
            domain = host_domain(target)
            if not domain:
                external_like.append(target)
                if topic == "file_audit":
                    if trust_wecom_directory:
                        relations.append("external")
                    else:
                        has_unknown = True
                elif wecom_directory_authoritative:
                    relations.append("external")
                else:
                    has_unknown = True
                continue
            entry = recipient_entry_for("domain", domain, recipient_map)
            if entry:
                if entry.relation == "internal":
                    has_internal = True
                    internal_like.append(display_recipient(target, entry))
                    continue
                external_like.append(display_recipient(target, entry))
                relations.append(entry.relation)
                continue
            if domain and domain_is_internal(domain, internal_domains):
                has_internal = True
                internal_like.append(target)
            elif domain:
                external_like.append(target)
                relations.append("external")
            else:
                has_unknown = True

    external_like = list(dict.fromkeys([item for item in external_like if item]))
    if external_like and has_unknown:
        return external_like, "unknown"
    if external_like:
        relation_set = {relation for relation in relations if relation in EXTERNAL_RELATIONS}
        if len(relation_set) == 1:
            return external_like, next(iter(relation_set))
        return external_like, "external"
    if has_internal:
        return list(dict.fromkeys([item for item in internal_like if item])), "internal"
    if group_like:
        return list(dict.fromkeys([item for item in group_like if item])), "group"
    return [], "unknown"


def people_candidates(event: AuditEvent) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    if "@" in event.person:
        candidates.append(("email", event.person))
    if "@" in event.account:
        candidates.append(("email", event.account))
    if event.topic == "im_audit":
        candidates.append(("im_nickname", event.person))
        candidates.append(("im_account", event.account))
    candidates.extend(
        [
            ("login_account", event.account),
            ("person", event.person),
            ("client_name", event.client_name),
            ("client_ip", event.client_ip),
        ]
    )
    for hint in event.identity_hints:
        candidates.append(("identity_hint", hint))
        candidates.append(("person", hint))
    seen: set[tuple[str, str]] = set()
    result = []
    for match_type, value in candidates:
        if not value:
            continue
        key = (match_type, normalize_key(value))
        if key in seen:
            continue
        seen.add(key)
        result.append((match_type, value))
    return result


def apply_terminal_identity_to_event(
    event: AuditEvent,
    terminal_identity_history: dict[tuple[str, str], list[TerminalIdentityObservation]],
    max_age_days: int | None = None,
) -> bool:
    observation = terminal_identity_observation_for(
        event.client_name,
        event.client_ip,
        event.ts,
        terminal_identity_history,
        max_age_days=max_age_days,
    )
    if not observation and event.ts:
        observation = terminal_identity_observation_for(
            event.client_name,
            event.client_ip,
            None,
            terminal_identity_history,
        )
    if not observation:
        return False
    event.resolved_person = observation.person_name
    event.resolved_company = observation.company
    event.resolved_department = observation.department
    event.position = observation.position
    event.mapping_source = observation.mapping_source
    return True


def default_disposition(event: AuditEvent) -> str:
    if event.topic == "mail_audit":
        return "待下载附件"
    if any(key.startswith("download_file_key=") for key in event.lookup_keys):
        return "待回查文件"
    return "待复核"


def enrich_events(
    events: list[AuditEvent],
    people_map: dict[tuple[str, str], PeopleEntry],
    wecom_people_map: dict[tuple[str, str], PeopleEntry],
    dispositions_by_event_id: dict[str, DispositionEntry],
    dispositions_by_search_id: dict[str, DispositionEntry],
    recipient_map: dict[tuple[str, str], RecipientEntry] | None = None,
    terminal_identity_history: dict[tuple[str, str], list[TerminalIdentityObservation]] | None = None,
    terminal_identity_max_age_days: int | None = None,
) -> None:
    terminal_identity_history = terminal_identity_history or {}
    recipient_map = recipient_map or {}
    repair_wecom_internal_recipient_relations(events, wecom_people_map, recipient_map)
    enrich_file_audit_im_recipients(events)
    repair_wecom_internal_recipient_relations(events, wecom_people_map, recipient_map)
    repair_wecom_recipients_from_event_context(events, wecom_people_map, recipient_map)
    repair_wecom_self_recipient_relations(events)
    for event in events:
        normalize_untrusted_internal_im_relation(event)
    for event in events:
        event.resolved_person = event.resolved_person or event.person
        event.resolved_company = event.resolved_company or ""
        event.resolved_department = event.resolved_department or ""
        matched = apply_terminal_identity_to_event(
            event,
            terminal_identity_history,
            max_age_days=terminal_identity_max_age_days,
        )
        if not matched:
            for mapping_name, mapping in [("wecom", wecom_people_map), ("people", people_map)]:
                for match_type, value in people_candidates(event):
                    entry = mapping.get((match_type, normalize_key(value)))
                    if not entry:
                        continue
                    event.resolved_person = entry.person_name
                    event.resolved_company = entry.company
                    event.resolved_department = entry.department
                    event.position = entry.position
                    event.sensitive_role = entry.sensitive_role
                    event.mapping_source = f"{mapping_name}:{match_type}:{value}"
                    matched = True
                    break
                if matched:
                    break

        disposition = dispositions_by_event_id.get(event.event_id)
        if not disposition and event.search_id:
            disposition = dispositions_by_search_id.get(event.search_id)
        if disposition:
            event.disposition_status = disposition.status or default_disposition(event)
            event.disposition_owner = disposition.owner or disposition.reviewer
            event.disposition_result = disposition.conclusion or disposition.notes
        else:
            event.disposition_status = default_disposition(event)


def apply_terminal_majority_identity(
    events: list[AuditEvent],
    terminal_identity_history: dict[tuple[str, str], list[TerminalIdentityObservation]] | None = None,
) -> None:
    terminal_identity_history = terminal_identity_history or {}
    terminal_groups: dict[tuple[str, str], list[AuditEvent]] = defaultdict(list)
    for event in events:
        key = terminal_key(event.client_name, event.client_ip)
        if key[0] or key[1]:
            terminal_groups[key].append(event)

    def best(counter: Counter, unmatched_prefix: str) -> str:
        for value, _count in counter.most_common():
            text = str(value or "").strip()
            if text and not text.startswith(unmatched_prefix):
                return text
        return ""

    for key, group_events in terminal_groups.items():
        observation = terminal_identity_observation_for(key[0], key[1], None, terminal_identity_history)
        company = observation.company if observation else ""
        department = observation.department if observation else ""
        person = observation.person_name if observation else ""
        company = company or best(Counter(event_company_label(event) for event in group_events), "未匹配")
        department = department or best(Counter(event_department_label(event) for event in group_events), "未匹配")
        person = person or best(Counter((event.resolved_person or event.person or "").strip() for event in group_events), "未匹配")
        if not (company or department or person):
            continue
        for event in group_events:
            if company:
                event.resolved_company = company
            if department:
                event.resolved_department = department
            current_person = (event.resolved_person or event.person or "").strip()
            if person and (not current_person or current_person.startswith("未匹配") or current_person.lower() == "unknown"):
                event.resolved_person = person


def build_event(
    record: RawRecord,
    internal_domains: set[str],
    recipient_map: dict[tuple[str, str], RecipientEntry],
    exclusion_rules: list[ExclusionRule] | None = None,
    include_firewall: bool = False,
    include_unknown_im: bool = True,
    include_untargeted_file: bool = False,
    wecom_directory_authoritative: bool = False,
) -> AuditEvent | None:
    obj = record.obj
    topic = str(obj.get("syslog_topic") or "unknown")
    if topic not in {"mail_audit", "im_audit", "file_audit", "firewall"}:
        return None

    names = file_names_for(obj, topic)
    exts = sorted({extension(name) for name in names if extension(name)})
    targets, target_domains = targets_for(obj, topic)
    process_name = first_nonempty(obj, ["process_name"])
    mail_subject = mail_subject_for(obj, topic)
    sender_mailbox = mail_sender_mailbox_for(obj, topic)
    external_sender_mailbox = topic == "mail_audit" and mailbox_is_external(sender_mailbox, internal_domains)
    if exclusion_match_name(exclusion_rules or [], topic, names, targets, target_domains, process_name, mail_subject):
        return None
    recipients, recipient_relation = classify_recipients(
        topic,
        targets,
        target_domains,
        internal_domains,
        recipient_map,
        wecom_directory_authoritative=wecom_directory_authoritative,
        trust_wecom_directory=topic not in {"im_audit", "file_audit"} or is_wecom_process_name(process_name),
    )
    if recipient_relation == "internal" and not external_sender_mailbox and topic not in {"im_audit", "file_audit"}:
        return None
    if topic == "mail_audit" and not recipients and not external_sender_mailbox:
        return None
    if topic == "im_audit" and recipient_relation == "unknown" and not include_unknown_im:
        return None
    if topic == "file_audit" and not recipients and not include_untargeted_file:
        return None
    person, account = person_for(obj, topic)
    file_size = parse_size(obj.get("file_size"))
    lookup_keys = lookup_keys_for(obj)
    channel = {
        "mail_audit": "邮件外发",
        "im_audit": "IM/协同传输",
        "file_audit": "文件传输/外设",
        "firewall": "外联拦截",
    }.get(topic, topic)
    if topic == "im_audit" and str(obj.get("message_type")) == "2" and str(obj.get("action")) == "1":
        channel = "IM附件外发"

    reasons: list[str] = []
    score = 0
    external = is_external(target_domains, internal_domains)
    if recipients and recipient_relation in EXTERNAL_RELATIONS:
        external = True
    if recipient_relation == "group":
        reasons.append("企业微信群忽略")
    personal = any(domain in PERSONAL_EMAIL_DOMAINS for domain in target_domains)
    high_risk_dest = has_high_risk_destination(target_domains)
    keyword_hits = sensitive_keyword_hits(names)

    if topic == "mail_audit":
        if not names:
            return None
        score += 25
        reasons.append("邮件带附件")
        if external:
            score += 25
            reasons.append("外部收件域名")
        if external_sender_mailbox:
            score += 40
            score = max(score, 75)
            reasons.append("外部发件箱")
    elif topic == "im_audit":
        has_transfer_key = obj.get("download_file_key") not in (None, "", [], {}, "[]")
        has_file_size = file_size not in (None, 0)
        if not (has_transfer_key or has_file_size):
            return None
        score += 20
        if str(obj.get("message_type")) == "2" and str(obj.get("action")) == "1":
            reasons.append("IM附件外发")
            score += 10
            if recipient_relation == "unknown":
                reasons.append("IM收件人关系待判定")
        else:
            reasons.append("IM文件/可回查传输")
    elif topic == "file_audit":
        score += 20
        reasons.append("文件审计事件")
        if external:
            score += 20
            reasons.append("外部上传/下载地址")
    elif topic == "firewall":
        if not include_firewall:
            return None
        rule_name = str(obj.get("rule_name") or "")
        if not (high_risk_dest or "网盘" in rule_name or "外部邮箱" in rule_name or external):
            return None
        score += 15
        reasons.append(f"策略拦截:{rule_name or '外联'}")

    if personal:
        score += 30
        reasons.append("个人邮箱域名")
    if high_risk_dest:
        score += 20
        reasons.append("网盘/高风险外联目标")
    if any(ext in ARCHIVE_EXTS for ext in exts):
        score += 20
        reasons.append("压缩包")
    if any(ext in DESIGN_EXTS for ext in exts):
        score += 35
        reasons.append("设计图纸后缀")
        for label in critical_design_labels_for_names(names):
            reasons.append(CRITICAL_DESIGN_REASON_PREFIX + label)
            score = max(score, 98)
        if any(ext in CONTROLLED_3D_EXTS for ext in exts):
            reasons.append("三维模型")
            score = max(score, 85)
        if any(ext in CONTROLLED_2D_CAD_EXTS for ext in exts):
            reasons.append("DWG二维图纸")
            score = max(score, 60)
        if any(ext in PCB_ECAD_EXTS for ext in exts):
            reasons.append("PCB/电气设计")
            score = max(score, 60)
    if any(ext in DATABASE_EXTS for ext in exts):
        score += 20
        reasons.append("数据库/备份文件")
    if any(ext in OFFICE_EXTS for ext in exts):
        score += 10
        reasons.append("办公文档")
    if any(ext in SOURCE_EXTS for ext in exts):
        score += 25
        reasons.append("源码/结构化数据")
    if keyword_hits:
        score += 25
        reasons.append("敏感文件名:" + ",".join(keyword_hits[:4]))
    if file_size is not None and file_size >= 50 * 1024 * 1024:
        score += 25
        reasons.append("超大文件")
    elif file_size is not None and file_size >= 10 * 1024 * 1024:
        score += 15
        reasons.append("大文件")
    if obj.get("download_file_key") not in (None, "", [], {}, "[]"):
        score += 10
        reasons.append("有download_file_key可回查")

    if score < 20:
        return None

    if score >= 75:
        level = "HIGH"
    elif score >= 45:
        level = "MEDIUM"
    else:
        level = "LOW"

    client_name = first_nonempty(obj, ["client_name"])
    client_ip = first_nonempty(obj, ["client_ip", "client_report_ip", "src_ip"])
    search_id = str(obj.get("search_id") or "")
    event_id = stable_event_id(record.ts, topic, person, client_name, client_ip, targets, names, search_id)

    event = AuditEvent(
        event_id=event_id,
        ts=record.ts,
        topic=topic,
        channel=channel,
        person=person,
        account=account,
        client_name=client_name,
        client_ip=client_ip,
        department=department(obj),
        org_path=organization_path(obj),
        process_name=process_name,
        mail_subject=mail_subject,
        sender_mailbox=sender_mailbox,
        targets=targets,
        target_domains=target_domains,
        recipients=recipients,
        recipient_relation=recipient_relation,
        file_names=names,
        file_exts=exts,
        file_size=file_size,
        lookup_keys=lookup_keys,
        search_id=search_id,
        score=score,
        level=level,
        reasons=list(dict.fromkeys(reasons)),
        identity_hints=identity_hints_for(obj, topic),
    )
    apply_file_audit_context(event, obj, internal_domains)
    apply_design_control_policy(event)
    return event


def format_ts(ts: datetime | None, tz: timezone) -> str:
    if ts is None:
        return ""
    return ts.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")


def summarize_files(event: AuditEvent, max_len: int = 72) -> str:
    return summarize_file_names(event.file_names, event.file_exts, max_len=max_len)


def summarize_file_names(names: list[str], exts: list[str] | None = None, max_len: int = 72) -> str:
    if names:
        text = "; ".join(names[:3])
        if len(names) > 3:
            text += f"; +{len(names) - 3}"
    elif exts:
        text = ",".join(exts)
    else:
        text = "-"
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def summarize_targets(event: AuditEvent, max_len: int = 56) -> str:
    values = event.recipients or event.target_domains or event.targets
    text = "; ".join(values[:3]) if values else "未取到"
    if len(values) > 3:
        text += f"; +{len(values) - 3}"
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def has_target_value(event: AuditEvent) -> bool:
    return bool(event.recipients or event.target_domains or event.targets)


def is_confirmed_external_event(event: AuditEvent) -> bool:
    if event.recipient_relation in EXTERNAL_RELATIONS:
        return True
    return any(
        reason in event.reasons
        for reason in {"个人邮箱域名", "网盘/高风险外联目标", "外部收件域名", "外部上传/下载地址", "外部站点上传"}
    )


def egress_judgement(event: AuditEvent) -> tuple[str, str]:
    if is_peripheral_copy_event(event):
        return "外设拷贝", "文件复制到外设或介质，和邮件/IM/Web外发分开复核。"
    if is_external_sender_mailbox(event):
        return "外部发件箱发送", "终端使用非 daqo.com 发件箱发送带附件邮件，需重点确认是否绕开公司邮箱管控。"
    if is_confirmed_external_event(event):
        return "明确外发", "日志包含外部收件人、外部域名、个人邮箱、高风险外联目标或外部上传目标。"
    if event.topic == "im_audit":
        if has_target_value(event):
            return "IM接收方待判定", "IM附件发送已发生，但接收方未在通讯录或映射表确认内外部关系。"
        return "IM接收方未取到", "IM附件发送日志未带接收方字段，需按download_file_key/search_id回天擎回查。"
    if event.topic == "file_audit":
        if has_target_value(event):
            return "文件传输目标待判定", "文件审计日志带有目标字段，但尚未确认目标是否外部。"
        if "应用发送" in event.reasons or event.channel == "应用发送/传输":
            return "疑似外发待回查", "文件审计识别到应用发送/传输行为，但日志未带接收方，需回查天擎归档或终端上下文。"
        return "文件操作待判定", "文件审计命中敏感文件或图纸，但当前日志未提供外部接收方。"
    return "待判定", "当前日志未提供足够接收方信息。"


def egress_judgement_cell(event: AuditEvent) -> HtmlCell:
    label, detail = egress_judgement(event)
    return tooltip_cell(label, detail)


def table(rows: list[list[str]], headers: list[str]) -> str:
    escaped = [[cell.replace("\n", " ") for cell in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in escaped:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))
    sep = "| " + " | ".join("-" * width for width in widths) + " |"
    out = ["| " + " | ".join(header.ljust(widths[idx]) for idx, header in enumerate(headers)) + " |", sep]
    for row in escaped:
        out.append("| " + " | ".join(row[idx].ljust(widths[idx]) for idx in range(len(headers))) + " |")
    return "\n".join(out)


def esc(value: Any) -> str:
    return html_lib.escape(str(value if value is not None else ""))


def apply_html_display_aliases(content: str) -> str:
    text = str(content)
    for source, target in HTML_DISPLAY_LABEL_ALIASES.items():
        text = text.replace(source, target)
    return text


def period_text(args: argparse.Namespace, start: datetime | None, end: datetime | None) -> str:
    if start or end:
        return f"{start.strftime('%Y-%m-%d %H:%M:%S') if start else 'begin'} 至 {end.strftime('%Y-%m-%d %H:%M:%S') if end else 'now'}"
    return args.period


def slug_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha1(str(value).encode("utf-8")).hexdigest()[:10]
    safe_prefix = re.sub(r"[^a-zA-Z0-9_-]+", "-", prefix).strip("-") or "item"
    return f"{safe_prefix}-{digest}"


def event_org_label(event: AuditEvent) -> str:
    company = event_company_label(event)
    department_label = event_department_label(event)
    if company.startswith("未匹配") and department_label.startswith("未匹配"):
        return UNMATCHED_DIRECTORY_LABEL
    return " / ".join([value for value in [company, department_label] if value])


def event_company_label(event: AuditEvent) -> str:
    text = str(event.resolved_company or "").strip()
    if text and text != "unknown":
        return text
    return UNMATCHED_COMPANY_LABEL


def event_department_label(event: AuditEvent) -> str:
    text = str(event.resolved_department or "").strip()
    if text and text != "unknown":
        return text
    return UNMATCHED_DEPARTMENT_LABEL


def im_channel_label(event: AuditEvent) -> str:
    process = normalize_key(event.process_name)
    if process in WECOM_PROCESS_NAMES:
        return "企业微信"
    if process in {"dingtalk.exe", "dingtalk"}:
        return "钉钉"
    if process in {"wechat.exe", "weixin.exe", "weixin", "wechat"}:
        return "微信"
    if process in {"qq.exe", "ntqq.exe", "tim.exe", "qq", "tim"}:
        return "QQ/TIM"
    if process in {"feishu.exe", "lark.exe", "feishu", "lark"}:
        return "飞书"
    if process in {"teams.exe", "msteams.exe", "teams", "msteams"}:
        return "Teams"
    return event.process_name or "未知IM"


def event_channel_label(event: AuditEvent) -> str:
    if event.topic == "im_audit":
        base = event.channel if event.channel and event.channel != "IM/协同传输" else "IM/协同传输"
        return f"{base}/{im_channel_label(event)}"
    if event.topic == "file_audit" and event.channel == "应用发送/传输":
        channel = im_channel_label(event)
        if channel and channel != "未知IM":
            return f"{channel}文件发送待判定"
        return "应用文件发送待判定"
    return event.channel or event.topic or "-"


def event_subject_label(event: AuditEvent, limit: int = 80) -> str:
    if not event.mail_subject:
        return "-"
    return compact_id(event.mail_subject, limit)


def full_targets(event: AuditEvent) -> str:
    values = event.recipients or event.target_domains or event.targets
    return "; ".join(values) if values else "当前日志未取到接收方/目标"


def full_file_names(names: list[str]) -> str:
    return "; ".join(names) if names else "-"


def tooltip_cell(display: Any, title: Any | None = None, raw: bool = False) -> HtmlCell:
    text = str(display if display is not None else "")
    title_text = str(title if title is not None else text)
    return HtmlCell(text, title_text, raw=raw)


def link_cell(label: Any, href: str, title: Any | None = None) -> HtmlCell:
    text = str(label if label is not None else "")
    title_text = str(title if title is not None else text)
    return HtmlCell(f'<a class="table-link" href="{esc(href)}">{esc(text)}</a>', title_text, raw=True)


def metric_chip_html(label: Any, value: Any, href: str | None = None, title: Any | None = None) -> str:
    label_text = str(label if label is not None else "")
    value_text = str(value if value is not None else "")
    title_text = str(title if title is not None else label_text)
    inner = f'<span title="{esc(title_text)}">{esc(label_text)}</span><strong>{esc(value_text)}</strong>'
    if href:
        return f'<a class="metric-chip metric-chip-link" href="{esc(href)}" title="{esc(title_text)}">{inner}</a>'
    return f'<div class="metric-chip">{inner}</div>'


def html_table(
    headers: list[str],
    rows: list[list[Any]],
    class_name: str = "",
    raw_columns: set[int] | None = None,
    page_size: int | None = None,
    header_html: str | None = None,
) -> str:
    raw_columns = raw_columns or set()
    if not rows:
        return '<p class="empty">无。</p>'
    thead = header_html or ("".join(f"<th>{esc(header)}</th>" for header in headers))
    body_rows = []
    for row in rows:
        cells = []
        for idx, cell in enumerate(row):
            raw = idx in raw_columns
            title = ""
            if isinstance(cell, HtmlCell):
                value = cell.value
                title = cell.title
                raw = raw or cell.raw
            else:
                value = str(cell)
                if not raw:
                    title = value
            attrs = f' title="{esc(title)}"' if title else ""
            cells.append(f"<td{attrs}>{value if raw else esc(value)}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
    wrap_attrs = ""
    if page_size and len(rows) > page_size:
        wrap_attrs = f' data-page-size="{page_size}"'
    if header_html:
        return f'<div class="table-wrap"{wrap_attrs}><table class="{esc(class_name)}"><thead>{thead}</thead><tbody>{"".join(body_rows)}</tbody></table></div>'
    return f'<div class="table-wrap"{wrap_attrs}><table class="{esc(class_name)}"><thead><tr>{thead}</tr></thead><tbody>{"".join(body_rows)}</tbody></table></div>'


def risk_badge(level: str) -> str:
    label = esc(level)
    return f'<span class="risk risk-{label.lower()}">{label}</span>'


def relation_badge(relation: str) -> str:
    label = RELATION_LABELS.get(relation, relation)
    return f'<span class="relation relation-{esc(relation)}">{esc(label)}</span>'


def bar_list(
    counter: Counter,
    limit: int = 8,
    empty_text: str = "无。",
    link_prefix: str | None = None,
    link_map: dict[str, str] | None = None,
) -> str:
    items = [(name, count) for name, count in counter.most_common(limit) if count > 0]
    if not items:
        return f'<p class="empty">{esc(empty_text)}</p>'
    max_count = max(count for _, count in items) or 1
    rows = []
    for name, count in items:
        width = max(4, int(count / max_count * 100))
        href = (link_map or {}).get(str(name))
        if not href and link_prefix:
            href = f"#{slug_id(link_prefix, name)}"
        content = (
            f'<div class="bar-label" title="{esc(name)}">{esc(name)}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{width}%"></div></div>'
            f'<div class="bar-count">{count}</div>'
        )
        if href:
            rows.append(f'<a class="bar-row bar-row-link" href="{esc(href)}" title="点击查看{esc(name)}明细">{content}</a>')
        else:
            rows.append(f'<div class="bar-row">{content}</div>')
    return "\n".join(rows)


CHART_COLORS = ["#2563eb", "#0f766e", "#b45309", "#b42318", "#7c3aed", "#157347", "#c2410c", "#475467"]


def donut_chart(counter: Counter, limit: int = 6, empty_text: str = "无。", link_map: dict[str, str] | None = None) -> str:
    items = [(str(name), count) for name, count in counter.most_common(limit) if count > 0]
    if not items:
        return f'<p class="empty">{esc(empty_text)}</p>'
    total = sum(count for _, count in items)
    if total <= 0:
        return f'<p class="empty">{esc(empty_text)}</p>'
    start = 0.0
    segments = []
    legend = []
    for idx, (name, count) in enumerate(items):
        color = CHART_COLORS[idx % len(CHART_COLORS)]
        span = count / total * 100
        end = start + span
        segments.append(f"{color} {start:.2f}% {end:.2f}%")
        href = (link_map or {}).get(name)
        content = (
            f'<span class="dot" style="background:{color}"></span>'
            f'<span class="legend-label" title="{esc(name)}">{esc(name)}</span>'
            f'<span class="legend-value">{count}</span>'
            f'<span class="legend-rate">{count / total * 100:.0f}%</span>'
        )
        if href:
            legend.append(f'<a class="donut-legend-row donut-legend-row-link" href="{esc(href)}" title="点击查看{esc(name)}明细">{content}</a>')
        else:
            legend.append(f'<div class="donut-legend-row">{content}</div>')
        start = end
    return (
        '<div class="donut-wrap">'
        f'<div class="donut" style="background: conic-gradient({", ".join(segments)});"><div><strong>{total}</strong><span>合计</span></div></div>'
        f'<div class="donut-legend">{"".join(legend)}</div>'
        '</div>'
    )


def compact_counter_links(counter: Counter, link_map: dict[str, str] | None = None, limit: int = 8) -> str:
    items = [(str(name), count) for name, count in counter.most_common(limit) if count > 0]
    if not items:
        return '<p class="empty">无。</p>'
    cells = []
    for name, count in items:
        href = (link_map or {}).get(name)
        cells.append(metric_chip_html(name, count, href=href, title=f"点击查看{name}明细" if href else name))
    return f'<div class="metric-chips">{"".join(cells)}</div>'


def event_matches_target(event: AuditEvent, target: str) -> bool:
    target = str(target).lower()
    values = event.recipients + event.target_domains + event.targets
    return any(target == str(value).lower() or target in str(value).lower() for value in values)


def reason_matches_event(reason: str, event: AuditEvent) -> bool:
    names = leadership_file_names(event)
    if reason == "二维/三维设计图纸":
        return is_design_event(event) or any(extension(name) in DESIGN_EXTS for name in names)
    if reason == "设计图纸后缀":
        return is_design_event(event)
    if reason == "三维模型":
        return is_three_d_model_event(event)
    if reason in {"二维/CAD图纸", "DWG二维图纸"}:
        return is_two_d_cad_event(event)
    if reason == "PCB/电气设计":
        return is_pcb_ecad_event(event)
    if reason.startswith(("敏感附件名称:", "敏感关键词:")):
        keywords = [item for item in reason.split(":", 1)[-1].split(",") if item]
        hits = set(event_leadership_keyword_hits(event))
        return any(keyword in hits for keyword in keywords)
    if reason == "压缩包":
        return any(extension(name) in ARCHIVE_EXTS for name in names)
    if reason == "个人邮箱域名":
        return "个人邮箱域名" in event.reasons
    if reason == "外部目标":
        return "外部收件域名" in event.reasons or "外部上传/下载地址" in event.reasons
    if reason == "大文件":
        return "大文件" in event.reasons
    if reason == "超大文件":
        return "超大文件" in event.reasons
    if reason == "IM附件外发":
        return event.topic == "im_audit"
    return reason in event.reasons


def pagination_script() -> str:
    return """
  <script>
    (function () {
      function initPager(wrap) {
        var pageSize = parseInt(wrap.getAttribute("data-page-size") || "0", 10);
        var rows = Array.prototype.slice.call(wrap.querySelectorAll("tbody tr"));
        if (!pageSize || rows.length <= pageSize) {
          return;
        }
        var page = 0;
        var pageCount = Math.ceil(rows.length / pageSize);
        var pager = document.createElement("div");
        pager.className = "pager";
        var prev = document.createElement("button");
        prev.type = "button";
        prev.textContent = "上一页";
        var label = document.createElement("span");
        label.className = "pager-label";
        var next = document.createElement("button");
        next.type = "button";
        next.textContent = "下一页";
        pager.appendChild(prev);
        pager.appendChild(label);
        pager.appendChild(next);
        wrap.insertAdjacentElement("afterend", pager);

        function render() {
          var start = page * pageSize;
          var end = start + pageSize;
          rows.forEach(function (row, idx) {
            row.style.display = idx >= start && idx < end ? "" : "none";
          });
          label.textContent = "第 " + (page + 1) + " / " + pageCount + " 页，共 " + rows.length + " 条";
          prev.disabled = page <= 0;
          next.disabled = page >= pageCount - 1;
        }

        prev.addEventListener("click", function () {
          if (page > 0) {
            page -= 1;
            render();
          }
        });
        next.addEventListener("click", function () {
          if (page < pageCount - 1) {
            page += 1;
            render();
          }
        });
        render();
      }

      Array.prototype.forEach.call(document.querySelectorAll(".table-wrap[data-page-size]"), initPager);

      function clamp(value, min, max) {
        return Math.max(min, Math.min(max, value));
      }

      function matrixLeafCount(table) {
        var explicit = parseInt(table.getAttribute("data-matrix-data-cols") || "0", 10);
        if (explicit > 0) {
          return explicit;
        }
        var secondHeader = table.querySelector("thead tr:nth-child(2)");
        return secondHeader ? secondHeader.children.length : 0;
      }

      function setPx(table, name, value) {
        table.style.setProperty(name, Math.max(1, Math.round(value)) + "px");
      }

      function distributeWidths(total, minimums, weights) {
        var minTotal = minimums.reduce(function (sum, item) { return sum + item; }, 0);
        if (total <= minTotal) {
          return minimums.slice();
        }
        var extra = total - minTotal;
        var weightTotal = weights.reduce(function (sum, item) { return sum + item; }, 0) || 1;
        return minimums.map(function (min, idx) {
          return min + extra * (weights[idx] / weightTotal);
        });
      }

      function sumWidths(widths) {
        return widths.reduce(function (sum, item) { return sum + item; }, 0);
      }

      function capWidths(widths, maximums) {
        return widths.map(function (value, idx) {
          return Math.min(value, maximums[idx]);
        });
      }

      function adaptOrganizationMatrix(table) {
        var wrap = table.closest(".channel-matrix-wrap") || table.parentElement;
        if (!wrap) {
          return;
        }
        var width = Math.max(760, Math.floor(wrap.clientWidth || 0));
        var dataCols = matrixLeafCount(table);
        if (!dataCols) {
          return;
        }
        var totalWidth = width >= 1280 ? 46 : 42;
        var numberMin = width >= 1280 ? 32 : 30;
        var numberComfort = width >= 1500 ? 48 : width >= 1200 ? 44 : 40;
        var labelMin = width >= 1280 ? 166 : 146;
        var labelMax = width >= 1500 ? 224 : width >= 1200 ? 206 : 188;
        var numberTarget = clamp(Math.floor((width - labelMin - totalWidth - 2) / dataCols), numberMin, numberComfort);
        var numberArea = dataCols * numberTarget;
        var labelWidth = clamp(width - numberArea - totalWidth - 2, labelMin, labelMax);
        var numberWidth = clamp(Math.floor((width - labelWidth - totalWidth - 2) / dataCols), numberMin, numberComfort);
        var tableWidth = labelWidth + dataCols * numberWidth + totalWidth + 2;
        if (tableWidth < width) {
          var extra = width - tableWidth;
          var growNumber = Math.min(numberComfort - numberWidth, extra / dataCols);
          if (growNumber > 0) {
            numberWidth += growNumber;
            extra -= growNumber * dataCols;
          }
          if (extra > 0) {
            labelWidth += Math.min(labelMax - labelWidth, extra);
          }
          tableWidth = labelWidth + dataCols * numberWidth + totalWidth + 2;
        }
        setPx(table, "--org-col-width", labelWidth);
        setPx(table, "--matrix-number-col-width", numberWidth);
        setPx(table, "--matrix-total-col-width", totalWidth);
        table.style.width = Math.floor(width) + "px";
      }

      function adaptTerminalMatrix(table) {
        var wrap = table.closest(".channel-matrix-wrap") || table.parentElement;
        if (!wrap) {
          return;
        }
        var width = Math.max(960, Math.floor(wrap.clientWidth || 0));
        var dataCols = matrixLeafCount(table);
        if (!dataCols) {
          return;
        }
        var rankWidth = 34;
        var totalWidth = 52;
        var numberMin = 36;
        var numberComfort = width >= 1500 ? 58 : width >= 1200 ? 52 : 44;
        var numberWidth = numberMin;
        var minimums = [92, 76, 70, 94, 112];
        var maximums = [146, 116, 104, 118, 142];
        var weights = [1.05, 0.85, 0.75, 0.85, 1.05];
        var minIdentityTotal = sumWidths(minimums);
        var maxIdentityTotal = sumWidths(maximums);
        var fixed = rankWidth + totalWidth + dataCols * numberWidth + 2;
        var identityAvailable = width - fixed;
        if (identityAvailable > minIdentityTotal) {
          var identityTarget = clamp(Math.floor(width * 0.34), minIdentityTotal, maxIdentityTotal);
          var numberRoom = Math.floor((width - rankWidth - totalWidth - identityTarget - 2) / dataCols);
          numberWidth = clamp(numberRoom, numberMin, numberComfort);
          fixed = rankWidth + totalWidth + dataCols * numberWidth + 2;
          identityAvailable = width - fixed;
        }
        var identityWidths = capWidths(distributeWidths(Math.max(identityAvailable, minIdentityTotal), minimums, weights), maximums);
        var tableWidth = rankWidth + sumWidths(identityWidths) + dataCols * numberWidth + totalWidth + 2;
        if (tableWidth < width) {
          var extra = width - tableWidth;
          for (var i = 0; i < identityWidths.length && extra > 0; i += 1) {
            var growIdentity = Math.min(maximums[i] - identityWidths[i], extra * 0.18);
            if (growIdentity > 0) {
              identityWidths[i] += growIdentity;
              extra -= growIdentity;
            }
          }
          if (extra > 0) {
            numberWidth += extra / dataCols;
          }
          tableWidth = rankWidth + sumWidths(identityWidths) + dataCols * numberWidth + totalWidth + 2;
        }
        setPx(table, "--terminal-rank-width", rankWidth);
        setPx(table, "--terminal-company-width", identityWidths[0]);
        setPx(table, "--terminal-department-width", identityWidths[1]);
        setPx(table, "--terminal-person-width", identityWidths[2]);
        setPx(table, "--terminal-ip-width", identityWidths[3]);
        setPx(table, "--terminal-mac-width", identityWidths[4]);
        setPx(table, "--matrix-number-col-width", numberWidth);
        setPx(table, "--matrix-total-col-width", totalWidth);
        table.style.width = Math.floor(width) + "px";
      }

      function adaptMatrices() {
        Array.prototype.forEach.call(document.querySelectorAll("table.organization-matrix"), adaptOrganizationMatrix);
        Array.prototype.forEach.call(document.querySelectorAll("table.terminal-matrix"), adaptTerminalMatrix);
      }

      var resizeTimer = null;
      function scheduleAdaptMatrices() {
        if (resizeTimer) {
          window.cancelAnimationFrame(resizeTimer);
        }
        resizeTimer = window.requestAnimationFrame(adaptMatrices);
      }

      adaptMatrices();
      window.addEventListener("resize", scheduleAdaptMatrices);
      if (window.ResizeObserver) {
        var observer = new ResizeObserver(scheduleAdaptMatrices);
        Array.prototype.forEach.call(document.querySelectorAll(".channel-matrix-wrap"), function (wrap) {
          observer.observe(wrap);
        });
      }
    })();
  </script>"""


def event_identity(event: AuditEvent) -> tuple[str, str, str, str, str]:
    return (
        event.resolved_person or event.person or "unknown",
        event_company_label(event),
        event_department_label(event),
        event.client_name or "-",
        event.client_ip or "-",
    )


def local_ts(event: AuditEvent, tz: timezone) -> datetime | None:
    return event.ts.astimezone(tz) if event.ts else None


def is_deep_night(local: datetime) -> bool:
    local_time = local.time()
    return local_time >= DEEP_NIGHT_START or local_time < DEEP_NIGHT_END


def is_high_signal_event(event: AuditEvent) -> bool:
    names = behavior_file_names(event)
    exts = {extension(name) for name in names}
    return (
        event.priority == PRIORITY_ACTION
        or bool(exts & (DESIGN_EXTS | ARCHIVE_EXTS))
        or bool(event_leadership_keyword_hits(event))
        or any(reason in event.reasons for reason in ["个人邮箱域名", "网盘/高风险外联目标", "大文件", "超大文件"])
    )


def is_abnormal_time(event: AuditEvent, tz: timezone) -> bool:
    local = local_ts(event, tz)
    if not local:
        return False
    if is_deep_night(local):
        return True
    return local.weekday() >= 5 and is_high_signal_event(event)


def behavior_file_names(event: AuditEvent) -> list[str]:
    names = leadership_file_names(event) or non_image_file_names(event.file_names)
    return list(dict.fromkeys(names))


def sample_file_label(events: list[AuditEvent], max_len: int = 72) -> HtmlCell:
    names: list[str] = []
    for event in events:
        for name in behavior_file_names(event):
            if name not in names:
                names.append(name)
    return tooltip_cell(summarize_file_names(names, max_len=max_len), full_file_names(names))


def sample_target_label(events: list[AuditEvent], max_len: int = 60) -> HtmlCell:
    targets: list[str] = []
    for event in events:
        for value in event.recipients or event.target_domains or event.targets:
            if value and value not in targets:
                targets.append(value)
    display = "; ".join(targets[:3]) if targets else "-"
    if len(targets) > 3:
        display += f"; +{len(targets) - 3}"
    if len(display) > max_len:
        display = display[: max_len - 3] + "..."
    return tooltip_cell(display, "; ".join(targets) if targets else "-")


def event_target_values(event: AuditEvent) -> list[str]:
    return list(dict.fromkeys([value for value in (event.recipients or event.target_domains or event.targets) if value]))


def event_domain_values(event: AuditEvent) -> list[str]:
    domains: list[str] = []
    for value in event.target_domains:
        if value:
            domains.append(value.lower().strip("."))
    for value in event.targets + event.recipients:
        domain = email_domain(value) or host_domain(value)
        if domain:
            domains.append(domain.lower().strip("."))
    return list(dict.fromkeys([domain for domain in domains if domain]))


def event_has_personal_or_cloud_target(event: AuditEvent) -> bool:
    domains = event_domain_values(event)
    return any(domain in PERSONAL_EMAIL_DOMAINS for domain in domains) or has_high_risk_destination(domains)


def total_file_size(events: list[AuditEvent]) -> int:
    return sum(event.file_size or 0 for event in events)


def best_concentrated_window(
    events: list[AuditEvent],
    window_minutes: int,
    min_events: int,
    min_high_signal_events: int = 0,
    min_total_size: int = 0,
) -> tuple[tuple[int, int, int, int], list[AuditEvent]] | None:
    ordered = sorted(
        [event for event in events if event.ts],
        key=lambda event: event.ts or datetime.min.replace(tzinfo=timezone.utc),
    )
    left = 0
    best: tuple[tuple[int, int, int, int], list[AuditEvent]] | None = None
    for right, event in enumerate(ordered):
        right_ts = event.ts or datetime.min.replace(tzinfo=timezone.utc)
        while left <= right:
            left_ts = ordered[left].ts or datetime.min.replace(tzinfo=timezone.utc)
            if right_ts - left_ts <= timedelta(minutes=window_minutes):
                break
            left += 1
        window = ordered[left : right + 1]
        high_signal_count = sum(1 for item in window if is_high_signal_event(item))
        size_sum = total_file_size(window)
        if len(window) < min_events or high_signal_count < min_high_signal_events or size_sum < min_total_size:
            continue
        action_count = sum(1 for item in window if item.priority == PRIORITY_ACTION)
        target_count = len({value for item in window for value in event_target_values(item)})
        score_sum = sum(item.priority_score for item in window)
        rank = (action_count, high_signal_count, size_sum, score_sum + len(window) + target_count)
        if best is None or rank > best[0]:
            best = (rank, window)
    return best


def best_split_like_window(events: list[AuditEvent]) -> tuple[tuple[int, int, int, int], list[AuditEvent]] | None:
    ordered = sorted(
        [event for event in events if event.ts and event.file_size and event.file_size > 0],
        key=lambda event: event.ts or datetime.min.replace(tzinfo=timezone.utc),
    )
    left = 0
    best: tuple[tuple[int, int, int, int], list[AuditEvent]] | None = None
    for right, event in enumerate(ordered):
        right_ts = event.ts or datetime.min.replace(tzinfo=timezone.utc)
        while left <= right:
            left_ts = ordered[left].ts or datetime.min.replace(tzinfo=timezone.utc)
            if right_ts - left_ts <= timedelta(minutes=SPLIT_TRANSFER_WINDOW_MINUTES):
                break
            left += 1
        window = ordered[left : right + 1]
        if len(window) < 4:
            continue
        sizes = sorted([item.file_size or 0 for item in window if item.file_size and item.file_size > 0])
        if len(sizes) < 4:
            continue
        median = sizes[len(sizes) // 2]
        if median <= 0:
            continue
        similar_count = sum(1 for value in sizes if abs(value - median) <= max(128 * 1024, median * 0.15))
        small_piece_count = sum(1 for value in sizes if value <= 10 * 1024 * 1024)
        if similar_count < 4 and small_piece_count < 5:
            continue
        action_count = sum(1 for item in window if item.priority == PRIORITY_ACTION)
        high_signal_count = sum(1 for item in window if is_high_signal_event(item))
        rank = (action_count, high_signal_count, len(window), total_file_size(window))
        if best is None or rank > best[0]:
            best = (rank, window)
    return best


def best_multi_channel_window(events: list[AuditEvent]) -> tuple[tuple[int, int, int, int], list[AuditEvent]] | None:
    ordered = sorted(
        [event for event in events if event.ts],
        key=lambda event: event.ts or datetime.min.replace(tzinfo=timezone.utc),
    )
    left = 0
    best: tuple[tuple[int, int, int, int], list[AuditEvent]] | None = None
    for right, event in enumerate(ordered):
        right_ts = event.ts or datetime.min.replace(tzinfo=timezone.utc)
        while left <= right:
            left_ts = ordered[left].ts or datetime.min.replace(tzinfo=timezone.utc)
            if right_ts - left_ts <= timedelta(minutes=RISKY_TARGET_WINDOW_MINUTES):
                break
            left += 1
        window = ordered[left : right + 1]
        channels = {item.topic for item in window}
        high_signal_count = sum(1 for item in window if is_high_signal_event(item))
        if len(channels) < 2 or len(window) < 2 or (len(window) < 3 and high_signal_count == 0):
            continue
        action_count = sum(1 for item in window if item.priority == PRIORITY_ACTION)
        rank = (action_count, high_signal_count, len(channels), sum(item.priority_score for item in window) + len(window))
        if best is None or rank > best[0]:
            best = (rank, window)
    return best


def time_window_label(events: list[AuditEvent], tz: timezone) -> str:
    times = [local_ts(event, tz) for event in events if local_ts(event, tz)]
    if not times:
        return "-"
    start = min(times).strftime("%m-%d %H:%M")
    end = max(times).strftime("%m-%d %H:%M")
    return start if start == end else f"{start} 至 {end}"


def best_concentrated_abnormal_window(events: list[AuditEvent], tz: timezone) -> tuple[tuple[int, int, int, int], list[AuditEvent]] | None:
    ordered = sorted(
        [event for event in events if is_abnormal_time(event, tz)],
        key=lambda event: event.ts or datetime.min.replace(tzinfo=timezone.utc),
    )
    left = 0
    best: tuple[tuple[int, int, int, int], list[AuditEvent]] | None = None
    for right, event in enumerate(ordered):
        right_ts = event.ts or datetime.min.replace(tzinfo=timezone.utc)
        while left <= right:
            left_ts = ordered[left].ts or datetime.min.replace(tzinfo=timezone.utc)
            if right_ts - left_ts <= timedelta(minutes=ABNORMAL_BURST_WINDOW_MINUTES):
                break
            left += 1
        window = ordered[left : right + 1]
        action_count = sum(1 for item in window if item.priority == PRIORITY_ACTION)
        high_signal_count = sum(1 for item in window if is_high_signal_event(item))
        target_count = len({value for item in window for value in (item.recipients or item.target_domains or item.targets) if value})
        score_sum = sum(item.priority_score for item in window)
        concentrated = len(window) >= ABNORMAL_BURST_MIN_EVENTS or (
            len(window) >= ABNORMAL_BURST_HIGH_SIGNAL_MIN_EVENTS and high_signal_count > 0
        )
        if not concentrated:
            continue
        rank = (action_count, high_signal_count, len(window), score_sum + target_count)
        if best is None or rank > best[0]:
            best = (rank, window)
    return best


def build_behavior_anomaly_rows(events: list[AuditEvent], tz: timezone) -> dict[str, list[list[Any]]]:
    filtered_events = [
        event
        for event in events
        if event.ts
        and event.topic in {"mail_audit", "im_audit", "file_audit"}
        and event.file_names
        and event.recipient_relation in EXTERNAL_RELATIONS | {"unknown"}
        and (
            is_high_signal_event(event)
            or event_has_personal_or_cloud_target(event)
            or bool(event.file_size and event.file_size >= 10 * 1024 * 1024)
        )
    ]
    grouped: dict[tuple[str, str, str, str, str], list[AuditEvent]] = defaultdict(list)
    for event in filtered_events:
        grouped[event_identity(event)].append(event)
    debug_timing(f"behavior filtered={len(filtered_events)} groups={len(grouped)}")

    def behavior_rank(event: AuditEvent) -> tuple[int, int, int, int, float]:
        ts = event.ts.timestamp() if event.ts else 0.0
        return (
            1 if is_leadership_focus_event(event) else 0,
            1 if event.priority == PRIORITY_ACTION else 0,
            int(event.priority_score or 0),
            int(event.file_size or 0),
            ts,
        )

    def group_rank(group: list[AuditEvent]) -> tuple[int, int, int, int, int, int, float]:
        latest_ts = max((event.ts.timestamp() for event in group if event.ts), default=0.0)
        return (
            sum(1 for event in group if is_leadership_focus_event(event)),
            sum(1 for event in group if event.priority == PRIORITY_ACTION),
            sum(1 for event in group if is_high_signal_event(event)),
            len(group),
            max((int(event.priority_score or 0) for event in group), default=0),
            sum(int(event.file_size or 0) for event in group),
            latest_ts,
        )

    behavior_groups: list[tuple[tuple[str, str, str, str, str], list[AuditEvent]]] = []
    for key, group in grouped.items():
        if len(group) > BEHAVIOR_MAX_GROUP_EVENTS:
            # This only bounds behavior-pattern mining for a very chatty identity.
            # Event/asset detail pages below still render every matched row.
            group = sorted(group, key=behavior_rank, reverse=True)[:BEHAVIOR_MAX_GROUP_EVENTS]
        behavior_groups.append((key, group))
    if len(behavior_groups) > BEHAVIOR_MAX_GROUPS:
        behavior_groups = sorted(behavior_groups, key=lambda item: group_rank(item[1]), reverse=True)[:BEHAVIOR_MAX_GROUPS]
    debug_timing(
        f"behavior mining groups={len(behavior_groups)} max_group_events={BEHAVIOR_MAX_GROUP_EVENTS} max_groups={BEHAVIOR_MAX_GROUPS}"
    )

    burst_candidates = []
    archive_design_candidates = []
    for key, group in behavior_groups:
        ordered = sorted(group, key=lambda event: event.ts or datetime.min.replace(tzinfo=timezone.utc))
        left = 0
        best_burst: tuple[tuple[int, int, int, int], list[AuditEvent]] | None = None
        best_archive: tuple[tuple[int, int, int, int], list[AuditEvent]] | None = None
        for right, event in enumerate(ordered):
            right_ts = event.ts or datetime.min.replace(tzinfo=timezone.utc)
            while left <= right:
                left_ts = ordered[left].ts or datetime.min.replace(tzinfo=timezone.utc)
                if right_ts - left_ts <= timedelta(minutes=30):
                    break
                left += 1
            window = ordered[left : right + 1]
            action_count = sum(1 for item in window if item.priority == PRIORITY_ACTION)
            target_count = len({value for item in window for value in (item.recipients or item.target_domains or item.targets) if value})
            score_sum = sum(item.priority_score for item in window)
            rank = (action_count, score_sum, len(window), target_count)
            if len(window) >= 5 or (len(window) >= 3 and action_count >= 1):
                if best_burst is None or rank > best_burst[0]:
                    best_burst = (rank, window)
            intent_window = [
                item
                for item in window
                if any(extension(name) in DESIGN_EXTS | ARCHIVE_EXTS for name in behavior_file_names(item))
            ]
            if len(intent_window) >= 3:
                intent_rank = (action_count, score_sum, len(intent_window), target_count)
                if best_archive is None or intent_rank > best_archive[0]:
                    best_archive = (intent_rank, intent_window)
        if best_burst:
            burst_candidates.append((best_burst[0], key, best_burst[1]))
        if best_archive:
            archive_design_candidates.append((best_archive[0], key, best_archive[1]))

    offhour_candidates = []
    spread_candidates = []
    risky_target_candidates = []
    volume_candidates = []
    split_candidates = []
    same_file_candidates = []
    multi_channel_candidates = []
    for key, group in behavior_groups:
        abnormal_window = best_concentrated_abnormal_window(group, tz)
        if abnormal_window:
            offhour_candidates.append((abnormal_window[0], key, abnormal_window[1]))
        risky_target_window = best_concentrated_window(
            [event for event in group if event_has_personal_or_cloud_target(event)],
            RISKY_TARGET_WINDOW_MINUTES,
            min_events=2,
            min_high_signal_events=1,
        )
        if risky_target_window:
            risky_target_candidates.append((risky_target_window[0], key, risky_target_window[1]))
        volume_window = best_concentrated_window(
            [event for event in group if event.file_size and event.file_size > 0],
            VOLUME_WINDOW_MINUTES,
            min_events=2,
            min_total_size=VOLUME_BURST_MIN_BYTES,
        )
        if volume_window:
            volume_candidates.append((volume_window[0], key, volume_window[1]))
        target_groups: dict[str, list[AuditEvent]] = defaultdict(list)
        for event in group:
            targets = event_target_values(event) or ["unknown"]
            for target in targets:
                target_groups[normalize_key(target)].append(event)
        for target_group in target_groups.values():
            split_window = best_split_like_window(target_group)
            if split_window:
                split_candidates.append((split_window[0], key, split_window[1]))
                break
        file_groups: dict[str, list[AuditEvent]] = defaultdict(list)
        for event in group:
            for name in behavior_file_names(event):
                if extension(name) in DESIGN_EXTS or leadership_keyword_hits([name]):
                    file_groups[normalize_key(name)].append(event)
        best_same_file: tuple[tuple[int, int, int, int], list[AuditEvent]] | None = None
        for file_group in file_groups.values():
            targets = {value for item in file_group for value in event_target_values(item)}
            if len(file_group) >= 2 and len(targets) >= 2:
                action_count = sum(1 for item in file_group if item.priority == PRIORITY_ACTION)
                high_signal_count = sum(1 for item in file_group if is_high_signal_event(item))
                rank = (action_count, high_signal_count, len(targets), len(file_group))
                if best_same_file is None or rank > best_same_file[0]:
                    best_same_file = (rank, file_group)
        if best_same_file:
            same_file_candidates.append((best_same_file[0], key, best_same_file[1]))
        multi_channel_window = best_multi_channel_window(group)
        if multi_channel_window:
            multi_channel_candidates.append((multi_channel_window[0], key, multi_channel_window[1]))
        targets = {value for event in group for value in (event.recipients or event.target_domains or event.targets) if value}
        if len(targets) >= 4 or (len(targets) >= 3 and len(group) >= 5):
            spread_candidates.append(((sum(1 for item in group if item.priority == PRIORITY_ACTION), len(targets), len(group)), key, group))

    def identity_cells(key: tuple[str, str, str, str, str]) -> list[Any]:
        person, company, dept, terminal, ip = key
        return [company, dept, person, tooltip_cell(f"{terminal} / {ip}", f"{terminal} / {ip}")]

    def suppress_normal_procurement_noise(group: list[AuditEvent]) -> bool:
        return bool(group) and all(is_normal_procurement_inquiry_event(event) for event in group)

    def filtered_noise_candidates(candidates: list[tuple[tuple[int, int, int, int], tuple[str, str, str, str, str], list[AuditEvent]]]):
        return [item for item in sorted(candidates, reverse=True) if not suppress_normal_procurement_noise(item[2])]

    burst_rows = []
    for _, key, group in filtered_noise_candidates(burst_candidates):
        burst_rows.append(
            [
                "30分钟集中外发",
                time_window_label(group, tz),
                *identity_cells(key),
                str(len(group)),
                str(sum(1 for event in group if event.priority == PRIORITY_ACTION)),
                sample_target_label(group),
                sample_file_label(group),
            ]
        )

    offhour_rows = []
    for _, key, group in filtered_noise_candidates(offhour_candidates):
        offhour_rows.append(
            [
                "异常时间集中外发",
                time_window_label(group, tz),
                *identity_cells(key),
                str(len(group)),
                str(sum(1 for event in group if event.priority == PRIORITY_ACTION)),
                sample_target_label(group),
                sample_file_label(group),
            ]
        )

    spread_rows = []
    for _, key, group in filtered_noise_candidates(spread_candidates):
        targets = {value for event in group for value in (event.recipients or event.target_domains or event.targets) if value}
        spread_rows.append(
            [
                "接收方扩散",
                time_window_label(group, tz),
                *identity_cells(key),
                str(len(group)),
                str(len(targets)),
                sample_target_label(group),
                sample_file_label(group),
            ]
        )

    archive_design_rows = []
    for _, key, group in filtered_noise_candidates(archive_design_candidates):
        archive_design_rows.append(
            [
                "压缩包/图纸集中",
                time_window_label(group, tz),
                *identity_cells(key),
                str(len(group)),
                str(sum(1 for event in group if event.priority == PRIORITY_ACTION)),
                sample_target_label(group),
                sample_file_label(group),
            ]
        )

    risky_target_rows = []
    for _, key, group in filtered_noise_candidates(risky_target_candidates):
        risky_target_rows.append(
            [
                "个人邮箱/高风险目标集中",
                time_window_label(group, tz),
                *identity_cells(key),
                str(len(group)),
                str(sum(1 for event in group if event.priority == PRIORITY_ACTION)),
                sample_target_label(group),
                sample_file_label(group),
            ]
        )

    volume_rows = []
    for _, key, group in sorted(volume_candidates, reverse=True):
        volume_rows.append(
            [
                "大体量集中外发",
                time_window_label(group, tz),
                *identity_cells(key),
                str(len(group)),
                size_label(total_file_size(group)),
                sample_target_label(group),
                sample_file_label(group),
            ]
        )

    split_rows = []
    for _, key, group in sorted(split_candidates, reverse=True):
        split_rows.append(
            [
                "疑似分片/定长外发",
                time_window_label(group, tz),
                *identity_cells(key),
                str(len(group)),
                size_label(total_file_size(group)),
                sample_target_label(group),
                sample_file_label(group),
            ]
        )

    same_file_rows = []
    for _, key, group in sorted(same_file_candidates, reverse=True):
        targets = {value for event in group for value in event_target_values(event)}
        same_file_rows.append(
            [
                "同名敏感文件多目标",
                time_window_label(group, tz),
                *identity_cells(key),
                str(len(group)),
                str(len(targets)),
                sample_target_label(group),
                sample_file_label(group),
            ]
        )

    multi_channel_rows = []
    for _, key, group in sorted(multi_channel_candidates, reverse=True):
        channels = {event_channel_label(event) for event in group}
        multi_channel_rows.append(
            [
                "多通道外发尝试",
                time_window_label(group, tz),
                *identity_cells(key),
                str(len(group)),
                str(len(channels)),
                sample_target_label(group),
                sample_file_label(group),
            ]
        )

    return {
        "burst": burst_rows,
        "offhour": offhour_rows,
        "spread": spread_rows,
        "archive_design": archive_design_rows,
        "risky_target": risky_target_rows,
        "volume": volume_rows,
        "split": split_rows,
        "same_file": same_file_rows,
        "multi_channel": multi_channel_rows,
    }


def detail_page_filename(args: argparse.Namespace, keyword: str) -> str:
    return sidecar_page_filename(args, "kw", keyword)


def sidecar_page_filename(args: argparse.Namespace, prefix: str, value: Any) -> str:
    output_name = Path(str(getattr(args, "output", "") or "tianqing_leadership_report.html")).name
    stem = Path(output_name).stem or "tianqing_leadership_report"
    return f"{stem}_{slug_id(prefix, value)}.html"


class SidecarReportStore:
    def __init__(self, output_dir: Path | None = None) -> None:
        self.output_dir = output_dir
        self._items: dict[str, str] = {}
        self._written: set[str] = set()

    def __setitem__(self, filename: str, content: str) -> None:
        content = apply_html_display_aliases(content)
        if self.output_dir is None:
            self._items[filename] = content
            return
        sidecar_path = self.output_dir / filename
        sidecar_path.write_text(content, encoding="utf-8")
        self._written.add(filename)
        print(f"Wrote {sidecar_path}")

    def __len__(self) -> int:
        if self.output_dir is None:
            return len(self._items)
        return len(self._written)

    def items(self) -> Any:
        return self._items.items()


def detail_hero_html(
    title: str,
    eyebrow: str,
    report_period: str,
    source_label: str,
    note: str,
    metric_label: str,
    metric_value: Any,
) -> str:
    return f"""
    <section class="detail-hero">
      <div class="detail-hero-main">
        <div class="detail-eyebrow">{esc(eyebrow)}</div>
        <h1>{esc(title)}</h1>
        <p>{esc(note)}</p>
        <div class="detail-meta-grid">
          <span>统计周期：{esc(report_period)}</span>
          <span>数据来源：{esc(source_label)}</span>
        </div>
      </div>
      <aside class="detail-hero-aside">
        <span>{esc(metric_label)}</span>
        <strong>{esc(metric_value)}</strong>
        <a class="detail-back" href="#" onclick="history.back(); return false;">返回主报告</a>
      </aside>
    </section>
"""


def detail_metric_chips(chips: list[tuple[Any, ...]]) -> str:
    cells = []
    for chip in chips:
        label = chip[0] if len(chip) > 0 else ""
        value = chip[1] if len(chip) > 1 else ""
        title = chip[2] if len(chip) > 2 else None
        href = chip[3] if len(chip) > 3 else None
        cells.append(metric_chip_html(label, value, href=href or None, title=title))
    return '<section class="detail-metrics">' + "".join(cells) + "</section>"


def event_mac_label(
    event: AuditEvent,
    asset_by_terminal: dict[tuple[str, str], AssetSnapshot] | None = None,
) -> str:
    asset = asset_for_event(event, asset_by_terminal or {})
    if asset and asset.client_mac:
        return asset.client_mac
    return "-"


def event_identity_cells(
    event: AuditEvent,
    tz: timezone,
    asset_by_terminal: dict[tuple[str, str], AssetSnapshot] | None = None,
) -> list[Any]:
    return [
        format_ts(event.ts, tz),
        event_company_label(event),
        event_department_label(event),
        event.resolved_person,
        event.client_ip or "-",
        event_mac_label(event, asset_by_terminal),
    ]


def mail_event_detail_rows(
    detail_events: list[AuditEvent],
    tz: timezone,
    keyword: str | None = None,
    asset_by_terminal: dict[tuple[str, str], AssetSnapshot] | None = None,
) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for event in detail_events:
        rows.append(
            event_identity_cells(event, tz, asset_by_terminal)
            + [
                tooltip_cell(event_subject_label(event), event.mail_subject or "-"),
                sender_mailbox_cell(event),
                sender_mailbox_type_cell(event),
                tooltip_cell(summarize_targets(event), full_targets(event)),
                detail_event_names(event, keyword=keyword),
                event_object_cell(event),
                size_label(event.file_size),
            ]
        )
    return rows


def is_im_detail_event(event: AuditEvent) -> bool:
    return event.topic == "im_audit" or (event.topic == "file_audit" and event.channel == "应用发送/传输")


def event_detail_mode(detail_events: list[AuditEvent]) -> str:
    if not detail_events:
        return "common"
    if all(event.topic == "mail_audit" for event in detail_events):
        return "mail"
    if all(is_im_detail_event(event) for event in detail_events):
        return "im"
    if all(is_peripheral_copy_event(event) for event in detail_events):
        return "peripheral"
    if all(event.topic != "mail_audit" for event in detail_events):
        return "file"
    return "common"


def detail_event_names(event: AuditEvent, keyword: str | None = None, max_len: int = 90) -> HtmlCell:
    names = event_display_file_names(event)
    if keyword:
        keyword_lower = keyword.lower()
        keyword_names = [name for name in names if keyword_lower in name.lower()]
        names = keyword_names or names
    title = full_file_names(names)
    if not names and event.file_exts:
        title = "原始日志未取到文件名；依据 file_exts 后缀字段：" + ",".join(event.file_exts)
    elif not names and event.mail_subject:
        title = "原始日志未取到附件名；可参考邮件主题：" + event.mail_subject
    return tooltip_cell(summarize_file_names(names, event.file_exts if not names else None, max_len=max_len), title)


def event_display_file_names(event: AuditEvent) -> list[str]:
    names = leadership_file_names(event)
    if names:
        return names
    return non_image_file_names(event.file_names)


def object_exts_for_bucket(bucket: str) -> set[str]:
    if bucket == "三维模型":
        return CONTROLLED_3D_EXTS
    if bucket == "DWG二维图纸":
        return CONTROLLED_2D_CAD_EXTS
    if bucket == "压缩包":
        return ARCHIVE_EXTS
    return set()


def event_object_cell(event: AuditEvent) -> HtmlCell:
    bucket = audit_matrix_bucket(event)
    display = bucket or design_category_label(event)
    if not display or display == "-":
        return tooltip_cell("-", "-")

    basis: list[str] = []
    if bucket in CRITICAL_DESIGN_LABELS:
        matched_names = [name for name in event.file_names if bucket in critical_design_labels_for_name(name)]
        if matched_names:
            basis.append("最高预警命名规则命中：" + "; ".join(matched_names[:5]))
        reason = CRITICAL_DESIGN_REASON_PREFIX + bucket
        if reason in event.reasons:
            basis.append(reason)
    ext_set = object_exts_for_bucket(bucket or "")
    if ext_set:
        matched_names = [name for name in event.file_names if extension(name) in ext_set]
        matched_exts = [ext for ext in event.file_exts if ext in ext_set]
        if matched_names:
            basis.append("文件名后缀命中：" + "; ".join(matched_names[:5]))
        elif matched_exts:
            basis.append("原始日志 file_exts 命中：" + ",".join(matched_exts))

    if bucket == "敏感名称":
        hits = event_leadership_keyword_hits(event)
        if hits:
            basis.append("命中关键词：" + ",".join(hits[:6]))
        subject_hits = leadership_keyword_hits([event.mail_subject]) if event.mail_subject else []
        file_hits = leadership_keyword_hits(non_image_file_names(event.file_names))
        sources = []
        if subject_hits:
            sources.append("邮件主题")
        if file_hits:
            sources.append("附件/文件名")
        if sources:
            basis.append("命中字段：" + "/".join(sources))

    if not basis and event.reasons:
        basis.append("规则原因：" + ";".join(prioritized_reasons(event.reasons)[:4]))
    if not basis:
        basis.append(display)
    return tooltip_cell(display, "；".join(basis))


def common_event_detail_rows(
    detail_events: list[AuditEvent],
    tz: timezone,
    keyword: str | None = None,
    channel_label: str = "通道",
    asset_by_terminal: dict[tuple[str, str], AssetSnapshot] | None = None,
) -> tuple[list[str], list[list[Any]], set[int]]:
    rows: list[list[Any]] = []
    for event in detail_events:
        rows.append(
            event_identity_cells(event, tz, asset_by_terminal)
            + [
                event_channel_label(event) if channel_label != "IM渠道" else im_channel_label(event),
                egress_judgement_cell(event),
                tooltip_cell(summarize_targets(event), full_targets(event)),
                detail_event_names(event, keyword=keyword),
                event_object_cell(event),
                size_label(event.file_size),
            ]
        )
    return (
        ["时间", "公司", "部门", "人员/账号", "IP地址", "MAC地址", channel_label, "外发判定", "接收方/目标", "文件", "资料类型", "大小"],
        rows,
        set(),
    )


def peripheral_event_detail_rows(
    detail_events: list[AuditEvent],
    tz: timezone,
    keyword: str | None = None,
    asset_by_terminal: dict[tuple[str, str], AssetSnapshot] | None = None,
) -> tuple[list[str], list[list[Any]], set[int]]:
    rows: list[list[Any]] = []
    for event in detail_events:
        media_label = summarize_targets(event) if has_target_value(event) else event_channel_label(event)
        media_title = f"动作：{event_channel_label(event)}；目标/介质：{full_targets(event)}"
        rows.append(
            event_identity_cells(event, tz, asset_by_terminal)
            + [
                tooltip_cell(media_label, media_title),
                detail_event_names(event, keyword=keyword),
                event_object_cell(event),
                size_label(event.file_size),
            ]
        )
    return (
        ["时间", "公司", "部门", "人员/账号", "IP地址", "MAC地址", "动作/介质", "文件", "资料类型", "大小"],
        rows,
        set(),
    )


def event_detail_table_html(
    detail_events: list[AuditEvent],
    tz: timezone,
    keyword: str | None = None,
    page_size: int = 20,
    asset_by_terminal: dict[tuple[str, str], AssetSnapshot] | None = None,
) -> str:
    mode = event_detail_mode(detail_events)
    if mode == "mail":
        return html_table(
            ["时间", "公司", "部门", "人员/账号", "IP地址", "MAC地址", "邮件主题", "发件箱", "发件箱类型", "收件方/目标", "文件", "资料类型", "大小"],
            mail_event_detail_rows(detail_events, tz, keyword=keyword, asset_by_terminal=asset_by_terminal),
            "events",
            raw_columns=set(),
            page_size=page_size,
        )
    if mode == "im":
        headers, rows, raw_columns = common_event_detail_rows(detail_events, tz, keyword=keyword, channel_label="IM渠道", asset_by_terminal=asset_by_terminal)
        return html_table(headers, rows, "events", raw_columns=raw_columns, page_size=page_size)
    if mode == "peripheral":
        headers, rows, raw_columns = peripheral_event_detail_rows(detail_events, tz, keyword=keyword, asset_by_terminal=asset_by_terminal)
        return html_table(headers, rows, "events", raw_columns=raw_columns, page_size=page_size)
    headers, rows, raw_columns = common_event_detail_rows(detail_events, tz, keyword=keyword, asset_by_terminal=asset_by_terminal)
    return html_table(headers, rows, "events", raw_columns=raw_columns, page_size=page_size)


def build_event_detail_page(
    title: str,
    detail_events: list[AuditEvent],
    args: argparse.Namespace,
    tz: timezone,
    report_period: str,
    source_label: str,
    note: str,
    keyword: str | None = None,
    metrics_html: str | None = None,
) -> str:
    ordered = sorted(detail_events, key=event_priority_sort_key)
    design_count = sum(1 for event in ordered if is_design_event(event))
    external_count = sum(1 for event in ordered if event.recipient_relation in EXTERNAL_RELATIONS)
    lookup_count = sum(1 for event in ordered if any(key.startswith(("search_id=", "download_file_key=", "file_id=")) for key in event.lookup_keys))
    metrics = metrics_html or detail_metric_chips(
        [
            ("总事件", len(ordered), "本页命中的全部事件数"),
            ("设计资料", design_count, "三维模型和 DWG 二维图纸等强管控设计资料"),
            ("明确外部", external_count, "接收方为外部/客户/供应商/合作方"),
            ("可回查", lookup_count, "包含 search_id、download_file_key 或 file_id"),
        ]
    )
    body = f"""
    {detail_hero_html(title, "审计明细", report_period, source_label, note, "事件数", len(ordered))}
    {metrics}
    <section id="event-list" class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Evidence List</span>
          <h2>事件清单</h2>
        </div>
        <span class="section-count">共 {len(ordered)} 条</span>
      </div>
      {event_detail_table_html(ordered, tz, keyword=keyword, page_size=20, asset_by_terminal=getattr(args, "asset_by_terminal", {}))}
    </section>
"""
    return html_detail_document(title, body)


def channel_focus_metric_chips(
    total_count: int,
    channel_rows: list[str],
    row_totals: Counter,
    row_links: dict[str, str],
) -> str:
    chips: list[tuple[Any, ...]] = [
        ("合计", total_count, "当前页重点事件，点击跳转事件清单", "#event-list"),
    ]
    for row_label in channel_rows:
        count = int(row_totals.get(row_label, 0) or 0)
        chips.append(
            (
                row_label,
                count,
                f"查看{row_label}通道重点事件",
                row_links.get(row_label, "") if count else "",
            )
        )
    return detail_metric_chips(chips)


def build_false_positive_detail_page(
    title: str,
    detail_events: list[AuditEvent],
    false_positive_reasons: dict[str, str],
    args: argparse.Namespace,
    tz: timezone,
    report_period: str,
    source_label: str,
    note: str,
) -> str:
    ordered = sorted(
        detail_events,
        key=lambda ev: (false_positive_reasons.get(ev.event_id, ""), ev.ts or datetime.min.replace(tzinfo=timezone.utc)),
    )
    base_headers, base_rows, _ = common_event_detail_rows(ordered, tz, asset_by_terminal=getattr(args, "asset_by_terminal", {}))
    rows = [[tooltip_cell(false_positive_reasons.get(event.event_id, "疑似误判"), false_positive_reasons.get(event.event_id, "疑似误判")), *row] for event, row in zip(ordered, base_rows)]
    reason_counts = Counter(false_positive_reasons.get(event.event_id, "疑似误判") for event in ordered)
    metrics = detail_metric_chips(
        [
            ("误判/噪音", len(ordered), "已从重点事件剔除的误判或低置信噪音"),
            ("FILEASSIST", reason_counts.get("FILEASSIST/文件助手自传，不属于外部接收方", 0), "企业微信文件助手自传"),
            ("重复伴随", reason_counts.get("应用发送伴随记录，与IM附件外发重复", 0), "file_audit 与 IM 附件外发重复"),
            ("缺接收方", reason_counts.get("应用发送无接收方，非图纸/非高危目标，缺少外发判定证据", 0), "应用发送日志缺接收方且非硬管控对象"),
        ]
    )
    body = f"""
    {detail_hero_html(title, "误判降噪明细", report_period, source_label, note, "记录数", len(ordered))}
    {metrics}
    <section class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">False Positive Review</span>
          <h2>误判/噪音清单</h2>
        </div>
        <span class="section-count">共 {len(ordered)} 条</span>
      </div>
      {html_table(["误判判断", *base_headers], rows, "events", raw_columns=set(), page_size=20)}
      <p class="note">误判降噪只影响重点报告口径，不删除原始 syslog、ClickHouse 审计底稿和可回查线索。</p>
    </section>
"""
    return html_detail_document(title, body)


BEHAVIOR_SECTION_META = {
    "burst": ("短时间集中外发", ["信号", "时间窗口", "公司", "部门", "人员/账号", "终端/IP", "事件数", "高风险", "接收方/目标", "文件样例"]),
    "offhour": ("异常时间集中外发", ["信号", "时间窗口", "公司", "部门", "人员/账号", "终端/IP", "事件数", "高风险", "接收方/目标", "文件样例"]),
    "risky_target": ("个人邮箱/高风险目标集中外发", ["信号", "时间窗口", "公司", "部门", "人员/账号", "终端/IP", "事件数", "高风险", "接收方/目标", "文件样例"]),
    "volume": ("大体量集中外发", ["信号", "时间窗口", "公司", "部门", "人员/账号", "终端/IP", "事件数", "总量", "接收方/目标", "文件样例"]),
    "split": ("疑似分片/定长外发", ["信号", "时间窗口", "公司", "部门", "人员/账号", "终端/IP", "事件数", "总量", "接收方/目标", "文件样例"]),
    "same_file": ("同名敏感文件多目标", ["信号", "时间窗口", "公司", "部门", "人员/账号", "终端/IP", "事件数", "接收方数", "接收方/目标", "文件样例"]),
    "multi_channel": ("多通道外发尝试", ["信号", "时间窗口", "公司", "部门", "人员/账号", "终端/IP", "事件数", "通道数", "接收方/目标", "文件样例"]),
    "spread": ("接收方扩散", ["信号", "时间窗口", "公司", "部门", "人员/账号", "终端/IP", "事件数", "接收方数", "接收方/目标", "文件样例"]),
    "archive_design": ("压缩包/图纸集中外发", ["信号", "时间窗口", "公司", "部门", "人员/账号", "终端/IP", "事件数", "高风险", "接收方/目标", "文件样例"]),
}


def build_behavior_detail_page(
    behavior_rows: dict[str, list[list[Any]]],
    report_period: str,
    source_label: str,
) -> str:
    sections = []
    for key, (label, headers) in BEHAVIOR_SECTION_META.items():
        rows = behavior_rows.get(key, [])
        sections.append(
            f"""
    <section class="detail-section behavior-detail-section" id="behavior-{esc(key)}">
      <div class="section-head">
        <div>
          <span class="section-kicker">Behavior Signal</span>
          <h2>{esc(label)}</h2>
        </div>
        <span class="section-count">{len(rows)} 组</span>
      </div>
      {html_table(headers, rows, "anomalies", page_size=20)}
    </section>
"""
        )
    total_groups = sum(len(rows) for rows in behavior_rows.values())
    active_sections = sum(1 for rows in behavior_rows.values() if rows)
    metrics = detail_metric_chips(
        [
            ("异常组数", total_groups, "全部规则发现的异常行为组"),
            ("命中类型", active_sections, "有数据的异常行为类型数"),
            ("集中外发", len(behavior_rows.get("burst", [])), "短时间集中外发线索"),
            ("接收方扩散", len(behavior_rows.get("spread", [])), "短周期内接收方明显扩散"),
            ("多通道尝试", len(behavior_rows.get("multi_channel", [])), "同一人员/终端出现多通道外发"),
        ]
    )
    body = f"""
    {detail_hero_html("行为异常线索详情", "规则异常明细", report_period, source_label, "以下为规则自动发现的集中外发、扩散、分片、多通道等线索；首页仅展示数量分布。", "异常组数", total_groups)}
    {metrics}
    {"".join(sections)}
"""
    return html_detail_document("行为异常线索详情", body)


def asset_detail_rows(assets: list[AssetSnapshot], tz: timezone, as_of: datetime) -> list[list[Any]]:
    ordered = sorted(
        assets,
        key=lambda asset: (
            -int(asset.recent_risk_events or 0),
            -(offline_days(asset, as_of) or 0),
            asset.observed_at or datetime.min.replace(tzinfo=timezone.utc),
            asset.client_name,
        ),
    )
    rows: list[list[Any]] = []
    for asset in ordered:
        rows.append(
            [
                asset.company or "-",
                asset.department or "-",
                asset.login_account or "-",
                asset.client_name or "-",
                asset.client_ip or "-",
                asset.client_mac or "-",
                tooltip_cell(asset.brand_model or "-", asset.brand_model or "-"),
                asset.board_serial_number or "-",
                asset.manufacture_date.isoformat() if asset.manufacture_date else "未知",
                asset_age_bucket(asset, as_of),
                asset_os_label(asset),
                str(asset.memory_mb or "-"),
                str(asset.sys_space_mb or "-"),
                asset.main_program_version or "未知",
                asset.patch_version or "未知",
                asset.virus_version or "未知",
                tooltip_cell(asset_online_label(asset, as_of), asset_online_label(asset, as_of)),
                format_ts(asset.last_online_time, tz) if asset.last_online_time else "-",
                format_ts(asset.observed_at, tz) if asset.observed_at else "-",
                str(asset.recent_risk_events or 0),
            ]
        )
    return rows


def build_asset_detail_page(
    title: str,
    assets: list[AssetSnapshot],
    args: argparse.Namespace,
    tz: timezone,
    report_period: str,
    source_label: str,
    note: str,
    as_of: datetime,
) -> str:
    rows = asset_detail_rows(assets, tz, as_of)
    offline_count = sum(1 for asset in assets if not asset.is_online)
    old_count = sum(1 for asset in assets if asset.manufacture_date and (as_of.date() - asset.manufacture_date).days >= 365 * 5)
    risk_count = sum(1 for asset in assets if int(asset.recent_risk_events or 0) > 0)
    metrics = detail_metric_chips(
        [
            ("终端数", len(assets), "本页纳入复核的风险资产数"),
            ("离线", offline_count, "天擎在线状态为离线的终端"),
            ("5年以上", old_count, "按出厂日期估算超过5年的设备"),
            ("近30天有风险", risk_count, "近30天存在外发/外设拷贝等风险事件"),
        ]
    )
    body = f"""
    {detail_hero_html(title, "资产风险明细", report_period, source_label + " + ClickHouse:tianqing.asset_observations", note, "终端数", len(assets))}
    {metrics}
    <section class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Asset Risk List</span>
          <h2>风险资产清单</h2>
        </div>
        <span class="section-count">共 {len(assets)} 台</span>
      </div>
      {html_table(["公司", "部门", "登录账号", "计算机名", "IP地址", "MAC", "型号", "主板序列号", "出厂日期", "设备年代", "操作系统", "内存MB", "系统盘剩余MB", "主程序", "补丁", "病毒库", "在线/离线", "最后在线", "最后观察", "近30天风险事件"], rows, "assets", page_size=20)}
    </section>
"""
    return html_detail_document(title, body)


def asset_analysis_html(
    analysis: AssetAnalysis,
    age_links: dict[str, str],
    online_links: dict[str, str],
    os_links: dict[str, str],
    virus_links: dict[str, str],
    patch_links: dict[str, str],
    main_links: dict[str, str],
    risk_links: dict[str, str],
) -> str:
    if not analysis.available:
        return f'<p class="empty">{esc(analysis.error or "资产分析暂无数据。")}</p>'
    parse_rate = (analysis.parsed_manufacture_dates / analysis.total_assets * 100) if analysis.total_assets else 0
    missing_link = risk_links.get("7天未观察到")
    offline_link = risk_links.get("当前离线终端")
    suspected_uninstall_link = risk_links.get("疑似已卸载")
    unknown_date_link = risk_links.get("未知出厂日期")
    summary_chips = "".join(
        [
            metric_chip_html("纳入分析终端", analysis.total_assets),
            metric_chip_html("本周期观察到", analysis.observed_in_period),
            metric_chip_html("出厂日期解析率", f"{parse_rate:.0f}%", href=unknown_date_link, title="点击查看未知出厂日期终端" if unknown_date_link else "出厂日期解析率"),
            metric_chip_html("当前离线终端", len(analysis.offline_assets), href=offline_link, title="点击查看当前离线终端" if offline_link else "当前离线终端"),
            metric_chip_html("7天未观察到", len(analysis.missing_assets), href=missing_link, title="点击查看7天未观察到终端" if missing_link else "7天未观察到"),
            metric_chip_html("疑似已卸载", len(analysis.suspected_uninstalled_assets), href=suspected_uninstall_link, title="点击查看疑似已卸载终端" if suspected_uninstall_link else "疑似已卸载"),
        ]
    )
    return f"""
      <div class="metric-chips">{summary_chips}</div>
      <div class="dashboard asset-dashboard">
        <div class="chart-panel">
          <h2>设备年代分布</h2>
          {donut_chart(analysis.age_counts, 5, link_map=age_links)}
        </div>
        <div class="chart-panel">
          <h2>操作系统分布</h2>
          {bar_list(analysis.os_counts, 8, link_map=os_links)}
        </div>
        <div class="chart-panel">
          <h2>在线状态/离线时长</h2>
          {donut_chart(analysis.online_counts, 6, link_map=online_links)}
          <p class="note">按天擎 online_info.is_online 与 last_time 统计；和“7天未观察到”不是同一口径。</p>
        </div>
        <div class="chart-panel">
          <h2>病毒库版本分布</h2>
          {bar_list(analysis.virus_counts, 8, link_map=virus_links)}
          <p class="note">当前最高版本：{esc(analysis.latest_virus_version or "未知")}</p>
        </div>
        <div class="chart-panel">
          <h2>补丁版本分布</h2>
          {bar_list(analysis.patch_counts, 8, link_map=patch_links)}
          <p class="note">当前最高版本：{esc(analysis.latest_patch_version or "未知")}</p>
        </div>
        <div class="chart-panel">
          <h2>主程序版本分布</h2>
          {bar_list(analysis.main_version_counts, 8, link_map=main_links)}
          <p class="note">当前最高版本：{esc(analysis.latest_main_version or "未知")}</p>
        </div>
        <div class="chart-panel">
          <h2>资产风险线索</h2>
          {compact_counter_links(analysis.risk_counts, risk_links, 8)}
          <p class="note">仅列风险资产详情，不展示全量资产台账；“疑似已卸载”按 30 天未观察且无同硬件重装记录统计。</p>
        </div>
      </div>
"""


def executive_asset_analysis_html(analysis: AssetAnalysis, risk_links: dict[str, str]) -> str:
    if not analysis.available:
        return f'<p class="empty">{esc(analysis.error or "资产分析暂无数据。")}</p>'
    chips = "".join(
        [
            metric_chip_html("纳入资产", analysis.total_assets),
            metric_chip_html("5年以上设备", len(analysis.old_device_assets), href=risk_links.get("5年以上设备"), title="点击查看5年以上设备"),
            metric_chip_html("老旧系统", len(analysis.old_os_assets), href=risk_links.get("老旧系统"), title="点击查看老旧系统"),
            metric_chip_html("版本落后/未知", len(analysis.lagging_version_assets), href=risk_links.get("版本落后/未知"), title="点击查看版本落后或未知终端"),
            metric_chip_html("离线超7天", len(analysis.long_offline_assets), href=risk_links.get("天擎离线超7天"), title="点击查看离线超7天终端"),
            metric_chip_html("疑似已卸载", len(analysis.suspected_uninstalled_assets), href=risk_links.get("疑似已卸载"), title="点击查看疑似已卸载终端"),
            metric_chip_html("消失前有风险", len(analysis.high_attention_missing_assets), href=risk_links.get("消失前有风险行为"), title="点击查看消失前有风险行为终端"),
        ]
    )
    return f"""
      <div class="metric-chips">{chips}</div>
      <p class="note">首页仅展示需要管理关注的资产风险，不展示全量资产台账和版本分布；点击指标进入风险资产详情。</p>
"""


def html_detail_document(title: str, body_html: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)}</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --paper: #ffffff;
      --ink: #172033;
      --muted: #667085;
      --line: #d9e0ea;
      --blue: #2563eb;
      --amber: #b45309;
      --red: #b42318;
      --green: #157347;
      --font-sans: "MiSans", "HarmonyOS Sans SC", "Alibaba PuHuiTi 3.0", "Source Han Sans SC", "Noto Sans CJK SC", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei UI", "Microsoft YaHei", -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    html {{
      -webkit-font-smoothing: antialiased;
      text-rendering: optimizeLegibility;
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: var(--font-sans);
      font-size: 14px;
      line-height: 1.58;
      letter-spacing: 0;
    }}
    body, table, button, input, textarea, select {{
      font-family: var(--font-sans);
    }}
    .report {{
      width: 100%;
      min-height: 100vh;
      margin: 0;
      padding: 24px 32px 42px;
      background: var(--paper);
    }}
    h1 {{ margin: 0 0 8px; font-size: 28px; font-weight: 700; line-height: 1.25; letter-spacing: 0; }}
    h2 {{ font-weight: 700; line-height: 1.35; letter-spacing: 0; }}
    h3 {{ font-weight: 680; line-height: 1.4; letter-spacing: 0; }}
    .meta {{ color: var(--muted); font-size: 13px; line-height: 1.7; margin-bottom: 20px; }}
    a {{ color: #175cd3; text-decoration: none; border-bottom: 1px solid rgba(23, 92, 211, 0.28); }}
    .table-link {{ font-weight: 700; }}
    .table-wrap {{ overflow-x: auto; border: 1px solid var(--line); border-radius: 8px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; line-height: 1.55; background: #fff; }}
    th, td {{ padding: 9px 10px; border-bottom: 1px solid #e7ecf3; text-align: left; vertical-align: top; white-space: nowrap; }}
    th {{ background: #f7f9fc; color: #475467; font-weight: 700; padding-top: 12px; padding-bottom: 12px; text-align: center; vertical-align: middle; }}
    td {{ color: #344054; }}
    tr:last-child td {{ border-bottom: 0; }}
    table.events {{
      font-size: 12px;
      line-height: 1.45;
    }}
    table.events th {{
      padding: 10px 8px;
      color: #516173;
      font-size: 11px;
      font-weight: 800;
      background: #f3f8ff;
    }}
    table.events td {{
      padding: 8px 8px;
      color: #344054;
      font-weight: 520;
      vertical-align: middle;
    }}
    .events td:nth-child(10), .events td:nth-child(11), .events td:nth-child(14), .events td:nth-child(16), .events td:nth-child(18) {{
      max-width: 250px;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .risk, .relation {{
      display: inline-flex;
      align-items: center;
      min-height: 22px;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
    }}
    .risk-high {{ color: var(--red); background: #fef3f2; }}
    .risk-medium {{ color: var(--amber); background: #fffaeb; }}
    .risk-low {{ color: var(--green); background: #ecfdf3; }}
    .risk-action {{ color: var(--red); background: #fef3f2; }}
    .risk-review {{ color: var(--amber); background: #fffaeb; }}
    .risk-general {{ color: #175cd3; background: #eff6ff; }}
    .risk-watch {{ color: var(--green); background: #ecfdf3; }}
    .relation-external, .relation-customer, .relation-partner, .relation-supplier {{ color: #175cd3; background: #eff6ff; }}
    .relation-unknown {{ color: var(--amber); background: #fffaeb; }}
    .note {{ color: var(--muted); font-size: 13px; line-height: 1.65; }}
    .empty {{ color: var(--muted); margin: 8px 0; }}    .pager {{ display: flex; justify-content: flex-end; align-items: center; gap: 10px; margin: 8px 0 2px; color: var(--muted); font-size: 12px; }}
    .pager button {{ border: 1px solid var(--line); border-radius: 6px; background: #fff; color: #344054; padding: 4px 10px; cursor: pointer; }}
    .pager button:disabled {{ color: #98a2b3; cursor: default; background: #f7f9fc; }}
    body {{
      background:
        radial-gradient(circle at 8% 0%, rgba(8, 116, 111, 0.14), transparent 28%),
        linear-gradient(180deg, #e9eef5 0%, #f7f9fc 380px, #eef2f7 100%);
      color: #172033;
    }}
    .report {{
      width: 100%;
      max-width: none;
      padding: 30px 38px 56px;
      background: transparent;
    }}
    .detail-hero {{
      position: relative;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 260px;
      gap: 26px;
      align-items: stretch;
      min-height: 218px;
      margin: 0 0 18px;
      padding: 30px;
      overflow: hidden;
      border-radius: 16px;
      border: 1px solid rgba(255, 255, 255, 0.18);
      background: linear-gradient(135deg, #111c2c 0%, #17314a 48%, #0d756e 100%);
      box-shadow: 0 24px 55px rgba(17, 28, 44, 0.18);
      color: #fff;
    }}
    .detail-hero::after {{
      content: "";
      position: absolute;
      right: -120px;
      bottom: -150px;
      width: 380px;
      height: 380px;
      border-radius: 50%;
      border: 70px solid rgba(255, 255, 255, 0.055);
      pointer-events: none;
    }}
    .detail-hero-main {{
      position: relative;
      z-index: 1;
      display: grid;
      align-content: center;
      max-width: 1100px;
    }}
    .detail-eyebrow {{
      width: fit-content;
      margin-bottom: 12px;
      padding: 5px 10px;
      border: 1px solid rgba(255, 255, 255, 0.18);
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.09);
      color: #b9f2e7;
      font-size: 12px;
      font-weight: 760;
    }}
    .detail-hero h1 {{
      max-width: 980px;
      margin: 0 0 12px;
      color: #fff;
      font-size: 34px;
      font-weight: 760;
      line-height: 1.2;
    }}
    .detail-hero p {{
      max-width: 980px;
      margin: 0;
      color: rgba(255, 255, 255, 0.76);
      font-size: 14px;
      line-height: 1.78;
    }}
    .detail-meta-grid {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }}
    .detail-meta-grid span {{
      display: inline-flex;
      align-items: center;
      min-height: 30px;
      padding: 5px 10px;
      border: 1px solid rgba(255, 255, 255, 0.16);
      border-radius: 7px;
      background: rgba(255, 255, 255, 0.08);
      color: rgba(255, 255, 255, 0.78);
      font-size: 12px;
      line-height: 1.4;
    }}
    .detail-hero-aside {{
      position: relative;
      z-index: 1;
      display: grid;
      align-content: space-between;
      gap: 16px;
      min-height: 158px;
      padding: 18px;
      border: 1px solid rgba(255, 255, 255, 0.18);
      border-radius: 12px;
      background: rgba(255, 255, 255, 0.10);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.12);
      backdrop-filter: blur(10px);
    }}
    .detail-hero-aside span {{
      color: rgba(255, 255, 255, 0.70);
      font-size: 13px;
      font-weight: 700;
    }}
    .detail-hero-aside strong {{
      color: #fff;
      font-size: 46px;
      line-height: 1;
      font-weight: 760;
      font-variant-numeric: tabular-nums;
    }}
    .detail-back {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 36px;
      width: fit-content;
      padding: 7px 13px;
      border: 1px solid rgba(255, 255, 255, 0.22);
      border-radius: 8px;
      background: #ffffff;
      color: #132238;
      font-size: 13px;
      font-weight: 760;
      text-decoration: none;
      box-shadow: 0 8px 18px rgba(0, 0, 0, 0.12);
    }}
    .detail-metrics {{
      display: grid;
      grid-template-columns: repeat(5, minmax(140px, 1fr));
      gap: 12px;
      margin: 0 0 18px;
    }}
    .metric-chip {{
      display: grid;
      gap: 8px;
      min-height: 88px;
      padding: 15px 16px;
      border: 1px solid #dbe3ee;
      border-radius: 12px;
      background: linear-gradient(180deg, #ffffff 0%, #fbfcff 100%);
      box-shadow: 0 10px 24px rgba(23, 32, 51, 0.06);
    }}
    .metric-chip span {{
      color: #667085;
      font-size: 13px;
      font-weight: 680;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .metric-chip strong {{
      color: #172033;
      font-size: 28px;
      line-height: 1;
      font-weight: 760;
      font-variant-numeric: tabular-nums;
    }}
    .metric-chip-link {{
      text-decoration: none;
      border-bottom: 0;
    }}
    .detail-section {{
      margin: 18px 0 0;
      padding: 20px;
      border: 1px solid #dbe3ee;
      border-radius: 14px;
      background: rgba(255, 255, 255, 0.96);
      box-shadow: 0 14px 34px rgba(23, 32, 51, 0.07);
    }}
    .behavior-detail-section {{
      scroll-margin-top: 16px;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      margin-bottom: 14px;
    }}
    .section-head h2 {{
      margin: 2px 0 0;
      color: #172033;
      font-size: 20px;
      font-weight: 760;
      line-height: 1.35;
    }}
    .section-kicker {{
      display: block;
      color: #0f766e;
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    .section-count {{
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 4px 10px;
      border: 1px solid #d7e3f8;
      border-radius: 999px;
      background: #f2f7ff;
      color: #175cd3;
      font-size: 12px;
      font-weight: 760;
      white-space: nowrap;
    }}
    a {{
      color: #175cd3;
      text-decoration: none;
      border-bottom: 1px solid rgba(23, 92, 211, 0.22);
    }}
    .table-link {{
      color: #175cd3;
      font-weight: 760;
      border-bottom-color: rgba(23, 92, 211, 0.36);
    }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid #dbe3ee;
      border-radius: 12px;
      background: #fff;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.8);
    }}
    table {{
      width: 100%;
      min-width: 1120px;
      border-collapse: separate;
      border-spacing: 0;
      background: #fff;
      color: #344054;
      font-size: 13px;
      line-height: 1.58;
    }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid #edf1f6;
      border-right: 1px solid #f1f4f8;
      text-align: left;
      vertical-align: top;
      white-space: nowrap;
    }}
    th:last-child, td:last-child {{
      border-right: 0;
    }}
    th {{
      position: sticky;
      top: 0;
      z-index: 1;
      background: #f6f8fb;
      color: #475467;
      font-size: 12px;
      font-weight: 800;
      box-shadow: inset 0 -1px 0 #dbe3ee;
    }}
    tbody tr:nth-child(even) td {{
      background: #fcfdff;
    }}
    tbody tr:hover td {{
      background: #f3f8ff;
    }}
    td {{
      color: #344054;
    }}
    tr:last-child td {{
      border-bottom: 0;
    }}
    table.events {{
      font-size: 12px;
      line-height: 1.45;
    }}
    table.events th {{
      padding: 10px 8px;
      color: #516173;
      font-size: 11px;
      font-weight: 800;
      background: #f3f8ff;
    }}
    table.events td {{
      padding: 8px 8px;
      color: #344054;
      font-weight: 520;
      vertical-align: middle;
    }}
    th {{
      text-align: center;
      vertical-align: middle;
    }}
    .channel-matrix-wrap {{
      overflow-x: auto;
      border: 1px solid #dbe3ee;
      border-radius: 12px;
      background: #fff;
      box-shadow: 0 10px 24px rgba(23, 32, 51, 0.05);
    }}
    .channel-matrix {{
      width: 100%;
      min-width: 780px;
      border-collapse: collapse;
      table-layout: fixed;
    }}
    .channel-matrix th,
    .channel-matrix td {{
      text-align: center;
      vertical-align: middle;
      padding: 12px 10px;
    }}
    .channel-matrix thead th {{
      background: #f3f8ff;
      color: #344054;
      font-size: 12px;
      font-weight: 800;
    }}
    .channel-matrix .channel-name {{
      width: 180px;
      text-align: left;
      color: #172033;
      background: #fbfdff;
      font-weight: 760;
    }}
    .matrix-count,
    .matrix-total,
    .detail-count,
    .terminal-count {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 32px;
      min-height: 24px;
      border-radius: 999px;
      padding: 2px 8px;
      background: #f8fafc;
      color: #667085;
      font-weight: 820;
      font-variant-numeric: tabular-nums;
      text-decoration: none;
      border-bottom: 0;
      transition: box-shadow 0.15s ease, transform 0.15s ease;
    }}
    .matrix-count,
    .matrix-total {{
      min-width: 42px;
      min-height: 28px;
      padding: 4px 10px;
    }}
    .matrix-count.matrix-heat-low,
    .matrix-total.matrix-heat-low,
    .detail-count-low,
    .terminal-count-low {{
      color: #067647;
      background: #ecfdf3;
    }}
    .matrix-count.matrix-heat-mid,
    .matrix-total.matrix-heat-mid,
    .detail-count-mid,
    .terminal-count-mid {{
      color: #3f6212;
      background: #f7fee7;
    }}
    .matrix-count.matrix-heat-high,
    .matrix-total.matrix-heat-high,
    .detail-count-high,
    .terminal-count-high {{
      color: #c2410c;
      background: #fff7ed;
    }}
    .matrix-count.matrix-heat-critical,
    .matrix-total.matrix-heat-critical,
    .detail-count-critical,
    .terminal-count-critical {{
      color: #be123c;
      background: #fff1f2;
    }}
    .detail-count-link,
    .terminal-count-link {{
      display: inline-flex;
      text-decoration: none;
      border-bottom: 0;
    }}
    .matrix-count:hover,
    .matrix-total:hover,
    .detail-count-link:hover .detail-count,
    .terminal-count-link:hover .terminal-count {{
      box-shadow: 0 8px 16px rgba(37, 99, 235, 0.12);
      transform: translateY(-1px);
    }}
    .matrix-zero {{
      color: #a7b2c2;
      font-variant-numeric: tabular-nums;
    }}
    .organization-matrix-wrap {{
      overflow-x: hidden;
      border-radius: 13px;
    }}
    .organization-matrix {{
      min-width: 0;
    }}
    .organization-matrix-wide {{
      width: auto;
      min-width: 100%;
      table-layout: fixed;
      font-size: 12px;
    }}
    .organization-matrix col.org-label-col {{
      width: var(--org-col-width, 176px);
    }}
    .organization-matrix col.matrix-number-col {{
      width: var(--matrix-number-col-width, 30px);
    }}
    .organization-matrix col.matrix-total-col {{
      width: var(--matrix-total-col-width, 46px);
    }}
    .organization-matrix-wide th,
    .organization-matrix-wide td {{
      padding: 6px 2px;
      text-align: center;
      vertical-align: middle;
    }}
    .organization-matrix-wide thead th {{
      font-size: 10px;
      line-height: 1.15;
      padding-top: 9px;
      padding-bottom: 9px;
      white-space: normal;
    }}
    .organization-matrix-wide .channel-name {{
      width: var(--org-col-width, 260px);
      padding: 7px 8px;
    }}
    .organization-matrix-wide .org-matrix-channel {{
      background: #eaf3ff;
      border-left: 1px solid #d8e4f2;
      border-right: 1px solid #d8e4f2;
      text-align: center;
    }}
    .org-matrix-label {{
      display: grid;
      gap: 2px;
      min-width: 0;
    }}
    .org-matrix-label strong {{
      display: -webkit-box;
      -webkit-box-orient: vertical;
      -webkit-line-clamp: 2;
      overflow: hidden;
      color: #122033;
      font-size: 12px;
      font-weight: 820;
      line-height: 1.35;
      text-overflow: ellipsis;
      white-space: normal;
    }}
    .org-matrix-label small {{
      overflow: hidden;
      color: #64748b;
      font-size: 11px;
      font-weight: 650;
      line-height: 1.35;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .org-matrix-label-link {{
      display: block;
      color: inherit;
      text-decoration: none;
      border-bottom: 0;
    }}
    .organization-matrix .matrix-count,
    .organization-matrix .matrix-total {{
      min-width: 26px;
      min-height: 22px;
      padding: 2px 6px;
      font-size: 12px;
    }}
    .terminal-matrix-wrap {{
      overflow-x: hidden;
      border-radius: 13px;
    }}
    .terminal-matrix {{
      width: auto;
      min-width: 0;
      table-layout: fixed;
      font-size: 12px;
    }}
    .terminal-matrix col.terminal-rank-colgroup {{
      width: var(--terminal-rank-width, 34px);
    }}
    .terminal-matrix col.terminal-company-colgroup {{
      width: var(--terminal-company-width, 96px);
    }}
    .terminal-matrix col.terminal-department-colgroup {{
      width: var(--terminal-department-width, 78px);
    }}
    .terminal-matrix col.terminal-person-colgroup {{
      width: var(--terminal-person-width, 72px);
    }}
    .terminal-matrix col.terminal-ip-colgroup {{
      width: var(--terminal-ip-width, 96px);
    }}
    .terminal-matrix col.terminal-mac-colgroup {{
      width: var(--terminal-mac-width, 116px);
    }}
    .terminal-matrix col.matrix-number-col {{
      width: var(--matrix-number-col-width, 30px);
    }}
    .terminal-matrix col.matrix-total-col {{
      width: var(--matrix-total-col-width, 46px);
    }}
    .terminal-matrix th,
    .terminal-matrix td {{
      padding: 9px 3px;
      line-height: 1.28;
      text-align: center;
      vertical-align: middle;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .terminal-matrix thead th {{
      font-size: 10.5px;
      line-height: 1.15;
      padding-top: 10px;
      padding-bottom: 10px;
      white-space: normal;
    }}
    .terminal-matrix .terminal-matrix-channel {{
      background: #eaf3ff;
      border-left: 1px solid #d8e4f2;
      border-right: 1px solid #d8e4f2;
      font-weight: 840;
    }}
    .terminal-matrix .terminal-rank-col,
    .terminal-matrix .terminal-matrix-rank {{
      width: var(--terminal-rank-width, 34px);
    }}
    .terminal-matrix .terminal-company-col {{
      width: var(--terminal-company-width, 96px);
    }}
    .terminal-matrix .terminal-department-col {{
      width: var(--terminal-department-width, 78px);
    }}
    .terminal-matrix .terminal-person-col {{
      width: var(--terminal-person-width, 72px);
    }}
    .terminal-matrix .terminal-ip-col {{
      width: var(--terminal-ip-width, 96px);
    }}
    .terminal-matrix .terminal-mac-col {{
      width: var(--terminal-mac-width, 116px);
    }}
    .terminal-matrix .terminal-total-col {{
      width: var(--matrix-total-col-width, 46px);
    }}
    .terminal-matrix-company,
    .terminal-matrix-department,
    .terminal-matrix-person {{
      text-align: left !important;
      color: #172033;
      font-weight: 720;
    }}
    .terminal-matrix-ip,
    .terminal-matrix-mac {{
      text-align: left !important;
      color: #344054;
      font-weight: 500;
    }}
    .terminal-matrix .matrix-count,
    .terminal-matrix .matrix-total {{
      min-width: 24px;
      min-height: 22px;
      padding: 2px 6px;
      font-size: 12px;
    }}
    table.terminal-risk {{
      font-family: var(--font-sans);
      font-size: 12px;
      line-height: 1.45;
      table-layout: fixed;
    }}
    table.terminal-risk th,
    table.terminal-risk td {{
      padding: 8px 7px;
      vertical-align: middle;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      text-align: center;
    }}
    table.terminal-risk td:nth-child(2),
    table.terminal-risk td:nth-child(3),
    table.terminal-risk td:nth-child(4),
    table.terminal-risk td:nth-child(5),
    table.terminal-risk td:nth-child(6) {{
      text-align: left;
    }}
    table.terminal-risk .terminal-risk-group-row th {{
      background: #eaf3ff;
      border-bottom: 1px solid #d8e4f2;
      text-align: center;
      color: #243245;
      font-size: 11px;
      font-weight: 840;
    }}
    table.terminal-risk .terminal-risk-sub-row th {{
      background: #f6f9ff;
      color: #516173;
      font-size: 10px;
      font-weight: 820;
      line-height: 1.18;
      white-space: normal;
      padding: 7px 5px;
      text-align: center;
    }}
    table.terminal-risk .terminal-group-disposition,
    table.terminal-risk .terminal-group-object,
    table.terminal-risk .terminal-group-process,
    table.terminal-risk .terminal-group-time {{
      border-left: 1px solid #d8e4f2;
      border-right: 1px solid #d8e4f2;
    }}
    .events td:nth-child(4), .events td:nth-child(5), .events td:nth-child(6),
    .events td:nth-child(8), .events td:nth-child(9), .events td:nth-child(11),
    .events td:nth-child(13), .assets td:nth-child(7), .assets td:nth-child(8),
    .anomalies td:nth-child(9), .anomalies td:nth-child(10) {{
      max-width: 320px;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .events td:nth-child(2), .events td:nth-child(14), .assets td:nth-child(12),
    .assets td:nth-child(13), .assets td:nth-child(20) {{
      font-variant-numeric: tabular-nums;
    }}
    .risk, .relation {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 24px;
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
      border: 1px solid transparent;
    }}
    .risk-high {{
      color: #b42318;
      background: #fff2f0;
      border-color: #ffd8d2;
    }}
    .risk-medium {{
      color: #b25e09;
      background: #fff7e8;
      border-color: #fedf89;
    }}
    .risk-low {{
      color: #0f766e;
      background: #eaf8f5;
      border-color: #c8eee5;
    }}
    .risk-action {{
      color: #b42318;
      background: #fff2f0;
      border-color: #ffd8d2;
    }}
    .risk-review {{
      color: #b25e09;
      background: #fff7e8;
      border-color: #fedf89;
    }}
    .risk-general {{
      color: #175cd3;
      background: #eff6ff;
      border-color: #cfe2ff;
    }}
    .risk-watch {{
      color: #0f766e;
      background: #eaf8f5;
      border-color: #c8eee5;
    }}
    .relation-external, .relation-customer, .relation-partner, .relation-supplier {{
      color: #175cd3;
      background: #eff6ff;
      border-color: #cfe2ff;
    }}
    .relation-internal {{
      color: #157347;
      background: #edfdf3;
      border-color: #ccefdc;
    }}
    .relation-unknown {{
      color: #b25e09;
      background: #fff8e8;
      border-color: #fedf89;
    }}
    .note, .empty {{
      color: #667085;
      font-size: 13px;
      line-height: 1.7;
    }}
    .note {{
      margin: 12px 0 0;
      padding: 9px 11px;
      border: 1px solid #e4eaf2;
      border-radius: 8px;
      background: #fafcff;
    }}
    .empty {{
      margin: 8px 0;
      padding: 12px 14px;
      border: 1px dashed #dbe3ee;
      border-radius: 10px;
      background: #fbfcff;
    }}
    .grid-2 {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }}
    .panel {{
      min-width: 0;
      border: 1px solid #e4eaf2;
      border-radius: 12px;
      padding: 15px;
      background: #fbfcff;
    }}
    .panel h3 {{
      margin: 0 0 12px;
      color: #172033;
      font-size: 16px;
    }}
    .donut-wrap {{
      display: grid;
      grid-template-columns: 150px minmax(0, 1fr);
      gap: 14px;
      align-items: center;
    }}
    .donut {{
      width: 142px;
      height: 142px;
      display: grid;
      place-items: center;
      border-radius: 50%;
    }}
    .donut > div {{
      width: 86px;
      height: 86px;
      display: grid;
      place-items: center;
      border-radius: 50%;
      background: #fff;
      box-shadow: inset 0 0 0 1px #e4eaf2;
    }}
    .donut strong, .donut span {{
      display: block;
      text-align: center;
    }}
    .donut strong {{
      color: #172033;
      font-size: 22px;
      line-height: 1;
    }}
    .donut span {{
      color: #667085;
      font-size: 12px;
    }}
    .donut-legend {{
      display: grid;
      gap: 7px;
      min-width: 0;
    }}
    .donut-legend-row {{
      display: grid;
      grid-template-columns: 12px minmax(0, 1fr) 42px 42px;
      gap: 8px;
      align-items: center;
      font-size: 13px;
    }}
    .dot {{
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
    }}
    .legend-label {{
      overflow: hidden;
      color: #344054;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .legend-value, .legend-rate {{
      color: #667085;
      text-align: right;
      font-variant-numeric: tabular-nums;
    }}
    .org-tags {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      min-width: 0;
    }}
    .org-tags span {{
      display: inline-flex;
      max-width: 100%;
      border: 1px solid #d7e3f8;
      border-radius: 999px;
      padding: 3px 8px;
      background: #f6f9ff;
      color: #31435a;
      font-size: 12px;
      font-weight: 720;
      line-height: 1.35;
      white-space: nowrap;
    }}
    .org-tags-link {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      border-bottom: 0;
      color: inherit;
    }}
    .org-profile-tags {{
      margin: 4px 0 10px;
    }}
    .pager {{
      justify-content: flex-end;
      gap: 9px;
      margin: 12px 0 0;
      color: #667085;
      font-size: 12px;
    }}
    .pager button {{
      min-height: 30px;
      border: 1px solid #dbe3ee;
      border-radius: 8px;
      background: #fff;
      color: #344054;
      padding: 5px 12px;
      font-weight: 700;
      box-shadow: 0 4px 10px rgba(23, 32, 51, 0.05);
    }}
    .pager button:not(:disabled):hover {{
      border-color: #9fc1ff;
      color: #175cd3;
      background: #f5f9ff;
    }}
    .pager button:disabled {{
      color: #98a2b3;
      background: #f7f9fc;
      box-shadow: none;
    }}    @media (max-width: 980px) {{
      .report {{
        padding: 18px 14px 36px;
      }}
      .detail-hero {{
        grid-template-columns: 1fr;
        min-height: auto;
        padding: 22px;
      }}
      .detail-hero h1 {{
        font-size: 28px;
      }}
      .detail-hero-aside {{
        min-height: auto;
      }}
      .detail-metrics {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }}
      .section-head {{
        flex-direction: column;
      }}
    }}
    @media (max-width: 620px) {{
      .detail-metrics {{
        grid-template-columns: 1fr;
      }}
      .detail-meta-grid {{
        display: grid;
      }}
      .detail-hero h1 h1 {{
        font-size: 24px;
      }}
    }}
  </style>
</head>
<body>
  <main class="report">
    {body_html}
  </main>
  {pagination_script()}
</body>
</html>"""


def wecom_directory_summary(args: argparse.Namespace) -> str:
    meta = getattr(args, "wecom_directory_meta", None) or {}
    if not meta or not meta.get("enabled"):
        return "企业微信目录：未启用。"
    if meta.get("ok"):
        source_label = {"remote": "实时", "cache": "缓存", "stale-cache": "历史缓存"}.get(str(meta.get("source")), str(meta.get("source") or ""))
        mode = "权威模式，未命中按外部/待判定线索保留" if getattr(args, "wecom_directory_authoritative_effective", False) else "只确认内部，未命中仍按待判定处理"
        return (
            f"企业微信目录：{source_label}读取 {meta.get('count', 0)} 名内部成员、"
            f"{meta.get('departments', 0)} 个部门；用于确认内部 IM 接收方，并作为责任人公司、部门来源，"
            f"未匹配人员公司显示“{UNMATCHED_COMPANY_LABEL}”、部门显示“{UNMATCHED_DEPARTMENT_LABEL}”，{mode}。"
        )
    error = str(meta.get("error") or "unknown")
    return f"企业微信目录：读取失败，未命中不作外部判定；错误：{compact_id(error, 80)}。"


def plain_cell(value: Any) -> str:
    if isinstance(value, HtmlCell):
        text = value.title or value.value
    else:
        text = str(value if value is not None else "")
    text = re.sub(r"<[^>]+>", "", text)
    return html_lib.unescape(" ".join(text.split()))


def sh_quote(value: str) -> str:
    return shlex.quote(value)


CHANNEL_MATRIX_COLUMNS = [
    CRITICAL_STRUCTURE_LABEL,
    CRITICAL_ELECTRICAL_LABEL,
    "三维模型",
    "DWG二维图纸",
    "敏感名称",
    "压缩包",
]
CHANNEL_MATRIX_BASE_ROWS = [
    "邮件外发",
    "IM附件",
    "外部站点上传",
    "外设拷贝",
]
CHANNEL_MATRIX_SHORT_LABELS = {
    "邮件外发": "邮件外发",
    "IM附件": "IM",
    "外部站点上传": "外部站点",
    "外设拷贝": "外设",
}

TREND_COLORS = [
    "#1d4ed8",  # blue
    "#ea580c",  # orange
    "#047857",  # emerald
    "#7c3aed",  # violet
    "#dc2626",  # red
    "#0891b2",  # cyan
    "#be185d",  # magenta
    "#334155",  # slate
    "#65a30d",  # lime
    "#a16207",  # amber-brown
]
TREND_WINDOW_DAYS = [7, 30, 90]
DEFAULT_TREND_WINDOW_DAYS = 30
RISK_OVERVIEW_HISTORY_DAYS = [90, 180]
THREE_D_RENAME_TRACK_DAYS = 180
THREE_D_RENAME_CONFIRMED_CONFIDENCES = {"强匹配", "可信匹配"}
THREE_D_RENAME_OUTBOUND_CHANNELS = {"邮件外发", "IM附件", "外部站点上传", "外设拷贝"}
RISK_OVERVIEW_OBJECT_ORDER = CHANNEL_MATRIX_COLUMNS
RISK_OVERVIEW_OBJECT_IMPORTANCE = {
    CRITICAL_STRUCTURE_LABEL: "最高预警",
    CRITICAL_ELECTRICAL_LABEL: "最高预警",
    "三维模型": "最高关注",
    "DWG二维图纸": "重点关注",
    "敏感名称": "重点关注",
    "压缩包": "重点关注",
}
TREND_GRANULARITY_LABELS = {
    "hour": "按小时",
    "day": "按天",
    "week": "按周",
    "month": "按月",
}


def quantile_value(values: list[int], quantile: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    pos = min(max(int(round((len(ordered) - 1) * quantile)), 0), len(ordered) - 1)
    return ordered[pos]


def heat_thresholds_from_counts(values: Iterable[int]) -> dict[str, int]:
    positives = [int(value) for value in values if int(value or 0) > 0]
    return {
        "p50": quantile_value(positives, 0.50),
        "p75": quantile_value(positives, 0.75),
        "p90": quantile_value(positives, 0.90),
    }


def heat_class_for_count(count: int, thresholds: dict[str, int]) -> str:
    count = int(count or 0)
    if count <= 0:
        return "zero"
    if count <= thresholds.get("p50", 0):
        return "low"
    if count <= thresholds.get("p75", 0):
        return "mid"
    if count <= thresholds.get("p90", 0):
        return "high"
    return "critical"


def heat_title_suffix(thresholds: dict[str, int]) -> str:
    return f"；颜色按当前矩阵正数分位计算：P50={thresholds.get('p50', 0)}，P75={thresholds.get('p75', 0)}，P90={thresholds.get('p90', 0)}"


def matrix_number_html(
    count: int,
    href: str | None,
    title: str,
    thresholds: dict[str, int],
    total: bool = False,
) -> str:
    count = int(count or 0)
    if count <= 0:
        return '<span class="matrix-zero">0</span>'
    base_class = "matrix-total" if total else "matrix-count"
    heat_class = heat_class_for_count(count, thresholds)
    css_class = f"{base_class} matrix-heat-{heat_class}"
    title_text = f"{title}{heat_title_suffix(thresholds)}"
    if href:
        return f'<a class="{esc(css_class)}" href="{esc(href)}" title="{esc(title_text)}">{esc(count)}</a>'
    return f'<span class="{esc(css_class)}" title="{esc(title_text)}">{esc(count)}</span>'








def process_family_for(process_name: str) -> str:
    return FORBIDDEN_PROCESS_FAMILIES.get(normalize_key(process_name), "")


def os_version_from_process_row(row: dict[str, Any]) -> str:
    parts = [
        str(row.get("os_main") or "").strip(),
        str(row.get("os_release_id") or "").strip(),
        str(row.get("os_build_version") or "").strip(),
    ]
    label = " ".join(part for part in parts if part)
    describe = str(row.get("os_describe") or "").strip()
    if describe and describe not in label:
        label = f"{label} {describe}".strip()
    return label


def forbidden_terminal_key(client_name: str, client_ip: str) -> str:
    return normalize_key(client_name) or normalize_key(client_ip) or "-"


def forbidden_identity_hints(row: dict[str, Any]) -> list[str]:
    values = [
        row.get("user_real_name"),
        row.get("user_user_name"),
        row.get("user_id"),
        row.get("user_email"),
        row.get("user_group_names"),
        row.get("login_account"),
        row.get("client_user_name"),
        row.get("local_account"),
        row.get("local_nickname"),
        row.get("staff_name"),
        row.get("user_name"),
        row.get("account"),
        row.get("client_name"),
        row.get("client_ip"),
    ]
    hints: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in hints:
            hints.append(text)
    return hints


def forbidden_people_candidates(finding: ForbiddenProcessFinding) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    if finding.login_account:
        if "@" in finding.login_account:
            candidates.append(("email", finding.login_account))
        candidates.extend(
            [
                ("login_account", finding.login_account),
                ("im_account", finding.login_account),
                ("person", finding.login_account),
                ("identity_hint", finding.login_account),
            ]
        )
    candidates.extend(
        [
            ("client_name", finding.client_name),
            ("client_ip", finding.client_ip),
        ]
    )
    for hint in finding.identity_hints:
        if "@" in hint:
            candidates.append(("email", hint))
        candidates.append(("login_account", hint))
        candidates.append(("im_account", hint))
        candidates.append(("person", hint))
        candidates.append(("identity_hint", hint))
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for match_type, value in candidates:
        if not value:
            continue
        key = (match_type, normalize_key(value))
        if key in seen:
            continue
        seen.add(key)
        result.append((match_type, value))
    return result


def enrich_forbidden_process_findings(
    findings: Iterable[ForbiddenProcessFinding],
    people_map: dict[tuple[str, str], PeopleEntry],
    wecom_people_map: dict[tuple[str, str], PeopleEntry],
    terminal_identity_history: dict[tuple[str, str], list[TerminalIdentityObservation]] | None = None,
    terminal_identity_max_age_days: int | None = None,
) -> None:
    terminal_identity_history = terminal_identity_history or {}
    for finding in findings:
        observation = terminal_identity_observation_for(
            finding.client_name,
            finding.client_ip,
            finding.last_seen or finding.first_seen,
            terminal_identity_history,
            max_age_days=terminal_identity_max_age_days,
        )
        if observation:
            finding.resolved_person = observation.person_name
            finding.resolved_company = observation.company
            finding.resolved_department = observation.department
            finding.mapping_source = observation.mapping_source
            continue
        for mapping_name, mapping in [("wecom", wecom_people_map), ("people", people_map)]:
            matched = False
            for match_type, value in forbidden_people_candidates(finding):
                entry = mapping.get((match_type, normalize_key(value)))
                if not entry:
                    continue
                finding.resolved_person = entry.person_name
                finding.resolved_company = entry.company
                finding.resolved_department = entry.department
                finding.mapping_source = f"{mapping_name}:{match_type}:{value}"
                matched = True
                break
            if matched:
                break


def add_forbidden_process_observation(
    aggregate: dict[tuple[str, str, str, str, str], ForbiddenProcessFinding],
    row: dict[str, Any],
    tz: timezone,
) -> None:
    process_name = str(row.get("process_name") or "").strip()
    family = process_family_for(process_name)
    if not family:
        return
    client_name = str(row.get("client_name") or "").strip()
    client_ip = str(row.get("client_ip") or "").strip()
    login_account = str(row.get("login_account") or "").strip()
    key = (family, process_name, client_name, client_ip, login_account)
    ts = row.get("ts")
    if not isinstance(ts, datetime):
        ts = parse_clickhouse_ts(ts, tz)
    finding = aggregate.get(key)
    if not finding:
        finding = ForbiddenProcessFinding(
            family=family,
            process_name=process_name,
            process_md5=str(row.get("process_md5") or "").strip(),
            client_name=client_name,
            client_ip=client_ip,
            login_account=login_account,
            os_version=os_version_from_process_row(row),
            group_name=str(row.get("group_name") or "").strip(),
            first_seen=ts,
            last_seen=ts,
            log_count=0,
            identity_hints=forbidden_identity_hints(row),
        )
        aggregate[key] = finding
    finding.log_count += 1
    if ts and (finding.first_seen is None or ts < finding.first_seen):
        finding.first_seen = ts
    if ts and (finding.last_seen is None or ts > finding.last_seen):
        finding.last_seen = ts
    search_id = str(row.get("search_id") or "").strip()
    if search_id and search_id not in finding.search_ids:
        finding.search_ids.append(search_id)
    if row.get("process_md5") and not finding.process_md5:
        finding.process_md5 = str(row.get("process_md5") or "").strip()
    if row.get("group_name") and not finding.group_name:
        finding.group_name = str(row.get("group_name") or "").strip()
    os_version = os_version_from_process_row(row)
    if os_version and not finding.os_version:
        finding.os_version = os_version
    for hint in forbidden_identity_hints(row):
        if hint not in finding.identity_hints:
            finding.identity_hints.append(hint)


def forbidden_process_analysis_from_rows(
    rows: Iterable[dict[str, Any]],
    tz: timezone,
    people_map: dict[tuple[str, str], PeopleEntry] | None = None,
    wecom_people_map: dict[tuple[str, str], PeopleEntry] | None = None,
    terminal_identity_history: dict[tuple[str, str], list[TerminalIdentityObservation]] | None = None,
    terminal_identity_max_age_days: int | None = None,
) -> ForbiddenProcessAnalysis:
    aggregate: dict[tuple[str, str, str, str, str], ForbiddenProcessFinding] = {}
    for row in rows:
        add_forbidden_process_observation(aggregate, row, tz)
    enrich_forbidden_process_findings(
        aggregate.values(),
        people_map or {},
        wecom_people_map or {},
        terminal_identity_history or {},
        terminal_identity_max_age_days=terminal_identity_max_age_days,
    )
    findings = sorted(
        aggregate.values(),
        key=lambda finding: (
            FORBIDDEN_PROCESS_ORDER.index(finding.family) if finding.family in FORBIDDEN_PROCESS_ORDER else 99,
            0 if finding.resolved_person else 1,
            -(finding.log_count or 0),
            -(finding.last_seen.timestamp() if finding.last_seen else 0),
        ),
    )
    terminal_by_family: dict[str, set[str]] = defaultdict(set)
    all_terminals: set[str] = set()
    accounts: set[str] = set()
    matched_people: set[str] = set()
    family_counts = Counter()
    latest_seen: datetime | None = None
    for finding in findings:
        terminal = forbidden_terminal_key(finding.client_name, finding.client_ip)
        terminal_by_family[finding.family].add(terminal)
        all_terminals.add(terminal)
        if finding.login_account:
            accounts.add(finding.login_account)
        if finding.resolved_person:
            matched_people.add(finding.resolved_person)
        family_counts[finding.family] += finding.log_count
        if finding.last_seen and (latest_seen is None or finding.last_seen > latest_seen):
            latest_seen = finding.last_seen
    return ForbiddenProcessAnalysis(
        available=True,
        findings=findings,
        family_counts=family_counts,
        family_terminal_counts=Counter({family: len(terminals) for family, terminals in terminal_by_family.items()}),
        total_terminal_count=len(all_terminals),
        total_account_count=len(accounts),
        matched_person_count=len(matched_people),
        latest_seen=latest_seen,
    )


def fetch_forbidden_process_analysis(
    args: argparse.Namespace,
    records: list[RawRecord],
    start: datetime | None,
    end: datetime | None,
    tz: timezone,
    risk_events: list[AuditEvent],
) -> ForbiddenProcessAnalysis:
    if getattr(args, "use_clickhouse", False):
        where = clickhouse_time_filter(start, end)
        process_values = clickhouse_array_literal(sorted(FORBIDDEN_PROCESS_FAMILIES))
        query = (
            "SELECT ts, "
            "JSONExtractString(raw_json, 'process_name') AS process_name, "
            "JSONExtractString(raw_json, 'process_md5') AS process_md5, "
            "JSONExtractString(raw_json, 'client_name') AS client_name, "
            "JSONExtractString(raw_json, 'client_ip') AS client_ip, "
            "JSONExtractString(raw_json, 'client_login_account') AS login_account, "
            "JSONExtractString(raw_json, 'client_user_name') AS client_user_name, "
            "JSONExtractString(raw_json, 'local_account') AS local_account, "
            "JSONExtractString(raw_json, 'local_nickname') AS local_nickname, "
            "JSONExtractString(raw_json, 'staff_name') AS staff_name, "
            "JSONExtractString(raw_json, 'user_name') AS user_name, "
            "JSONExtractString(raw_json, 'account') AS account, "
            "JSONExtractString(raw_json, 'user_real_name') AS user_real_name, "
            "JSONExtractString(raw_json, 'user_user_name') AS user_user_name, "
            "JSONExtractString(raw_json, 'user_id') AS user_id, "
            "JSONExtractString(raw_json, 'user_email') AS user_email, "
            "JSONExtractString(raw_json, 'user_group_names') AS user_group_names, "
            "JSONExtractString(raw_json, 'group_node_name') AS group_name, "
            "JSONExtractString(raw_json, 'client_os_version_main') AS os_main, "
            "JSONExtractString(raw_json, 'client_os_version_release_id') AS os_release_id, "
            "JSONExtractString(raw_json, 'client_os_version_build_version') AS os_build_version, "
            "JSONExtractString(raw_json, 'client_os_version_describe') AS os_describe, "
            "JSONExtractString(raw_json, 'search_id') AS search_id "
            f"FROM raw_syslog WHERE {where} AND topic = 'process_log' "
            f"AND has({process_values}, lower(JSONExtractString(raw_json, 'process_name'))) "
            "FORMAT JSONEachRow"
        )
        try:
            query_text = clickhouse_query(args, query)
        except Exception as exc:
            return ForbiddenProcessAnalysis(available=False, error=f"禁止软件运行分析查询失败：{exc}")
        rows = (json.loads(line) for line in query_text.splitlines() if line.strip())
        return forbidden_process_analysis_from_rows(
            rows,
            tz,
            getattr(args, "people_map_loaded", {}),
            getattr(args, "wecom_people_map_loaded", {}),
            getattr(args, "terminal_identity_history", {}),
            terminal_identity_max_age_days=getattr(args, "terminal_identity_max_age_days", None),
        )

    rows: list[dict[str, Any]] = []
    for record in records:
        obj = record.obj
        if obj.get("syslog_topic") != "process_log":
            continue
        rows.append(
            {
                "ts": record.ts,
                "process_name": obj.get("process_name"),
                "process_md5": obj.get("process_md5"),
                "client_name": obj.get("client_name"),
                "client_ip": obj.get("client_ip"),
                "login_account": obj.get("client_login_account"),
                "client_user_name": obj.get("client_user_name"),
                "local_account": obj.get("local_account"),
                "local_nickname": obj.get("local_nickname"),
                "staff_name": obj.get("staff_name"),
                "user_name": obj.get("user_name"),
                "account": obj.get("account"),
                "user_real_name": obj.get("user_real_name"),
                "user_user_name": obj.get("user_user_name"),
                "user_id": obj.get("user_id"),
                "user_email": obj.get("user_email"),
                "user_group_names": obj.get("user_group_names"),
                "group_name": obj.get("group_node_name"),
                "os_main": obj.get("client_os_version_main"),
                "os_release_id": obj.get("client_os_version_release_id"),
                "os_build_version": obj.get("client_os_version_build_version"),
                "os_describe": obj.get("client_os_version_describe"),
                "search_id": obj.get("search_id"),
            }
        )
    return forbidden_process_analysis_from_rows(
        rows,
        tz,
        getattr(args, "people_map_loaded", {}),
        getattr(args, "wecom_people_map_loaded", {}),
        getattr(args, "terminal_identity_history", {}),
        terminal_identity_max_age_days=getattr(args, "terminal_identity_max_age_days", None),
    )


def forbidden_process_summary_html(analysis: ForbiddenProcessAnalysis, detail_href: str, tz: timezone) -> str:
    if not analysis.available:
        return f'<p class="empty">{esc(analysis.error or "禁止软件运行暂无数据。")}</p>'
    latest = format_ts(analysis.latest_seen, tz) if analysis.latest_seen else "-"
    chips = [
        metric_chip_html("命中终端", analysis.total_terminal_count, href=detail_href, title="点击查看禁止软件运行终端"),
        metric_chip_html("已匹配使用人", analysis.matched_person_count, href=detail_href, title="点击查看已匹配使用人的禁止软件运行记录"),
        metric_chip_html("命中账号", analysis.total_account_count, href=detail_href, title="点击查看禁止软件运行账号"),
        metric_chip_html("微信终端", analysis.family_terminal_counts.get("微信", 0), href=detail_href, title="点击查看微信运行终端"),
        metric_chip_html("QQ终端", analysis.family_terminal_counts.get("QQ", 0), href=detail_href, title="点击查看QQ运行终端"),
        metric_chip_html("最近运行", latest, href=detail_href, title="点击查看最近运行记录"),
    ]
    return f"""
      <div class="metric-chips forbidden-chips">{"".join(chips)}</div>
      <p class="note">process_log 只证明终端运行过禁止进程，不证明发生附件外发；微信/QQ命中用于发现策略库未及时拦截的终端。</p>
"""


def build_forbidden_process_detail_page(
    analysis: ForbiddenProcessAnalysis,
    tz: timezone,
    report_period: str,
    source_label: str,
) -> str:
    findings = analysis.findings if analysis.available else []
    rows: list[list[Any]] = []
    for finding in findings:
        rows.append(
            [
                finding.family,
                finding.resolved_company or UNMATCHED_COMPANY_LABEL,
                finding.resolved_department or UNMATCHED_DEPARTMENT_LABEL,
                finding.resolved_person or "未匹配通讯录",
                finding.client_name or "-",
                finding.client_ip or "-",
                finding.os_version or "未知",
                finding.login_account or "-",
                finding.group_name or "-",
                finding.process_name or "-",
                compact_id(finding.process_md5, 18) or "-",
                format_ts(finding.first_seen, tz) if finding.first_seen else "-",
                format_ts(finding.last_seen, tz) if finding.last_seen else "-",
                str(finding.log_count),
            ]
        )
    metrics = detail_metric_chips(
        [
            ("命中终端", analysis.total_terminal_count if analysis.available else 0, "运行过微信或QQ主进程的终端数"),
            ("已匹配使用人", analysis.matched_person_count if analysis.available else 0, "通过企业微信通讯录或人员映射识别到使用人的数量"),
            ("微信终端", analysis.family_terminal_counts.get("微信", 0) if analysis.available else 0, "运行过 Weixin.exe 或 WeChat.exe 的终端数"),
            ("QQ终端", analysis.family_terminal_counts.get("QQ", 0) if analysis.available else 0, "运行过 QQ.exe、NTQQ.exe 或 TIM.exe 的终端数"),
        ]
    )
    body = f"""
    {detail_hero_html("禁止软件运行明细", "策略补漏明细", report_period, source_label + " + ClickHouse:tianqing.raw_syslog", "用于发现安全策略未及时拦截但终端实际运行过的微信/QQ主进程；本页不作为附件外发证据。", "命中终端", analysis.total_terminal_count if analysis.available else 0)}
    {metrics}
    <section class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Forbidden Process Evidence</span>
          <h2>运行证据清单</h2>
        </div>
        <span class="section-count">共 {len(rows)} 条聚合记录</span>
      </div>
      {html_table(["软件", "公司", "部门", "使用人", "计算机名", "IP地址", "操作系统版本", "登录账号", "终端分组", "进程", "MD5", "首次发现", "最后发现", "日志次数"], rows, "events", page_size=20)}
      <p class="note">QQProtect、QQPCRTP 等辅助进程不单独判定为 QQ 运行；当前只统计 QQ.exe、NTQQ.exe、TIM.exe。</p>
    </section>
    """
    return html_detail_document("禁止软件运行明细", body)


def terminal_key(client_name: str, client_ip: str) -> tuple[str, str]:
    return (str(client_name or "-").strip() or "-", str(client_ip or "-").strip() or "-")


def terminal_display_identity(values: Counter, fallback: str) -> str:
    for value, count in values.most_common():
        text = str(value or "").strip()
        if text and text not in {"-", "unknown"}:
            return text
    return fallback


def build_terminal_risk_findings(
    events: list[AuditEvent],
    terminal_identity_history: dict[tuple[str, str], list[TerminalIdentityObservation]] | None = None,
    asset_by_terminal: dict[tuple[str, str], AssetSnapshot] | None = None,
) -> list[TerminalRiskFinding]:
    terminal_identity_history = terminal_identity_history or {}
    asset_by_terminal = asset_by_terminal or {}
    aggregates: dict[tuple[str, str], dict[str, Any]] = {}

    def ensure(key: tuple[str, str]) -> dict[str, Any]:
        if key not in aggregates:
            aggregates[key] = {
                "client_name": key[0],
                "client_ip": key[1],
                "client_macs": Counter(),
                "persons": Counter(),
                "companies": Counter(),
                "departments": Counter(),
                "events": [],
                "event_count": 0,
                "three_d_count": 0,
                "two_d_cad_count": 0,
                "sensitive_name_count": 0,
                "peripheral_copy_count": 0,
                "event_score": 0,
                "action_count": 0,
                "review_count": 0,
                "general_count": 0,
                "watch_count": 0,
                "channels": set(),
                "targets": set(),
                "latest_seen": None,
            }
        return aggregates[key]

    for event in events:
        key = terminal_key(event.client_name, event.client_ip)
        item = ensure(key)
        item["events"].append(event)
        item["event_count"] += 1
        item["event_score"] += event.priority_score or event.score
        priority = event.priority or PRIORITY_WATCH
        if priority == PRIORITY_ACTION:
            item["action_count"] += 1
        elif priority == PRIORITY_REVIEW:
            item["review_count"] += 1
        elif priority == PRIORITY_GENERAL:
            item["general_count"] += 1
        else:
            item["watch_count"] += 1
        item["channels"].add(event_channel_label(event))
        item["targets"].update(event_target_values(event))
        asset = asset_for_event(event, asset_by_terminal)
        if asset and asset.client_mac:
            item["client_macs"][asset.client_mac] += 1
        item["persons"][event.resolved_person or event.person or "unknown"] += 1
        item["companies"][event_company_label(event)] += 1
        item["departments"][event_department_label(event)] += 1
        if is_three_d_model_event(event):
            item["three_d_count"] += 1
        if is_two_d_cad_event(event):
            item["two_d_cad_count"] += 1
        if event_leadership_keyword_hits(event):
            item["sensitive_name_count"] += 1
        if is_peripheral_copy_event(event):
            item["peripheral_copy_count"] += 1
        if event.ts and (item["latest_seen"] is None or event.ts > item["latest_seen"]):
            item["latest_seen"] = event.ts

    findings: list[TerminalRiskFinding] = []
    for item in aggregates.values():
        terminal_identity = terminal_identity_observation_for(
            item["client_name"],
            item["client_ip"],
            None,
            terminal_identity_history,
        )
        display_person = terminal_display_identity(item["persons"], "未匹配使用人")
        display_company = terminal_display_identity(item["companies"], UNMATCHED_COMPANY_LABEL)
        display_department = terminal_display_identity(item["departments"], UNMATCHED_DEPARTMENT_LABEL)
        if terminal_identity:
            display_person = terminal_identity.person_name or display_person
            display_company = terminal_identity.company or display_company
            display_department = terminal_identity.department or display_department
        cross_channel_bonus = 20 if len(item["channels"]) >= 2 else 0
        if len(item["channels"]) >= 3:
            cross_channel_bonus = 40
        target_spread_bonus = 15 if len(item["targets"]) >= 3 else 0
        if len(item["targets"]) >= 5:
            target_spread_bonus = 30
        risk_score = (
            item["action_count"] * PRIORITY_WEIGHTS[PRIORITY_ACTION]
            + item["review_count"] * PRIORITY_WEIGHTS[PRIORITY_REVIEW]
            + item["general_count"] * PRIORITY_WEIGHTS[PRIORITY_GENERAL]
            + item["watch_count"] * PRIORITY_WEIGHTS[PRIORITY_WATCH]
            + cross_channel_bonus
            + target_spread_bonus
        )
        findings.append(
            TerminalRiskFinding(
                client_name=item["client_name"],
                client_ip=item["client_ip"],
                client_mac=terminal_display_identity(item["client_macs"], "-"),
                person=display_person,
                company=display_company,
                department=display_department,
                event_count=item["event_count"],
                three_d_count=item["three_d_count"],
                two_d_cad_count=item["two_d_cad_count"],
                sensitive_name_count=item["sensitive_name_count"],
                peripheral_copy_count=item["peripheral_copy_count"],
                action_count=item["action_count"],
                review_count=item["review_count"],
                general_count=item["general_count"],
                watch_count=item["watch_count"],
                latest_seen=item["latest_seen"],
                risk_score=risk_score,
                events=sorted(item["events"], key=lambda ev: ev.ts or datetime.min.replace(tzinfo=timezone.utc), reverse=True),
            )
        )
    return sorted(
        findings,
        key=lambda item: (
            -item.risk_score,
            -item.action_count,
            -item.review_count,
            -item.three_d_count,
            -item.two_d_cad_count,
            -item.peripheral_copy_count,
            -item.event_count,
            -(item.latest_seen.timestamp() if item.latest_seen else 0),
        ),
    )


def terminal_matrix_detail_key(
    finding: TerminalRiskFinding,
    channel: str,
    bucket: str,
) -> tuple[str, str, str, str]:
    return (finding.client_name or "", finding.client_ip or "", channel, bucket)


def terminal_channel_object_counts(
    finding: TerminalRiskFinding,
    internal_domains: set[str],
) -> Counter:
    counts: Counter = Counter()
    for event in finding.events:
        channel = audit_channel_group(event, internal_domains)
        if not channel:
            continue
        bucket = audit_matrix_bucket(event)
        if not bucket:
            continue
        counts[(channel, bucket)] += 1
    return counts


def terminal_channel_events(
    finding: TerminalRiskFinding,
    internal_domains: set[str],
    channel: str | None = None,
    bucket: str | None = None,
) -> list[AuditEvent]:
    matched: list[AuditEvent] = []
    for event in finding.events:
        event_channel = audit_channel_group(event, internal_domains)
        if not event_channel:
            continue
        event_bucket = audit_matrix_bucket(event)
        if not event_bucket:
            continue
        if channel is not None and event_channel != channel:
            continue
        if bucket is not None and event_bucket != bucket:
            continue
        matched.append(event)
    return matched


def terminal_matrix_identity_cell(value: str, css_class: str = "") -> str:
    text = str(value or "-")
    class_attr = f' class="{esc(css_class)}"' if css_class else ""
    return f'<td{class_attr} title="{esc(text)}">{esc(text)}</td>'


def terminal_matrix_html(
    findings: list[TerminalRiskFinding],
    terminal_links: dict[tuple[str, str], str],
    detail_links: dict[tuple[str, str, str, str], str],
    internal_domains: set[str],
    limit: int | None = 10,
    page_size: int | None = None,
) -> str:
    comparable = [finding for finding in findings if organization_channel_events(finding, internal_domains)]
    visible = comparable if limit is None else comparable[:limit]
    if not visible:
        return '<p class="empty">暂无终端风险数据。</p>'
    channels = organization_matrix_channels(comparable, internal_domains)
    channel_headers = "".join(
        f'<th class="terminal-matrix-channel" colspan="{len(CHANNEL_MATRIX_COLUMNS)}" title="{esc(channel)}">{esc(CHANNEL_MATRIX_SHORT_LABELS.get(channel, channel))}</th>'
        for channel in channels
    )
    object_headers = "".join(
        f'<th title="{esc(channel)} / {esc(column)}">{esc(ORG_MATRIX_OBJECT_SHORT_LABELS.get(column, column))}</th>'
        for channel in channels
        for column in CHANNEL_MATRIX_COLUMNS
    )
    data_col_count = len(channels) * len(CHANNEL_MATRIX_COLUMNS)
    colgroup = (
        '<colgroup>'
        '<col class="terminal-rank-colgroup">'
        '<col class="terminal-company-colgroup">'
        '<col class="terminal-department-colgroup">'
        '<col class="terminal-person-colgroup">'
        '<col class="terminal-ip-colgroup">'
        '<col class="terminal-mac-colgroup">'
        + "".join('<col class="matrix-number-col">' for _ in range(data_col_count))
        + '<col class="matrix-total-col">'
        '</colgroup>'
    )
    all_cell_counts: list[int] = []
    all_total_counts: list[int] = []
    for finding in comparable:
        counts = terminal_channel_object_counts(finding, internal_domains)
        all_cell_counts.extend(counts.get((channel, column), 0) for channel in channels for column in CHANNEL_MATRIX_COLUMNS)
        all_total_counts.append(sum(counts.values()))
    cell_thresholds = heat_thresholds_from_counts(all_cell_counts)
    total_thresholds = heat_thresholds_from_counts(all_total_counts)
    rows: list[str] = []
    for idx, finding in enumerate(visible, 1):
        key = terminal_key(finding.client_name, finding.client_ip)
        cell_counts = terminal_channel_object_counts(finding, internal_domains)
        cells = [
            f'<td class="terminal-matrix-rank">{idx}</td>',
            terminal_matrix_identity_cell(finding.company or UNMATCHED_COMPANY_LABEL, "terminal-matrix-company"),
            terminal_matrix_identity_cell(finding.department or UNMATCHED_DEPARTMENT_LABEL, "terminal-matrix-department"),
            terminal_matrix_identity_cell(finding.person or "未匹配使用人", "terminal-matrix-person"),
            terminal_matrix_identity_cell(finding.client_ip or "-", "terminal-matrix-ip"),
            terminal_matrix_identity_cell(finding.client_mac or "-", "terminal-matrix-mac"),
        ]
        for channel in channels:
            for column in CHANNEL_MATRIX_COLUMNS:
                count = cell_counts.get((channel, column), 0)
                detail_href = detail_links.get(terminal_matrix_detail_key(finding, channel, column), "")
                title = f"查看{finding.client_name or '-'} / {finding.client_ip or '-'}：{channel} / {column}明细"
                cells.append(f"<td>{matrix_number_html(count, detail_href, title, cell_thresholds)}</td>")
        total_count = sum(cell_counts.values())
        total_href = terminal_links.get(key, "")
        cells.append(f"<td>{matrix_number_html(total_count, total_href, f'查看该终端全部风险事件', total_thresholds, total=True)}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    wrap_classes = "channel-matrix-wrap terminal-matrix-wrap"
    wrap_attrs = ""
    if page_size and len(visible) > page_size:
        wrap_classes += " table-wrap"
        wrap_attrs = f' data-page-size="{int(page_size)}"'
    return f"""
      <div class="{wrap_classes}"{wrap_attrs}>
        <table class="channel-matrix terminal-matrix" data-matrix-data-cols="{data_col_count}">
          {colgroup}
          <thead>
            <tr>
              <th rowspan="2" class="terminal-rank-col">#</th>
              <th rowspan="2" class="terminal-company-col">公司</th>
              <th rowspan="2" class="terminal-department-col">部门</th>
              <th rowspan="2" class="terminal-person-col">使用人</th>
              <th rowspan="2" class="terminal-ip-col">IP地址</th>
              <th rowspan="2" class="terminal-mac-col">MAC地址</th>
              {channel_headers}
              <th rowspan="2" class="terminal-total-col">合计</th>
            </tr>
            <tr>{object_headers}</tr>
          </thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
      </div>
"""


TERMINAL_RISK_COUNT_NOTE = "终端矩阵按“通道 × 对象”展示真实外发、上传和外设拷贝事实；同一事件只落在一个通道，但可按资料类型进入对应对象列。数字颜色按当前矩阵正数分位计算：P50及以下为绿色，P50-P75为黄绿，P75-P90为橙色，P90以上为红色。"


def identity_value_unmatched(value: str) -> bool:
    text = str(value or "").strip()
    return not text or text.startswith("未匹配")


def terminal_identity_incomplete(finding: TerminalRiskFinding) -> bool:
    return (
        identity_value_unmatched(finding.company)
        or identity_value_unmatched(finding.department)
        or identity_value_unmatched(finding.person)
    )


def organization_identity_incomplete(finding: OrganizationRiskFinding) -> bool:
    return identity_value_unmatched(finding.company) or identity_value_unmatched(finding.department)


def terminal_risk_summary_html(
    findings: list[TerminalRiskFinding],
    terminal_links: dict[tuple[str, str], str],
    terminal_matrix_detail_links: dict[tuple[str, str, str, str], str],
    detail_href: str,
    tz: timezone,
    internal_domains: set[str],
) -> str:
    event_terminals = sum(1 for finding in findings if terminal_channel_events(finding, internal_domains))
    chips = [
        metric_chip_html("风险终端", event_terminals, href=detail_href, title="点击查看终端风险排行"),
        metric_chip_html("三维模型终端", sum(1 for finding in findings if finding.three_d_count), href=detail_href, title="点击查看三维模型相关终端"),
        metric_chip_html("DWG图纸终端", sum(1 for finding in findings if finding.two_d_cad_count), href=detail_href, title="点击查看DWG图纸相关终端"),
        metric_chip_html("敏感名称终端", sum(1 for finding in findings if finding.sensitive_name_count), href=detail_href, title="点击查看敏感名称相关终端"),
    ]
    table_html = terminal_matrix_html(findings, terminal_links, terminal_matrix_detail_links, internal_domains, limit=10)
    return f"""
      <div class="metric-chips terminal-risk-chips">{"".join(chips)}</div>
      <div class="terminal-risk-table">
        {table_html}
      </div>
      <p class="note"><a class="table-link" href="{esc(detail_href)}">查看全部终端风险排行</a>。{esc(TERMINAL_RISK_COUNT_NOTE)}</p>
"""


def build_terminal_risk_detail_page(
    findings: list[TerminalRiskFinding],
    terminal_links: dict[tuple[str, str], str],
    terminal_matrix_detail_links: dict[tuple[str, str, str, str], str],
    internal_domains: set[str],
    tz: timezone,
    report_period: str,
    source_label: str,
) -> str:
    metrics = detail_metric_chips(
        [
            ("风险终端", sum(1 for finding in findings if terminal_channel_events(finding, internal_domains)), "存在外发/拷贝重点事件的终端数"),
            ("图纸终端", sum(1 for finding in findings if finding.three_d_count or finding.two_d_cad_count), "存在三维模型或DWG图纸事件的终端数"),
            ("敏感名称终端", sum(1 for finding in findings if finding.sensitive_name_count), "存在敏感名称事件的终端数"),
        ]
    )
    body = f"""
    {detail_hero_html("终端风险排行", "终端聚合明细", report_period, source_label, "按计算机名/IP聚合外发、上传和外设拷贝重点事件；公司部门来自通讯录缓存或人员映射。", "终端数", len(findings))}
    {metrics}
    <section class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Terminal Ranking</span>
          <h2>终端风险聚合清单</h2>
        </div>
        <span class="section-count">共 {sum(1 for finding in findings if terminal_channel_events(finding, internal_domains))} 台终端</span>
      </div>
      {terminal_matrix_html(findings, terminal_links, terminal_matrix_detail_links, internal_domains, limit=None, page_size=20)}
      <p class="note">排序分仅在后台用于决定 Top 顺序；页面只展示通道、资料类型和事实数量。{esc(TERMINAL_RISK_COUNT_NOTE)}</p>
    </section>
"""
    return html_detail_document("终端风险排行", body)


def organization_key(finding: OrganizationRiskFinding) -> tuple[str, str, str]:
    return (finding.scope, finding.company or "", finding.department or "")


def organization_matrix_detail_key(
    finding: OrganizationRiskFinding,
    channel: str,
    bucket: str,
) -> tuple[str, str, str, str, str]:
    scope, company, department = organization_key(finding)
    return (scope, company, department, channel, bucket)


def organization_asset_counts(asset_analysis: AssetAnalysis) -> tuple[Counter, Counter, Counter]:
    company_counts: Counter = Counter()
    company_department_counts: Counter = Counter()
    department_type_counts: Counter = Counter()
    if not asset_analysis.available:
        return company_counts, company_department_counts, department_type_counts
    for asset in asset_analysis.asset_by_terminal.values():
        company = str(asset.company or "").strip() or UNMATCHED_COMPANY_LABEL
        department = str(asset.department or "").strip() or UNMATCHED_DEPARTMENT_LABEL
        company_counts[company] += 1
        company_department_counts[(company, department)] += 1
        department_type_counts[department] += 1
    return company_counts, company_department_counts, department_type_counts


def organization_base_count(raw_count: int, risk_terminal_count: int) -> tuple[int, bool]:
    if raw_count <= 0:
        return max(risk_terminal_count, 0), True
    if raw_count < risk_terminal_count:
        return risk_terminal_count, True
    return raw_count, False


def organization_label(scope: str, company: str, department: str) -> str:
    if scope == "company":
        return company or UNMATCHED_COMPANY_LABEL
    if scope == "department_type":
        return department or UNMATCHED_DEPARTMENT_LABEL
    return " / ".join([value for value in [company or UNMATCHED_COMPANY_LABEL, department or UNMATCHED_DEPARTMENT_LABEL] if value])


def new_org_bucket(scope: str, company: str, department: str) -> dict[str, Any]:
    return {
        "scope": scope,
        "company": company,
        "department": department,
        "terminals": [],
        "events": [],
        "covered_companies": Counter(),
        "event_count": 0,
        "three_d_count": 0,
        "two_d_cad_count": 0,
        "sensitive_name_count": 0,
        "peripheral_copy_count": 0,
        "action_count": 0,
        "review_count": 0,
        "general_count": 0,
        "watch_count": 0,
        "external_sender_count": 0,
        "im_event_count": 0,
        "risk_score": 0,
        "latest_seen": None,
    }


def add_terminal_to_org_bucket(bucket: dict[str, Any], terminal: TerminalRiskFinding, internal_domains: set[str]) -> None:
    bucket["terminals"].append(terminal)
    bucket["events"].extend(terminal.events)
    bucket["event_count"] += terminal.event_count
    bucket["three_d_count"] += terminal.three_d_count
    bucket["two_d_cad_count"] += terminal.two_d_cad_count
    bucket["sensitive_name_count"] += terminal.sensitive_name_count
    bucket["peripheral_copy_count"] += terminal.peripheral_copy_count
    bucket["action_count"] += terminal.action_count
    bucket["review_count"] += terminal.review_count
    bucket["general_count"] += terminal.general_count
    bucket["watch_count"] += terminal.watch_count
    bucket["risk_score"] += terminal.risk_score
    bucket["covered_companies"][terminal.company or UNMATCHED_COMPANY_LABEL] += 1
    for event in terminal.events:
        if is_external_sender_mailbox(event):
            bucket["external_sender_count"] += 1
        if audit_channel_group(event, internal_domains) == "IM附件":
            bucket["im_event_count"] += 1
    if terminal.latest_seen and (bucket["latest_seen"] is None or terminal.latest_seen > bucket["latest_seen"]):
        bucket["latest_seen"] = terminal.latest_seen


def organization_issue_tags(finding: OrganizationRiskFinding) -> list[str]:
    tags: list[str] = []
    event_count = max(finding.event_count, 1)
    design_count = finding.three_d_count + finding.two_d_cad_count
    if finding.three_d_count and (finding.three_d_count >= 3 or finding.three_d_count / event_count >= 0.12):
        tags.append("三维模型高发")
    if design_count and (design_count >= 3 or design_count / event_count >= 0.18):
        tags.append("图纸外发集中")
    if finding.peripheral_copy_count and (finding.peripheral_copy_count >= 3 or finding.peripheral_copy_count / event_count >= 0.15):
        tags.append("外设拷贝突出")
    if finding.external_sender_count and (finding.external_sender_count >= 3 or finding.external_sender_count / event_count >= 0.15):
        tags.append("外部邮箱使用突出")
    if finding.im_event_count and (finding.im_event_count >= 3 or finding.im_event_count / event_count >= 0.18):
        tags.append("IM附件集中")
    if finding.top3_contribution_rate >= 0.6 and finding.risk_terminal_count >= 3:
        tags.append("少数终端拖累")
    elif finding.risk_terminal_count >= 5 and finding.event_count >= 10:
        tags.append("面上管理问题")
    if (
        finding.company.startswith("未匹配")
        or finding.department.startswith("未匹配")
        or finding.label.startswith("未匹配")
    ):
        tags.append("身份匹配不足")
    if not tags:
        tags.append("常规关注")
    return tags


def finalize_organization_findings(
    buckets: dict[Any, dict[str, Any]],
    asset_counts: Counter,
    scope: str,
) -> list[OrganizationRiskFinding]:
    findings: list[OrganizationRiskFinding] = []
    for key, bucket in buckets.items():
        terminals = sorted(
            bucket["terminals"],
            key=lambda terminal: (
                -terminal.risk_score,
                -terminal.action_count,
                -terminal.review_count,
                -terminal.three_d_count,
                -terminal.two_d_cad_count,
                -terminal.event_count,
            ),
        )
        risk_terminal_count = len(terminals)
        raw_asset_count = asset_counts.get(key, 0)
        asset_count, incomplete = organization_base_count(raw_asset_count, risk_terminal_count)
        top3_score = sum(terminal.risk_score for terminal in terminals[:3])
        risk_score = int(bucket["risk_score"])
        company = str(bucket["company"] or "")
        department = str(bucket["department"] or "")
        finding = OrganizationRiskFinding(
            scope=scope,
            label=organization_label(scope, company, department),
            company=company,
            department=department,
            asset_terminal_count=asset_count,
            asset_base_incomplete=incomplete,
            risk_terminal_count=risk_terminal_count,
            event_count=int(bucket["event_count"]),
            three_d_count=int(bucket["three_d_count"]),
            two_d_cad_count=int(bucket["two_d_cad_count"]),
            sensitive_name_count=int(bucket["sensitive_name_count"]),
            peripheral_copy_count=int(bucket["peripheral_copy_count"]),
            action_count=int(bucket["action_count"]),
            review_count=int(bucket["review_count"]),
            general_count=int(bucket["general_count"]),
            watch_count=int(bucket["watch_count"]),
            external_sender_count=int(bucket["external_sender_count"]),
            im_event_count=int(bucket["im_event_count"]),
            risk_score=risk_score,
            top3_contribution_rate=top3_score / max(risk_score, 1),
            covered_companies=bucket["covered_companies"],
            terminal_findings=terminals,
            events=sorted(bucket["events"], key=lambda ev: ev.ts or datetime.min.replace(tzinfo=timezone.utc), reverse=True),
            latest_seen=bucket["latest_seen"],
        )
        finding.issue_tags = organization_issue_tags(finding)
        findings.append(finding)
    return sorted(
        findings,
        key=lambda item: (
            item.label.startswith("未匹配"),
            -item.risk_score,
            -item.action_count,
            -item.review_count,
            -item.risk_terminal_count,
            -(item.latest_seen.timestamp() if item.latest_seen else 0),
        ),
    )


def build_organization_risk_analysis(
    terminal_findings: list[TerminalRiskFinding],
    asset_analysis: AssetAnalysis,
    internal_domains: set[str],
) -> OrganizationRiskAnalysis:
    company_asset_counts, company_department_asset_counts, department_type_asset_counts = organization_asset_counts(asset_analysis)
    company_buckets: dict[str, dict[str, Any]] = {}
    company_department_buckets: dict[tuple[str, str], dict[str, Any]] = {}
    department_type_buckets: dict[str, dict[str, Any]] = {}

    for terminal in terminal_findings:
        if not terminal.event_count:
            continue
        company = terminal.company or UNMATCHED_COMPANY_LABEL
        department = terminal.department or UNMATCHED_DEPARTMENT_LABEL
        company_bucket = company_buckets.setdefault(company, new_org_bucket("company", company, ""))
        add_terminal_to_org_bucket(company_bucket, terminal, internal_domains)
        company_department_key = (company, department)
        company_department_bucket = company_department_buckets.setdefault(
            company_department_key,
            new_org_bucket("company_department", company, department),
        )
        add_terminal_to_org_bucket(company_department_bucket, terminal, internal_domains)
        department_type_bucket = department_type_buckets.setdefault(
            department,
            new_org_bucket("department_type", "", department),
        )
        add_terminal_to_org_bucket(department_type_bucket, terminal, internal_domains)

    return OrganizationRiskAnalysis(
        companies=finalize_organization_findings(company_buckets, company_asset_counts, "company"),
        company_departments=finalize_organization_findings(company_department_buckets, company_department_asset_counts, "company_department"),
        department_types=finalize_organization_findings(department_type_buckets, department_type_asset_counts, "department_type"),
    )


ORG_MATRIX_OBJECT_SHORT_LABELS = {
    "三维模型": "三维",
    "DWG二维图纸": "DWG",
    "敏感名称": "敏感",
    "压缩包": "压缩",
}


ORG_OBJECT_CHIP_LABELS = {
    "三维模型": "三维模型",
    "DWG二维图纸": "DWG图纸",
    "敏感名称": "敏感名称",
    "压缩包": "压缩包",
}


def organization_object_metric_key(bucket: str) -> str:
    return f"object:{bucket}"


def organization_matrix_channels(
    findings: list[OrganizationRiskFinding],
    internal_domains: set[str],
) -> list[str]:
    seen = set(CHANNEL_MATRIX_BASE_ROWS)
    dynamic = sorted(
        {
            channel
            for finding in findings
            for event in finding.events
            for channel in [audit_channel_group(event, internal_domains)]
            if channel and channel not in seen
        }
    )
    return CHANNEL_MATRIX_BASE_ROWS + dynamic


def organization_channel_object_counts(
    finding: OrganizationRiskFinding,
    internal_domains: set[str],
) -> Counter:
    counts: Counter = Counter()
    for event in finding.events:
        channel = audit_channel_group(event, internal_domains)
        if not channel:
            continue
        bucket = audit_matrix_bucket(event)
        if not bucket:
            continue
        counts[(channel, bucket)] += 1
    return counts


def organization_channel_events(
    finding: OrganizationRiskFinding,
    internal_domains: set[str],
    channel: str | None = None,
    bucket: str | None = None,
) -> list[AuditEvent]:
    matched: list[AuditEvent] = []
    for event in finding.events:
        event_channel = audit_channel_group(event, internal_domains)
        if not event_channel:
            continue
        event_bucket = audit_matrix_bucket(event)
        if not event_bucket:
            continue
        if channel is not None and event_channel != channel:
            continue
        if bucket is not None and event_bucket != bucket:
            continue
        matched.append(event)
    return matched


def organization_scope_channel_events(
    findings: list[OrganizationRiskFinding],
    internal_domains: set[str],
    channel: str | None = None,
    bucket: str | None = None,
) -> list[AuditEvent]:
    matched: list[AuditEvent] = []
    seen: set[str] = set()
    for finding in findings:
        for event in organization_channel_events(finding, internal_domains, channel=channel, bucket=bucket):
            key = event.event_id or f"{event.raw_hash}|{event.client_name}|{event.client_ip}|{event.ts}"
            if key in seen:
                continue
            seen.add(key)
            matched.append(event)
    return matched


def organization_scope_metric_chips(
    findings: list[OrganizationRiskFinding],
    detail_links: dict[str, str],
    internal_domains: set[str],
) -> str:
    total_events = organization_scope_channel_events(findings, internal_domains)
    chips: list[tuple[Any, ...]] = [
        (
            "风险终端",
            sum(finding.risk_terminal_count for finding in findings),
            "本页组织范围内聚合后的风险终端数，点击跳转到组织矩阵",
            "#organization-matrix",
        ),
        (
            "合计",
            len(total_events),
            "查看本页组织范围内全部外发、上传和外设拷贝明细",
            detail_links.get("__all__", ""),
        ),
    ]
    for bucket in CHANNEL_MATRIX_COLUMNS:
        bucket_events = organization_scope_channel_events(findings, internal_domains, bucket=bucket)
        chips.append(
            (
                ORG_OBJECT_CHIP_LABELS.get(bucket, bucket),
                len(bucket_events),
                f"查看本页组织范围内 {bucket} 全部明细",
                detail_links.get(organization_object_metric_key(bucket), "") if bucket_events else "",
            )
        )
    for channel in organization_matrix_channels(findings, internal_domains):
        channel_events = organization_scope_channel_events(findings, internal_domains, channel=channel)
        chips.append(
            (
                channel,
                len(channel_events),
                f"查看本页组织范围内 {channel} 通道全部明细",
                detail_links.get(channel, "") if channel_events else "",
            )
        )
    return detail_metric_chips(chips)


def organization_profile_metric_chips(
    finding: OrganizationRiskFinding,
    detail_links: dict[tuple[str, str, str, str, str], str],
    internal_domains: set[str],
) -> str:
    total_events = organization_channel_events(finding, internal_domains)
    chips: list[tuple[Any, ...]] = [
        (
            "风险终端",
            finding.risk_terminal_count,
            "该组织聚合后的风险终端数，点击跳转到本页风险终端矩阵",
            "#risk-terminals",
        ),
        (
            "合计",
            len(total_events),
            "查看该组织全部外发、上传和外设拷贝事件",
            detail_links.get(organization_matrix_detail_key(finding, "__all__", "__all__"), ""),
        ),
    ]
    for bucket in CHANNEL_MATRIX_COLUMNS:
        bucket_events = organization_channel_events(finding, internal_domains, bucket=bucket)
        href = detail_links.get(organization_matrix_detail_key(finding, "__all__", bucket), "")
        chips.append(
            (
                ORG_OBJECT_CHIP_LABELS.get(bucket, bucket),
                len(bucket_events),
                f"查看该组织全部通道中的 {bucket} 明细",
                href if bucket_events else "",
            )
        )
    for channel in organization_matrix_channels([finding], internal_domains):
        channel_events = organization_channel_events(finding, internal_domains, channel=channel)
        href = detail_links.get(organization_matrix_detail_key(finding, channel, "__all__"), "")
        chips.append(
            (
                channel,
                len(channel_events),
                f"查看该组织 {channel} 通道全部明细",
                href if channel_events else "",
            )
        )
    return detail_metric_chips(chips)


def organization_matrix_html(
    findings: list[OrganizationRiskFinding],
    profile_links: dict[tuple[str, str, str], str],
    detail_links: dict[tuple[str, str, str, str, str], str],
    internal_domains: set[str],
    limit: int | None = 10,
    page_size: int | None = None,
) -> str:
    comparable = [finding for finding in findings if terminal_channel_events(finding, internal_domains)]
    visible = comparable if limit is None else comparable[:limit]
    if not visible:
        return '<p class="empty">暂无组织风险数据。</p>'
    channels = organization_matrix_channels(comparable, internal_domains)
    channel_headers = "".join(
        f'<th class="org-matrix-channel" colspan="{len(CHANNEL_MATRIX_COLUMNS)}" title="{esc(channel)}">{esc(CHANNEL_MATRIX_SHORT_LABELS.get(channel, channel))}</th>'
        for channel in channels
    )
    object_headers = "".join(
        f'<th title="{esc(channel)} / {esc(column)}">{esc(ORG_MATRIX_OBJECT_SHORT_LABELS.get(column, column))}</th>'
        for channel in channels
        for column in CHANNEL_MATRIX_COLUMNS
    )
    data_col_count = len(channels) * len(CHANNEL_MATRIX_COLUMNS)
    colgroup = (
        '<colgroup>'
        '<col class="org-label-col">'
        + "".join('<col class="matrix-number-col">' for _ in range(data_col_count))
        + '<col class="matrix-total-col">'
        '</colgroup>'
    )
    rows = []
    all_cell_counts: list[int] = []
    all_total_counts: list[int] = []
    for finding in comparable:
        counts = organization_channel_object_counts(finding, internal_domains)
        all_cell_counts.extend(counts.get((channel, column), 0) for channel in channels for column in CHANNEL_MATRIX_COLUMNS)
        all_total_counts.append(sum(counts.values()))
    cell_thresholds = heat_thresholds_from_counts(all_cell_counts)
    total_thresholds = heat_thresholds_from_counts(all_total_counts)
    for finding in visible:
        href = profile_links.get(organization_key(finding), "")
        cell_counts = organization_channel_object_counts(finding, internal_domains)
        company_hint = ""
        if finding.scope == "department_type":
            company_hint = f"覆盖 {len(finding.covered_companies)} 家公司"
        elif finding.scope == "company_department":
            company_hint = finding.company or "-"
        else:
            company_hint = f"{finding.risk_terminal_count} 台风险终端"
        row_label_inner = f"""
          <div class="org-matrix-label">
            <strong title="{esc(finding.label)}">{esc(finding.label)}</strong>
            <small>{esc(company_hint)}</small>
          </div>
"""
        if href:
            row_label = f'<a class="org-matrix-label-link" href="{esc(href)}" title="查看{esc(finding.label)}画像">{row_label_inner}</a>'
        else:
            row_label = row_label_inner
        cells = [f'<th class="channel-name org-matrix-name" scope="row">{row_label}</th>']
        for channel in channels:
            for column in CHANNEL_MATRIX_COLUMNS:
                count = cell_counts.get((channel, column), 0)
                title = f"查看{finding.label}：{channel} / {column}"
                detail_href = detail_links.get(organization_matrix_detail_key(finding, channel, column), "")
                cells.append(f"<td>{matrix_number_html(count, detail_href, f'{title}明细', cell_thresholds)}</td>")
        total_count = sum(cell_counts.values())
        total_href = detail_links.get(organization_matrix_detail_key(finding, "__all__", "__all__"), "")
        cells.append(f"<td>{matrix_number_html(total_count, total_href, f'查看{finding.label}全部外发/拷贝事件', total_thresholds, total=True)}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    wrap_classes = "channel-matrix-wrap organization-matrix-wrap"
    wrap_attrs = ""
    if page_size and len(visible) > page_size:
        wrap_classes += " table-wrap"
        wrap_attrs = f' data-page-size="{int(page_size)}"'
    return f"""
      <div class="{wrap_classes}"{wrap_attrs}>
        <table class="channel-matrix organization-matrix organization-matrix-wide" data-matrix-data-cols="{data_col_count}">
          {colgroup}
          <thead>
            <tr><th rowspan="2">组织</th>{channel_headers}<th rowspan="2">合计</th></tr>
            <tr>{object_headers}</tr>
          </thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
      </div>
"""

def build_organization_risk_summary_html(
    analysis: OrganizationRiskAnalysis,
    terminal_findings: list[TerminalRiskFinding],
    terminal_links: dict[tuple[str, str], str],
    terminal_matrix_detail_links: dict[tuple[str, str, str, str], str],
    terminal_detail_href: str,
    org_links: dict[tuple[str, str, str], str],
    org_matrix_detail_links: dict[tuple[str, str, str, str, str], str],
    company_page: str,
    department_type_page: str,
    company_department_page: str,
    identity_gap_page: str,
    tz: timezone,
    internal_domains: set[str],
) -> str:
    unmatched_terminal_count = sum(1 for finding in terminal_findings if terminal_identity_incomplete(finding))
    identity_gap_note = ""
    if unmatched_terminal_count:
        identity_gap_note = (
            f'<p class="note">数据质量提示：'
            f'<a class="table-link" href="{esc(identity_gap_page)}">身份匹配待完善 {unmatched_terminal_count} 台终端</a>'
            f'，仅用于补齐通讯录或终端归属，不参与公司、部门风险表现比较。</p>'
        )
    terminal_table = terminal_matrix_html(terminal_findings, terminal_links, terminal_matrix_detail_links, internal_domains, limit=10)
    return f"""
      {identity_gap_note}
      <div class="org-insight-grid">
        <section class="org-panel">
          <div class="org-panel-head">
            <span>Company Risk</span>
            <a href="{esc(company_page)}">更多</a>
          </div>
          <h3>公司风险矩阵</h3>
          {organization_matrix_html(analysis.companies, org_links, org_matrix_detail_links, internal_domains, limit=10)}
        </section>
        <section class="org-panel">
          <div class="org-panel-head">
            <span>Department Risk</span>
            <a href="{esc(department_type_page)}">更多</a>
          </div>
          <h3>部门风险矩阵</h3>
          {organization_matrix_html(analysis.department_types, org_links, org_matrix_detail_links, internal_domains, limit=10)}
        </section>
      </div>
      <p class="note">组织矩阵按“渠道 × 对象”展开，列口径与外发通道风险矩阵保持一致；只统计真实外发、上传和外设拷贝重点事件。</p>
      <section class="terminal-drilldown-panel">
        <div class="org-panel-head">
          <span>Terminal Drilldown</span>
          <a href="{esc(terminal_detail_href)}">查看全部终端</a>
        </div>
        <h3>终端风险 Top 10</h3>
        {terminal_table}
      <p class="note">终端排行用于定位具体责任人和设备；组织洞察用于先发现公司、跨公司部门和公司内部门的规律。{esc(TERMINAL_RISK_COUNT_NOTE)}</p>
      </section>
"""


def build_organization_risk_list_page(
    title: str,
    subtitle: str,
    findings: list[OrganizationRiskFinding],
    org_links: dict[tuple[str, str, str], str],
    org_matrix_detail_links: dict[tuple[str, str, str, str, str], str],
    list_metric_links: dict[str, str],
    internal_domains: set[str],
    tz: timezone,
    report_period: str,
    source_label: str,
) -> str:
    comparable_count = sum(1 for finding in findings if organization_channel_events(finding, internal_domains))
    matrix = organization_matrix_html(
        findings,
        org_links,
        org_matrix_detail_links,
        internal_domains,
        limit=None,
        page_size=20,
    )
    metrics = organization_scope_metric_chips(findings, list_metric_links, internal_domains)
    body = f"""
    {detail_hero_html(title, subtitle, report_period, source_label, "按组织聚合终端风险，用于从公司和部门视角发现规律；未匹配组织单独作为身份数据质量问题处理。", "组织数", len(findings))}
    {metrics}
    <section id="organization-matrix" class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Organization Matrix</span>
          <h2>{esc(title)}</h2>
        </div>
        <span class="section-count">共 {comparable_count} 条</span>
      </div>
      {matrix}
      <p class="note">本页延续首页“渠道 × 对象”的双层矩阵口径；外设拷贝作为一级通道展示，不与三维模型、DWG图纸、敏感名称并列。</p>
    </section>
"""
    return html_detail_document(title, body)


def build_identity_gap_page(
    terminal_findings: list[TerminalRiskFinding],
    organization_findings: list[OrganizationRiskFinding],
    terminal_links: dict[tuple[str, str], str],
    terminal_matrix_detail_links: dict[tuple[str, str, str, str], str],
    org_links: dict[tuple[str, str, str], str],
    org_matrix_detail_links: dict[tuple[str, str, str, str, str], str],
    internal_domains: set[str],
    tz: timezone,
    report_period: str,
    source_label: str,
) -> str:
    gap_terminals = [finding for finding in terminal_findings if terminal_identity_incomplete(finding)]
    gap_organizations = [finding for finding in organization_findings if organization_identity_incomplete(finding)]
    metrics = detail_metric_chips(
        [
            ("待完善终端", len(gap_terminals), "公司、部门或使用人未匹配的终端数"),
            ("未匹配组织", len(gap_organizations), "公司或部门未匹配的组织聚合数"),
            ("图纸终端", sum(1 for finding in gap_terminals if finding.three_d_count or finding.two_d_cad_count), "身份待完善终端中的图纸事件终端数"),
        ]
    )
    body = f"""
    {detail_hero_html("身份匹配待完善", "身份数据质量", report_period, source_label, "仅展示公司、部门或使用人未匹配的终端和组织聚合，用于补齐企业微信通讯录、人员映射或终端使用人归属。", "待完善终端", len(gap_terminals))}
    {metrics}
    <section class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Terminal Identity</span>
          <h2>待完善终端清单</h2>
        </div>
        <span class="section-count">共 {len(gap_terminals)} 台</span>
      </div>
      {terminal_matrix_html(gap_terminals, terminal_links, terminal_matrix_detail_links, internal_domains, limit=None, page_size=20)}
      <p class="note">本页只说明身份数据需要补齐，不改变风险事件本身的审计结论。</p>
    </section>
    <section class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Organization Identity</span>
          <h2>未匹配组织聚合</h2>
        </div>
        <span class="section-count">共 {len(gap_organizations)} 条</span>
      </div>
      {organization_matrix_html(gap_organizations, org_links, org_matrix_detail_links, internal_domains, limit=None, page_size=20)}
    </section>
"""
    return html_detail_document("身份匹配待完善", body)


def organization_scope_description(finding: OrganizationRiskFinding) -> str:
    if finding.scope == "company":
        return f"{finding.label} 公司画像：展示公司内部门分布、通道分布、风险终端和事件明细。"
    if finding.scope == "department_type":
        return f"{finding.label} 部门画像：跨公司汇总同名部门风险，用于发现集团共性问题。"
    return f"{finding.label} 部门画像：展示该公司该部门的风险终端和事件明细。"


def child_org_rows(
    children: list[OrganizationRiskFinding],
    org_links: dict[tuple[str, str, str], str],
    org_matrix_detail_links: dict[tuple[str, str, str, str, str], str],
    internal_domains: set[str],
    limit: int | None = 12,
    page_size: int = 12,
) -> str:
    if not children:
        return '<p class="empty">无下级组织分布。</p>'
    return organization_matrix_html(
        children,
        org_links,
        org_matrix_detail_links,
        internal_domains,
        limit=limit,
        page_size=page_size,
    )


def child_org_breakdown_html(
    finding: OrganizationRiskFinding,
    children: list[OrganizationRiskFinding],
    org_links: dict[tuple[str, str, str], str],
    org_matrix_detail_links: dict[tuple[str, str, str, str, str], str],
    tz: timezone,
    internal_domains: set[str],
) -> str:
    if not children:
        return '<p class="empty">无下级组织分布。</p>'
    if finding.scope == "company":
        more = ""
        if len(children) > 10:
            more = f"""
      <details class="org-more-details">
        <summary>查看该公司全部部门（{len(children)}）</summary>
        {child_org_rows(children, org_links, org_matrix_detail_links, internal_domains, limit=None, page_size=12)}
      </details>
"""
        return organization_matrix_html(children, org_links, org_matrix_detail_links, internal_domains, limit=10) + more
    return child_org_rows(children, org_links, org_matrix_detail_links, internal_domains, limit=None, page_size=12)


def build_organization_profile_page(
    finding: OrganizationRiskFinding,
    child_findings: list[OrganizationRiskFinding],
    org_links: dict[tuple[str, str, str], str],
    org_matrix_detail_links: dict[tuple[str, str, str, str, str], str],
    terminal_links: dict[tuple[str, str], str],
    terminal_matrix_detail_links: dict[tuple[str, str, str, str], str],
    args: argparse.Namespace,
    tz: timezone,
    report_period: str,
    source_label: str,
    internal_domains: set[str],
) -> str:
    profile_matrix_events = [event for event in finding.events if audit_channel_group(event, internal_domains) and audit_matrix_bucket(event)]
    channel_counts = Counter(audit_channel_group(event, internal_domains) for event in profile_matrix_events)
    bucket_counts = Counter(bucket for event in profile_matrix_events for bucket in [audit_matrix_bucket(event)] if bucket)
    metrics = organization_profile_metric_chips(finding, org_matrix_detail_links, internal_domains)
    child_title = "公司内部门风险矩阵" if finding.scope == "company" else "覆盖公司与部门分布"
    if finding.scope == "company_department":
        child_title = "下级组织分布"
    body = f"""
    {detail_hero_html(f"{finding.label} 风险画像", "组织画像", report_period, source_label, organization_scope_description(finding), "风险终端", finding.risk_terminal_count)}
    {metrics}
    <section id="risk-terminals" class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Organization Breakdown</span>
          <h2>{esc(child_title)}</h2>
        </div>
      </div>
      {child_org_breakdown_html(finding, child_findings, org_links, org_matrix_detail_links, tz, internal_domains)}
    </section>
    <section class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Channel Slice</span>
          <h2>通道与资料类型切片</h2>
        </div>
      </div>
      <div class="grid-2">
        <div class="panel"><h3>通道分布</h3>{donut_chart(channel_counts, limit=6)}</div>
        <div class="panel"><h3>资料类型分布</h3>{donut_chart(bucket_counts, limit=4)}</div>
      </div>
    </section>
    <section class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Terminal Drilldown</span>
          <h2>风险终端</h2>
        </div>
        <span class="section-count">共 {len(finding.terminal_findings)} 台</span>
      </div>
      {terminal_matrix_html(finding.terminal_findings, terminal_links, terminal_matrix_detail_links, internal_domains, limit=None, page_size=20)}
      <p class="note">{esc(TERMINAL_RISK_COUNT_NOTE)}</p>
    </section>
    <section class="detail-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Event Evidence</span>
          <h2>事件明细</h2>
        </div>
        <span class="section-count">共 {len(finding.events)} 条</span>
      </div>
      {event_detail_table_html(finding.events, tz, page_size=20, asset_by_terminal=getattr(args, "asset_by_terminal", {}))}
    </section>
"""
    return html_detail_document(f"{finding.label} 风险画像", body)








def build_html_report(
    events: list[AuditEvent],
    records: list[RawRecord],
    args: argparse.Namespace,
    tz: timezone,
    start: datetime | None,
    end: datetime | None,
    internal_domains: set[str],
) -> tuple[str, SidecarReportStore]:
    bind_report_submodule_dependencies()
    debug_timing(f"build_html_report start audit_events={len(events)} records={len(records)}")
    audit_events = events
    procurement_muted_events = [event for event in audit_events if is_normal_procurement_inquiry_event(event)]
    focus_candidates_for_noise = [event for event in audit_events if is_leadership_focus_event(event, internal_domains)]
    events, false_positive_reasons = report_focus_events(audit_events, internal_domains)
    false_positive_events = [event for event in focus_candidates_for_noise if event.event_id in false_positive_reasons]
    debug_timing(
        f"leadership_filter focus_events={len(events)} false_positive={len(false_positive_events)} procurement_muted={len(procurement_muted_events)}"
    )
    trend_end = trend_reference_end(args, events, start, end, tz)
    trend_windows = load_trend_window_event_sets(args, events, trend_end, tz, internal_domains, start, end)
    debug_timing(
        "trend_windows="
        + ",".join(f"{days}d:{len(payload.get('events') or [])}" for days, payload in sorted(trend_windows.items()))
    )
    priority_counts = event_priority_counts(events)
    channel_counts = Counter(event_channel_label(event) for event in events)
    im_channel_counts = Counter(
        im_channel_label(event)
        for event in events
        if audit_channel_group(event, internal_domains) == "IM附件"
    )
    topic_counts = report_topic_counts(args, records)
    raw_record_count = report_raw_record_count(args, records)
    person_counts = Counter()
    person_action = Counter()
    company_counts = Counter()
    dept_counts = Counter()
    target_counts = Counter()
    unknown_im_recipient_counts = Counter()
    ext_counts = Counter()
    design_ext_counts = Counter()
    three_d_ext_counts = Counter()
    two_d_cad_ext_counts = Counter()
    pcb_ecad_ext_counts = Counter()
    design_category_counts = Counter()
    reason_counts = Counter()
    keyword_counts = Counter()
    keyword_event_map: dict[str, list[AuditEvent]] = defaultdict(list)
    status_counts = Counter()
    with_lookup = 0

    for event in events:
        important_names = leadership_file_names(event)
        person_key = (
            event.resolved_person or event.person or "unknown",
            event_company_label(event),
            event_department_label(event),
            event.client_name or "-",
            event.client_ip or "-",
        )
        person_counts[person_key] += 1
        if event.priority == PRIORITY_ACTION:
            person_action[person_key] += 1
        company_counts[event_company_label(event)] += 1
        dept_counts[event_department_label(event)] += 1
        status_counts[event.disposition_status] += 1
        for domain in event.target_domains:
            if not domain_is_internal(domain, internal_domains):
                target_counts[domain] += 1
        if not event.target_domains and event.recipients:
            for recipient in event.recipients:
                target_counts[recipient] += 1
                if event.topic == "im_audit" and event.recipient_relation == "unknown":
                    unknown_im_recipient_counts[recipient] += 1
        for name in important_names:
            ext = extension(name)
            if not ext:
                continue
            ext_counts[ext] += 1
            if ext in DESIGN_EXTS:
                design_ext_counts[ext] += 1
            if ext in CONTROLLED_3D_EXTS:
                three_d_ext_counts[ext] += 1
            if ext in CONTROLLED_2D_CAD_EXTS:
                two_d_cad_ext_counts[ext] += 1
            if ext in PCB_ECAD_EXTS:
                pcb_ecad_ext_counts[ext] += 1
        keyword_hits = event_leadership_keyword_hits(event)
        for keyword in keyword_hits:
            keyword_counts[keyword] += 1
            keyword_event_map[keyword].append(event)
        if any(extension(name) in DESIGN_EXTS for name in important_names):
            for category in ordered_design_categories(event):
                reason_counts["DWG二维图纸" if category == "DWG二维图纸" else category] += 1
                design_category_counts[category] += 1
        if keyword_hits:
            reason_counts["敏感关键词:" + ",".join(keyword_hits[:3])] += 1
        if any(extension(name) in ARCHIVE_EXTS for name in important_names):
            reason_counts["压缩包"] += 1
        if "个人邮箱域名" in event.reasons:
            reason_counts["个人邮箱域名"] += 1
        if "外部发件箱" in event.reasons:
            reason_counts["外部发件箱"] += 1
        if "外部收件域名" in event.reasons or "外部上传/下载地址" in event.reasons:
            reason_counts["外部目标"] += 1
        if "大文件" in event.reasons:
            reason_counts["大文件"] += 1
        if "超大文件" in event.reasons:
            reason_counts["超大文件"] += 1
        if event.topic == "im_audit":
            reason_counts["IM附件外发"] += 1
        if any(key.startswith(("search_id=", "download_file_key=", "file_id=")) for key in event.lookup_keys):
            with_lookup += 1
    debug_timing("focus counters complete")

    sorted_events = sorted(events, key=event_priority_sort_key)
    shortlist = sorted_events
    debug_timing("before behavior rows")
    audit_events_for_behavior = [event for event in audit_events if event.event_id not in false_positive_reasons]
    behavior_rows = build_behavior_anomaly_rows(audit_events_for_behavior, tz)
    debug_timing("after behavior rows")
    behavior_signal_count = sum(len(rows) for rows in behavior_rows.values())
    confirmed_external = sum(1 for event in events if is_confirmed_external_event(event))
    unknown_im = sum(1 for event in events if event.topic == "im_audit" and event.recipient_relation == "unknown")
    mail_events_count = sum(1 for event in events if event.topic == "mail_audit")
    external_sender_count = sum(1 for event in events if is_external_sender_mailbox(event))
    im_events_count = sum(1 for event in events if event.topic == "im_audit")
    unclear_target_count = sum(
        1
        for event in events
        if not is_confirmed_external_event(event) and not is_peripheral_copy_event(event) and not is_external_sender_mailbox(event)
    )
    design_events = sum(1 for event in events if any(extension(name) in DESIGN_EXTS for name in leadership_file_names(event)))
    design_send_events = sum(1 for event in events if is_design_send_event(event))
    peripheral_copy_events = sum(1 for event in events if is_peripheral_copy_event(event) and is_design_event(event))
    three_d_events = sum(1 for event in events if is_three_d_model_event(event))
    two_d_cad_events = sum(1 for event in events if is_two_d_cad_event(event))
    pcb_ecad_events = sum(1 for event in events if is_pcb_ecad_event(event))
    sensitive_name_events = sum(1 for event in events if event_leadership_keyword_hits(event))
    mapped_people = sum(1 for event in events if event.mapping_source)
    debug_timing("post behavior counters complete")
    report_period = period_text(args, start, end)
    source_label = report_source_label(args)
    generated_at = os.environ.get("TIANQING_REPORT_GENERATED_AT") or datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    debug_timing("before asset analysis")
    asset_analysis = fetch_asset_analysis(args, tz, start, end, internal_domains)
    debug_timing("after asset analysis")
    args.asset_by_terminal = asset_analysis.asset_by_terminal
    asset_as_of = end or datetime.now(tz)
    args.asset_as_of = asset_as_of
    debug_timing("before three dimensional rename tracking")
    three_d_rename_findings = load_three_d_rename_findings(args, start, end, tz, internal_domains)
    debug_timing(f"after three dimensional rename tracking findings={len(three_d_rename_findings)}")
    debug_timing("before decrypt drawing risk analysis")
    decrypt_risk_analysis = load_decrypt_risk_analysis(args, start, end, tz, audit_events, internal_domains)
    debug_timing(
        f"after decrypt drawing risk analysis records={len(decrypt_risk_analysis.records)} trend={len(decrypt_risk_analysis.trend_records)}"
    )
    public_base_url = str(getattr(args, "public_base_url", "") or DEFAULT_PUBLIC_BASE_URL).rstrip("/")
    reports_url = f"{public_base_url}/reports"
    settings_url = f"{public_base_url}/settings"
    terminal_check_params = urllib.parse.urlencode(
        {
            "preset": "custom",
            "start": start.strftime("%Y-%m-%dT%H:%M"),
            "end": end.strftime("%Y-%m-%dT%H:%M"),
        }
    )
    terminal_check_url = f"{public_base_url}/terminal-check?{terminal_check_params}"
    home_url = f"{public_base_url}/"
    sidecar_reports = SidecarReportStore(getattr(args, "sidecar_output_dir", None))
    decrypt_module_result = build_decrypt_audit_module_result(
        args,
        decrypt_risk_analysis,
        tz,
        report_period,
        source_label,
        end,
    )
    for page, content in decrypt_module_result.sidecar_pages.items():
        sidecar_reports[page] = content
    debug_timing(
        f"decrypt module complete pages={len(decrypt_module_result.sidecar_pages)} sidecars={len(sidecar_reports)}"
    )
    tianqing_builders = TianqingOutboundModuleBuilders(
        build_channel_matrix_result=build_tianqing_channel_matrix_result,
        build_rename_tracking_result=build_tianqing_rename_tracking_result,
        build_organization_risk_result=build_tianqing_organization_risk_result,
        build_evidence_detail_result=build_tianqing_evidence_detail_result,
        build_trend_summary=build_trend_summary,
        trend_comparison_html=trend_comparison_html,
        build_rule_risk_overview_html=build_rule_risk_overview_html,
        is_large_archive_event=is_large_archive_event,
        is_tianqing_level_one_event=lambda event: is_tianqing_level_one_event(event, internal_domains),
        debug_timing=debug_timing,
    )
    tianqing_module_result = build_tianqing_outbound_module_result(
        args,
        events,
        procurement_muted_events,
        false_positive_events,
        false_positive_reasons,
        behavior_rows,
        keyword_counts,
        keyword_event_map,
        asset_analysis,
        asset_as_of,
        three_d_rename_findings,
        trend_windows,
        tz,
        start,
        end,
        internal_domains,
        report_period,
        source_label,
        tianqing_builders,
    )
    for page, content in tianqing_module_result.sidecar_pages.items():
        sidecar_reports[page] = content
    debug_timing(
        f"tianqing outbound module complete pages={len(tianqing_module_result.sidecar_pages)} metrics={tianqing_module_result.metrics} sidecars={len(sidecar_reports)}"
    )
    plm_home_module = build_plm_login_audit_home_module(enabled=False)
    global_management_summary_html = build_global_management_summary_html(
        decrypt_module_result.metrics,
        tianqing_module_result.metrics,
        {"enabled": False},
    )
    home_focus_text = (
        "一级风险定义：标准图纸解密；天擎标准图纸外发/拷贝；"
        "天擎大于100MB压缩包外发/上传/外设拷贝；PLM技术、研发、工艺账号池外登录。"
    )
    home_evidence_text = "一级风险进入顶部汇总管理结论，矩阵、趋势和明细用于定位组织、终端与证据链。"
    home_modules = [
        decrypt_module_result.home_module,
        tianqing_module_result.home_module,
        plm_home_module,
    ]
    home_modules_html = render_report_home_modules(home_modules)
    main_html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>数据安全审计报告</title>
  <style>
    :root {{
      --bg: #edf2f7;
      --paper: #ffffff;
      --surface: #ffffff;
      --surface-soft: #f8fafc;
      --ink: #182230;
      --muted: #667085;
      --line: #d8e0ea;
      --line-strong: #b9c6d5;
      --navy: #122033;
      --teal: #08746f;
      --blue: #245edb;
      --amber: #b25e09;
      --red: #b42318;
      --green: #157347;
      --shadow: 0 16px 38px rgba(24, 34, 48, 0.08);
      --shadow-soft: 0 8px 22px rgba(24, 34, 48, 0.06);
      --font-sans: "MiSans", "HarmonyOS Sans SC", "Alibaba PuHuiTi 3.0", "Source Han Sans SC", "Noto Sans CJK SC", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei UI", "Microsoft YaHei", -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    html {{
      scroll-behavior: smooth;
      -webkit-font-smoothing: antialiased;
      text-rendering: optimizeLegibility;
    }}
    body {{
      margin: 0;
      background: linear-gradient(180deg, #e9eff6 0%, #f6f8fb 360px, #edf2f7 100%);
      color: var(--ink);
      font-family: var(--font-sans);
      font-size: 14px;
      line-height: 1.58;
      letter-spacing: 0;
    }}
    body, table, button, input, textarea, select {{
      font-family: var(--font-sans);
    }}
    .report {{
      width: 100%;
      min-height: 100vh;
      margin: 0;
      padding: 28px 36px 50px;
      background: transparent;
    }}
    header {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 28px;
      align-items: start;
      padding: 28px 30px;
      border: 1px solid rgba(255, 255, 255, 0.16);
      border-radius: 14px;
      background: linear-gradient(135deg, #121f31 0%, #16334a 48%, #0f766e 100%);
      box-shadow: var(--shadow);
    }}
    h1 {{
      margin: 0 0 10px;
      font-size: 34px;
      font-weight: 700;
      line-height: 1.22;
      letter-spacing: 0;
    }}
    header h1 {{ color: #fff; }}
    h2 {{
      margin: 30px 0 14px;
      font-size: 20px;
      font-weight: 700;
      line-height: 1.35;
      letter-spacing: 0;
    }}
    h3 {{
      margin: 20px 0 10px;
      font-size: 15px;
      font-weight: 680;
      line-height: 1.4;
      color: #344054;
      letter-spacing: 0;
    }}
    .meta {{
      display: grid;
      gap: 4px;
      color: rgba(255, 255, 255, 0.74);
      font-size: 13px;
      line-height: 1.7;
    }}
    .stamp {{
      min-width: 190px;
      border: 1px solid rgba(255, 255, 255, 0.22);
      border-left: 4px solid #93c5fd;
      border-radius: 12px;
      padding: 12px 14px;
      color: rgba(255, 255, 255, 0.72);
      background: rgba(255, 255, 255, 0.08);
      font-size: 13px;
      line-height: 1.65;
    }}
    .stamp a {{
      display: block;
      color: inherit;
      text-decoration: none;
    }}
    .stamp strong {{
      display: block;
      color: #fff;
      font-size: 17px;
      margin-bottom: 4px;
      letter-spacing: 0;
    }}
    .top-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 14px;
    }}
    .top-action {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 34px;
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 6px 12px;
      color: #dceafe;
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.20);
      font-size: 13px;
      font-weight: 680;
      text-decoration: none;
    }}
    .top-action.primary {{
      border-color: rgba(255, 255, 255, 0.26);
      color: #122033;
      background: #fff;
    }}
    .top-action:hover {{
      border-color: rgba(255, 255, 255, 0.52);
      background: rgba(255, 255, 255, 0.15);
    }}
    .top-action.primary:hover {{
      background: #eef6ff;
    }}
    .top-action.danger {{
      border-color: rgba(248, 113, 113, 0.62);
      color: #fff;
      background: linear-gradient(180deg, #ef4444 0%, #dc2626 100%);
      box-shadow: 0 10px 22px rgba(220, 38, 38, 0.22);
    }}
    .top-action.danger:hover {{
      border-color: rgba(254, 202, 202, 0.9);
      background: linear-gradient(180deg, #f87171 0%, #dc2626 100%);
    }}
    .kpis {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
      gap: 14px;
      margin: 22px 0 8px;
    }}
    .kpi {{
      position: relative;
      display: block;
      overflow: hidden;
      border: 1px solid rgba(216, 224, 234, 0.95);
      border-radius: 10px;
      padding: 16px 16px 15px;
      background: var(--surface);
      min-height: 122px;
      color: inherit;
      text-decoration: none;
      box-shadow: var(--shadow-soft);
      transition: border-color 0.15s ease, box-shadow 0.15s ease, transform 0.15s ease;
    }}
    .kpi::before {{
      content: "";
      position: absolute;
      inset: 0 0 auto;
      height: 3px;
      background: linear-gradient(90deg, var(--teal), var(--blue));
    }}
    .kpi:nth-child(2)::before {{ background: linear-gradient(90deg, var(--red), var(--amber)); }}
    .kpi:nth-child(4)::before {{ background: linear-gradient(90deg, #7c3aed, var(--blue)); }}
    .kpi:nth-child(6)::before {{ background: linear-gradient(90deg, var(--amber), #0f766e); }}
    .kpi:nth-child(2) .kpi-value {{ color: var(--red); }}
    .kpi:nth-child(4) .kpi-value, .kpi:nth-child(5) .kpi-value {{ color: #1d4ed8; }}
    .kpi:hover {{
      border-color: #93c5fd;
      box-shadow: 0 18px 34px rgba(24, 34, 48, 0.13);
      transform: translateY(-1px);
    }}
    .kpi-label {{
      color: var(--muted);
      font-size: 13px;
      font-weight: 650;
    }}
    .kpi-value {{
      margin-top: 8px;
      font-size: 34px;
      font-weight: 750;
      line-height: 1.05;
      font-variant-numeric: tabular-nums;
    }}
    .kpi-note {{
      margin-top: 8px;
      color: var(--muted);
      font-size: 12px;
    }}
    .summary {{
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 24px;
      align-items: start;
      margin-top: 22px;
    }}
    .panel {{
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 18px 20px;
      background: var(--surface);
      box-shadow: var(--shadow-soft);
    }}
    .panel h2 {{
      margin-top: 0;
    }}
    .panel li {{
      padding-left: 2px;
    }}
    .noise-summary {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(260px, 360px);
      gap: 18px;
      align-items: center;
      border: 1px solid #c8d7eb;
      border-radius: 10px;
      padding: 15px 17px;
      margin-top: 16px;
      background: #f8fbff;
      box-shadow: var(--shadow-soft);
    }}
    .noise-summary h2 {{
      margin: 0;
      font-size: 17px;
    }}
    .noise-summary .note {{
      margin: 6px 0 0;
    }}
    .noise-metrics {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }}    ul {{
      margin: 0;
      padding-left: 20px;
    }}
    li {{ margin: 7px 0; }}
    .grid-2 {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 22px;
    }}
    .dashboard {{
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 18px;
      margin-top: 22px;
    }}
    .chart-panel {{
      grid-column: span 6;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 17px 18px;
      background: var(--surface);
      min-height: 260px;
      box-shadow: var(--shadow-soft);
    }}
    .chart-panel.wide {{ grid-column: span 12; }}
    .chart-panel h2, .chart-panel h3 {{
      margin-top: 0;
    }}
    .donut-wrap {{
      display: grid;
      grid-template-columns: 168px 1fr;
      gap: 18px;
      align-items: center;
    }}
    .donut {{
      width: 160px;
      height: 160px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      box-shadow: inset 0 0 0 1px rgba(0, 0, 0, 0.04);
    }}
    .donut > div {{
      width: 92px;
      height: 92px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      align-content: center;
      background: var(--surface);
      border: 1px solid var(--line);
    }}
    .donut strong {{
      font-size: 26px;
      font-weight: 750;
      line-height: 1;
      font-variant-numeric: tabular-nums;
    }}
    .donut span {{
      color: var(--muted);
      font-size: 12px;
    }}
    .donut-legend {{
      display: grid;
      gap: 8px;
      min-width: 0;
    }}
    .donut-legend-row {{
      display: grid;
      grid-template-columns: 12px minmax(0, 1fr) 42px 42px;
      gap: 8px;
      align-items: center;
      font-size: 13px;
    }}
    .donut-legend-row-link {{
      color: inherit;
      text-decoration: none;
      border-radius: 7px;
      padding: 3px 5px;
      margin: -3px -5px;
      transition: background 0.15s ease, box-shadow 0.15s ease;
    }}
    .donut-legend-row-link:hover {{
      background: #eff6ff;
      box-shadow: inset 0 0 0 1px #bfdbfe;
    }}
    .donut-legend-row-link .legend-label {{
      color: #175cd3;
      font-weight: 650;
    }}
    .dot {{
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
    }}
    .legend-label {{
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: #344054;
    }}
    .legend-label a {{
      color: #175cd3;
      text-decoration: none;
      border-bottom: 1px solid rgba(23, 92, 211, 0.28);
    }}
    .legend-value, .legend-rate {{
      color: var(--muted);
      text-align: right;
      font-variant-numeric: tabular-nums;
    }}
    .metric-chips {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 10px;
    }}
    .metric-chip {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 10px;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 11px 13px;
      background: var(--surface);
      min-height: 52px;
      box-shadow: 0 5px 14px rgba(24, 34, 48, 0.04);
    }}
    a.metric-chip {{
      color: inherit;
      text-decoration: none;
    }}
    .metric-chip-link {{
      transition: border-color 0.15s ease, background 0.15s ease, box-shadow 0.15s ease, transform 0.15s ease;
    }}
    .metric-chip-link:hover {{
      border-color: #93c5fd;
      background: #eff6ff;
      box-shadow: 0 8px 18px rgba(37, 99, 235, 0.10);
      transform: translateY(-1px);
    }}
    .metric-chip-link span {{
      color: #175cd3;
      font-weight: 650;
    }}
    .metric-chip span {{
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: #344054;
    }}
    .metric-chip strong {{
      font-size: 20px;
      color: var(--ink);
      font-variant-numeric: tabular-nums;
    }}
    .trend-shell {{
      background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
    }}
    .trend-control-row {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin: 0 0 10px;
    }}
    .trend-range-tabs,
    .trend-tabs {{
      display: inline-flex;
      flex-wrap: wrap;
      gap: 4px;
      padding: 4px;
      border: 1px solid #dbe6f5;
      border-radius: 9px;
      background: #eef5ff;
    }}
    .trend-range-tabs {{
      background: #f3f7fb;
    }}
    .trend-range-tabs button,
    .trend-tabs button {{
      min-height: 26px;
      border: 0;
      border-radius: 6px;
      padding: 3px 10px;
      color: #516173;
      background: transparent;
      font: inherit;
      font-size: 11px;
      font-weight: 760;
      cursor: pointer;
    }}
    .trend-range-tabs button.active,
    .trend-tabs button.active {{
      color: #175cd3;
      background: #fff;
      box-shadow: 0 5px 14px rgba(24, 34, 48, 0.08);
    }}
    .trend-range-panel {{
      display: none;
    }}
    .trend-range-panel.active {{
      display: block;
    }}
    .trend-range-note {{
      margin: 0 0 12px;
    }}
    .trend-panel {{
      display: none;
    }}
    .trend-panel.active {{
      display: block;
    }}
    .trend-channel-grid.active,
    .trend-org-grid.active {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    .trend-chart-card {{
      border: 1px solid #e4ebf5;
      border-radius: 10px;
      padding: 9px 12px 8px;
      background: rgba(255, 255, 255, 0.78);
      box-shadow: 0 5px 14px rgba(24, 34, 48, 0.035);
    }}
    .trend-chart-head {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 2px;
    }}
    .trend-chart-head h3 {{
      margin: 0;
      color: #122033;
      font-size: 12px;
      font-weight: 800;
    }}
    .trend-chart-head span {{
      color: #667085;
      font-size: 9px;
      line-height: 1.35;
      text-align: right;
    }}
    .trend-svg {{
      display: block;
      width: 100%;
      height: 296px;
      min-height: 0;
    }}
    .trend-svg-bg {{
      fill: #fcfdff;
    }}
    .trend-grid-line {{
      stroke: #e8eef7;
      stroke-width: 0.7;
    }}
    .trend-axis-label {{
      fill: #98a4b3;
      font-size: 10.2px;
      font-weight: 880;
    }}
    .trend-axis-label-x {{
      font-size: 10px;
      font-weight: 880;
    }}
    .trend-line-group {{
      outline: none;
    }}
    .trend-line-group.is-hidden {{
      display: none;
    }}
    .trend-line {{
      transition: stroke-width 0.12s ease, opacity 0.12s ease;
    }}
    .trend-line-shadow {{
      opacity: 0.16;
      transition: stroke-width 0.12s ease, opacity 0.12s ease;
    }}
    .trend-hit-line {{
      fill: none;
      stroke: transparent;
      stroke-width: 14;
      stroke-linecap: round;
      stroke-linejoin: round;
      pointer-events: stroke;
    }}
    .trend-point-hit {{
      fill: transparent;
      stroke: transparent;
      pointer-events: all;
      cursor: crosshair;
    }}
    .trend-line-group:hover .trend-line,
    .trend-line-group:focus .trend-line {{
      stroke-width: 3.8;
    }}
    .trend-line-group:hover .trend-line-shadow,
    .trend-line-group:focus .trend-line-shadow {{
      opacity: 0.24;
      stroke-width: 8;
    }}
    .trend-hover-tip {{
      position: fixed;
      z-index: 50;
      display: none;
      max-width: 240px;
      border: 1px solid #d9e0ea;
      border-radius: 7px;
      padding: 6px 8px;
      background: rgba(255, 255, 255, 0.96);
      color: #172033;
      box-shadow: 0 8px 24px rgba(15, 23, 42, 0.13);
      font-size: 12px;
      font-weight: 820;
      line-height: 1.35;
      pointer-events: none;
      white-space: nowrap;
    }}
    .trend-legend {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 5px 14px;
      margin-top: 1px;
      padding: 0 2px 1px;
    }}
    .trend-legend-item {{
      display: inline-flex;
      gap: 6px;
      align-items: center;
      min-width: 0;
      max-width: 170px;
      min-height: 20px;
      border: 0;
      border-radius: 6px;
      padding: 0 2px;
      color: inherit;
      background: transparent;
      font: inherit;
      text-decoration: none;
      cursor: pointer;
      appearance: none;
    }}
    .trend-legend-item:hover {{
      color: #175cd3;
      background: #eff6ff;
    }}
    .trend-legend-item.is-muted {{
      opacity: 0.36;
    }}
    .trend-line-swatch {{
      flex: 0 0 auto;
      width: 38px;
      height: 7px;
      background: var(--trend-color);
      border-radius: 999px;
      box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.95), 0 2px 7px rgba(15, 23, 42, 0.16);
    }}
    .trend-legend-label {{
      overflow: hidden;
      color: #344054;
      font-size: 10px;
      font-weight: 760;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .trend-legend-item strong {{
      color: #122033;
      font-size: 10px;
      font-weight: 820;
      font-variant-numeric: tabular-nums;
    }}
    .trend-small-multiples {{
      margin-top: 12px;
      padding-top: 10px;
      border-top: 1px solid #e8eef7;
    }}
    .trend-small-head {{
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 8px;
    }}
    .trend-small-head strong {{
      color: #122033;
      font-size: 12px;
      font-weight: 860;
    }}
    .trend-small-head span {{
      color: #667085;
      font-size: 10px;
      font-weight: 720;
      text-align: right;
    }}
    .trend-mini-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
    }}
    .trend-mini-card {{
      min-width: 0;
      border: 1px solid #e8eef7;
      border-radius: 10px;
      padding: 7px 8px 5px;
      background: #fbfdff;
    }}
    .trend-mini-title {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 2px;
    }}
    .trend-mini-title span {{
      overflow: hidden;
      color: #172033;
      font-size: 11px;
      font-weight: 840;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .trend-mini-title strong {{
      flex: 0 0 auto;
      color: #667085;
      font-size: 9px;
      font-weight: 760;
      font-variant-numeric: tabular-nums;
    }}
    .trend-mini-svg {{
      display: block;
      width: 100%;
      height: 168px;
    }}
    .trend-mini-svg .trend-axis-label {{
      font-size: 9.5px;
      font-weight: 840;
    }}
    .trend-mini-svg .trend-axis-label-x {{
      font-size: 9.2px;
    }}
    .rename-tracking-shell {{
      border-color: #d7e3f8;
      background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
    }}
    .rename-card-grid {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 9px;
      margin-top: 14px;
    }}
    .rename-card-grid-compact {{
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }}
    .standard-design-alert-shell {{
      border-color: #f0c4cb;
      background: linear-gradient(180deg, #ffffff 0%, #fff8f9 100%);
    }}
    .decrypt-risk-shell {{
      border-color: #d8e4f2;
      background: linear-gradient(180deg, #ffffff 0%, #f7fbff 100%);
    }}
    .decrypt-card-grid {{
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 9px;
      margin-top: 14px;
    }}
    .decrypt-mini-card {{
      position: relative;
      overflow: hidden;
      display: grid;
      grid-template-rows: auto 1fr;
      min-height: 68px;
      border: 1px solid #dfe8f4;
      border-radius: 10px;
      padding: 10px 11px 9px;
      background: rgba(255, 255, 255, 0.92);
      color: #172033;
      text-decoration: none;
      box-shadow: 0 7px 16px rgba(24, 34, 48, 0.045);
      transition: border-color 0.14s ease, box-shadow 0.14s ease, transform 0.14s ease;
    }}
    .decrypt-mini-card::before {{
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 3px;
      background: var(--decrypt-accent, #2563eb);
    }}
    .decrypt-mini-card-main {{
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 8px;
      min-width: 0;
    }}
    .decrypt-mini-card-main span {{
      overflow: hidden;
      color: #334155;
      font-size: 11px;
      font-weight: 830;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .decrypt-mini-card-main strong {{
      flex: 0 0 auto;
      color: #111827;
      font-size: 20px;
      font-weight: 900;
      line-height: 1;
      font-variant-numeric: tabular-nums;
    }}
    .decrypt-mini-card em {{
      overflow: hidden;
      display: -webkit-box;
      margin-top: 7px;
      color: #667085;
      font-size: 10px;
      font-style: normal;
      font-weight: 720;
      line-height: 1.35;
      -webkit-box-orient: vertical;
      -webkit-line-clamp: 2;
    }}
    .decrypt-mini-card:hover {{
      border-color: #9fc1ff;
      box-shadow: 0 10px 22px rgba(37, 99, 235, 0.11);
      transform: translateY(-1px);
    }}
    .decrypt-mini-card-red {{ --decrypt-accent: #dc2626; }}
    .decrypt-mini-card-blue {{ --decrypt-accent: #2563eb; }}
    .decrypt-mini-card-amber {{ --decrypt-accent: #ea580c; }}
    .decrypt-mini-card-violet {{ --decrypt-accent: #7c3aed; }}
    .decrypt-mini-card-slate {{ --decrypt-accent: #334155; }}
    .rename-card {{
      position: relative;
      overflow: hidden;
      display: grid;
      grid-template-rows: auto 1fr;
      min-height: 68px;
      border: 1px solid #dbe5f2;
      border-radius: 10px;
      padding: 10px 11px 9px;
      background: rgba(255, 255, 255, 0.92);
      color: #172033;
      text-decoration: none;
      box-shadow: 0 7px 16px rgba(23, 32, 51, 0.045);
      transition: border-color 0.14s ease, box-shadow 0.14s ease, transform 0.14s ease;
    }}
    .rename-card::before {{
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 3px;
      background: var(--rename-accent, #2563eb);
    }}
    .rename-card-main {{
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 8px;
      min-width: 0;
    }}
    .rename-card span {{
      overflow: hidden;
      color: #334155;
      font-size: 11px;
      font-weight: 830;
      letter-spacing: 0;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .rename-card strong {{
      flex: 0 0 auto;
      color: #111827;
      font-size: 20px;
      font-weight: 900;
      line-height: 1;
      font-variant-numeric: tabular-nums;
    }}
    .rename-card em {{
      overflow: hidden;
      display: -webkit-box;
      margin-top: 7px;
      color: #667085;
      font-size: 10px;
      font-style: normal;
      font-weight: 700;
      line-height: 1.35;
      -webkit-box-orient: vertical;
      -webkit-line-clamp: 2;
    }}
    .rename-card:hover {{
      border-color: #9fc1ff;
      box-shadow: 0 10px 22px rgba(37, 99, 235, 0.11);
      transform: translateY(-1px);
    }}
    .rename-card-red {{ --rename-accent: #be123c; }}
    .rename-card-blue {{ --rename-accent: #2563eb; }}
    .rename-card-amber {{ --rename-accent: #b45309; }}
    .rename-card-violet {{ --rename-accent: #7c3aed; }}
    .rename-card-slate {{ --rename-accent: #334155; }}
    .rename-empty {{
      margin: 12px 0 0;
      border: 1px solid #e4eaf2;
      border-radius: 10px;
      padding: 10px 12px;
      background: #fbfdff;
      color: #667085;
      font-size: 13px;
      font-weight: 700;
    }}
    .decrypt-trend-panel {{
      margin-top: 12px;
    }}
    .decrypt-trend-row {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    .decrypt-trend-panel .trend-chart-card {{
      background: rgba(255, 255, 255, 0.9);
    }}
    .decrypt-trend-card {{
      min-width: 0;
    }}
    .decrypt-trend-card .trend-svg {{
      height: 220px;
    }}
    .decrypt-trend-panel .trend-chart-head span {{
      font-weight: 760;
    }}
    .decrypt-company-panel {{
      margin-top: 14px;
      border: 1px solid #e4ebf5;
      border-radius: 12px;
      padding: 12px 12px 10px;
      background: rgba(255, 255, 255, 0.78);
      box-shadow: 0 5px 14px rgba(24, 34, 48, 0.035);
    }}
    .decrypt-company-panel h3 {{
      margin: 6px 0 10px;
      color: #122033;
      font-size: 14px;
      font-weight: 860;
    }}
    .decrypt-company-matrix th,
    .decrypt-company-matrix td {{
      padding-top: 11px;
      padding-bottom: 11px;
    }}
    .matrix-shell {{
      background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
    }}
    .channel-matrix-wrap {{
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fff;
      box-shadow: 0 8px 20px rgba(24, 34, 48, 0.05);
    }}
    .channel-matrix {{
      min-width: 780px;
      border-collapse: collapse;
      table-layout: fixed;
    }}
    .channel-matrix th,
    .channel-matrix td {{
      text-align: center;
      vertical-align: middle;
      padding: 12px 13px;
    }}
    .channel-matrix thead th {{
      background: #f3f8ff;
      color: #344054;
      font-size: 12px;
    }}
    .channel-matrix .channel-name {{
      width: 180px;
      text-align: left;
      color: #172033;
      background: #fbfdff;
      font-weight: 760;
    }}
    .matrix-count,
    .matrix-total {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 42px;
      min-height: 28px;
      border-radius: 999px;
      padding: 4px 10px;
      color: #175cd3;
      background: #eff6ff;
      font-weight: 800;
      text-decoration: none;
      font-variant-numeric: tabular-nums;
      transition: background 0.15s ease, box-shadow 0.15s ease, transform 0.15s ease;
    }}
    .matrix-total {{
      color: #0f766e;
      background: #eaf8f5;
    }}
    .matrix-count.matrix-heat-low,
    .matrix-total.matrix-heat-low {{
      color: #067647;
      background: #ecfdf3;
    }}
    .matrix-count.matrix-heat-mid,
    .matrix-total.matrix-heat-mid {{
      color: #3f6212;
      background: #f7fee7;
    }}
    .matrix-count.matrix-heat-high,
    .matrix-total.matrix-heat-high {{
      color: #c2410c;
      background: #fff7ed;
    }}
    .matrix-count.matrix-heat-critical,
    .matrix-total.matrix-heat-critical {{
      color: #be123c;
      background: #fff1f2;
    }}
    .matrix-count:hover,
    .matrix-total:hover {{
      box-shadow: 0 8px 16px rgba(37, 99, 235, 0.12);
      transform: translateY(-1px);
    }}
    .detail-count,
    .terminal-count {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 32px;
      min-height: 24px;
      border-radius: 999px;
      padding: 2px 8px;
      background: #f8fafc;
      color: #667085;
      font-weight: 820;
      font-variant-numeric: tabular-nums;
      text-decoration: none;
    }}
    .detail-count-link,
    .terminal-count-link {{
      display: inline-flex;
      text-decoration: none;
      border-bottom: 0;
    }}
    .detail-count-low,
    .terminal-count-low {{
      color: #067647;
      background: #ecfdf3;
    }}
    .detail-count-mid,
    .terminal-count-mid {{
      color: #3f6212;
      background: #f7fee7;
    }}
    .detail-count-high,
    .terminal-count-high {{
      color: #c2410c;
      background: #fff7ed;
    }}
    .detail-count-critical,
    .terminal-count-critical {{
      color: #be123c;
      background: #fff1f2;
    }}
    .detail-count-link:hover .detail-count,
    .terminal-count-link:hover .terminal-count {{
      box-shadow: 0 8px 16px rgba(37, 99, 235, 0.12);
      transform: translateY(-1px);
    }}
    .matrix-zero {{
      color: #a7b2c2;
      font-variant-numeric: tabular-nums;
    }}
    .matrix-footnote {{
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(360px, 0.9fr);
      gap: 18px;
      align-items: start;
      margin-top: 16px;
      border: 1px solid #c8d7eb;
      border-radius: 12px;
      padding: 15px 17px;
      background: #f8fbff;
    }}
    .matrix-footnote h3 {{
      margin: 0 0 6px;
      font-size: 16px;
    }}
    .terminal-risk-shell {{
      border-color: #cfe0f2;
      background: linear-gradient(180deg, #ffffff 0%, #f7fbff 100%);
    }}
    .terminal-risk-shell .section-title-row h2 {{
      color: #122033;
      font-size: 25px;
      font-weight: 820;
      line-height: 1.22;
    }}
    .terminal-risk-shell .section-title-row p {{
      color: #516173;
      font-size: 14px;
      line-height: 1.75;
    }}
    .terminal-risk-chips {{
      margin-bottom: 16px;
    }}
    .terminal-risk-chips .metric-chip {{
      min-height: 78px;
      border-radius: 13px;
      background: linear-gradient(180deg, #ffffff 0%, #f7fafc 100%);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.9);
    }}
    .terminal-risk-chips .metric-chip span {{
      color: #516173;
      font-size: 12px;
      font-weight: 760;
    }}
    .terminal-risk-chips .metric-chip strong {{
      color: #122033;
      font-size: 25px;
      font-weight: 840;
    }}
    .terminal-risk-table {{
      margin-top: 8px;
    }}
    .terminal-risk-table .table-wrap {{
      border-color: #d8e4f2;
      border-radius: 13px;
      box-shadow: 0 12px 28px rgba(23, 32, 51, 0.05);
    }}
    table.terminal-risk {{
      font-family: var(--font-sans);
      font-size: 12px;
      line-height: 1.45;
      table-layout: fixed;
    }}
    table.terminal-risk th,
    table.terminal-risk td {{
      padding: 8px 7px;
      vertical-align: middle;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      text-align: center;
    }}
    table.terminal-risk td:nth-child(2),
    table.terminal-risk td:nth-child(3),
    table.terminal-risk td:nth-child(4),
    table.terminal-risk td:nth-child(5),
    table.terminal-risk td:nth-child(6) {{
      text-align: left;
    }}
    table.terminal-risk th {{
      background: #f3f8ff;
      color: #344054;
      font-size: 12px;
      font-weight: 800;
    }}
    table.terminal-risk .terminal-risk-group-row th {{
      background: #eaf3ff;
      border-bottom: 1px solid #d8e4f2;
      text-align: center;
      color: #243245;
      font-size: 11px;
      font-weight: 840;
    }}
    table.terminal-risk .terminal-risk-sub-row th {{
      background: #f6f9ff;
      color: #516173;
      font-size: 10px;
      font-weight: 820;
      line-height: 1.18;
      white-space: normal;
      padding: 7px 5px;
    }}
    table.terminal-risk .terminal-group-disposition,
    table.terminal-risk .terminal-group-object,
    table.terminal-risk .terminal-group-process,
    table.terminal-risk .terminal-group-time {{
      border-left: 1px solid #d8e4f2;
      border-right: 1px solid #d8e4f2;
    }}
    table.terminal-risk td {{
      color: #344054;
    }}
    table.terminal-risk tbody tr:nth-child(even) td {{
      background: #fbfdff;
    }}
    table.terminal-risk tbody tr:hover td {{
      background: #f3f8ff;
    }}
    table.terminal-risk td:nth-child(2),
    table.terminal-risk td:nth-child(3),
    table.terminal-risk td:nth-child(4) {{
      color: #172033;
      font-weight: 760;
    }}
    table.terminal-risk td:nth-child(n+7) {{
      font-variant-numeric: tabular-nums;
    }}
    table.terminal-risk .terminal-risk-sub-row th:nth-child(1),
    table.terminal-risk td:nth-child(1) {{ width: 34px; }}
    table.terminal-risk .terminal-risk-sub-row th:nth-child(2),
    table.terminal-risk td:nth-child(2) {{ width: 112px; }}
    table.terminal-risk .terminal-risk-sub-row th:nth-child(3),
    table.terminal-risk td:nth-child(3) {{ width: 94px; }}
    table.terminal-risk .terminal-risk-sub-row th:nth-child(4),
    table.terminal-risk td:nth-child(4) {{ width: 86px; }}
    table.terminal-risk .terminal-risk-sub-row th:nth-child(5),
    table.terminal-risk td:nth-child(5) {{ width: 160px; }}
    table.terminal-risk .terminal-risk-sub-row th:nth-child(6),
    table.terminal-risk td:nth-child(6) {{ width: 104px; }}
    table.terminal-risk .terminal-risk-sub-row th:nth-child(7),
    table.terminal-risk td:nth-child(7),
    table.terminal-risk .terminal-risk-sub-row th:nth-child(8),
    table.terminal-risk td:nth-child(8),
    table.terminal-risk .terminal-risk-sub-row th:nth-child(9),
    table.terminal-risk td:nth-child(9),
    table.terminal-risk .terminal-risk-sub-row th:nth-child(10),
    table.terminal-risk td:nth-child(10),
    table.terminal-risk .terminal-risk-sub-row th:nth-child(11),
    table.terminal-risk td:nth-child(11),
    table.terminal-risk .terminal-risk-sub-row th:nth-child(12),
    table.terminal-risk td:nth-child(12),
    table.terminal-risk .terminal-risk-sub-row th:nth-child(13),
    table.terminal-risk td:nth-child(13),
    table.terminal-risk .terminal-risk-sub-row th:nth-child(14),
    table.terminal-risk td:nth-child(14) {{ width: 48px; }}
    table.terminal-risk .terminal-risk-sub-row th:nth-child(15),
    table.terminal-risk td:nth-child(15) {{ width: 78px; }}
    table.terminal-risk .terminal-risk-sub-row th:nth-child(16),
    table.terminal-risk td:nth-child(16) {{ width: 118px; }}
    table.terminal-risk .terminal-risk-sub-row th:nth-child(n+7) {{
      white-space: normal;
      line-height: 1.16;
    }}
    table.terminal-risk .table-link {{
      display: inline-block;
      max-width: 100%;
      overflow: hidden;
      text-overflow: ellipsis;
      vertical-align: bottom;
      white-space: nowrap;
    }}
    .terminal-matrix-wrap {{
      overflow-x: hidden;
      border-radius: 13px;
    }}
    .terminal-matrix {{
      width: auto;
      min-width: 0;
      table-layout: fixed;
      font-size: 12px;
    }}
    .terminal-matrix col.terminal-rank-colgroup {{
      width: var(--terminal-rank-width, 34px);
    }}
    .terminal-matrix col.terminal-company-colgroup {{
      width: var(--terminal-company-width, 96px);
    }}
    .terminal-matrix col.terminal-department-colgroup {{
      width: var(--terminal-department-width, 78px);
    }}
    .terminal-matrix col.terminal-person-colgroup {{
      width: var(--terminal-person-width, 72px);
    }}
    .terminal-matrix col.terminal-ip-colgroup {{
      width: var(--terminal-ip-width, 96px);
    }}
    .terminal-matrix col.terminal-mac-colgroup {{
      width: var(--terminal-mac-width, 116px);
    }}
    .terminal-matrix col.matrix-number-col {{
      width: var(--matrix-number-col-width, 30px);
    }}
    .terminal-matrix col.matrix-total-col {{
      width: var(--matrix-total-col-width, 46px);
    }}
    .terminal-matrix th,
    .terminal-matrix td {{
      padding: 9px 3px;
      line-height: 1.28;
      text-align: center;
      vertical-align: middle;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .terminal-matrix thead th {{
      font-size: 10.5px;
      line-height: 1.15;
      padding-top: 10px;
      padding-bottom: 10px;
      white-space: normal;
    }}
    .terminal-matrix .terminal-matrix-channel {{
      background: #eaf3ff;
      border-left: 1px solid #d8e4f2;
      border-right: 1px solid #d8e4f2;
      font-weight: 840;
    }}
    .terminal-matrix .terminal-rank-col,
    .terminal-matrix .terminal-matrix-rank {{
      width: var(--terminal-rank-width, 34px);
    }}
    .terminal-matrix .terminal-company-col {{
      width: var(--terminal-company-width, 96px);
    }}
    .terminal-matrix .terminal-department-col {{
      width: var(--terminal-department-width, 78px);
    }}
    .terminal-matrix .terminal-person-col {{
      width: var(--terminal-person-width, 72px);
    }}
    .terminal-matrix .terminal-ip-col {{
      width: var(--terminal-ip-width, 96px);
    }}
    .terminal-matrix .terminal-mac-col {{
      width: var(--terminal-mac-width, 116px);
    }}
    .terminal-matrix .terminal-total-col {{
      width: var(--matrix-total-col-width, 46px);
    }}
    .terminal-matrix-company,
    .terminal-matrix-department,
    .terminal-matrix-person {{
      text-align: left !important;
      color: #172033;
      font-weight: 720;
    }}
    .terminal-matrix-ip,
    .terminal-matrix-mac {{
      text-align: left !important;
      color: #344054;
      font-weight: 500;
    }}
    .terminal-matrix .matrix-count,
    .terminal-matrix .matrix-total {{
      min-width: 24px;
      min-height: 22px;
      padding: 2px 6px;
      font-size: 12px;
    }}
    .org-insight-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 16px;
      margin-bottom: 16px;
    }}
    .org-panel {{
      border: 1px solid #d8e4f2;
      border-radius: 14px;
      padding: 16px;
      background: linear-gradient(180deg, #ffffff 0%, #fbfdff 100%);
      box-shadow: 0 12px 28px rgba(23, 32, 51, 0.05);
      min-width: 0;
    }}
    .org-panel-wide {{
      margin: 16px 0;
    }}
    .org-panel-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 8px;
    }}
    .org-panel-head span {{
      display: inline-flex;
      width: fit-content;
      min-height: 24px;
      align-items: center;
      border: 1px solid #bfe5dc;
      border-radius: 999px;
      padding: 3px 9px;
      color: #0f766e;
      background: #eaf8f5;
      font-size: 11px;
      font-weight: 820;
      letter-spacing: 0;
      text-transform: uppercase;
    }}
    .org-panel-head a {{
      color: #175cd3;
      font-size: 13px;
      font-weight: 750;
      text-decoration: none;
      border-bottom: 1px solid rgba(23, 92, 211, 0.28);
    }}
    .org-panel h3,
    .terminal-drilldown-panel h3 {{
      margin: 0 0 12px;
      color: #122033;
      font-size: 18px;
      font-weight: 820;
    }}
    .organization-matrix-wrap {{
      overflow-x: hidden;
      border-radius: 13px;
      box-shadow: 0 12px 28px rgba(23, 32, 51, 0.05);
    }}
    .organization-matrix {{
      min-width: 0;
    }}
    .organization-matrix-wide {{
      width: auto;
      min-width: 0;
      table-layout: fixed;
      font-size: 12px;
    }}
    .organization-matrix col.org-label-col {{
      width: var(--org-col-width, 260px);
    }}
    .organization-matrix col.matrix-number-col {{
      width: var(--matrix-number-col-width, 30px);
    }}
    .organization-matrix col.matrix-total-col {{
      width: var(--matrix-total-col-width, 46px);
    }}
    .organization-matrix-wide th,
    .organization-matrix-wide td {{
      padding: 6px 2px;
      text-align: center;
    }}
    .organization-matrix-wide thead tr:first-child th:first-child {{
      width: var(--org-col-width, 176px);
    }}
    .organization-matrix-wide thead tr:first-child th:last-child {{
      width: var(--matrix-total-col-width, 46px);
    }}
    .organization-matrix-wide thead tr:first-child th {{
      text-align: center;
      border-bottom-color: #d8e4f2;
      background: #eaf3ff;
      color: #243245;
      font-size: 10px;
      font-weight: 820;
      line-height: 1.15;
      padding-top: 10px;
      padding-bottom: 10px;
      white-space: normal;
    }}
    .organization-matrix-wide thead tr:nth-child(2) th {{
      min-width: 0;
      padding: 8px 1px;
      color: #516173;
      font-size: 9.5px;
      font-weight: 820;
      line-height: 1.15;
    }}
    .organization-matrix-wide .org-matrix-channel {{
      border-left: 1px solid #d8e4f2;
      border-right: 1px solid #d8e4f2;
    }}
    .organization-matrix .org-matrix-name {{
      width: var(--org-col-width, 176px);
      padding: 8px 7px;
      text-align: left;
      vertical-align: middle;
    }}
    .org-matrix-label {{
      display: grid;
      gap: 3px;
      min-width: 0;
    }}
    .org-matrix-label strong {{
      display: block;
      overflow: hidden;
      color: #122033;
      font-size: 12px;
      font-weight: 820;
      line-height: 1.35;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .org-matrix-label small {{
      overflow: hidden;
      color: #64748b;
      font-size: 11px;
      font-weight: 650;
      line-height: 1.35;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .org-matrix-label-link {{
      display: block;
      color: inherit;
      text-decoration: none;
      border-bottom: 0;
    }}
    .organization-matrix .matrix-count,
    .organization-matrix .matrix-total {{
      min-width: 24px;
      min-height: 22px;
      padding: 2px 5px;
      font-size: 12px;
    }}
    .org-more-details {{
      margin-top: 14px;
      border-top: 1px solid #e5edf7;
      padding-top: 12px;
    }}
    .org-more-details summary {{
      width: fit-content;
      cursor: pointer;
      color: #175cd3;
      font-size: 13px;
      font-weight: 780;
      list-style-position: inside;
    }}
    .org-more-details[open] summary {{
      margin-bottom: 12px;
    }}
    .org-tags {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      min-width: 0;
    }}
    .org-tags span {{
      display: inline-flex;
      align-items: center;
      max-width: 100%;
      border: 1px solid #d7e3f8;
      border-radius: 999px;
      padding: 3px 8px;
      background: #f6f9ff;
      color: #31435a;
      font-size: 12px;
      font-weight: 700;
      line-height: 1.3;
      white-space: nowrap;
    }}
    .org-tags-link {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      color: inherit;
      text-decoration: none;
    }}
    .terminal-drilldown-panel {{
      margin-top: 16px;
      border: 1px solid #d8e4f2;
      border-radius: 14px;
      padding: 16px;
      background: linear-gradient(180deg, #ffffff 0%, #fbfdff 100%);
      box-shadow: 0 12px 28px rgba(23, 32, 51, 0.05);
    }}
    .org-profile-tags {{
      margin: 4px 0 10px;
    }}
    .forbidden-shell {{
      background: linear-gradient(180deg, #ffffff 0%, #fbfcff 100%);
    }}
    .forbidden-shell .metric-chips {{
      gap: 12px;
    }}
    .forbidden-shell .metric-chip {{
      min-height: 72px;
      border-radius: 12px;
      background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
    }}
    .forbidden-shell .metric-chip strong {{
      font-size: 24px;
    }}
    .bar-row {{
      display: grid;
      grid-template-columns: minmax(120px, 1fr) 2fr 42px;
      gap: 10px;
      align-items: center;
      margin: 9px 0;
      font-size: 13px;
      line-height: 1.45;
    }}
    a.bar-row {{
      color: inherit;
      text-decoration: none;
    }}
    .bar-row-link {{
      border-radius: 7px;
      padding: 4px 6px;
      margin: 5px -6px;
      transition: background 0.15s ease, box-shadow 0.15s ease;
    }}
    .bar-row-link:hover {{
      background: #eff6ff;
      box-shadow: inset 0 0 0 1px #bfdbfe;
    }}
    .bar-row-link .bar-label {{
      color: #175cd3;
    }}
    .bar-label {{
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: #344054;
      font-weight: 550;
    }}
    .bar-label a {{
      color: #175cd3;
      text-decoration: none;
      border-bottom: 1px solid rgba(23, 92, 211, 0.28);
    }}
    .bar-label a:hover {{
      border-bottom-color: #175cd3;
    }}
    .table-link {{
      color: #175cd3;
      font-weight: 700;
      text-decoration: none;
      border-bottom: 1px solid rgba(23, 92, 211, 0.28);
    }}
    .table-link:hover {{
      border-bottom-color: #175cd3;
    }}
    .bar-track {{
      height: 9px;
      background: #edf1f6;
      border-radius: 999px;
      overflow: hidden;
    }}
    .bar-fill {{
      height: 100%;
      background: linear-gradient(90deg, #0f766e, #245edb);
      border-radius: 999px;
    }}
    .bar-count {{
      color: var(--muted);
      text-align: right;
      font-variant-numeric: tabular-nums;
    }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 10px;
      box-shadow: 0 8px 20px rgba(24, 34, 48, 0.05);
    }}
    .pager {{
      display: flex;
      justify-content: flex-end;
      align-items: center;
      gap: 10px;
      margin: 8px 0 2px;
      color: var(--muted);
      font-size: 12px;
    }}
    .pager button {{
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: #344054;
      padding: 4px 10px;
      cursor: pointer;
    }}
    .pager button:disabled {{
      color: #98a2b3;
      cursor: default;
      background: #f7f9fc;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      line-height: 1.55;
      background: #fff;
    }}
    th, td {{
      padding: 9px 10px;
      border-bottom: 1px solid #e7ecf3;
      text-align: left;
      vertical-align: top;
      white-space: nowrap;
    }}
    th {{
      background: #f3f6fb;
      color: #475467;
      font-weight: 700;
      padding-top: 12px;
      padding-bottom: 12px;
      text-align: center;
      vertical-align: middle;
    }}
    td {{ color: #344054; }}
    tbody tr:hover td {{ background: #fbfdff; }}
    tr:last-child td {{ border-bottom: 0; }}
    table.events {{
      font-size: 12px;
      line-height: 1.45;
    }}
    table.events th {{
      padding: 10px 8px;
      color: #516173;
      font-size: 11px;
      font-weight: 800;
      background: #f3f8ff;
    }}
    table.events td {{
      padding: 8px 8px;
      color: #344054;
      font-weight: 520;
      vertical-align: middle;
    }}
    .events td:nth-child(5), .events td:nth-child(6), .events td:nth-child(8), .events td:nth-child(9), .events td:nth-child(11), .events td:nth-child(12) {{
      max-width: 250px;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .anomalies td:nth-child(3), .anomalies td:nth-child(4), .anomalies td:nth-child(5), .anomalies td:nth-child(9), .anomalies td:nth-child(10) {{
      max-width: 230px;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .risk, .relation {{
      display: inline-flex;
      align-items: center;
      min-height: 22px;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
    }}
    .risk-high {{ color: var(--red); background: #fef3f2; }}
    .risk-medium {{ color: var(--amber); background: #fffaeb; }}
    .risk-low {{ color: var(--green); background: #ecfdf3; }}
    .risk-action {{ color: var(--red); background: #fef3f2; }}
    .risk-review {{ color: var(--amber); background: #fffaeb; }}
    .risk-general {{ color: #175cd3; background: #eff6ff; }}
    .risk-watch {{ color: var(--green); background: #ecfdf3; }}
    .relation-external, .relation-customer, .relation-partner, .relation-supplier {{ color: #175cd3; background: #eff6ff; }}
    .relation-unknown {{ color: var(--amber); background: #fffaeb; }}
    .empty {{
      color: var(--muted);
      margin: 8px 0 0;
      font-size: 13px;
    }}
    .note {{
      color: var(--muted);
      font-size: 13px;
      line-height: 1.65;
      margin-top: 8px;
    }}
    .keyword-detail {{
      scroll-margin-top: 18px;
      padding-top: 2px;
    }}
    .keyword-detail:target {{
      outline: 2px solid #bfdbfe;
      outline-offset: 8px;
      border-radius: 8px;
    }}
    .section-count {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 500;
    }}
    .actions {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-top: 10px;
    }}
    .action {{
      border-left: 4px solid var(--teal);
      padding: 4px 0 4px 12px;
      min-height: 92px;
    }}
    .action strong {{
      display: block;
      margin-bottom: 5px;
    }}
    .decision-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-top: 10px;
    }}
    .decision-card {{
      display: grid;
      gap: 8px;
      min-height: 150px;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 17px 18px;
      color: inherit;
      text-decoration: none;
      background: var(--surface);
      box-shadow: var(--shadow-soft);
      transition: border-color 0.15s ease, box-shadow 0.15s ease, transform 0.15s ease;
    }}
    .decision-card:hover {{
      border-color: #93c5fd;
      box-shadow: 0 8px 20px rgba(37, 99, 235, 0.12);
      transform: translateY(-1px);
    }}
    .decision-card span {{
      color: #175cd3;
      font-size: 13px;
      font-weight: 720;
    }}
    .decision-card strong {{
      font-size: 24px;
      line-height: 1.1;
      font-variant-numeric: tabular-nums;
    }}
    .decision-card p {{
      margin: 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.65;
    }}
    .eyebrow {{
      display: inline-flex;
      align-items: center;
      width: fit-content;
      min-height: 26px;
      margin-bottom: 12px;
      border: 1px solid rgba(255, 255, 255, 0.24);
      border-radius: 999px;
      padding: 3px 10px;
      color: #bff7e8;
      background: rgba(255, 255, 255, 0.08);
      font-size: 12px;
      font-weight: 760;
    }}
    header {{
      min-height: 245px;
      padding: 34px 36px 58px;
      background:
        linear-gradient(135deg, rgba(18, 31, 49, 0.98) 0%, rgba(19, 45, 71, 0.96) 54%, rgba(8, 116, 111, 0.92) 100%);
      position: relative;
      overflow: hidden;
    }}
    header::after {{
      content: "";
      position: absolute;
      right: -120px;
      top: -160px;
      width: 420px;
      height: 420px;
      border-radius: 50%;
      border: 1px solid rgba(255, 255, 255, 0.14);
      box-shadow: inset 0 0 0 48px rgba(255, 255, 255, 0.035);
      pointer-events: none;
    }}
    header > * {{
      position: relative;
      z-index: 1;
    }}
    header h1 {{
      max-width: 920px;
      font-size: 42px;
      line-height: 1.12;
    }}
    .meta {{
      max-width: 980px;
      gap: 8px;
    }}
    .meta span {{
      width: fit-content;
      max-width: 100%;
      border-left: 3px solid rgba(110, 231, 183, 0.72);
      padding-left: 10px;
    }}
    .stamp {{
      min-width: 200px;
      backdrop-filter: blur(6px);
    }}
    .top-actions {{
      margin-top: 20px;
    }}
    .top-action {{
      min-height: 38px;
      border-radius: 999px;
      padding: 7px 15px;
    }}
    .kpis {{
      position: relative;
      z-index: 3;
      grid-template-columns: repeat(12, minmax(0, 1fr));
      gap: 16px;
      margin: -34px 18px 22px;
    }}
    .kpi {{
      grid-column: span 2;
      min-height: 136px;
      border-radius: 12px;
      padding: 18px 18px 16px;
    }}
    .kpi:first-child {{
      grid-column: span 3;
      background: linear-gradient(180deg, #ffffff 0%, #f9fbff 100%);
      border-color: rgba(216, 224, 234, 0.95);
      color: inherit;
      box-shadow: var(--shadow-soft);
    }}
    .kpi:first-child .kpi-label,
    .kpi:first-child .kpi-note {{
      color: var(--muted);
    }}
    .kpi:nth-child(2) {{
      grid-column: span 3;
      background: linear-gradient(180deg, #fff7f5 0%, #fff 100%);
      border-color: #fed5cc;
    }}
    .kpi:nth-child(n+3) {{
      background: linear-gradient(180deg, #ffffff 0%, #f9fbff 100%);
    }}
    .kpi-value {{
      font-size: 38px;
    }}
    .kpi:first-child .kpi-value,
    .kpi:nth-child(2) .kpi-value {{
      font-size: 46px;
    }}
    .summary {{
      grid-template-columns: minmax(0, 1.35fr) minmax(360px, 0.65fr);
      margin-top: 24px;
    }}
    .summary .panel:first-child {{
      background: #111d2e;
      color: #fff;
      border-color: #111d2e;
      box-shadow: 0 20px 42px rgba(17, 29, 46, 0.18);
    }}
    .summary .panel:first-child h2 {{
      color: #fff;
    }}
    .summary .panel:first-child li {{
      margin: 10px 0;
      color: rgba(255, 255, 255, 0.82);
    }}
    .summary .panel:first-child li::marker {{
      color: #6ee7b7;
    }}
    .summary .panel:nth-child(2) {{
      background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
    }}
    .noise-summary {{
      margin: 0 18px 22px;
      border-color: #c7d7fe;
      background: linear-gradient(90deg, #f8fbff 0%, #ffffff 100%);
    }}
    .decision-grid {{
      counter-reset: decision;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 18px;
    }}
    .decision-card {{
      position: relative;
      min-height: 178px;
      padding: 22px 20px 18px;
      overflow: hidden;
      border-radius: 12px;
    }}
    .decision-card::before {{
      counter-increment: decision;
      content: counter(decision, decimal-leading-zero);
      position: absolute;
      right: 16px;
      top: 12px;
      color: rgba(36, 94, 219, 0.12);
      font-size: 54px;
      font-weight: 820;
      line-height: 1;
    }}
    .decision-card span,
    .decision-card strong,
    .decision-card p {{
      position: relative;
      z-index: 1;
    }}
    .decision-card strong {{
      margin-top: 16px;
      font-size: 30px;
    }}
    .dashboard {{
      gap: 20px;
    }}
    .chart-panel {{
      min-height: 286px;
      border-radius: 12px;
      padding: 20px 20px 18px;
    }}
    .chart-panel:nth-child(1),
    .chart-panel:nth-child(2) {{
      grid-column: span 6;
      min-height: 310px;
    }}
    .chart-panel:nth-child(3),
    .chart-panel:nth-child(4),
    .chart-panel:nth-child(5),
    .chart-panel:nth-child(6),
    .chart-panel:nth-child(7),
    .chart-panel:nth-child(8),
    .chart-panel:nth-child(9) {{
      grid-column: span 4;
    }}
    .chart-panel h2 {{
      display: flex;
      align-items: center;
      gap: 8px;
      padding-bottom: 11px;
      border-bottom: 1px solid #edf1f6;
    }}
    .chart-panel h2::before {{
      content: "";
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--teal);
      box-shadow: 0 0 0 4px rgba(8, 116, 111, 0.12);
    }}
    #asset-analysis {{
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 20px;
      margin-top: 26px;
      background: var(--surface);
      box-shadow: var(--shadow-soft);
    }}
    #asset-analysis > h2 {{
      margin-top: 0;
      padding-bottom: 12px;
      border-bottom: 1px solid #edf1f6;
    }}
    #asset-analysis .metric-chips {{
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    }}
    #asset-analysis .metric-chip {{
      min-height: 66px;
      background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
    }}
    #asset-analysis .metric-chip strong {{
      font-size: 24px;
    }}
    .section-block {{
      position: relative;
      margin-top: 26px;
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 22px;
      background: rgba(255, 255, 255, 0.94);
      box-shadow: var(--shadow-soft);
    }}
    .global-management-summary {{
      position: relative;
      overflow: hidden;
      margin-top: 28px;
      border: 1px solid rgba(18, 32, 51, 0.10);
      border-radius: 18px;
      padding: 22px;
      background:
        radial-gradient(circle at 92% 4%, rgba(23, 92, 211, 0.12) 0, transparent 32%),
        linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
      box-shadow: var(--shadow-soft);
    }}
    .global-management-summary::before {{
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 5px;
      background: linear-gradient(180deg, #7c3aed, var(--blue), var(--teal));
    }}
    .global-management-head {{
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 18px;
      margin-bottom: 16px;
    }}
    .global-management-head h2 {{
      margin: 3px 0 0;
      color: #122033;
      font-size: 24px;
      font-weight: 900;
      letter-spacing: 0;
    }}
    .global-management-head p {{
      max-width: 880px;
      margin: 0;
      color: #475467;
      font-size: 14px;
      font-weight: 720;
      line-height: 1.75;
    }}
    .management-summary-list {{
      display: grid;
      gap: 10px;
    }}
    .management-summary-row {{
      display: grid;
      grid-template-columns: 150px minmax(0, 1fr);
      align-items: center;
      gap: 14px;
      min-height: 54px;
      border: 1px solid #dbe6f3;
      border-radius: 12px;
      padding: 12px 15px;
      color: #122033;
      background: #ffffff;
      box-shadow: 0 8px 18px rgba(18, 32, 51, 0.045);
      text-decoration: none;
    }}
    .management-summary-row:hover {{
      border-color: #93c5fd;
      box-shadow: 0 10px 22px rgba(18, 32, 51, 0.065);
    }}
    .management-summary-row span {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 30px;
      border-radius: 999px;
      padding: 0 12px;
      background: #eff6ff;
      color: #175cd3;
      font-size: 13px;
      font-weight: 900;
      white-space: nowrap;
    }}
    .management-summary-row p {{
      margin: 0;
      color: #344054;
      font-size: 15px;
      font-weight: 780;
      line-height: 1.6;
    }}
    .management-summary-row-decrypt span {{
      background: #f5f3ff;
      color: #6d28d9;
    }}
    .management-summary-row-tianqing span {{
      background: #ecfdf3;
      color: #08746f;
    }}
    .management-summary-row-plm span {{
      background: #fffbeb;
      color: #b45309;
    }}
    .management-summary-row-review span {{
      background: #eef4ff;
      color: #175cd3;
    }}
    .management-module-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }}
    .management-module-card {{
      display: flex;
      min-height: 150px;
      flex-direction: column;
      border: 1px solid #dbe6f3;
      border-radius: 14px;
      padding: 16px;
      color: #122033;
      background: #ffffff;
      box-shadow: 0 10px 24px rgba(18, 32, 51, 0.055);
      text-decoration: none;
      transition: transform 0.16s ease, border-color 0.16s ease, box-shadow 0.16s ease;
    }}
    .management-module-card:hover {{
      transform: translateY(-1px);
      border-color: #93c5fd;
      box-shadow: 0 14px 30px rgba(18, 32, 51, 0.085);
    }}
    .management-module-card span {{
      color: #175cd3;
      font-size: 12px;
      font-weight: 850;
    }}
    .management-module-card strong {{
      margin-top: 8px;
      font-size: 30px;
      font-weight: 920;
      line-height: 1;
    }}
    .management-module-card em {{
      margin-top: 7px;
      color: #475467;
      font-size: 13px;
      font-style: normal;
      font-weight: 800;
      line-height: 1.4;
    }}
    .management-module-card p {{
      margin: auto 0 0;
      padding-top: 12px;
      color: #667085;
      font-size: 13px;
      font-weight: 680;
      line-height: 1.65;
    }}
    .management-module-card-decrypt {{
      border-color: rgba(124, 58, 237, 0.22);
    }}
    .management-module-card-tianqing {{
      border-color: rgba(15, 118, 110, 0.22);
    }}
    .management-module-card-plm {{
      border-color: rgba(180, 83, 9, 0.22);
    }}
    .global-management-action {{
      margin: 14px 0 0;
      border-top: 1px solid #e6edf5;
      padding-top: 13px;
      color: #475467;
      font-size: 13px;
      font-weight: 760;
      line-height: 1.7;
    }}
    .audit-domain {{
      margin-top: 30px;
    }}
    .audit-domain-head {{
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 18px;
      border: 1px solid #dce7f4;
      border-radius: 16px;
      padding: 18px 20px;
      background: linear-gradient(180deg, #ffffff 0%, #f7fbff 100%);
      box-shadow: 0 12px 28px rgba(24, 34, 48, 0.055);
    }}
    .audit-domain-head h2 {{
      margin: 3px 0 5px;
      color: #122033;
      font-size: 24px;
      font-weight: 900;
      letter-spacing: 0;
    }}
    .audit-domain-head p {{
      max-width: 960px;
      margin: 0;
      color: #667085;
      font-size: 13px;
      font-weight: 680;
      line-height: 1.7;
    }}
    .audit-domain-kicker {{
      display: inline-flex;
      width: fit-content;
      min-height: 24px;
      align-items: center;
      border: 1px solid #c7d7ee;
      border-radius: 999px;
      padding: 3px 10px;
      color: #175cd3;
      background: #eff6ff;
      font-size: 11px;
      font-weight: 820;
    }}
    .audit-domain-source {{
      flex: 0 0 auto;
      color: #516173;
      font-size: 11px;
      font-weight: 760;
      text-align: right;
    }}
    .audit-domain .section-block:first-of-type {{
      margin-top: 16px;
    }}
    .section-title-row {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 18px;
      margin-bottom: 18px;
    }}
    .section-title-row h2 {{
      margin: 2px 0 6px;
      font-size: 22px;
    }}
    .section-title-row p {{
      max-width: 880px;
      margin: 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.7;
    }}
    .section-eyebrow {{
      display: inline-flex;
      width: fit-content;
      min-height: 24px;
      align-items: center;
      border: 1px solid #bfe5dc;
      border-radius: 999px;
      padding: 3px 9px;
      color: #0f766e;
      background: #eaf8f5;
      font-size: 11px;
      font-weight: 820;
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    .section-action {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 36px;
      padding: 7px 13px;
      border: 1px solid #cfe2ff;
      border-radius: 8px;
      color: #175cd3;
      background: #f3f8ff;
      font-size: 13px;
      font-weight: 760;
      text-decoration: none;
      white-space: nowrap;
    }}
    .section-action:hover {{
      border-color: #93c5fd;
      background: #eaf3ff;
    }}
    .risk-overview-shell {{
      overflow: hidden;
      border-color: rgba(18, 32, 51, 0.10);
      background:
        radial-gradient(circle at 92% 0%, rgba(8, 116, 111, 0.12) 0, transparent 30%),
        linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
    }}
    .risk-overview-shell::before {{
      content: "";
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 5px;
      background: linear-gradient(180deg, var(--teal), var(--blue));
    }}
    .risk-overview-hero {{
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 18px;
      align-items: stretch;
    }}
    .risk-overview-conclusions {{
      min-width: 0;
      border: 1px solid #d7e3f8;
      border-radius: 16px;
      padding: 20px 22px;
      background:
        linear-gradient(135deg, rgba(18, 31, 49, 0.98) 0%, rgba(22, 51, 74, 0.96) 54%, rgba(15, 118, 110, 0.92) 100%);
      box-shadow: 0 16px 34px rgba(18, 31, 49, 0.16);
      color: #fff;
    }}
    .risk-overview-conclusions > span {{
      display: inline-flex;
      min-height: 24px;
      align-items: center;
      margin-bottom: 12px;
      border: 1px solid rgba(255, 255, 255, 0.18);
      border-radius: 999px;
      padding: 3px 10px;
      color: #bff7e8;
      background: rgba(255, 255, 255, 0.08);
      font-size: 12px;
      font-weight: 820;
    }}
    .risk-overview-conclusions ul {{
      display: grid;
      gap: 11px;
      margin: 0;
      padding-left: 19px;
    }}
    .risk-overview-conclusions li {{
      margin: 0;
      color: rgba(255, 255, 255, 0.84);
      font-size: 15px;
      line-height: 1.78;
    }}
    .risk-overview-conclusions li::marker {{
      color: #6ee7b7;
    }}
    .risk-overview-note {{
      margin: 14px 0 0;
    }}
    .decrypt-overview-shell {{
      border-color: rgba(124, 58, 237, 0.14);
      background:
        radial-gradient(circle at 92% 0%, rgba(124, 58, 237, 0.10) 0, transparent 30%),
        linear-gradient(180deg, #ffffff 0%, #fbf8ff 100%);
    }}
    .decrypt-overview-shell::before {{
      background: linear-gradient(180deg, #7c3aed, #ea580c);
    }}
    .risk-overview-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 16px;
      padding-top: 14px;
      border-top: 1px solid rgba(255, 255, 255, 0.14);
    }}
    .risk-overview-actions a {{
      display: inline-flex;
      min-height: 28px;
      align-items: center;
      border: 1px solid rgba(255, 255, 255, 0.20);
      border-radius: 999px;
      padding: 4px 11px;
      color: #e5f6ff;
      background: rgba(255, 255, 255, 0.08);
      font-size: 12px;
      font-weight: 820;
      text-decoration: none;
    }}
    .risk-overview-actions a:hover {{
      color: #ffffff;
      background: rgba(255, 255, 255, 0.14);
    }}
    .decision-section {{
      overflow: hidden;
      background:
        linear-gradient(180deg, rgba(255, 255, 255, 0.96) 0%, rgba(248, 251, 255, 0.96) 100%);
    }}
    .decision-section::before {{
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 5px;
      background: linear-gradient(180deg, var(--teal), var(--blue));
    }}
    .dashboard-shell {{
      background: linear-gradient(180deg, #ffffff 0%, #f7f9fc 100%);
    }}
    .dashboard-shell .dashboard {{
      margin-top: 0;
    }}
    .chart-panel {{
      position: relative;
      overflow: hidden;
      background: linear-gradient(180deg, #ffffff 0%, #fbfcff 100%);
    }}
    .chart-panel::after {{
      content: "";
      position: absolute;
      left: 20px;
      right: 20px;
      top: 0;
      height: 3px;
      border-radius: 0 0 999px 999px;
      background: linear-gradient(90deg, var(--teal), var(--blue));
      opacity: 0.78;
    }}
    .chart-panel:nth-child(2)::after,
    .chart-panel:nth-child(4)::after {{
      background: linear-gradient(90deg, var(--amber), var(--red));
    }}
    .chart-panel:nth-child(3)::after,
    .chart-panel:nth-child(7)::after {{
      background: linear-gradient(90deg, #7c3aed, var(--blue));
    }}
    .chart-panel .note {{
      border: 1px solid #e4eaf2;
      border-radius: 8px;
      padding: 8px 10px;
      background: #fafcff;
    }}
    .bar-row {{
      min-height: 32px;
    }}
    .bar-row-link {{
      border: 1px solid transparent;
    }}
    .bar-row-link:hover {{
      border-color: #cfe2ff;
      background: #f3f8ff;
    }}
    .asset-shell {{
      padding: 22px;
    }}
    #asset-analysis {{
      margin-top: 26px;
    }}
    #asset-analysis > h2 {{
      border-bottom: 0;
      padding-bottom: 0;
    }}
    #asset-analysis .metric-chips {{
      gap: 12px;
    }}
    #asset-analysis .metric-chip {{
      border-radius: 12px;
      min-height: 78px;
      padding: 14px 15px;
    }}    footer {{
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px 16px;
      background: rgba(255, 255, 255, 0.72);
    }}
    footer {{
      margin-top: 34px;
      padding-top: 14px;
      border-top: 1px solid var(--line);
      color: var(--muted);
      font-size: 13px;
      line-height: 1.65;
    }}
    @media (max-width: 900px) {{
      .report {{ margin: 0; padding: 22px; }}
      header, .summary, .grid-2, .actions, .decision-grid, .noise-summary, .matrix-footnote {{ grid-template-columns: 1fr; }}
      header {{ min-height: 0; padding: 24px; }}
      header h1 {{ font-size: 30px; }}
      .kpis {{ grid-template-columns: repeat(2, minmax(0, 1fr)); margin: 16px 0 8px; }}
      .kpi, .kpi:first-child, .kpi:nth-child(2) {{ grid-column: span 1; }}
      .section-block {{ padding: 18px; }}
      .section-title-row {{ flex-direction: column; }}
      .global-management-head {{ flex-direction: column; align-items: flex-start; }}
      .management-summary-row {{ grid-template-columns: 1fr; align-items: flex-start; }}
      .management-module-grid {{ grid-template-columns: 1fr; }}
      .audit-domain-head {{ flex-direction: column; align-items: flex-start; }}
      .audit-domain-source {{ text-align: left; }}
      .section-action {{ width: 100%; }}
      .risk-overview-hero {{ grid-template-columns: 1fr; }}
      .trend-channel-grid.active, .trend-org-grid.active, .trend-mini-grid, .decrypt-trend-row {{ grid-template-columns: 1fr; }}
      .rename-card-grid, .decrypt-card-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .dashboard {{ grid-template-columns: 1fr; }}
      .org-insight-grid {{ grid-template-columns: 1fr; }}
      .chart-panel, .chart-panel.wide, .chart-panel:nth-child(n) {{ grid-column: span 1; }}
      .donut-wrap {{ grid-template-columns: 1fr; }}
      .donut {{ margin: 0 auto; }}
    }}
    @media (max-width: 620px) {{
      .rename-card-grid, .decrypt-card-grid {{ grid-template-columns: 1fr; }}
    }}
    @media print {{
      body {{ background: #fff; }}
      .report {{ margin: 0; max-width: none; border: 0; box-shadow: none; }}
      .table-wrap {{ overflow: visible; }}
      .pager {{ display: none; }}
      h2 {{ break-after: avoid; }}
      .panel, .kpi, .action {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <main class="report">
    <header>
      <div>
        <div class="eyebrow">数据安全风险简报</div>
        <h1>数据安全审计报告</h1>
        <div class="meta">
          <span>统计周期：{esc(report_period)}</span>
          <span>{esc(home_focus_text)}</span>
          <span>{esc(home_evidence_text)}</span>
        </div>
        <div class="top-actions">
          <a class="top-action danger" href="{esc(terminal_check_url)}">风险终端复核</a>
          <a class="top-action" href="{esc(home_url)}">当前报告首页</a>
        </div>
      </div>
      <aside class="stamp">
        <a href="{esc(settings_url)}">
          <strong>策略管理</strong>
          <span>规则、账号与数据源维护</span>
        </a>
      </aside>
    </header>

    {global_management_summary_html}

    {home_modules_html}

    <footer>
      数据来源：天擎审计底稿（{esc(source_label)}，原始日志 {raw_record_count} 条，审计底稿 {len(audit_events)} 条）及加密软件解密记录；下钻明细保留可追溯线索。{esc(wecom_directory_summary(args))}；{esc(sensitive_keywords_summary(args))}；{esc(audit_policy_summary(args))}；{esc(exclusion_summary(args))}。
    </footer>
  </main>
  {pagination_script()}
</body>
</html>"""
    debug_timing(f"main html complete sidecars={len(sidecar_reports)}")
    return main_html, sidecar_reports


def build_report(
    events: list[AuditEvent],
    records: list[RawRecord],
    args: argparse.Namespace,
    tz: timezone,
    start: datetime | None,
    end: datetime | None,
    internal_domains: set[str],
) -> str:
    audit_events = events
    procurement_muted_events = [event for event in audit_events if is_normal_procurement_inquiry_event(event)]
    focus_candidates = [event for event in audit_events if is_leadership_focus_event(event, internal_domains)]
    false_positive_reasons = report_false_positive_map(focus_candidates, audit_events)
    false_positive_events = [event for event in focus_candidates if event.event_id in false_positive_reasons]
    events = [event for event in focus_candidates if event.event_id not in false_positive_reasons]
    priority_counts = event_priority_counts(events)
    channel_counts = Counter(event_channel_label(event) for event in events)
    im_channel_counts = Counter(im_channel_label(event) for event in events if event.topic == "im_audit")
    topic_counts = report_topic_counts(args, records)
    raw_record_count = report_raw_record_count(args, records)
    person_counts = Counter()
    person_action = Counter()
    company_counts = Counter()
    dept_counts = Counter()
    target_counts = Counter()
    unknown_im_recipient_counts = Counter()
    ext_counts = Counter()
    design_ext_counts = Counter()
    three_d_ext_counts = Counter()
    two_d_cad_ext_counts = Counter()
    pcb_ecad_ext_counts = Counter()
    reason_counts = Counter()
    keyword_counts = Counter()
    keyword_event_map: dict[str, list[AuditEvent]] = defaultdict(list)
    process_counts = Counter()
    with_lookup = 0

    for event in events:
        person_key = (
            event.resolved_person or event.person or "unknown",
            event_company_label(event),
            event_department_label(event),
            event.client_name or "-",
            event.client_ip or "-",
        )
        person_counts[person_key] += 1
        if event.priority == PRIORITY_ACTION:
            person_action[person_key] += 1
        company_counts[event_company_label(event)] += 1
        dept_counts[event_department_label(event)] += 1
        process_counts[event.process_name or "-"] += 1
        for domain in event.target_domains:
            if not domain_is_internal(domain, internal_domains):
                target_counts[domain] += 1
        if not event.target_domains and event.recipients:
            for recipient in event.recipients:
                target_counts[recipient] += 1
                if event.topic == "im_audit" and event.recipient_relation == "unknown":
                    unknown_im_recipient_counts[recipient] += 1
        for ext in event.file_exts:
            ext_counts[ext] += 1
            if ext in DESIGN_EXTS:
                design_ext_counts[ext] += 1
            if ext in CONTROLLED_3D_EXTS:
                three_d_ext_counts[ext] += 1
            if ext in CONTROLLED_2D_CAD_EXTS:
                two_d_cad_ext_counts[ext] += 1
            if ext in PCB_ECAD_EXTS:
                pcb_ecad_ext_counts[ext] += 1
        for reason in prioritized_reasons(event.reasons):
            reason_counts[reason] += 1
        keyword_hits = event_leadership_keyword_hits(event)
        for keyword in keyword_hits:
            keyword_counts[keyword] += 1
            keyword_event_map[keyword].append(event)
        if any(key.startswith(("search_id=", "download_file_key=", "file_id=")) for key in event.lookup_keys):
            with_lookup += 1

    sorted_events = sorted(events, key=event_priority_sort_key)
    shortlist = sorted_events
    design_events = sum(1 for event in events if any(ext in DESIGN_EXTS for ext in event.file_exts))
    design_send_events = sum(1 for event in events if is_design_send_event(event))
    peripheral_copy_events = sum(1 for event in events if is_peripheral_copy_event(event) and is_design_event(event))
    three_d_events = sum(1 for event in events if is_three_d_model_event(event))
    two_d_cad_events = sum(1 for event in events if is_two_d_cad_event(event))
    pcb_ecad_events = sum(1 for event in events if is_pcb_ecad_event(event))
    external_sender_count = sum(1 for event in events if is_external_sender_mailbox(event))
    asset_analysis = fetch_asset_analysis(args, tz, start, end, internal_domains)

    period_text = args.period
    if start or end:
        period_text = f"{start.strftime('%Y-%m-%d %H:%M:%S') if start else 'begin'} 至 {end.strftime('%Y-%m-%d %H:%M:%S') if end else 'now'}"

    lines = [
        "# 数据安全审计报告",
        "",
        f"- 统计周期：{period_text}",
        f"- 日志来源：{report_source_label(args)}",
        f"- 原始日志记录：{raw_record_count} 条",
        f"- 重点事件：{len(events)} 条",
        f"- 已降噪正常采购询价：{len(procurement_muted_events)} 条（仅影响报告展示，不删除审计底稿）",
        f"- 已判定误判/低置信噪音：{len(false_positive_events)} 条（仅从重点关注队列剔除，不删除审计底稿）",
        f"- 接收方口径：内部收件已剔除；IM 未映射接收方按“待判定”保留",
        f"- {wecom_directory_summary(args)}",
        f"- 设计资料相关事件：{design_events} 条（发送/上传 {design_send_events} / 外设拷贝 {peripheral_copy_events} / 三维模型 {three_d_events} / DWG二维图纸 {two_d_cad_events}）",
        f"- 外部发件箱邮件：{external_sender_count} 条（内部邮箱后缀仅按 daqo.com 识别）",
        f"- 资产分析：纳入 {asset_analysis.total_assets} 台终端，出厂日期解析 {asset_analysis.parsed_manufacture_dates} 台，5年以上设备 {len(asset_analysis.old_device_assets)} 台，老旧系统 {len(asset_analysis.old_os_assets)} 台，当前离线 {len(asset_analysis.offline_assets)} 台，天擎离线超7天 {len(asset_analysis.long_offline_assets)} 台，7天未观察到 {len(asset_analysis.missing_assets)} 台，疑似已卸载 {len(asset_analysis.suspected_uninstalled_assets)} 台",
        f"- 可回查线索事件：{with_lookup} 条",
        "",
        "## 重点结论",
    ]

    if events:
        lines.extend(
            [
                f"- 当前报告已从普通日志收敛为外发审计队列，主队列只关注邮件附件、IM附件外发、文件上传/下载和敏感文件。",
                f"- 采购询价降噪：询价单、报价单、普通招标资料等正常业务已从重点关注队列降噪 {len(procurement_muted_events)} 条；设计图纸、外设拷贝、高风险外联目标、超大文件、源码/数据库和非采购敏感词仍强制保留。",
                f"- 误判/低置信剔除：FILEASSIST 自传、应用发送伴随重复记录、无接收方且非硬管控对象的低置信应用发送共 {len(false_positive_events)} 条，不参与首页矩阵、终端排行和行为异常统计。",
                f"- 设计图纸强管控：三维仅 `.prt/.asm/.sldasm/.sldprt/.step`，二维仅 `.dwg`；这些后缀不依赖关键词触发，发送/上传与外设拷贝分开展示，三维模型需单独复核。",
                f"- 邮件发件箱：`@daqo.com` 按内部邮箱处理，其他发件箱作为外部发件箱重点关注；本周期外部发件箱 {external_sender_count} 条。",
                f"- 收件方识别：{sum(1 for event in events if event.recipient_relation in EXTERNAL_RELATIONS)} 条明确外部/客户/供应商/合作方，{sum(1 for event in events if event.recipient_relation == 'unknown')} 条待判定。",
                f"- 最高频审计通道：{', '.join(f'{name} {count}' for name, count in channel_counts.most_common(4))}",
                f"- 主要风险原因：{', '.join(f'{name} {count}' for name, count in reason_counts.most_common(6))}",
                "- 未发现附件本体落盘字段；报告中的附件内容复核仍需回天擎 Web/API 下载。",
            ]
        )
    else:
        lines.append("- 当前周期未筛出外发/敏感文件候选事件。")

    lines.extend(["", "## 事件类型"])
    lines.append(table([[name, str(count)] for name, count in topic_counts.most_common()], ["原始类型", "日志数"]))
    lines.append("")
    lines.append(table([[name, str(count)] for name, count in channel_counts.most_common()], ["审计通道", "候选事件数"]))
    lines.append("")
    lines.append("### IM渠道")
    lines.append(table([[name, str(count)] for name, count in im_channel_counts.most_common()], ["IM渠道", "候选事件数"]) if im_channel_counts else "无。")
    lines.extend(["", "## 待复核清单"])
    if shortlist:
        rows = []
        for idx, event in enumerate(shortlist, 1):
            rows.append(
                [
                    str(idx),
                    event.event_id,
                    format_ts(event.ts, tz),
                    event_company_label(event),
                    event_department_label(event),
                    event.resolved_person,
                    event.client_ip or "-",
                    event_mac_label(event, asset_analysis.asset_by_terminal),
                    event_channel_label(event),
                    event_subject_label(event),
                    event.sender_mailbox or "-",
                    mail_sender_type_label(event),
                    summarize_targets(event),
                    RELATION_LABELS.get(event.recipient_relation, event.recipient_relation),
                    summarize_files(event),
                    design_category_label(event),
                    size_label(event.file_size),
                    compact_id(event.search_id, 18),
                ]
            )
        lines.append(
            table(
                rows,
                ["#", "事件ID", "时间", "公司", "部门", "人员/账号", "IP地址", "MAC地址", "通道", "邮件主题", "发件箱", "发件箱类型", "接收方/目标", "关系", "文件", "资料类型", "大小", "search_id"],
            )
        )
    else:
        lines.append("无。")

    lines.extend(["", "## 人员与终端排行"])
    rows = []
    for key, count in person_counts.most_common(15):
        person, company, dept, terminal, ip = key
        rows.append([company, dept, person, terminal, ip, str(count)])
    lines.append(table(rows, ["公司", "部门", "人员/账号", "计算机名", "IP地址", "候选事件"]) if rows else "无。")

    lines.extend(["", "## 资产分析"])
    if asset_analysis.available:
        lines.append("- 设备出厂日期来源：`client_info.asset_computer.board_bios` 末尾日期；`client_create_time` 仅作为纳管时间。")
        lines.append("- `7天未观察到` 是本系统日志观测口径；`离线时长` 是天擎 online_info.is_online/last_time 口径；`疑似已卸载` 按 30 天未观察且无同硬件重装记录统计。")
        lines.append(table([[name, str(count)] for name, count in asset_analysis.age_counts.most_common()], ["设备年代", "终端数"]))
        lines.append("")
        lines.append("### 在线状态/离线时长")
        lines.append(table([[name, str(count)] for name, count in asset_analysis.online_counts.most_common()], ["状态", "终端数"]))
        lines.append("")
        lines.append("### 操作系统分布")
        lines.append(table([[name, str(count)] for name, count in asset_analysis.os_counts.most_common(15)], ["操作系统", "终端数"]))
        lines.append("")
        lines.append("### 版本分布")
        lines.append(table([[name, str(count)] for name, count in asset_analysis.virus_counts.most_common(10)], ["病毒库版本", "终端数"]))
        lines.append(table([[name, str(count)] for name, count in asset_analysis.patch_counts.most_common(10)], ["补丁版本", "终端数"]))
        lines.append(table([[name, str(count)] for name, count in asset_analysis.main_version_counts.most_common(10)], ["主程序版本", "终端数"]))
        lines.append("")
        lines.append("### 资产风险线索")
        lines.append(table([[name, str(count)] for name, count in asset_analysis.risk_counts.most_common()], ["线索", "终端数"]))
    else:
        lines.append(asset_analysis.error or "暂无资产分析数据。")

    mapped_count = sum(1 for event in events if event.mapping_source)
    status_counts = Counter(event.disposition_status for event in events)
    lines.extend(["", "## 处置状态"])
    lines.append(f"- 人员映射命中：{mapped_count}/{len(events)}")
    lines.append(table([[status, str(count)] for status, count in status_counts.most_common()], ["状态", "事件数"]))

    lines.extend(["", "## 敏感文件与目标"])
    ext_rows = [[ext, str(count)] for ext, count in ext_counts.most_common(15)]
    three_d_ext_rows = [[ext, str(count)] for ext, count in three_d_ext_counts.most_common(15)]
    two_d_cad_ext_rows = [[ext, str(count)] for ext, count in two_d_cad_ext_counts.most_common(15)]
    pcb_ecad_ext_rows = [[ext, str(count)] for ext, count in pcb_ecad_ext_counts.most_common(15)]
    target_rows = [[domain, str(count)] for domain, count in target_counts.most_common(15)]
    reason_rows = [[reason, str(count)] for reason, count in reason_counts.most_common(15)]
    lines.append("### 三维模型文件类型")
    lines.append(table(three_d_ext_rows, ["扩展名", "次数"]) if three_d_ext_rows else "无。")
    lines.append("")
    lines.append("### DWG二维图纸文件类型")
    lines.append(table(two_d_cad_ext_rows, ["扩展名", "次数"]) if two_d_cad_ext_rows else "无。")
    lines.append("### 文件类型")
    lines.append(table(ext_rows, ["扩展名", "次数"]) if ext_rows else "无。")
    lines.append("")
    lines.append("### 外部/待判定接收方")
    lines.append(table(target_rows, ["接收方/目标", "次数"]) if target_rows else "无明确外部或待判定接收方。")
    if unknown_im_recipient_counts:
        lines.append("")
        lines.append("### 待判定 IM 接收方")
        lines.append("这些接收方需要补充到 `recipient_mapping.csv`；标记为 `internal` 后会从主队列剔除，标记为客户/供应商/合作方后会保留为外发。")
        lines.append(table([[target, str(count)] for target, count in unknown_im_recipient_counts.most_common(20)], ["IM接收方", "次数"]))
    lines.append("")
    lines.append("### 风险原因")
    lines.append(table(reason_rows, ["原因", "次数"]) if reason_rows else "无。")
    if keyword_counts:
        lines.append("")
        lines.append("### 敏感名称命中详情")
        for keyword, count in keyword_counts.most_common(10):
            lines.append("")
            lines.append(f"#### {keyword}（{count} 次）")
            keyword_rows = []
            for event in sorted(keyword_event_map[keyword], key=event_priority_sort_key):
                names = [name for name in non_image_file_names(event.file_names) if keyword.lower() in name.lower()] or non_image_file_names(event.file_names)
                keyword_rows.append(
                    [
                        format_ts(event.ts, tz),
                        event_company_label(event),
                        event_department_label(event),
                        event.resolved_person,
                        event.client_ip or "-",
                        event_mac_label(event, asset_analysis.asset_by_terminal),
                        event_channel_label(event),
                        event_subject_label(event),
                        event.sender_mailbox or "-",
                        mail_sender_type_label(event),
                        summarize_targets(event),
                        RELATION_LABELS.get(event.recipient_relation, event.recipient_relation),
                        summarize_file_names(names, max_len=72),
                    ]
                )
            lines.append(
                table(
                    keyword_rows,
                    ["时间", "公司", "部门", "人员/账号", "IP地址", "MAC地址", "通道", "邮件主题", "发件箱", "发件箱类型", "接收方/目标", "关系", "文件"],
                )
            )

    lines.extend(["", "## 审计建议"])
    lines.extend(
        [
            "- 高风险事实优先回天擎按 `search_id`、终端、时间、附件名复核附件内容。",
            "- 三维模型和DWG二维图纸分开复核；三维模型应从项目授权、接收方和审批依据单独确认。",
            "- 邮件外发优先看发件箱类型、外部域名、个人邮箱、压缩包、图纸、报价/合同/财务关键词；非 daqo.com 发件箱单独重点复核。",
            "- IM/文件审计优先验证 `download_file_key` 是否能在天擎 Web/API 回查到文件或附件。",
            "- 将内部 IM 昵称/账号维护到 `recipient_mapping.csv` 并标记 `internal` 后，内部发送会自动从主队列排除。",
            "- 公司、部门以企业微信通讯录缓存或显式人员映射为准并分列展示；未匹配时不使用天擎用户分组兜底。",
        ]
    )

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Tianqing external-send audit report.")
    parser.add_argument("--ssh-host", default=DEFAULT_SSH_HOST)
    parser.add_argument("--remote-log", default=DEFAULT_REMOTE_LOG)
    parser.add_argument("--local-log")
    parser.add_argument("--use-clickhouse", action="store_true", help="Read the indexed audit events from ClickHouse instead of scanning the syslog file.")
    parser.add_argument("--clickhouse-url", default=os.getenv("CLICKHOUSE_URL", DEFAULT_CLICKHOUSE_URL))
    parser.add_argument("--clickhouse-database", default=os.getenv("CLICKHOUSE_DB", "tianqing"))
    parser.add_argument("--clickhouse-user", default=os.getenv("CLICKHOUSE_USER", ""))
    parser.add_argument("--clickhouse-password", default=os.getenv("CLICKHOUSE_PASSWORD", ""))
    parser.add_argument("--clickhouse-timeout", type=int, default=int(os.getenv("CLICKHOUSE_TIMEOUT", "120")))
    parser.add_argument("--period", choices=["all", "today", "previous-day", "current-week", "previous-week", "current-month", "previous-month"], default="current-week")
    parser.add_argument("--start", help="Custom start time, e.g. 2026-05-01 or 2026-05-01 08:30:00.")
    parser.add_argument("--end", help="Custom end time, e.g. 2026-05-05 or 2026-05-05 18:00:00. Date-only end is exclusive next day.")
    parser.add_argument("--timezone", default="Asia/Shanghai")
    parser.add_argument("--internal-domain", action="append", default=[])
    parser.add_argument("--max-events", type=int, default=0, help="兼容旧参数；HTML/Markdown清单不再按条数截断。")
    parser.add_argument("--include-firewall", action="store_true", help="Include firewall-only events in the main review queue.")
    parser.add_argument("--include-unknown-im", action="store_true", default=True, help="Keep IM attachment sends whose recipient is not yet classified.")
    parser.add_argument("--exclude-unknown-im", action="store_false", dest="include_unknown_im", help="Drop IM attachment sends unless the recipient map marks the recipient external/partner/customer/supplier.")
    parser.add_argument("--include-untargeted-file", action="store_true", help="Keep sensitive file_audit events even when no external upload/download target is present.")
    parser.add_argument("--people-map", default=DEFAULT_PEOPLE_MAP, help="CSV mapping identities to real people.")
    parser.add_argument("--recipient-map", default=DEFAULT_RECIPIENT_MAP, help="CSV mapping recipients to internal/external relation.")
    parser.add_argument("--sensitive-keywords-file", default=DEFAULT_SENSITIVE_KEYWORDS_FILE, help="JSON rule file defining all sensitive filename keywords. No built-in sensitive words are used.")
    parser.add_argument("--audit-policy-file", default=DEFAULT_AUDIT_POLICY_FILE, help="JSON policy file defining controlled 2D/3D design suffixes and report policy knobs.")
    parser.add_argument("--exclusion-file", default=DEFAULT_EXCLUSION_FILE, help="JSON rule file defining known benign software sync/exclusion rules.")
    parser.add_argument("--disable-wecom-directory", action="store_true", help="Disable internal recipient lookup through the WeCom bridge.")
    parser.add_argument("--wecom-directory-host", default=DEFAULT_WECOM_DIRECTORY_HOST, help="SSH host for the WeCom bridge directory lookup.")
    parser.add_argument("--wecom-directory-container", default=DEFAULT_WECOM_DIRECTORY_CONTAINER, help="Docker container that has WeCom directory credentials.")
    parser.add_argument("--wecom-directory-cache", default=DEFAULT_WECOM_DIRECTORY_CACHE, help="Local cache for WeCom directory users.")
    parser.add_argument("--wecom-directory-cache-hours", type=int, default=int(os.getenv("TIANQING_WECOM_DIRECTORY_CACHE_HOURS", "0")), help="Use cached WeCom directory data when fresher than this many hours. Default 0 means refresh on every report run and use cache only as fallback.")
    parser.add_argument("--wecom-directory-refresh", action="store_true", help="Force refresh WeCom directory cache instead of using a fresh local cache.")
    parser.add_argument("--refresh-wecom-directory-cache-only", action="store_true", help="Refresh WeCom directory cache and exit without reading Tianqing logs.")
    parser.add_argument("--wecom-directory-min-users", type=int, default=100, help="Minimum directory size required before authoritative mode can take effect.")
    parser.add_argument("--wecom-directory-authoritative", action="store_true", help="Treat unmatched IM recipients as external-like after loading a full WeCom directory.")
    parser.add_argument("--terminal-identity-max-age-days", type=int, default=int(os.getenv("TIANQING_TERMINAL_IDENTITY_MAX_AGE_DAYS", "30")), help="Only apply a terminal WeCom identity to events within this many days after the observed WXWork login. Use 0 to disable the age limit.")
    parser.add_argument("--disposition-file", default=DEFAULT_DISPOSITION_FILE, help="CSV file tracking audit disposition status.")
    parser.add_argument("--format", choices=["markdown", "html"], default="markdown", help="Output format. Use html for leadership-facing report.")
    parser.add_argument("--output", help="Write report to this path instead of stdout.")
    parser.add_argument("--public-base-url", default=os.getenv("TIANQING_REPORT_PUBLIC_URL", DEFAULT_PUBLIC_BASE_URL), help="Public intranet base URL used by report navigation links.")
    args = parser.parse_args()

    tz = get_tz(args.timezone)
    internal_domains = set(DEFAULT_INTERNAL_DOMAINS)
    internal_domains.update(domain.lower().strip(".") for domain in args.internal_domain)
    if args.start or args.end:
        try:
            start = parse_custom_datetime(args.start, tz) if args.start else None
            end = parse_custom_datetime(args.end, tz, end_boundary=True) if args.end else None
        except ValueError as exc:
            parser.error(str(exc))
        if start and end and end <= start:
            parser.error("--end must be later than --start")
    else:
        start, end = period_bounds(args.period, tz)
    audit_policy = load_audit_policy(args.audit_policy_file)
    configure_audit_policy(audit_policy)
    internal_domains.update(policy_internal_domains(audit_policy))
    args.audit_policy_meta = {
        "path": args.audit_policy_file,
        "three_d": len(CONTROLLED_3D_EXTS),
        "two_d": len(CONTROLLED_2D_CAD_EXTS),
        "critical_design_patterns": len(CRITICAL_DESIGN_PATTERNS),
        "archive_suffixes": len(ARCHIVE_EXTS),
        "internal_domains": len(internal_domains),
        "internal_networks": len(INTERNAL_NETWORKS),
        "organization_aliases": len(ORGANIZATION_ALIASES),
    }
    keyword_rules = load_sensitive_keyword_rules(args.sensitive_keywords_file)
    configure_sensitive_keyword_rules(keyword_rules)
    args.sensitive_keyword_meta = {
        "path": args.sensitive_keywords_file,
        "loaded": len(keyword_rules),
        "risk": len(SENSITIVE_KEYWORD_RULES),
        "leadership": len(LEADERSHIP_KEYWORD_RULES),
    }
    exclusion_rules = load_exclusion_rules(args.exclusion_file)
    args.exclusion_meta = {
        "path": args.exclusion_file,
        "loaded": len(exclusion_rules),
        "enabled": sum(1 for rule in exclusion_rules if rule.enabled),
    }
    people_map = load_people_map(args.people_map)
    if args.refresh_wecom_directory_cache_only:
        args.wecom_directory_refresh = True
    wecom_items, wecom_meta = load_wecom_directory_items(args)
    args.wecom_directory_meta = wecom_meta
    args.wecom_directory_authoritative_effective = bool(
        args.wecom_directory_authoritative
        and wecom_meta.get("ok")
        and int(wecom_meta.get("count") or 0) >= args.wecom_directory_min_users
    )
    if args.refresh_wecom_directory_cache_only:
        print(wecom_directory_summary(args))
        if not wecom_meta.get("ok"):
            return 1
        return 0
    wecom_people_map = build_wecom_people_map(wecom_items)
    manual_recipient_map = load_recipient_map(args.recipient_map)
    recipient_map = build_wecom_recipient_map(wecom_items)
    recipient_map.update(load_observed_wecom_account_recipient_map(args, wecom_people_map))
    recipient_map.update(manual_recipient_map)
    args.people_map_loaded = people_map
    args.wecom_people_map_loaded = wecom_people_map
    args.recipient_map_loaded = recipient_map
    disposition_by_event_id, disposition_by_search_id = load_dispositions(args.disposition_file)

    records: list[RawRecord] = []
    events: list[AuditEvent] = []
    if args.use_clickhouse:
        debug_timing("main read clickhouse start")
        records, events = records_and_events_from_clickhouse(args, start, end, tz)
    else:
        debug_timing("main read raw log start")
        for line in read_lines(args):
            record = parse_syslog_json(line)
            if not record or not in_period(record.ts, start, end, tz):
                continue
            records.append(record)
            event = build_event(
                record,
                internal_domains,
                recipient_map,
                exclusion_rules=exclusion_rules,
                include_firewall=args.include_firewall,
                include_unknown_im=args.include_unknown_im,
                include_untargeted_file=args.include_untargeted_file,
                wecom_directory_authoritative=args.wecom_directory_authoritative_effective,
            )
            if event:
                events.append(event)
    debug_timing(f"main read complete records={len(records)} events={len(events)}")

    terminal_identity_history = load_terminal_identity_history(args, records, tz, start, end, wecom_people_map)
    args.terminal_identity_history = terminal_identity_history
    args.terminal_identity_meta = {
        "terminals": len(terminal_identity_history),
        "observations": sum(len(items) for items in terminal_identity_history.values()),
        "max_age_days": args.terminal_identity_max_age_days,
    }

    apply_report_policies(events, getattr(args, "file_audit_raw_map", {}), internal_domains)
    debug_timing("report policy complete")
    enrich_events(
        events,
        people_map,
        wecom_people_map,
        disposition_by_event_id,
        disposition_by_search_id,
        recipient_map=manual_recipient_map,
        terminal_identity_history=terminal_identity_history,
        terminal_identity_max_age_days=args.terminal_identity_max_age_days,
    )
    debug_timing("enrich complete")
    apply_terminal_majority_identity(events, terminal_identity_history)
    debug_timing("terminal majority identity complete")

    output_path = Path(args.output) if args.output else None
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    args.sidecar_output_dir = output_path.parent if output_path and args.format == "html" else None

    sidecar_reports: Any = {}
    if args.format == "html":
        report, sidecar_reports = build_html_report(events, records, args, tz, start, end, internal_domains)
        report = apply_html_display_aliases(report)
    else:
        report = build_report(events, records, args, tz, start, end, internal_domains)

    if output_path:
        for filename, content in sidecar_reports.items():
            sidecar_path = output_path.parent / filename
            sidecar_path.write_text(apply_html_display_aliases(content), encoding="utf-8")
            print(f"Wrote {sidecar_path}")
        output_path.write_text(report, encoding="utf-8")
        print(f"Wrote {output_path}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(0)
