#!/usr/bin/env python3
"""Small intranet web service for data-security audit reports.

It serves the generated HTML reports and provides a fixed, validated manual
generation form for custom date ranges. It does not expose arbitrary command
execution or arbitrary file reads.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import mimetypes
import os
import posixpath
import re
import secrets
import subprocess
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse
import urllib.error
import urllib.request

import tianqing_decrypt_records as decrypt_records
import tianqing_encryption_terminals as encryption_terminals
import tianqing_external_audit_report as report_gen
import tianqing_terminal_behavior_review as terminal_review

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None


DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 18088
DEFAULT_REPORT_DIR = "/opt/tianqing-reports"
DEFAULT_APP_DIR = "/opt/tianqing-report-app"
DEFAULT_LOG_FILE = "/data/tianqing-audit/raw-log/tianqing.log"
DEFAULT_CLICKHOUSE_URL = "http://127.0.0.1:8123"
DEFAULT_CLICKHOUSE_DATABASE = "tianqing"
DEFAULT_PUBLIC_BASE_URL = "https://audit.daqo.com"
DEFAULT_AUTH_CALLBACK_URL = "https://ai.daqo.com/audit/auth/callback"
DEFAULT_AUTH_COOKIE_DOMAIN = ".daqo.com"
DEFAULT_AUTH_PROXY_BASE_URL = "http://172.88.49.60:19001"
CANONICAL_HOSTS = {"audit.daqo.com", "ai.daqo.com", "127.0.0.1", "localhost"}
DEFAULT_TIMEZONE = "Asia/Shanghai"
FIXED_POLICY_ADMIN_USERID = "10056"
ROLE_LABELS = {
    "admin": "策略管理员",
    "global": "集团查看",
}
DEFAULT_ARCHIVE_SUFFIXES = ["zip", "rar", "7z", "tar", "gz", "gzip", "tgz", "bz2", "tbz", "tbz2", "xz", "txz", "zst", "zipx", "cab", "iso", "arj", "lzh", "001"]
DEFAULT_CRITICAL_DESIGN_PATTERNS = [
    {
        "key": "structure_standard",
        "label": "结构标准方案",
        "regex": r"^[3568][^\\/\.]{2}\.[^\\/\.]{3}\.[^\\/\.]{3}\.(?:sldasm|sldprt|step)$",
        "description": "结构方案图号主体为三段点号命名，每段固定三位，第一段以 3/5/6/8 开头，后缀为 SLDASM/SLDPRT/STEP。",
        "match_examples": ["356.123.456.sldprt", "5AB.CD1.999.SLDASM", "8XY.abc.DEF.step"],
        "miss_examples": ["123.456.789.sldprt", "356.1234.456.sldprt", "356.123.456.dwg"],
        "enabled": True,
    },
    {
        "key": "electrical_standard",
        "label": "电气标准方案",
        "regex": r"^dq[^\\/\-]+-[^\\/\-]+-[^\\/\-]+-[^\\/\-]+\.dwg$",
        "description": "电气方案图号以 DQ 开头，主体正好三个短横线，每段非空，后缀为 DWG。",
        "match_examples": ["DQ1-22-333-4444.dwg", "DQABC-DEF-G-HI.DWG", "dq低压柜-方案A-一次图-01.dwg"],
        "miss_examples": ["DQ001-002-003.dwg", "DQ001--003-004.dwg", "DQ001-002-003-004.dwg.zip"],
        "enabled": True,
    },
]


def sanitize_critical_design_patterns(rows: Any) -> list[dict[str, Any]]:
    source = rows if isinstance(rows, list) else DEFAULT_CRITICAL_DESIGN_PATTERNS
    sanitized: list[dict[str, Any]] = []
    for item in source:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip().lower()
        if key.startswith("yb_standard"):
            continue
        sanitized.append(item)
    return sanitized or [dict(item) for item in DEFAULT_CRITICAL_DESIGN_PATTERNS]


MAX_POST_BYTES = 256 * 1024
MAX_UPLOAD_POST_BYTES = 128 * 1024 * 1024
MAX_RANGE_DAYS = 370
MIN_MAX_EVENTS = 20
MAX_MAX_EVENTS = 2000
AUTH_COOKIE_NAME = "tq_audit_session"
AUTH_STATE_COOKIE_NAME = "tq_audit_state"
AUTH_PROXY_TOKEN_FILE = ".auth_proxy_token"
AUTH_SESSION_FILE = ".auth_sessions.json"
DEFAULT_POLICY_ADMIN_USERIDS = [FIXED_POLICY_ADMIN_USERID]
DEFAULT_PLM_CONSTRAINED_DEPARTMENTS = ["技术部", "研发部", "工艺部"]
DEFAULT_PLM_TERMINAL_MATCH_FIELDS = ["ip_address", "computer_name"]
ENCRYPTION_TERMINAL_TRUST_DAYS = 7
TOP_RISK_DEFINITION_TEXT = (
    "一级风险定义：标准图纸解密；天擎标准图纸外发/拷贝；"
    "天擎大于100MB压缩包外发/上传/外设拷贝；PLM技术、研发、工艺账号池外登录。"
)
TOP_RISK_EVIDENCE_TEXT = "一级风险进入顶部汇总管理结论，矩阵、趋势和明细用于定位组织、终端与证据链。"


def encryption_terminal_trust_condition(prefix: str = "") -> str:
    base = f"{prefix}." if prefix else ""
    return (
        f"notEmpty({base}ip_address) "
        f"AND notEmpty({base}computer_name) "
        f"AND NOT isNull({base}last_seen) "
        f"AND {base}last_seen >= now('Asia/Shanghai') - INTERVAL {ENCRYPTION_TERMINAL_TRUST_DAYS} DAY"
    )


def encryption_terminal_trust_status_sql(prefix: str = "") -> str:
    base = f"{prefix}." if prefix else ""
    return (
        "multiIf("
        f"empty({base}ip_address), '缺少IP地址', "
        f"empty({base}computer_name), '缺少计算机名', "
        f"isNull({base}last_seen), '无最后在线时间', "
        f"{base}last_seen < now('Asia/Shanghai') - INTERVAL {ENCRYPTION_TERMINAL_TRUST_DAYS} DAY, '最后在线超过{ENCRYPTION_TERMINAL_TRUST_DAYS}天', "
        "'授信有效')"
    )


def encryption_terminal_mac_key_sql(prefix: str = "") -> str:
    base = f"{prefix}." if prefix else ""
    return f"lowerUTF8(replaceAll(replaceAll(replaceAll({base}mac_address, '-', ''), ':', ''), ' ', ''))"


@dataclass
class AppConfig:
    host: str
    port: int
    report_dir: Path
    app_dir: Path
    policy_file: Path
    keywords_file: Path
    exclusions_file: Path
    log_file: Path
    timezone: str
    python: str
    use_clickhouse: bool
    clickhouse_url: str
    clickhouse_database: str
    clickhouse_user: str
    clickhouse_password: str
    clickhouse_timeout: int
    public_base_url: str
    auth_callback_url: str
    auth_cookie_domain: str
    auth_proxy_base_url: str
    auth_proxy_token: str


@dataclass
class Job:
    job_id: str
    label: str
    start_text: str
    end_text: str
    max_events: int
    output_name: str
    log_name: str
    refresh_clickhouse: bool = True
    archive_period: str = ""
    archive_stamp: str = ""
    status: str = "running"
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    return_code: int | None = None
    error: str = ""


@dataclass
class AuthSession:
    session_id: str
    userid: str
    name: str = ""
    company: str = ""
    department: str = ""
    status: str = ""
    role: str = ""
    csrf_token: str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()
RUN_LOCK = threading.Lock()
RULES_LOCK = threading.Lock()
SESSIONS: dict[str, AuthSession] = {}
SESSIONS_LOCK = threading.Lock()
TERMINAL_CHECK_CACHE_TTL_SECONDS = 30 * 60
TERMINAL_CHECK_CACHE_MAX_ENTRIES = 6
TERMINAL_CHECK_CACHE: dict[tuple[str, str, str], dict[str, Any]] = {}
TERMINAL_CHECK_CACHE_LOCK = threading.Lock()
DECRYPT_ANALYSIS_CACHE_TTL_SECONDS = 30 * 60
DECRYPT_ANALYSIS_CACHE_MAX_ENTRIES = 6
DECRYPT_ANALYSIS_CACHE: dict[tuple[str, str, str], dict[str, Any]] = {}
DECRYPT_ANALYSIS_CACHE_LOCK = threading.Lock()
RECENT_JOB_SECONDS = 12 * 3600
CUSTOM_REPORT_TTL_DAYS = int(os.getenv("TIANQING_CUSTOM_REPORT_TTL_DAYS", "7") or "7")
JOB_LOG_TTL_DAYS = int(os.getenv("TIANQING_JOB_LOG_TTL_DAYS", "30") or "30")
REPORT_ARCHIVE_RE = re.compile(r"^tianqing_leadership_(previous-day|today|current-week|previous-week)_(\d{8}-\d{6})\.html$")
REPORT_ARCHIVE_INDEX = "report_archives.jsonl"
TEMP_REPORT_GROUP_RE = re.compile(r"^(?P<stem>tianqing_custom_\d{12}_\d{12}_(?P<job_id>\d{14}-\d+-\d{4}))(?:_|\.html$)")
AI_DETAIL_REPORT_RE = re.compile(r"_ai-[0-9a-f]{10}\.html$", re.IGNORECASE)


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def local_tz(name: str):
    if ZoneInfo:
        return ZoneInfo(name)
    return None


def parse_local_datetime(value: str, tz_name: str) -> datetime:
    raw = (value or "").strip().replace("T", " ")
    if not raw:
        raise ValueError("开始和结束时间不能为空。")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError("时间格式不正确。") from exc
    tz = local_tz(tz_name)
    if parsed.tzinfo is None and tz is not None:
        parsed = parsed.replace(tzinfo=tz)
    elif parsed.tzinfo is not None and tz is not None:
        parsed = parsed.astimezone(tz)
    return parsed


def clamp_int(raw: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def safe_label(raw: str) -> str:
    cleaned = " ".join((raw or "").strip().split())
    return cleaned[:60] if cleaned else "自定义审计报告"


def make_job_id() -> str:
    return datetime.now().strftime("%Y%m%d%H%M%S") + f"-{os.getpid()}-{threading.get_ident() % 10000:04d}"


def auth_proxy_token(config: AppConfig) -> str:
    token = (config.auth_proxy_token or os.getenv("TIANQING_AUTH_PROXY_TOKEN") or "").strip()
    if token:
        return token
    token_path = config.app_dir / AUTH_PROXY_TOKEN_FILE
    try:
        return token_path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def auth_proxy_request(config: AppConfig, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    base = config.auth_proxy_base_url.rstrip("/")
    url = base + path
    headers = {"Accept": "application/json"}
    token = auth_proxy_token(config)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    method = "GET"
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def load_wecom_user_cache(config: AppConfig) -> dict[str, dict[str, Any]]:
    path = config.app_dir / "wecom_directory_cache.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    items = data.get("items") if isinstance(data, dict) else []
    result: dict[str, dict[str, Any]] = {}
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            userid = str(item.get("userid") or "").strip()
            if userid:
                result[userid] = item
    return result


def session_store_path(config: AppConfig) -> Path:
    return config.app_dir / AUTH_SESSION_FILE


def session_from_dict(raw: Any) -> AuthSession | None:
    if not isinstance(raw, dict):
        return None
    sid = str(raw.get("session_id") or "").strip()
    userid = str(raw.get("userid") or "").strip()
    if not sid or not userid:
        return None
    try:
        expires_at = float(raw.get("expires_at") or 0)
        created_at = float(raw.get("created_at") or time.time())
    except (TypeError, ValueError):
        return None
    return AuthSession(
        session_id=sid,
        userid=userid,
        name=str(raw.get("name") or ""),
        company=str(raw.get("company") or ""),
        department=str(raw.get("department") or ""),
        status=str(raw.get("status") or ""),
        role=str(raw.get("role") or ""),
        csrf_token=str(raw.get("csrf_token") or ""),
        created_at=created_at,
        expires_at=expires_at,
    )


def read_persisted_sessions(config: AppConfig, now: float | None = None) -> dict[str, AuthSession]:
    now = time.time() if now is None else now
    try:
        raw = json.loads(session_store_path(config).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    items = raw.get("sessions") if isinstance(raw, dict) else []
    result: dict[str, AuthSession] = {}
    if isinstance(items, list):
        for item in items:
            session = session_from_dict(item)
            if session and session.expires_at > now:
                result[session.session_id] = session
    return result


def write_sessions_locked(config: AppConfig) -> None:
    now = time.time()
    for sid, session in list(SESSIONS.items()):
        if session.expires_at <= now:
            SESSIONS.pop(sid, None)
    payload = {
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "sessions": [session.__dict__ for session in SESSIONS.values()],
    }
    path = session_store_path(config)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def policy_userid_list(value: Any, default: list[str] | None = None) -> list[str]:
    if value is None:
        value = default or []
    if isinstance(value, str):
        return normalize_userids(value)
    if not isinstance(value, list):
        value = default or []
    return [str(item).strip() for item in value if str(item).strip()]


def policy_bool(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "on", "enabled", "启用", "开启"}:
            return True
        if text in {"0", "false", "no", "off", "disabled", "停用", "关闭"}:
            return False
    return default


def ai_policy_enabled_from_doc(doc: dict[str, Any]) -> bool:
    return False


def ai_policy_enabled(config: AppConfig) -> bool:
    return False


def cookie_domain_suffix(config: AppConfig) -> str:
    domain = str(config.auth_cookie_domain or "").strip()
    if not domain:
        return ""
    if not re.fullmatch(r"\.?[A-Za-z0-9.-]+", domain):
        return ""
    return f"; Domain={domain}"


def auth_cookie_header(config: AppConfig, name: str, value: str, max_age: int) -> str:
    return f"{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax{cookie_domain_suffix(config)}"


def public_redirect_url(config: AppConfig, next_path: str) -> str:
    if not next_path.startswith("/") or next_path.startswith("//"):
        next_path = "/"
    return config.public_base_url.rstrip("/") + next_path


def normalize_login_next(next_path: str) -> str:
    path = next_path if next_path.startswith("/") and not next_path.startswith("//") else "/"
    settings_routes = {
        "/settings/keywords/": "/settings/keywords",
        "/settings/policy/": "/settings/policy",
        "/settings/internal-targets/": "/settings/internal-targets",
        "/settings/archive-suffixes/": "/settings/archive-suffixes",
        "/settings/plm-login/": "/settings/plm-login",
        "/settings/terminal-behavior-review/": "/settings/terminal-behavior-review",
        "/settings/decrypt-records/": "/settings/decrypt-records",
        "/settings/organization-aliases/": "/settings/organization-aliases",
        "/settings/organization-tree/": "/settings/organization-tree",
        "/settings/auth/": "/settings/auth",
        "/settings/exclusions/": "/settings/exclusions",
    }
    for prefix, target in settings_routes.items():
        if path.startswith(prefix):
            return target
    if path == "/api/generate":
        return "/manual"
    return path


def auth_identity_bar(session: AuthSession) -> str:
    display_name = session.name or session.userid
    role = ROLE_LABELS.get(session.role, session.role or "已登录")
    org_parts = [part for part in [session.company, session.department] if part]
    org_text = " / ".join(org_parts) if org_parts else "未匹配组织"
    return f"""
<style>
  .tq-authbar {{
    position: sticky;
    top: 0;
    z-index: 99999;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    min-height: 46px;
    padding: 8px 28px;
    background: rgba(255, 255, 255, 0.96);
    border-bottom: 1px solid #d9e0ea;
    box-shadow: 0 10px 28px rgba(15, 23, 42, 0.08);
    color: #172033;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", Arial, sans-serif;
    font-size: 13px;
    line-height: 1.35;
    backdrop-filter: blur(10px);
  }}
  .tq-authbar strong {{ font-weight: 800; }}
  .tq-authbar .tq-authmeta {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 12px;
  }}
  .tq-authbar .tq-authpill {{
    display: inline-flex;
    align-items: center;
    min-height: 24px;
    border-radius: 999px;
    padding: 2px 9px;
    background: #eef4ff;
    color: #175cd3;
    font-weight: 800;
  }}
  .tq-authbar .tq-authmuted {{ color: #667085; }}
  .tq-authbar .tq-authactions {{
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: 8px;
  }}
  .tq-authbar a.tq-authlink {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-height: 30px;
    padding: 5px 11px;
    border: 1px solid #d9e0ea;
    border-radius: 7px;
    color: #175cd3;
    background: #fff;
    font-weight: 800;
    text-decoration: none;
  }}
	  @media (max-width: 760px) {{
	    .tq-authbar {{ align-items: flex-start; padding: 8px 16px; }}
	    .tq-authbar .tq-authmeta {{ display: grid; gap: 4px; }}
	    .tq-authbar .tq-authactions {{ justify-content: flex-start; }}
	  }}
	</style>
<div class="tq-authbar">
  <div class="tq-authmeta">
    <span>当前登录：<strong>{esc(display_name)}</strong></span>
    <span class="tq-authmuted">userid={esc(session.userid)}</span>
    <span class="tq-authmuted">{esc(org_text)}</span>
    <span class="tq-authpill">{esc(role)}</span>
	  </div>
	  <div class="tq-authactions">
	    <a class="tq-authlink" href="/auth/logout">退出登录</a>
	  </div>
	</div>
	"""


def inject_identity_bar(data: bytes, session: AuthSession | None) -> bytes:
    if not session:
        return data
    text = data.decode("utf-8", errors="replace")
    if "tq-authbar" in text:
        return data
    bar = auth_identity_bar(session)
    if re.search(r"<body\b[^>]*>", text, flags=re.IGNORECASE):
        text = re.sub(r"(<body\b[^>]*>)", r"\1" + bar, text, count=1, flags=re.IGNORECASE)
    else:
        text = bar + text
    return text.encode("utf-8")


def session_can_view_job(session: AuthSession, job: Job) -> bool:
    return session.role in {"admin", "global"}


def current_job_for_session(session: AuthSession) -> Job | None:
    now = time.time()
    with JOBS_LOCK:
        visible_jobs = [job for job in JOBS.values() if session_can_view_job(session, job)]
    if not visible_jobs:
        return None
    running = [job for job in visible_jobs if job.status == "running"]
    if running:
        return max(running, key=lambda item: item.created_at)
    recent = [
        job
        for job in visible_jobs
        if (job.finished_at or job.created_at) and now - (job.finished_at or job.created_at) <= RECENT_JOB_SECONDS
    ]
    if not recent:
        return None
    return max(recent, key=lambda item: item.finished_at or item.created_at)


def job_status_bar(config: AppConfig, session: AuthSession) -> str:
    job = current_job_for_session(session)
    if not job:
        return ""
    status_label = {"running": "生成中", "done": "已完成", "failed": "失败"}.get(job.status, job.status)
    if job.status == "running":
        detail = "后台任务仍在运行，离开页面或返回首页不会中止生成。"
    elif job.status == "done":
        detail = "报告已生成完成，可打开报告或查看生成日志。"
    else:
        detail = job.error or "生成失败，可查看日志定位原因。"
    elapsed = ""
    if job.finished_at:
        elapsed = f"{int(job.finished_at - job.created_at)} 秒"
    elif job.created_at:
        elapsed = f"{int(time.time() - job.created_at)} 秒"
    actions: list[str] = []
    if job.status == "done":
        actions.insert(0, f'<a class="primary" href="/{esc(job.output_name)}">打开报告</a>')
    if job.status == "failed":
        actions.insert(0, '<a class="primary" href="/manual">重新生成</a>')
    return f"""
<style id="tq-jobbar-style">
  .tq-jobbar {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 10px 28px;
    border-bottom: 1px solid #dbe6f5;
    background: linear-gradient(90deg, #f8fbff 0%, #ffffff 100%);
    color: #172033;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", Arial, sans-serif;
    font-size: 13px;
    line-height: 1.45;
  }}
  .tq-jobbar strong {{ font-weight: 820; }}
  .tq-jobbar .tq-jobmeta {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 12px;
    min-width: 0;
  }}
  .tq-jobbar .tq-jobtitle {{
    max-width: 340px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }}
  .tq-jobbar .tq-jobmuted {{ color: #667085; }}
  .tq-jobbar .tq-jobstatus {{
    display: inline-flex;
    align-items: center;
    min-height: 23px;
    border-radius: 999px;
    padding: 2px 9px;
    font-size: 12px;
    font-weight: 820;
  }}
  .tq-jobbar .tq-jobstatus.running {{ background: #eef4ff; color: #175cd3; }}
  .tq-jobbar .tq-jobstatus.done {{ background: #ecfdf3; color: #067647; }}
  .tq-jobbar .tq-jobstatus.failed {{ background: #fff1f0; color: #b42318; }}
  .tq-jobbar .tq-jobactions {{
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: 8px;
    flex: 0 0 auto;
  }}
  .tq-jobbar a {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-height: 28px;
    border: 1px solid #d9e0ea;
    border-radius: 7px;
    padding: 4px 10px;
    color: #175cd3;
    background: #fff;
    font-weight: 800;
    text-decoration: none;
  }}
  .tq-jobbar a.primary {{
    border-color: #175cd3;
    background: #175cd3;
    color: #fff;
  }}
  @media (max-width: 900px) {{
    .tq-jobbar {{ align-items: flex-start; flex-direction: column; padding: 10px 16px; }}
    .tq-jobbar .tq-jobactions {{ justify-content: flex-start; }}
  }}
</style>
<div class="tq-jobbar">
  <div class="tq-jobmeta">
    <span class="tq-jobstatus {esc(job.status)}">{esc(status_label)}</span>
    <strong class="tq-jobtitle" title="{esc(job.label)}">{esc(job.label)}</strong>
    <span class="tq-jobmuted">{esc(detail)}</span>
    <span class="tq-jobmuted">耗时：{esc(elapsed)}</span>
  </div>
  <div class="tq-jobactions">{"".join(actions)}</div>
</div>
"""


def inject_job_status_bar(data: bytes, config: AppConfig, session: AuthSession | None) -> bytes:
    if not session:
        return data
    text = data.decode("utf-8", errors="replace")
    if "tq-jobbar" in text:
        return data
    bar = job_status_bar(config, session)
    if not bar:
        return data
    if "tq-authbar" in text:
        updated = re.sub(
            r'(<div class="tq-authbar">[\s\S]*?<div class="tq-authactions">[\s\S]*?</div>\s*</div>)',
            lambda match: match.group(1) + bar,
            text,
            count=1,
            flags=re.IGNORECASE,
        )
        if updated != text:
            return updated.encode("utf-8")
    if re.search(r"<body\b[^>]*>", text, flags=re.IGNORECASE):
        text = re.sub(r"(<body\b[^>]*>)", r"\1" + bar, text, count=1, flags=re.IGNORECASE)
    else:
        text = bar + text
    return text.encode("utf-8")


def inject_trend_visual_patch(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="replace")
    if 'id="tq-trend-visual-patch"' in text or 'id="risk-trend"' not in text:
        return data
    patch = r"""
<style id="tq-trend-visual-patch">
  #risk-trend .trend-svg {
    height: 280px !important;
  }
  #risk-trend .trend-chart-card,
  #decrypt-risk-tracking .trend-chart-card {
    padding: 9px 12px 8px !important;
  }
  #risk-trend .trend-chart-head h3,
  #decrypt-risk-tracking .trend-chart-head h3 {
    font-size: 12px !important;
    font-weight: 800 !important;
  }
  #risk-trend .trend-chart-head span,
  #decrypt-risk-tracking .trend-chart-head span {
    font-size: 9px !important;
  }
  #risk-trend .trend-axis-label,
  #decrypt-risk-tracking .trend-axis-label {
    font-size: 5px !important;
    font-weight: 520 !important;
  }
  #risk-trend .trend-line,
  #decrypt-risk-tracking .trend-line {
    stroke-width: 0.8 !important;
  }
  #risk-trend .trend-point-hit,
  #decrypt-risk-tracking .trend-point-hit {
    fill: transparent !important;
    stroke: transparent !important;
    pointer-events: all !important;
    cursor: crosshair !important;
  }
  #risk-trend .trend-line-group:hover .trend-line,
  #risk-trend .trend-line-group:focus .trend-line,
  #decrypt-risk-tracking .trend-line-group:hover .trend-line,
  #decrypt-risk-tracking .trend-line-group:focus .trend-line {
    stroke-width: 1.2 !important;
  }
  #risk-trend .trend-grid-line,
  #decrypt-risk-tracking .trend-grid-line {
    stroke-width: 0.6 !important;
  }
  #risk-trend .trend-legend,
  #decrypt-risk-tracking .trend-legend {
    gap: 3px 12px !important;
    margin-top: -3px !important;
  }
  #risk-trend .trend-legend-item,
  #decrypt-risk-tracking .trend-legend-item {
    max-width: 150px !important;
    min-height: 15px !important;
    gap: 4px !important;
    padding: 0 2px !important;
  }
  #risk-trend .trend-line-swatch,
  #decrypt-risk-tracking .trend-line-swatch {
    width: 17px !important;
    border-top-width: 1px !important;
  }
  #risk-trend .trend-legend-label,
  #risk-trend .trend-legend-item strong,
  #decrypt-risk-tracking .trend-legend-label,
  #decrypt-risk-tracking .trend-legend-item strong {
    font-size: 10px !important;
    font-weight: 760 !important;
  }
  #risk-trend .trend-legend-item strong,
  #decrypt-risk-tracking .trend-legend-item strong {
    font-weight: 820 !important;
  }
  .trend-hover-tip {
    position: fixed;
    z-index: 9999;
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
  }
</style>
<script id="tq-trend-combined-patch">
  document.addEventListener("DOMContentLoaded", function () {
    var root = document.getElementById("risk-trend");
    if (!root || root.getAttribute("data-channel-object-patched") === "1") {
      return;
    }
    root.setAttribute("data-channel-object-patched", "1");
    var channelTab = root.querySelector('[data-trend-tab="channel"]');
    if (channelTab) {
      channelTab.textContent = "通道与对象";
      channelTab.setAttribute("title", "同一视图展示外发通道和审计对象趋势");
    }
    var objectTab = root.querySelector('[data-trend-tab="object"]');
    if (objectTab) {
      objectTab.style.display = "none";
    }
    var highContrastPalette = ["#1d4ed8", "#ea580c", "#047857", "#7c3aed", "#dc2626", "#0891b2", "#be185d", "#334155", "#65a30d", "#a16207"];
    function applyTrendColor(card, key, color) {
      if (!key || !card) {
        return;
      }
      Array.prototype.forEach.call(card.querySelectorAll('[data-trend-line="' + key + '"]'), function (group) {
        group.setAttribute("data-trend-color", color);
        Array.prototype.forEach.call(group.querySelectorAll(".trend-line, .trend-line-shadow"), function (line) {
          line.setAttribute("stroke", color);
          line.style.stroke = color;
        });
      });
      Array.prototype.forEach.call(card.querySelectorAll('[data-trend-toggle="' + key + '"] .trend-line-swatch'), function (swatch) {
        swatch.style.setProperty("--trend-color", color);
        swatch.style.backgroundColor = color;
      });
    }
    function recolorTrendCards() {
      Array.prototype.forEach.call(root.querySelectorAll(".trend-chart-card"), function (card) {
        var seen = [];
        Array.prototype.forEach.call(card.querySelectorAll("[data-trend-toggle]"), function (toggle) {
          var key = toggle.getAttribute("data-trend-toggle");
          if (!key || seen.indexOf(key) >= 0) {
            return;
          }
          var color = highContrastPalette[seen.length % highContrastPalette.length];
          seen.push(key);
          applyTrendColor(card, key, color);
        });
      });
    }
    function bindLegend(toggle) {
      if (!toggle || toggle.getAttribute("data-tq-bound") === "1") {
        return;
      }
      toggle.setAttribute("data-tq-bound", "1");
      toggle.addEventListener("click", function () {
        var key = toggle.getAttribute("data-trend-toggle");
        if (!key) {
          return;
        }
        var hidden = toggle.classList.toggle("is-muted");
        toggle.setAttribute("aria-pressed", hidden ? "false" : "true");
        Array.prototype.forEach.call(root.querySelectorAll('[data-trend-line="' + key + '"]'), function (line) {
          line.classList.toggle("is-hidden", hidden);
        });
      });
    }
    Array.prototype.forEach.call(root.querySelectorAll("[data-trend-range-panel]"), function (rangePanel) {
      var channelPanel = rangePanel.querySelector('[data-trend-panel="channel"]');
      var objectPanel = rangePanel.querySelector('[data-trend-panel="object"]');
      if (!channelPanel || !objectPanel || channelPanel.querySelector(".tq-object-trend-copy")) {
        return;
      }
      Array.prototype.forEach.call(objectPanel.children, function (child) {
        var clone = child.cloneNode(true);
        clone.classList.add("tq-object-trend-copy");
        channelPanel.appendChild(clone);
        Array.prototype.forEach.call(clone.querySelectorAll("[data-trend-toggle]"), bindLegend);
      });
      objectPanel.parentNode.removeChild(objectPanel);
    });
    recolorTrendCards();
    var trendTip = document.querySelector(".trend-hover-tip");
    if (!trendTip) {
      trendTip = document.createElement("div");
      trendTip.className = "trend-hover-tip";
      document.body.appendChild(trendTip);
    }
    function parseJsonArray(raw) {
      try {
        var parsed = JSON.parse(raw || "[]");
        return Array.isArray(parsed) ? parsed : [];
      } catch (err) {
        return [];
      }
    }
    function pathPoints(group) {
      var path = group.querySelector(".trend-line");
      var raw = path ? (path.getAttribute("d") || "") : "";
      var points = [];
      raw.replace(/(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)/g, function (_, x, y) {
        points.push({x: Number(x), y: Number(y)});
        return "";
      });
      return points;
    }
    function fallbackBuckets(group, count) {
      var card = group.closest(".trend-chart-card");
      var labels = card ? Array.prototype.map.call(card.querySelectorAll(".trend-axis-label-x"), function (node) { return (node.textContent || "").trim(); }) : [];
      if (labels.length === count) {
        return labels;
      }
      var result = [];
      for (var i = 0; i < count; i += 1) {
        result.push(labels[i] || ("第" + (i + 1) + "点"));
      }
      return result;
    }
    function fallbackAxisMax(group) {
      var card = group.closest(".trend-chart-card");
      var values = card ? Array.prototype.map.call(card.querySelectorAll(".trend-axis-label:not(.trend-axis-label-x)"), function (node) { return Number((node.textContent || "").trim()); }) : [];
      values = values.filter(function (value) { return isFinite(value); });
      return values.length ? Math.max.apply(Math, values) : 1;
    }
    function labelForGroup(group) {
      var label = group.getAttribute("data-trend-label");
      if (label) {
        return label;
      }
      var key = group.getAttribute("data-trend-line");
      var legend = key ? root.querySelector('[data-trend-toggle="' + key + '"] .trend-legend-label') : null;
      return legend ? (legend.textContent || "").trim() : "趋势";
    }
    function totalForGroup(group, values) {
      var total = Number(group.getAttribute("data-trend-total") || 0);
      if (total) {
        return total;
      }
      var key = group.getAttribute("data-trend-line");
      var legend = key ? root.querySelector('[data-trend-toggle="' + key + '"] strong') : null;
      total = legend ? Number((legend.textContent || "").trim()) : 0;
      return total || values.reduce(function (sum, value) { return sum + value; }, 0);
    }
    function trendText(group, evt) {
      var direct = evt && evt.target && evt.target.getAttribute && evt.target.getAttribute("data-trend-tip");
      if (direct) {
        return direct;
      }
      var values = parseJsonArray(group.getAttribute("data-trend-values")).map(function (value) { return Number(value) || 0; });
      var buckets = parseJsonArray(group.getAttribute("data-trend-buckets"));
      var points = pathPoints(group);
      if (!points.length) {
        return labelForGroup(group);
      }
      if (!values.length) {
        var chartH = Math.max.apply(Math, points.map(function (point) { return point.y; })) || 1;
        var axisMax = fallbackAxisMax(group);
        values = points.map(function (point) { return Math.max(0, Math.round((chartH - point.y) / chartH * axisMax)); });
      }
      if (!buckets.length) {
        buckets = fallbackBuckets(group, points.length);
      }
      var idx = 0;
      if (evt && isFinite(evt.clientX)) {
        var svg = group.closest("svg");
        var rect = svg.getBoundingClientRect();
        var viewW = svg.viewBox && svg.viewBox.baseVal ? svg.viewBox.baseVal.width : rect.width;
        var localX = (evt.clientX - rect.left) * viewW / Math.max(rect.width, 1) - 30;
        var best = Infinity;
        points.forEach(function (point, pointIdx) {
          var distance = Math.abs(point.x - localX);
          if (distance < best) {
            best = distance;
            idx = pointIdx;
          }
        });
      }
      var total = totalForGroup(group, values);
      return labelForGroup(group) + " " + (buckets[idx] || ("第" + (idx + 1) + "点")) + "：" + (values[idx] || 0) + " 条 / 合计 " + total + " 条";
    }
    function showTrendTip(group, evt) {
      if (!group || group.classList.contains("is-hidden")) {
        trendTip.style.display = "none";
        return;
      }
      var text = trendText(group, evt);
      if (!text) {
        return;
      }
      trendTip.textContent = text;
      trendTip.style.display = "block";
      var x = evt && isFinite(evt.clientX) ? evt.clientX + 12 : 24;
      var y = evt && isFinite(evt.clientY) ? evt.clientY + 12 : 24;
      trendTip.style.left = Math.min(x, window.innerWidth - trendTip.offsetWidth - 12) + "px";
      trendTip.style.top = Math.min(y, window.innerHeight - trendTip.offsetHeight - 12) + "px";
    }
    Array.prototype.forEach.call(root.querySelectorAll(".trend-line-group"), function (group) {
      if (group.getAttribute("data-tq-tip-bound") === "1") {
        return;
      }
      group.setAttribute("data-tq-tip-bound", "1");
      group.addEventListener("mousemove", function (evt) { showTrendTip(group, evt); });
      group.addEventListener("click", function (evt) { showTrendTip(group, evt); });
      group.addEventListener("focus", function (evt) { showTrendTip(group, evt); });
      group.addEventListener("mouseleave", function () { trendTip.style.display = "none"; });
      group.addEventListener("blur", function () { trendTip.style.display = "none"; });
    });
  });
</script>
"""
    if re.search(r"</head>", text, flags=re.IGNORECASE):
        text = re.sub(r"</head>", lambda match: patch + "\n" + match.group(0), text, count=1, flags=re.IGNORECASE)
    else:
        text = patch + text
    return text.encode("utf-8")


def terminal_check_period_url(start: datetime, end: datetime, base_url: str = "") -> str:
    params = urlencode(
        {
            "preset": "custom",
            "start": datetime_input_value(start),
            "end": datetime_input_value(end),
        }
    )
    prefix = base_url.rstrip("/") if base_url else ""
    return f"{prefix}/terminal-check?{params}"


def report_period_for_html_or_path(config: AppConfig | None, target: Path | None, data: bytes) -> tuple[datetime, datetime] | None:
    if config is not None and target is not None:
        period = report_period_for_static_path(config, target)
        if period:
            return period
    if config is None:
        return None
    html_period = report_period_from_html(data)
    if not html_period:
        return None
    try:
        return parse_local_datetime(html_period[0], config.timezone), parse_local_datetime(html_period[1], config.timezone)
    except ValueError:
        return None


def inject_report_navigation_patch(data: bytes, config: AppConfig | None = None, target: Path | None = None) -> bytes:
    text = data.decode("utf-8", errors="replace")
    period = report_period_for_html_or_path(config, target, data) if config is not None else None
    terminal_check_href = terminal_check_period_url(*period) if period else "/terminal-check"
    settings_href = "/settings"
    if config is not None:
        settings_href = f"{config.public_base_url.rstrip('/')}/settings" if config.public_base_url else "/settings"
    updated = re.sub(
        r'\s*<a\s+class="top-action(?:\s+primary)?"\s+href="[^"]*/reports">历史报告</a>',
        "",
        text,
        count=1,
        flags=re.IGNORECASE,
    )
    updated = re.sub(
        r'<a\s+class="top-action\s+primary"\s+href="[^"]*/manual">自定义周期生成</a>',
        "",
        updated,
        count=1,
        flags=re.IGNORECASE,
    )
    updated = re.sub(
        r'\s*<a\s+class="top-action(?:\s+primary)?"\s+href="[^"]*/settings"\s*>策略管理</a>',
        "",
        updated,
        count=1,
        flags=re.IGNORECASE,
    )
    terminal_link = f'<a class="top-action danger" href="{esc(terminal_check_href)}">风险终端复核</a>'
    updated_with_period = re.sub(
        r'<a\s+class="top-action(?:\s+danger)?"\s+href="[^"]*/terminal-check(?:\?[^"]*)?"\s*>(?:异常终端行为核查|风险终端复核)</a>',
        terminal_link,
        updated,
        count=1,
        flags=re.IGNORECASE,
    )
    updated = updated_with_period
    if "风险终端复核" not in updated:
        updated = re.sub(
            r'(<div\s+class="top-actions"\s*>)',
            r"\1" + terminal_link,
            updated,
            count=1,
            flags=re.IGNORECASE,
        )
    settings_card = (
        f'<aside class="stamp"><a href="{esc(settings_href)}">'
        '<strong>策略管理</strong><span>规则、账号与数据源维护</span>'
        "</a></aside>"
    )
    updated = re.sub(
        r'<aside\s+class="stamp"[\s\S]*?</aside>',
        settings_card,
        updated,
        count=1,
        flags=re.IGNORECASE,
    )
    if "top-navigation-polish-style" not in updated:
        style = """
<style id="top-navigation-polish-style">
  header .stamp {
    min-width: 200px;
    border-left-color: #93c5fd;
    border-radius: 12px;
    padding: 12px 14px;
  }
  header .stamp a {
    display: block;
    color: inherit;
    text-decoration: none;
  }
  header .stamp strong {
    font-size: 17px;
    margin-bottom: 4px;
    letter-spacing: 0;
  }
  header .top-action.danger {
    border-color: rgba(248, 113, 113, 0.62);
    color: #fff;
    background: linear-gradient(180deg, #ef4444 0%, #dc2626 100%);
    box-shadow: 0 10px 22px rgba(220, 38, 38, 0.22);
  }
  header .top-action.danger:hover {
    border-color: rgba(254, 202, 202, 0.9);
    background: linear-gradient(180deg, #f87171 0%, #dc2626 100%);
  }
</style>
"""
        if re.search(r"</head>", updated, flags=re.IGNORECASE):
            updated = re.sub(r"</head>", style + r"\g<0>", updated, count=1, flags=re.IGNORECASE)
        else:
            updated = style + updated
    return updated.encode("utf-8") if updated != text else data


def inject_top_risk_definition(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="replace")
    if TOP_RISK_DEFINITION_TEXT in text and TOP_RISK_EVIDENCE_TEXT in text:
        return data
    updated = re.sub(
        r"<span>首页[^<]{0,240}</span>",
        f"<span>{esc(TOP_RISK_DEFINITION_TEXT)}</span>",
        text,
        count=1,
    )
    updated = re.sub(
        r"<span>所有数字均可下钻追溯，原始日志和审计底稿保留用于复核闭环。</span>",
        f"<span>{esc(TOP_RISK_EVIDENCE_TEXT)}</span>",
        updated,
        count=1,
    )
    return updated.encode("utf-8") if updated != text else data


def _html_plain_text(fragment: str) -> str:
    text = re.sub(r"(?is)<script\b.*?</script>|<style\b.*?</style>", " ", fragment)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def _section_html(text: str, section_id: str) -> str:
    pattern = rf'<section\b[^>]*\bid="{re.escape(section_id)}"[\s\S]*?(?=<section\b[^>]*\bid="(?:decrypt-audit|tianqing-audit|plm-login-audit)"|<footer\b|</main>)'
    match = re.search(pattern, text, flags=re.IGNORECASE)
    return match.group(0) if match else ""


def _first_conclusion_text(section: str, fallback: str) -> str:
    match = re.search(r"<li\b[^>]*>([\s\S]*?)</li>", section, flags=re.IGNORECASE)
    if not match:
        match = re.search(r"<p\b[^>]*>([\s\S]*?)</p>", section, flags=re.IGNORECASE)
    if not match:
        return fallback
    return _html_plain_text(match.group(1)) or fallback


def _first_regex_value(pattern: str, text: str, default: str = "-") -> str:
    match = re.search(pattern, text, flags=re.IGNORECASE)
    return match.group(1) if match else default


def _first_regex_int(pattern: str, text: str, default: int = 0, group: int = 1) -> int:
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if not match:
        return default
    try:
        return int(match.group(group))
    except (IndexError, TypeError, ValueError):
        return default


def _fallback_decrypt_management_metrics(text: str) -> dict[str, Any]:
    decrypt_section = _section_html(text, "decrypt-audit")
    decrypt_plain = _html_plain_text(decrypt_section)
    decrypt_standard = _first_regex_int(r"标准图纸\s*(\d+)\s*条", decrypt_plain)
    if not decrypt_standard:
        decrypt_standard = _first_regex_int(r"标准图纸解密总数\s*(\d+)", decrypt_plain)
    return {
        "standard": decrypt_standard,
        "structure": _first_regex_int(r"结构\s*(\d+)", decrypt_plain),
        "electrical": _first_regex_int(r"电气\s*(\d+)", decrypt_plain),
    }


def _fallback_tianqing_management_metrics(text: str) -> dict[str, Any]:
    tianqing_section = _section_html(text, "tianqing-audit")
    tianqing_plain = _html_plain_text(tianqing_section)
    structure = _first_regex_int(r"结构(?:标准方案)?\s*(\d+)", tianqing_plain)
    electrical = _first_regex_int(r"电气(?:标准方案)?\s*(\d+)", tianqing_plain)
    large_archive = _first_regex_int(r"(?:大于100MB|超过100MB|>100MB)\s*压缩包\s*(\d+)", tianqing_plain)
    standard = structure + electrical
    return {
        "critical_design": standard,
        "critical_structure": structure,
        "critical_electrical": electrical,
        "critical_large_archive": large_archive,
        "level_one": standard + large_archive,
    }


def _tianqing_array_pattern_condition(label: str) -> str:
    conditions: list[str] = []
    base_expr = "replaceRegexpOne(lowerUTF8(name), '^.*[\\\\\\\\/]', '')"
    for pattern in report_gen.CRITICAL_DESIGN_PATTERNS:
        if str(pattern.get("label") or "").strip() != label:
            continue
        regex = str(pattern.get("regex") or "").strip()
        if regex:
            conditions.append(f"arrayExists(name -> match({base_expr}, {report_gen.clickhouse_literal(regex.lower())}), file_names)")
    if not conditions:
        return "0"
    return "(" + " OR ".join(f"({condition})" for condition in conditions) + ")"


def _tianqing_archive_condition() -> str:
    archive_exts = sorted({str(item or "").strip().lower().lstrip(".") for item in report_gen.ARCHIVE_EXTS if str(item or "").strip()})
    if not archive_exts:
        return "0"
    literal = report_gen.clickhouse_array_literal(archive_exts)
    return (
        f"hasAny(arrayMap(ext -> lowerUTF8(ext), file_exts), {literal}) "
        f"OR arrayExists(name -> has({literal}, replaceRegexpOne(lowerUTF8(name), '^.*\\\\.', '')), file_names)"
    )


def _live_tianqing_management_metrics(config: AppConfig, start: datetime, end: datetime) -> dict[str, Any] | None:
    if not config.use_clickhouse:
        return None
    try:
        args, _tz, _internal_domains = live_decrypt_policy_context(config)
        event_where = report_gen.clickhouse_event_filter(start, end)
        structure_cond = _tianqing_array_pattern_condition(report_gen.CRITICAL_STRUCTURE_LABEL)
        electrical_cond = _tianqing_array_pattern_condition(report_gen.CRITICAL_ELECTRICAL_LABEL)
        standard_cond = f"(({structure_cond}) OR ((NOT ({structure_cond})) AND ({electrical_cond})))"
        large_archive_cond = f"(({_tianqing_archive_condition()}) AND ifNull(file_size, 0) > {report_gen.LARGE_ARCHIVE_RISK_BYTES})"
        query = f"""
SELECT
  countIf({standard_cond}) AS critical_design,
  countIf({structure_cond}) AS critical_structure,
  countIf((NOT ({structure_cond})) AND ({electrical_cond})) AS critical_electrical,
  countIf({large_archive_cond}) AS critical_large_archive,
  countIf(({standard_cond}) OR ({large_archive_cond})) AS level_one
FROM audit_events
WHERE {event_where}
FORMAT JSONEachRow
"""
        text = report_gen.clickhouse_query(args, query)
        row = json.loads(text.splitlines()[0]) if text.strip() else {}
    except Exception:
        return None
    return {
        "critical_design": int(row.get("critical_design") or 0),
        "critical_structure": int(row.get("critical_structure") or 0),
        "critical_electrical": int(row.get("critical_electrical") or 0),
        "critical_large_archive": int(row.get("critical_large_archive") or 0),
        "level_one": int(row.get("level_one") or 0),
    }


def _live_decrypt_management_metrics(config: AppConfig, start: datetime, end: datetime) -> dict[str, Any] | None:
    try:
        counts = live_decrypt_summary_counts(config, start, end)
    except Exception:
        return None
    return {
        "records": int(counts.get("records") or 0),
        "standard": int(counts.get("standard") or 0),
        "structure": int(counts.get("structure") or 0),
        "electrical": int(counts.get("electrical") or 0),
    }


def _terminal_review_management_metrics(config: AppConfig, start: datetime, end: datetime) -> dict[str, int]:
    try:
        reviews = terminal_review.fetch_reviews(config, start, end, include_all_status=False)
    except Exception:
        return {"total": 0, "pending": 0, "reviewed": 0}
    pending = sum(1 for review in reviews if str(review.status or "").strip() == "待核查")
    return {"total": len(reviews), "pending": pending, "reviewed": max(len(reviews) - pending, 0)}


def global_management_summary_style() -> str:
    return """
<style id="global-management-summary-style">
  .global-management-summary {
    position: relative;
    overflow: hidden;
    margin-top: 28px;
    border: 1px solid rgba(18, 32, 51, 0.10);
    border-radius: 18px;
    padding: 22px;
    background: radial-gradient(circle at 92% 4%, rgba(23, 92, 211, 0.12) 0, transparent 32%), linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
    box-shadow: 0 14px 34px rgba(16, 24, 40, 0.08);
  }
  .global-management-summary::before {
    content: "";
    position: absolute;
    inset: 0 auto 0 0;
    width: 5px;
    background: linear-gradient(180deg, #7c3aed, #245edb, #08746f);
  }
  .global-management-head {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 18px;
    margin-bottom: 16px;
  }
  .global-management-head h2 {
    margin: 3px 0 0;
    color: #122033;
    font-size: 24px;
    font-weight: 900;
    letter-spacing: 0;
  }
  .global-management-head p {
    max-width: 880px;
    margin: 0;
    color: #475467;
    font-size: 14px;
    font-weight: 720;
    line-height: 1.75;
  }
  .management-summary-list { display: grid; gap: 10px; }
  .management-summary-row {
    display: grid;
    grid-template-columns: 150px minmax(0, 1fr);
    align-items: center;
    gap: 14px;
    min-height: 54px;
    border: 1px solid #dbe6f3;
    border-radius: 12px;
    padding: 12px 15px;
    color: #122033;
    background: #fff;
    box-shadow: 0 8px 18px rgba(18, 32, 51, 0.045);
    text-decoration: none;
  }
  .management-summary-row:hover { border-color: #93c5fd; box-shadow: 0 10px 22px rgba(18, 32, 51, 0.065); }
  .management-summary-row span {
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
  }
  .management-summary-row p {
    margin: 0;
    color: #344054;
    font-size: 15px;
    font-weight: 780;
    line-height: 1.6;
  }
  .management-summary-row-decrypt span { background: #f5f3ff; color: #6d28d9; }
  .management-summary-row-tianqing span { background: #ecfdf3; color: #08746f; }
  .management-summary-row-plm span { background: #fffbeb; color: #b45309; }
  .management-summary-row-review span { background: #eef4ff; color: #175cd3; }
  @media (max-width: 900px) {
    .global-management-head { flex-direction: column; align-items: flex-start; }
    .management-summary-row { grid-template-columns: 1fr; align-items: flex-start; }
  }
</style>
"""


def inject_global_management_summary(data: bytes, config: AppConfig | None = None, target: Path | None = None) -> bytes:
    text = data.decode("utf-8", errors="replace")
    if 'id="decrypt-audit"' not in text and 'id="tianqing-audit"' not in text:
        return data

    period = report_period_for_html_or_path(config, target, data) if config is not None else None
    decrypt_metrics = _fallback_decrypt_management_metrics(text)
    if config is not None and period:
        live_metrics = _live_decrypt_management_metrics(config, period[0], period[1])
        if live_metrics:
            decrypt_metrics = live_metrics
    tianqing_metrics = _fallback_tianqing_management_metrics(text)
    review_metrics = (
        _terminal_review_management_metrics(config, period[0], period[1])
        if config is not None and period
        else {"total": 0, "pending": 0, "reviewed": 0}
    )
    block = report_gen.build_global_management_summary_html(
        decrypt_metrics,
        tianqing_metrics,
        {"enabled": False},
        review_metrics,
    )
    if period:
        block = block.replace('href="/terminal-check"', f'href="{esc(terminal_check_period_url(period[0], period[1]))}"')
    existing_match = re.search(
        r'<section\b[^>]*\bid="global-management-summary"[\s\S]*?(?=<section\b[^>]*\bid="(?:decrypt-audit|tianqing-audit|plm-login-audit)"|<footer\b|</main>)',
        text,
        flags=re.IGNORECASE,
    )
    marker_match = re.search(r'<section\b[^>]*\bid="(?:decrypt-audit|tianqing-audit)"', text, flags=re.IGNORECASE)
    if not existing_match and not marker_match:
        return data
    if existing_match:
        text = text[: existing_match.start()] + block + "\n" + text[existing_match.end() :]
    else:
        idx = marker_match.start()
        text = text[:idx] + block + "\n" + text[idx:]
    if "global-management-summary-style" not in text:
        style = global_management_summary_style()
        if re.search(r"</head>", text, flags=re.IGNORECASE):
            text = re.sub(r"</head>", style + r"\g<0>", text, count=1, flags=re.IGNORECASE)
        else:
            text = style + text
    return text.encode("utf-8")


def report_period_for_static_path(config: AppConfig, target: Path) -> tuple[datetime, datetime] | None:
    target = target.resolve()
    for item in read_report_archives(config):
        rel_path = str(item.get("path") or "")
        path = (config.report_dir / rel_path).resolve()
        if path != target:
            continue
        start_text = str(item.get("period_start") or "").strip()
        end_text = str(item.get("period_end") or "").strip()
        if not start_text or not end_text:
            return None
        try:
            return parse_local_datetime(start_text, config.timezone), parse_local_datetime(end_text, config.timezone)
        except ValueError:
            return None
    return None


def archive_dropdown_label(entry: dict[str, Any]) -> str:
    period = str(entry.get("period") or "报告")
    report_range = str(entry.get("report_range") or "").strip()
    return report_range or period


def home_history_dropdown_html(config: AppConfig, session: AuthSession) -> str:
    entries = report_archive_entries(config, session)
    grouped: dict[str, list[dict[str, Any]]] = {"日报": [], "周报": []}
    other_entries: list[dict[str, Any]] = []
    for entry in entries:
        href = str(entry.get("href") or "")
        if not href:
            continue
        period = str(entry.get("period") or "")
        if period in grouped:
            grouped[period].append(entry)
        else:
            other_entries.append(entry)
    grouped["日报"] = grouped["日报"][:7]
    grouped["周报"] = grouped["周报"][:4]
    options = ['<option value="" selected hidden>历史报告</option>']
    for group_name in ("日报", "周报"):
        group_items = []
        for entry in grouped[group_name]:
            href = str(entry.get("href") or "")
            label = archive_dropdown_label(entry)
            group_items.append(f'<option value="{esc(href)}">{esc(label)}</option>')
        if group_items:
            options.append(f'<optgroup label="{esc(group_name)}">{"".join(group_items)}</optgroup>')
    for entry in other_entries:
        href = str(entry.get("href") or "")
        label = f"{entry.get('period') or '报告'} {archive_dropdown_label(entry)}".strip()
        options.append(f'<option value="{esc(href)}">{esc(label)}</option>')
    options.append('<option value="/reports">查看全部历史报告...</option>')
    disabled = " disabled" if len(options) <= 2 and not entries else ""
    return f"""
<style id="tq-home-history-style">
  .tq-home-history {{
    display: inline-flex;
    align-items: center;
    min-height: 38px;
    border: 1px solid #175cd3;
    border-radius: 999px;
    padding: 0 12px;
    background: #175cd3;
    color: #fff;
    box-shadow: 0 9px 20px rgba(23, 92, 211, 0.16);
  }}
  .tq-home-history select {{
    min-width: 178px;
    max-width: 280px;
    min-height: 34px;
    border: 0;
    outline: 0;
    background: transparent;
    color: #fff;
    font: inherit;
    font-size: 13px;
    font-weight: 850;
    cursor: pointer;
    appearance: auto;
  }}
  .tq-home-history select:disabled {{
    cursor: default;
    opacity: 0.72;
  }}
  .tq-home-history select option {{
    color: #172033;
    background: #fff;
    font-weight: 700;
  }}
  .tq-home-history select optgroup {{
    color: #667085;
    background: #f8fbff;
    font-weight: 850;
  }}
</style>
<span class="tq-home-history">
  <select id="tq-home-history-select" aria-label="选择历史报告"{disabled}>
    {"".join(options)}
  </select>
</span>
<script id="tq-home-history-script">
  (function () {{
    var select = document.getElementById("tq-home-history-select");
    if (!select || select.getAttribute("data-bound") === "1") return;
    select.setAttribute("data-bound", "1");
    select.addEventListener("change", function () {{
      if (select.value) {{
        window.location.href = select.value;
      }}
    }});
  }})();
</script>
"""


def inject_home_history_dropdown(data: bytes, config: AppConfig, session: AuthSession | None) -> bytes:
    if not session:
        return data
    text = data.decode("utf-8", errors="replace")
    if "tq-home-history-select" in text or "top-actions" not in text:
        return data
    dropdown = home_history_dropdown_html(config, session)
    updated = re.sub(
        r'<a\s+class="top-action\s+primary"\s+href="[^"]*/reports">历史报告</a>',
        lambda match: dropdown,
        text,
        count=1,
        flags=re.IGNORECASE,
    )
    if updated == text:
        updated = re.sub(
            r'(<div\s+class="top-actions"\s*>)',
            lambda match: match.group(1) + dropdown,
            text,
            count=1,
            flags=re.IGNORECASE,
        )
    return updated.encode("utf-8") if updated != text else data


def event_table_sort_assets() -> str:
    return r"""
<style id="tq-event-sorter-style">
  table.events th[data-sortable="1"] {
    position: relative;
    cursor: pointer;
    user-select: none;
    padding-right: 24px;
  }
  table.events th[data-sortable="1"]::after {
    content: "↕";
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
    color: #98a2b3;
    font-size: 11px;
    font-weight: 900;
  }
  table.events th[data-sortable="1"].sort-asc,
  table.events th[data-sortable="1"].sort-desc {
    color: #175cd3;
    background: #eef4ff;
  }
  table.events th[data-sortable="1"].sort-asc::after {
    content: "↑";
    color: #175cd3;
  }
  table.events th[data-sortable="1"].sort-desc::after {
    content: "↓";
    color: #175cd3;
  }
  .tq-sort-pager {
    flex-wrap: wrap;
    gap: 8px 10px;
  }
  .tq-sort-pager .pager-size {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin-right: auto;
    color: #667085;
    font-size: 12px;
    font-weight: 700;
  }
  .tq-sort-pager .pager-size select {
    min-height: 28px;
    border: 1px solid #d9e0ea;
    border-radius: 6px;
    background: #fff;
    color: #172033;
    padding: 3px 24px 3px 8px;
    font: inherit;
    font-weight: 800;
  }
</style>
<script id="tq-event-sorter">
  (function () {
    function textOfCell(row, index) {
      var cell = row.children[index];
      if (!cell) {
        return "";
      }
      return (cell.getAttribute("data-sort-value") || cell.textContent || "").trim();
    }

    function parseDateValue(text) {
      var match = String(text || "").match(/(\d{4})[-\/](\d{1,2})[-\/](\d{1,2})(?:[ T](\d{1,2}):(\d{1,2})(?::(\d{1,2}))?)?/);
      if (!match) {
        return null;
      }
      var year = Number(match[1]);
      var month = Number(match[2]) - 1;
      var day = Number(match[3]);
      var hour = Number(match[4] || 0);
      var minute = Number(match[5] || 0);
      var second = Number(match[6] || 0);
      return new Date(year, month, day, hour, minute, second).getTime();
    }

    function parseSizeMb(text) {
      var value = String(text || "").trim().toLowerCase();
      if (!value || value === "-" || value === "unknown" || value === "未知") {
        return null;
      }
      if (/^<\s*1\s*mb$/.test(value)) {
        return 0.5;
      }
      if (/^1\s*-\s*10\s*mb$/.test(value)) {
        return 5;
      }
      if (/^10\s*-\s*50\s*mb$/.test(value)) {
        return 30;
      }
      if (/^(>|>=)\s*50\s*mb$/.test(value)) {
        return 50;
      }
      var match = value.replace(/,/g, "").match(/([\d.]+)\s*(b|kb|k|mb|m|gb|g|tb|t)?/);
      if (!match) {
        return null;
      }
      var number = Number(match[1]);
      if (!isFinite(number)) {
        return null;
      }
      var unit = match[2] || "mb";
      if (unit === "b") {
        return number / 1024 / 1024;
      }
      if (unit === "kb" || unit === "k") {
        return number / 1024;
      }
      if (unit === "gb" || unit === "g") {
        return number * 1024;
      }
      if (unit === "tb" || unit === "t") {
        return number * 1024 * 1024;
      }
      return number;
    }

    function parseNumberValue(text) {
      var normalized = String(text || "").replace(/,/g, "").replace(/%$/, "").trim();
      if (!normalized || normalized === "-") {
        return null;
      }
      if (!/^-?\d+(?:\.\d+)?$/.test(normalized)) {
        return null;
      }
      var number = Number(normalized);
      return isFinite(number) ? number : null;
    }

    function valueFor(text, header) {
      var cleanText = String(text || "").trim();
      var cleanHeader = String(header || "").trim();
      if (!cleanText || cleanText === "-") {
        return {type: "empty", value: null};
      }
      if (/时间|日期/.test(cleanHeader)) {
        var dateValue = parseDateValue(cleanText);
        if (dateValue !== null) {
          return {type: "number", value: dateValue};
        }
      }
      if (/大小|容量/.test(cleanHeader)) {
        var sizeValue = parseSizeMb(cleanText);
        if (sizeValue !== null) {
          return {type: "number", value: sizeValue};
        }
      }
      var numberValue = parseNumberValue(cleanText);
      if (numberValue !== null) {
        return {type: "number", value: numberValue};
      }
      var fallbackDate = parseDateValue(cleanText);
      if (fallbackDate !== null && /^\d{4}[-\/]\d{1,2}[-\/]\d{1,2}/.test(cleanText)) {
        return {type: "number", value: fallbackDate};
      }
      return {type: "text", value: cleanText.toLocaleLowerCase("zh-CN")};
    }

    function compareValues(a, b, direction) {
      if (a.type === "empty" && b.type === "empty") {
        return 0;
      }
      if (a.type === "empty") {
        return 1;
      }
      if (b.type === "empty") {
        return -1;
      }
      var result = 0;
      if (a.type === "number" && b.type === "number") {
        result = a.value === b.value ? 0 : (a.value > b.value ? 1 : -1);
      } else {
        result = String(a.value).localeCompare(String(b.value), "zh-CN", {numeric: true, sensitivity: "base"});
      }
      return direction === "desc" ? -result : result;
    }

    function removeExistingPager(wrap) {
      var next = wrap ? wrap.nextElementSibling : null;
      if (next && next.classList && next.classList.contains("pager")) {
        next.parentElement.removeChild(next);
      }
    }

    function makePager(wrap, table, pageSize) {
      var tbody = table.tBodies[0];
      if (!wrap || !tbody || !pageSize) {
        return {render: function () {}};
      }
      var pageSizeOptions = [20, 50, 100];
      if (pageSizeOptions.indexOf(pageSize) === -1) {
        pageSizeOptions.unshift(pageSize);
      }
      removeExistingPager(wrap);
      var state = {page: 0};
      var pager = document.createElement("div");
      pager.className = "pager tq-sort-pager";
      var sizeWrap = document.createElement("label");
      sizeWrap.className = "pager-size";
      var sizeLabel = document.createElement("span");
      sizeLabel.textContent = "每页";
      var sizeSelect = document.createElement("select");
      pageSizeOptions.forEach(function (option) {
        var item = document.createElement("option");
        item.value = String(option);
        item.textContent = option + " 条";
        if (option === pageSize) {
          item.selected = true;
        }
        sizeSelect.appendChild(item);
      });
      sizeWrap.appendChild(sizeLabel);
      sizeWrap.appendChild(sizeSelect);
      var prev = document.createElement("button");
      prev.type = "button";
      prev.textContent = "上一页";
      var label = document.createElement("span");
      label.className = "pager-label";
      var next = document.createElement("button");
      next.type = "button";
      next.textContent = "下一页";
      pager.appendChild(sizeWrap);
      pager.appendChild(prev);
      pager.appendChild(label);
      pager.appendChild(next);
      wrap.insertAdjacentElement("afterend", pager);

      function render(reset) {
        var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
        if (reset) {
          state.page = 0;
        }
        var pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
        if (state.page >= pageCount) {
          state.page = pageCount - 1;
        }
        rows.forEach(function (row, idx) {
          row.style.display = idx >= state.page * pageSize && idx < (state.page + 1) * pageSize ? "" : "none";
        });
        label.textContent = "第 " + (state.page + 1) + " / " + pageCount + " 页，共 " + rows.length + " 条";
        prev.disabled = state.page <= 0;
        next.disabled = state.page >= pageCount - 1;
      }

      prev.addEventListener("click", function () {
        if (state.page > 0) {
          state.page -= 1;
          render(false);
        }
      });
      next.addEventListener("click", function () {
        var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
        var pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
        if (state.page < pageCount - 1) {
          state.page += 1;
          render(false);
        }
      });
      sizeSelect.addEventListener("change", function () {
        var nextPageSize = parseInt(sizeSelect.value || String(pageSize), 10);
        if (nextPageSize && nextPageSize !== pageSize) {
          pageSize = nextPageSize;
          render(true);
        }
      });
      render(true);
      return {render: render};
    }

    function setupEventTable(table) {
      if (!table || table.getAttribute("data-tq-sort-ready") === "1") {
        return;
      }
      var tbody = table.tBodies[0];
      var headerRow = table.querySelector("thead tr:last-child");
      if (!tbody || !headerRow) {
        return;
      }
      var headers = Array.prototype.slice.call(headerRow.children);
      if (!headers.length) {
        return;
      }
      table.setAttribute("data-tq-sort-ready", "1");
      Array.prototype.forEach.call(tbody.querySelectorAll("tr"), function (row, idx) {
        row.setAttribute("data-original-index", String(idx));
      });

      var wrap = table.closest(".table-wrap");
      var pageSize = wrap ? parseInt(wrap.getAttribute("data-page-size") || "0", 10) : 0;
      var pager = pageSize && tbody.rows.length > pageSize ? makePager(wrap, table, pageSize) : {render: function () {}};

      headers.forEach(function (th, columnIndex) {
        if (!th || th.colSpan > 1 || th.rowSpan > 1) {
          return;
        }
        th.setAttribute("data-sortable", "1");
        th.setAttribute("tabindex", "0");
        th.setAttribute("role", "button");
        th.title = th.title ? th.title + "，点击排序" : "点击排序";
        function sortColumn() {
          var current = th.classList.contains("sort-asc") ? "asc" : (th.classList.contains("sort-desc") ? "desc" : "");
          var direction = current === "asc" ? "desc" : "asc";
          headers.forEach(function (other) {
            other.classList.remove("sort-asc", "sort-desc");
            other.removeAttribute("aria-sort");
          });
          th.classList.add(direction === "asc" ? "sort-asc" : "sort-desc");
          th.setAttribute("aria-sort", direction === "asc" ? "ascending" : "descending");
          var headerText = th.textContent || "";
          var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
          rows.sort(function (rowA, rowB) {
            var valueA = valueFor(textOfCell(rowA, columnIndex), headerText);
            var valueB = valueFor(textOfCell(rowB, columnIndex), headerText);
            var result = compareValues(valueA, valueB, direction);
            if (result !== 0) {
              return result;
            }
            return Number(rowA.getAttribute("data-original-index") || 0) - Number(rowB.getAttribute("data-original-index") || 0);
          });
          rows.forEach(function (row) {
            tbody.appendChild(row);
          });
          pager.render(true);
        }
        th.addEventListener("click", sortColumn);
        th.addEventListener("keydown", function (event) {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            sortColumn();
          }
        });
      });
    }

    function setupSortableEventTables() {
      Array.prototype.forEach.call(document.querySelectorAll("table.events"), setupEventTable);
    }

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", setupSortableEventTables);
    } else {
      setupSortableEventTables();
    }
  })();
</script>
"""


def inject_event_table_sorting(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="replace")
    if "tq-event-sorter" in text or "table" not in text or "events" not in text:
        return data
    assets = event_table_sort_assets()
    if re.search(r"</body\s*>", text, flags=re.IGNORECASE):
        text = re.sub(r"</body\s*>", lambda match: assets + match.group(0), text, count=1, flags=re.IGNORECASE)
    else:
        text += assets
    return text.encode("utf-8")


def suppress_static_ai_section(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="replace")
    if 'id="ai-analysis"' not in text and "id='ai-analysis'" not in text:
        return data
    text = re.sub(
        r"\n?\s*<section\b[^>]*\bid=[\"']ai-analysis[\"'][\s\S]*?</section>\s*",
        "\n",
        text,
        count=1,
        flags=re.IGNORECASE,
    )
    text = text.replace("首页按 AI 研判、风险趋势、", "首页按风险趋势、")
    text = text.replace("首页按 AI 研判、外发通道矩阵、", "首页按外发通道矩阵、")
    return text.encode("utf-8")


def auth_policy(config: AppConfig) -> dict[str, Any]:
    doc = load_policy_doc(config)
    auth = doc.get("auth") if isinstance(doc.get("auth"), dict) else {}
    return {
        "policy_admin_userids": policy_userid_list(auth.get("policy_admin_userids"), DEFAULT_POLICY_ADMIN_USERIDS),
        "global_viewer_userids": policy_userid_list(auth.get("global_viewer_userids")),
        "session_hours": max(1, min(24, clamp_int(str(auth.get("session_hours", 8)), 8, 1, 24))),
    }


def role_for_user(config: AppConfig, userid: str, company: str, status: str) -> str:
    policy = auth_policy(config)
    if userid == FIXED_POLICY_ADMIN_USERID:
        return "admin"
    if userid in set(policy["global_viewer_userids"]):
        return "global"
    return ""


def session_is_allowed(config: AppConfig, session: AuthSession) -> bool:
    session.role = role_for_user(config, session.userid, session.company, session.status)
    return bool(session.role)


def command_for_job(config: AppConfig, job: Job, output_path: Path) -> list[str]:
    cmd = [
        config.python,
        str(config.app_dir / "tianqing_external_audit_report.py"),
        "--start",
        job.start_text,
        "--end",
        job.end_text,
        "--format",
        "html",
        "--wecom-directory-authoritative",
        "--people-map",
        str(config.app_dir / "people_mapping.csv"),
        "--recipient-map",
        str(config.app_dir / "recipient_mapping.csv"),
        "--disposition-file",
        str(config.app_dir / "audit_dispositions.csv"),
        "--sensitive-keywords-file",
        str(config.keywords_file),
        "--audit-policy-file",
        str(config.policy_file),
        "--exclusion-file",
        str(config.exclusions_file),
        "--wecom-directory-cache",
        str(config.app_dir / "wecom_directory_cache.json"),
        "--output",
        str(output_path),
    ]
    if config.use_clickhouse:
        cmd.extend(
            [
                "--use-clickhouse",
                "--clickhouse-url",
                config.clickhouse_url,
                "--clickhouse-database",
                config.clickhouse_database,
                "--clickhouse-timeout",
                str(config.clickhouse_timeout),
            ]
        )
    else:
        cmd.extend(["--local-log", str(config.log_file)])
    return cmd


def ingest_command(config: AppConfig) -> list[str]:
    return [
        config.python,
        str(config.app_dir / "tianqing_clickhouse_ingest.py"),
        "--log-file",
        str(config.log_file),
        "--clickhouse-url",
        config.clickhouse_url,
        "--clickhouse-database",
        config.clickhouse_database,
        "--timeout",
        str(config.clickhouse_timeout),
        "--audit-policy-file",
        str(config.policy_file),
    ]


def run_job(config: AppConfig, job: Job) -> None:
    output_path = config.report_dir / job.output_name
    log_path = config.report_dir / "jobs" / job.log_name
    command = command_for_job(config, job, output_path)
    env = os.environ.copy()
    env["CLICKHOUSE_URL"] = config.clickhouse_url
    env["CLICKHOUSE_DB"] = config.clickhouse_database
    if config.clickhouse_user:
        env["CLICKHOUSE_USER"] = config.clickhouse_user
    if config.clickhouse_password:
        env["CLICKHOUSE_PASSWORD"] = config.clickhouse_password
    env["PYTHONUNBUFFERED"] = "1"
    with log_path.open("w", encoding="utf-8") as log:
        log.write(f"job_id={job.job_id}\n")
        log.write(f"created_at={datetime.now().isoformat(timespec='seconds')}\n")
        log.write(f"range={job.start_text} -> {job.end_text}\n")
        log.write("mode=rule-overview\n\n")
        log.flush()
        try:
            if config.use_clickhouse and job.refresh_clickhouse:
                log.write("report_query_source=clickhouse\n")
                log.write(f"raw_log_ingest_source={config.log_file}\n")
                log.write("refresh_clickhouse_index=on\n")
                log.flush()
                ingest = subprocess.run(
                    ingest_command(config),
                    cwd=str(config.app_dir),
                    env=env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=60 * 20,
                    check=False,
                )
                if ingest.returncode != 0:
                    job.return_code = ingest.returncode
                    job.status = "failed"
                    job.error = f"入库刷新失败，退出码 {ingest.returncode}。"
                    return
                log.write("\n")
            elif config.use_clickhouse:
                log.write("report_query_source=clickhouse\n")
                log.write("refresh_clickhouse_index=skipped\n\n")
            else:
                log.write("report_query_source=raw-log\n\n")
            completed = subprocess.run(
                command,
                cwd=str(config.app_dir),
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60 * 45,
                check=False,
            )
            job.return_code = completed.returncode
            if completed.returncode == 0 and output_path.exists():
                job.status = "done"
                for path in config.report_dir.glob(f"{output_path.stem}*.html"):
                    try:
                        path.chmod(0o644)
                    except OSError:
                        pass
            else:
                job.status = "failed"
                job.error = f"生成失败，退出码 {completed.returncode}。"
        except subprocess.TimeoutExpired:
            job.status = "failed"
            job.error = "生成超时，已中止。"
        except Exception as exc:  # pragma: no cover - defensive service boundary.
            job.status = "failed"
            job.error = f"生成异常：{exc}"
        finally:
            job.finished_at = time.time()
            log.write(f"\nfinished_at={datetime.now().isoformat(timespec='seconds')}\n")
            log.write(f"status={job.status}\n")
            if job.error:
                log.write(f"error={job.error}\n")
            RUN_LOCK.release()


def tail_text(path: Path, limit: int = 6000) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return data[-limit:].decode("utf-8", errors="replace")


def cleanup_temporary_reports(config: AppConfig) -> None:
    now = time.time()
    custom_cutoff = now - max(1, CUSTOM_REPORT_TTL_DAYS) * 86400
    log_cutoff = now - max(1, JOB_LOG_TTL_DAYS) * 86400
    try:
        custom_paths = list(config.report_dir.glob("tianqing_custom_*.html"))
    except OSError:
        custom_paths = []
    for path in custom_paths:
        try:
            if path.is_file() and path.stat().st_mtime < custom_cutoff:
                path.unlink()
        except OSError:
            pass
    jobs_dir = config.report_dir / "jobs"
    try:
        job_logs = list(jobs_dir.glob("*.log"))
    except OSError:
        job_logs = []
    for path in job_logs:
        try:
            if path.is_file() and path.stat().st_mtime < log_cutoff:
                path.unlink()
        except OSError:
            pass


def temporary_report_group(path: Path) -> tuple[str, str] | None:
    match = TEMP_REPORT_GROUP_RE.match(path.name)
    if not match:
        return None
    return match.group("stem"), match.group("job_id")


def session_can_access_report_path(config: AppConfig, session: AuthSession, target: Path) -> bool:
    try:
        target.resolve().relative_to(config.report_dir.resolve())
    except ValueError:
        return False
    return True


def is_ai_detail_report_path(target: Path) -> bool:
    return bool(AI_DETAIL_REPORT_RE.search(target.name))


def cleanup_temporary_report(config: AppConfig, session: AuthSession, rel_path: str) -> int:
    raw = str(rel_path or "").strip().lstrip("/")
    if not raw or ".." in Path(raw).parts:
        return 0
    target = (config.report_dir / raw).resolve()
    try:
        target.relative_to(config.report_dir.resolve())
    except ValueError:
        return 0
    if not session_can_access_report_path(config, session, target):
        return 0
    group = temporary_report_group(target)
    if not group:
        return 0
    stem, job_id = group
    deleted = 0
    try:
        candidates = list(target.parent.glob(f"{stem}*.html"))
    except OSError:
        candidates = []
    for path in candidates:
        if temporary_report_group(path) != group:
            continue
        try:
            if path.is_file():
                path.unlink()
                deleted += 1
        except OSError:
            pass
    log_path = config.report_dir / "jobs" / f"{job_id}.log"
    try:
        if log_path.is_file() and job_id not in running_report_job_ids(config):
            log_path.unlink()
    except OSError:
        pass
    with JOBS_LOCK:
        JOBS.pop(job_id, None)
    return deleted


def temporary_report_cleanup_script(rel_path: str, stem: str) -> str:
    return f"""
<script id="tq-temp-report-cleanup">
  (function () {{
    var reportPath = {json.dumps(rel_path, ensure_ascii=False)};
    var groupStem = {json.dumps(stem, ensure_ascii=False)};
    var internalReportNav = false;
    document.addEventListener("click", function (event) {{
      var node = event.target;
      while (node && node.tagName !== "A") node = node.parentElement;
      if (!node || !node.href) return;
      try {{
        var url = new URL(node.href, window.location.href);
        var name = decodeURIComponent((url.pathname.split("/").pop() || ""));
        if (url.origin === window.location.origin && name.indexOf(groupStem) === 0) {{
          internalReportNav = true;
        }}
      }} catch (err) {{}}
    }}, true);
    function cleanup() {{
      if (internalReportNav) return;
      var body = "path=" + encodeURIComponent(reportPath);
      if (navigator.sendBeacon) {{
        navigator.sendBeacon("/api/temporary-report/cleanup", new Blob([body], {{type: "application/x-www-form-urlencoded"}}));
      }} else {{
        fetch("/api/temporary-report/cleanup", {{
          method: "POST",
          credentials: "same-origin",
          keepalive: true,
          headers: {{"Content-Type": "application/x-www-form-urlencoded"}},
          body: body
        }}).catch(function () {{}});
      }}
    }}
    window.addEventListener("pagehide", function (event) {{
      if (event.persisted) return;
      cleanup();
    }});
  }})();
</script>
"""


def temporary_report_cleanup_script_for_path(config: AppConfig, output: Path | None) -> str:
    if not output:
        return ""
    group = temporary_report_group(output)
    if not group:
        return ""
    stem, _ = group
    try:
        rel_path = output.resolve().relative_to(config.report_dir.resolve()).as_posix()
    except ValueError:
        return ""
    return temporary_report_cleanup_script(rel_path, stem)


def inject_temporary_report_cleanup(data: bytes, config: AppConfig, target: Path) -> bytes:
    group = temporary_report_group(target)
    if not group:
        return data
    stem, _ = group
    try:
        rel_path = target.resolve().relative_to(config.report_dir.resolve()).as_posix()
    except ValueError:
        return data
    text = data.decode("utf-8", errors="replace")
    if "tq-temp-report-cleanup" in text:
        return data
    script = temporary_report_cleanup_script(rel_path, stem)
    if re.search(r"</body>", text, flags=re.IGNORECASE):
        text = re.sub(r"</body>", script + r"\g<0>", text, count=1, flags=re.IGNORECASE)
    else:
        text += script
    return text.encode("utf-8")


def report_url_for_path(config: AppConfig, path: Path) -> str:
    try:
        rel = path.resolve().relative_to(config.report_dir.resolve())
    except ValueError:
        return "#"
    return "/" + quote(rel.as_posix())


def report_size_text(path: Path) -> str:
    try:
        size = path.stat().st_size
    except OSError:
        return "-"
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f}{unit}" if unit != "B" else f"{int(value)}B"
        value /= 1024
    return f"{size}B"


def parse_stamp_text(value: str) -> str:
    try:
        return datetime.strptime(value, "%Y%m%d-%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


def compact_archive_datetime(value: str) -> str:
    text = str(value or "").strip().replace("T", " ")
    text = re.sub(r"\+\d{2}:?\d{2}$", "", text).strip()
    return text[:19] if text else ""


def report_archive_index_path(config: AppConfig) -> Path:
    return config.report_dir / REPORT_ARCHIVE_INDEX


def read_report_archives(config: AppConfig) -> list[dict[str, Any]]:
    path = report_archive_index_path(config)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    entries: list[dict[str, Any]] = []
    for line in lines:
        text = line.strip()
        if not text:
            continue
        try:
            item = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        rel_path = str(item.get("path") or "").strip().lstrip("/")
        if not rel_path or ".." in Path(rel_path).parts:
            continue
        item["path"] = rel_path
        entries.append(item)
    return entries


def archive_period_label(period: str) -> str:
    return {
        "previous-day": "日报",
        "today": "当日日报",
        "current-week": "周报",
        "previous-week": "周报",
    }.get(period, period)


def archive_report_range_label(item: dict[str, Any]) -> str:
    period = str(item.get("period") or "")
    start = compact_archive_datetime(str(item.get("period_start") or ""))
    end = compact_archive_datetime(str(item.get("period_end") or ""))
    if period in {"previous-day", "today"} and start:
        return start[:10]
    if period in {"current-week", "previous-week"} and end:
        return end[:10]
    if start and end:
        return f"{start[:16]} 至 {end[:16]}"
    if start:
        return start[:16]
    return parse_stamp_text(str(item.get("stamp") or ""))


def archive_entry_unique_key(item: dict[str, Any], scope: str, company: str) -> tuple[str, str, str, str]:
    period = str(item.get("period") or "")
    return (scope or "global", company or "", period, archive_report_range_label(item))


def report_archive_entries(config: AppConfig, session: AuthSession) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in read_report_archives(config):
        period = str(item.get("period") or "")
        if period not in {"previous-day", "today", "current-week", "previous-week"}:
            continue
        scope = str(item.get("scope") or "global")
        company = str(item.get("company") or "")
        if scope != "global":
            continue
        rel_path = str(item.get("path") or "")
        if rel_path in seen:
            continue
        seen.add(rel_path)
        path = config.report_dir / rel_path
        if not path.exists() or not path.is_file():
            continue
        stamp = str(item.get("stamp") or "")
        match = REPORT_ARCHIVE_RE.match(path.name)
        if match and not stamp:
            stamp = match.group(2)
        root = path.parent
        try:
            sidecars = [sidecar for sidecar in root.glob(f"{path.stem}_*.html") if sidecar.is_file()]
        except OSError:
            sidecars = []
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0
        entries.append(
            {
                "path": path,
                "period": archive_period_label(period),
                "report_range": archive_report_range_label(item),
                "generated_at": compact_archive_datetime(str(item.get("generated_at") or parse_stamp_text(stamp))),
                "sort_key": compact_archive_datetime(str(item.get("period_end") or item.get("generated_at") or parse_stamp_text(stamp))),
                "mtime": mtime,
                "size": report_size_text(path),
                "sidecars": len(sidecars),
                "href": report_url_for_path(config, path),
                "scope": scope,
                "company": company,
                "_archive_key": archive_entry_unique_key(item, scope, company),
            }
        )
    latest_by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for entry in entries:
        key = entry.get("_archive_key")
        if not isinstance(key, tuple):
            continue
        current = latest_by_key.get(key)
        entry_rank = (str(entry.get("sort_key") or ""), float(entry.get("mtime") or 0.0))
        current_rank = (str(current.get("sort_key") or ""), float(current.get("mtime") or 0.0)) if current else ("", 0.0)
        if current is None or entry_rank >= current_rank:
            latest_by_key[key] = entry
    deduped = list(latest_by_key.values())
    for entry in deduped:
        entry.pop("_archive_key", None)
    return sorted(deduped, key=lambda item: str(item.get("sort_key") or ""), reverse=True)


def default_home_report_path(config: AppConfig) -> Path | None:
    tz = local_tz(config.timezone)
    today = datetime.now(tz).date() if tz else datetime.now().date()
    yesterday = today - timedelta(days=1)
    exact: list[tuple[str, float, Path]] = []
    fallback: list[tuple[str, float, Path]] = []
    for item in read_report_archives(config):
        if str(item.get("period") or "") != "previous-day":
            continue
        if str(item.get("scope") or "global") != "global":
            continue
        rel_path = str(item.get("path") or "")
        path = (config.report_dir / rel_path).resolve()
        try:
            path.relative_to(config.report_dir.resolve())
        except ValueError:
            continue
        if not path.exists() or not path.is_file():
            continue
        start_date = compact_archive_datetime(str(item.get("period_start") or ""))[:10]
        sort_key = compact_archive_datetime(str(item.get("period_end") or item.get("generated_at") or ""))
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0
        row = (sort_key, mtime, path)
        if start_date == yesterday.isoformat():
            exact.append(row)
        fallback.append(row)
    candidates = exact or fallback
    if not candidates:
        return None
    return sorted(candidates, key=lambda row: (row[0], row[1]), reverse=True)[0][2]


def running_report_job_ids(config: AppConfig) -> set[str]:
    try:
        result = subprocess.run(
            ["pgrep", "-af", f"^{re.escape(config.python)} {re.escape(str(config.app_dir / 'tianqing_external_audit_report.py'))}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=3,
        )
    except Exception:
        return set()
    ids: set[str] = set()
    for line in result.stdout.splitlines():
        match = re.search(r"_(\d{14}-\d+-\d+)\.html\b", line)
        if match:
            ids.add(match.group(1))
    return ids


def parse_job_log(path: Path) -> dict[str, Any]:
    text = tail_text(path, 200000)
    info: dict[str, Any] = {
        "job_id": path.stem,
        "log_path": path,
        "mtime": path.stat().st_mtime,
        "created_at": "",
        "range": "",
        "ai": "",
        "status": "",
        "error": "",
    }
    for line in text.splitlines():
        if line.startswith("created_at="):
            info["created_at"] = line.split("=", 1)[1]
        elif line.startswith("range="):
            info["range"] = line.split("=", 1)[1]
        elif line.startswith("ai="):
            info["ai"] = line.split("=", 1)[1]
        elif line.startswith("status="):
            info["status"] = line.split("=", 1)[1]
        elif line.startswith("error="):
            info["error"] = line.split("=", 1)[1]
    return info


def main_output_for_job(config: AppConfig, job_id: str) -> Path | None:
    try:
        candidates = list(config.report_dir.rglob(f"*{job_id}.html"))
    except OSError:
        return None
    for path in candidates:
        if path.name.endswith(f"{job_id}.html"):
            return path
    return None


def output_count_for_job(config: AppConfig, job_id: str) -> int:
    try:
        return sum(1 for path in config.report_dir.rglob(f"*{job_id}*.html") if path.is_file())
    except OSError:
        return 0


def job_history_entries(config: AppConfig, session: AuthSession, limit: int = 50) -> list[dict[str, Any]]:
    running_ids = running_report_job_ids(config)
    with JOBS_LOCK:
        memory_jobs = {job.job_id: job for job in JOBS.values() if session_can_view_job(session, job)}
    try:
        logs = sorted((config.report_dir / "jobs").glob("*.log"), key=lambda path: path.stat().st_mtime, reverse=True)
    except OSError:
        logs = []
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for log_path in logs[:limit]:
        info = parse_job_log(log_path)
        job_id = str(info["job_id"])
        memory_job = memory_jobs.get(job_id)
        output = main_output_for_job(config, job_id)
        if output and not session_can_access_report_path(config, session, output):
            continue
        status = str(info.get("status") or "")
        if memory_job:
            status = memory_job.status
        elif job_id in running_ids:
            status = "running"
        elif output and not status:
            status = "done"
        elif not status:
            status = "interrupted"
        entries.append(
            {
                **info,
                "status": status,
                "output": output,
                "output_count": output_count_for_job(config, job_id),
                "href": report_url_for_path(config, output) if output else "",
            }
        )
        seen.add(job_id)
    for job_id, job in memory_jobs.items():
        if job_id in seen:
            continue
        output = config.report_dir / job.output_name
        entries.append(
            {
                "job_id": job_id,
                "log_path": config.report_dir / "jobs" / job.log_name,
                "mtime": job.finished_at or job.created_at,
                "created_at": datetime.fromtimestamp(job.created_at).isoformat(timespec="seconds"),
                "range": f"{job.start_text} -> {job.end_text}",
                "status": job.status,
                "error": job.error,
                "output": output if output.exists() else None,
                "output_count": output_count_for_job(config, job_id),
                "href": report_url_for_path(config, output) if output.exists() else "",
            }
        )
    return sorted(entries, key=lambda item: float(item.get("mtime") or 0), reverse=True)[:limit]


def session_can_view_job_log(config: AppConfig, session: AuthSession, job_id: str) -> bool:
    if session.role not in {"admin", "global"}:
        return False
    with JOBS_LOCK:
        memory_job = JOBS.get(job_id)
    if memory_job:
        return True
    output = main_output_for_job(config, job_id)
    if not output:
        return False
    try:
        output.resolve().relative_to(config.report_dir.resolve())
    except ValueError:
        return False
    return True


def page_shell(title: str, body: str, refresh_seconds: int | None = None) -> bytes:
    refresh = f'<meta http-equiv="refresh" content="{refresh_seconds}">' if refresh_seconds else ""
    html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {refresh}
  <title>{esc(title)}</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --paper: #fff;
      --ink: #172033;
      --muted: #667085;
      --line: #d9e0ea;
      --blue: #2563eb;
      --red: #b42318;
      --green: #157347;
      --amber: #b45309;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", Arial, sans-serif;
      line-height: 1.5;
    }}
    main {{
      width: 100%;
      min-height: 100vh;
      padding: 28px 36px 48px;
      background: var(--paper);
    }}
    header {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 20px;
      border-bottom: 2px solid #1f2937;
      padding-bottom: 18px;
      margin-bottom: 22px;
    }}
    h1 {{ margin: 0 0 8px; font-size: 28px; letter-spacing: 0; }}
    h2 {{ margin: 26px 0 12px; font-size: 18px; letter-spacing: 0; }}
    p {{ margin: 8px 0; }}
    .muted {{ color: var(--muted); font-size: 13px; }}
    a {{ color: #175cd3; text-decoration: none; border-bottom: 1px solid rgba(23, 92, 211, 0.28); }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 12px; }}
    .button, button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 36px;
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 7px 13px;
      background: #fff;
      color: #175cd3;
      font-weight: 700;
      cursor: pointer;
    }}
    button.primary, .button.primary {{ background: var(--blue); border-color: var(--blue); color: #fff; }}
    form {{
      display: grid;
      grid-template-columns: repeat(2, minmax(260px, 1fr));
      gap: 16px 18px;
      max-width: none;
    }}
    label {{ display: grid; gap: 6px; color: #344054; font-size: 13px; font-weight: 700; }}
    input, select, textarea {{
      min-height: 40px;
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 8px 10px;
      font-size: 14px;
      font-family: inherit;
    }}
    textarea {{
      min-height: 150px;
      resize: vertical;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      background: #fff;
    }}
    th, td {{
      border-bottom: 1px solid #e7ecf3;
      padding: 9px 10px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background: #f7f9fc;
      color: #475467;
      font-weight: 760;
    }}
    tr:last-child td {{ border-bottom: 0; }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      max-width: none;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 14px;
      max-width: none;
    }}
    .settings-groups {{
      display: grid;
      gap: 18px;
      max-width: none;
    }}
    .settings-group {{
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 16px;
      background: linear-gradient(180deg, #ffffff 0%, #fbfcfe 100%);
    }}
    .settings-group-head {{
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 16px;
      padding-bottom: 10px;
      margin-bottom: 12px;
      border-bottom: 1px solid #e7ecf3;
    }}
    .settings-group-kicker {{
      margin: 0 0 3px;
      color: #175cd3;
      font-size: 12px;
      font-weight: 850;
      letter-spacing: 0.04em;
    }}
    .settings-group-head h2 {{
      margin: 0;
      font-size: 17px;
    }}
    .settings-group-head p {{
      margin: 4px 0 0;
    }}
    .settings-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 12px;
    }}
    .settings-card {{
      display: flex;
      flex-direction: column;
      min-height: 158px;
      border: 1px solid #e1e7f0;
      border-radius: 9px;
      padding: 15px;
      background: #fff;
      box-shadow: 0 10px 26px rgba(15, 23, 42, 0.05);
    }}
    .settings-card h3 {{
      margin: 0 0 8px;
      font-size: 16px;
      letter-spacing: 0;
    }}
    .settings-card .metric {{
      margin: 0 0 6px;
      font-size: 20px;
      font-weight: 850;
      color: #172033;
    }}
    .settings-card .actions {{
      margin-top: auto;
      padding-top: 12px;
    }}
    .settings-toolbar {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 10px 14px;
      margin: 0 0 12px;
    }}
    .settings-toolbar .actions {{
      margin: 0;
    }}
    .mini-badge {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 22px;
      border: 1px solid #d9e0ea;
      border-radius: 999px;
      padding: 2px 8px;
      color: #475467;
      background: #f7f9fc;
      font-size: 12px;
      font-weight: 800;
      white-space: nowrap;
    }}
    .mini-badge.warn {{
      border-color: #fedf89;
      color: #b54708;
      background: #fffaeb;
    }}
    .mini-badge.danger {{
      border-color: #fecaca;
      color: #b42318;
      background: #fff1f0;
    }}
    tr.duplicate-ip-row td {{
      background: #fff8f8;
    }}
    tr.duplicate-ip-row td:first-child {{
      color: #b42318;
      font-weight: 850;
    }}
    .pager {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-top: 12px;
      color: var(--muted);
      font-size: 13px;
    }}
    .pager .actions {{
      margin: 0;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      min-height: 22px;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 12px;
      font-weight: 800;
      white-space: nowrap;
    }}
    .badge.on {{ color: var(--green); background: #ecfdf3; }}
    .badge.off {{ color: var(--muted); background: #f2f4f7; }}
    .switch-row {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      margin: 10px 0 4px;
    }}
    .switch-status {{
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      border-radius: 999px;
      padding: 3px 10px;
      font-size: 12px;
      font-weight: 900;
    }}
    .switch-status.on {{ color: var(--green); background: #ecfdf3; }}
    .switch-status.off {{ color: #667085; background: #f2f4f7; }}
    .switch-button {{
      position: relative;
      min-width: 74px;
      justify-content: flex-end;
      border-radius: 999px;
      padding: 5px 13px 5px 31px;
      color: #475467;
      background: #eef2f6;
      border-color: #d9e0ea;
    }}
    .switch-button::before {{
      content: "";
      position: absolute;
      left: 5px;
      width: 22px;
      height: 22px;
      border-radius: 50%;
      background: #fff;
      box-shadow: 0 1px 4px rgba(15, 23, 42, 0.22);
    }}
    .switch-button.on {{
      justify-content: flex-start;
      padding-left: 13px;
      padding-right: 31px;
      color: #fff;
      background: #157347;
      border-color: #157347;
    }}
    .switch-button.on::before {{
      left: auto;
      right: 5px;
    }}
    .inline-form {{
      display: inline;
      max-width: none;
    }}
    .inline-form button {{
      min-height: 30px;
      padding: 4px 8px;
    }}
    .danger {{
      color: var(--red);
      border-color: #fecdca;
      background: #fff;
    }}
    .check {{ display: flex; align-items: center; gap: 8px; font-weight: 700; }}
    .check input {{ min-height: auto; }}
    .full {{ grid-column: 1 / -1; }}
    .quick-ranges {{
      grid-column: 1 / -1;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      padding: 12px;
      border: 1px solid #e7ecf3;
      border-radius: 9px;
      background: #f8fbff;
    }}
    .quick-ranges strong {{
      margin-right: 4px;
      color: #344054;
      font-size: 13px;
    }}
    .quick-ranges button {{
      min-height: 30px;
      padding: 4px 10px;
      border-color: #cfe0f7;
      background: #fff;
      color: #175cd3;
      font-size: 12px;
      font-weight: 800;
    }}
    .quick-ranges button:hover {{
      border-color: #93c5fd;
      background: #eff6ff;
    }}
    .panel {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      background: #fbfcfe;
      max-width: none;
    }}
    .alias-table-wrap {{
      overflow-x: auto;
      width: 100%;
    }}
    .critical-rule-table {{
      min-width: 1220px;
      table-layout: fixed;
    }}
    .critical-rule-table th:nth-child(1) {{ width: 120px; }}
    .critical-rule-table th:nth-child(2) {{ width: 72px; }}
    .critical-rule-table th:nth-child(3) {{ width: 260px; }}
    .critical-rule-table th:nth-child(4),
    .critical-rule-table th:nth-child(5) {{ width: 240px; }}
    .critical-rule-table th:nth-child(6) {{ width: 300px; }}
    .example-list {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
    }}
    .example-list code,
    .regex-code {{
      display: inline-block;
      max-width: 100%;
      padding: 3px 6px;
      border: 1px solid #dbe5f1;
      border-radius: 6px;
      background: #f8fafc;
      color: #172033;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 11px;
      line-height: 1.45;
      white-space: normal;
      overflow-wrap: anywhere;
    }}
    .alias-table {{
      table-layout: fixed;
      min-width: 1180px;
    }}
    .alias-table th,
    .alias-table td {{
      padding: 7px 8px;
      vertical-align: middle;
    }}
    .alias-table input {{
      width: 100%;
      min-width: 0;
      font-size: 12px;
      padding: 6px 7px;
    }}
    .alias-table input[type="checkbox"] {{
      width: 14px;
      min-width: 14px;
      height: 14px;
      min-height: 14px;
      padding: 0;
      margin: 0;
      vertical-align: middle;
    }}
    .alias-table label {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 5px;
      margin: 0;
      font-size: 12px;
      line-height: 1;
      white-space: nowrap;
    }}
    .alias-table .alias-path-col {{ width: 260px; }}
    .alias-table .alias-company-col {{ width: 170px; }}
    .alias-table .alias-dept-col {{ width: 150px; }}
    .alias-table .alias-note-col {{ width: 150px; }}
    .alias-table .alias-status-col {{ width: 84px; text-align: center; }}
    .alias-table .alias-count-col {{ width: 80px; text-align: center; }}
    .alias-table .alias-action-col {{
      position: sticky;
      right: 0;
      z-index: 2;
      width: 122px;
      min-width: 122px;
      text-align: center;
      background: #fff;
      box-shadow: -8px 0 14px rgba(15, 23, 42, 0.06);
    }}
    .alias-table thead .alias-action-col {{
      z-index: 3;
      background: #f7f9fc;
    }}
    .alias-table .actions {{
      display: inline-flex;
      flex-wrap: nowrap;
      gap: 6px;
      margin: 0;
      align-items: center;
      justify-content: center;
    }}
    .alias-table button {{
      min-height: 30px;
      padding: 4px 8px;
      font-size: 12px;
      white-space: nowrap;
    }}
    .org-tree-table {{
      min-width: 980px;
      table-layout: fixed;
    }}
    .org-tree-table th,
    .org-tree-table td {{
      vertical-align: middle;
      padding: 8px 9px;
    }}
    .org-tree-path {{
      width: 38%;
      color: #172033;
      font-weight: 780;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .org-tree-company {{ width: 24%; }}
    .org-tree-dept {{ width: 22%; }}
    .org-tree-type {{ width: 96px; text-align: center; }}
    .org-tree-count {{ width: 92px; text-align: right; }}
    .org-tree-indent {{
      display: inline-block;
      width: calc(var(--level, 0) * 18px);
      min-width: calc(var(--level, 0) * 18px);
    }}
    .org-tree-toggle {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      height: 18px;
      min-height: 18px;
      margin-right: 5px;
      padding: 0;
      border: 0;
      border-radius: 5px;
      background: #eef4ff;
      color: #175cd3;
      font-size: 11px;
      font-weight: 900;
    }}
    button.org-tree-toggle {{
      cursor: pointer;
    }}
    .org-tree-leaf {{
      background: transparent;
      color: #98a2b3;
    }}
    .archive-toolbar {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      max-width: 1280px;
      margin: 0 0 12px;
      padding: 12px 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #f8fbff;
    }}
    .archive-toolbar label {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 0;
      font-size: 13px;
    }}
    .archive-toolbar-main {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 12px;
    }}
    .archive-toolbar-actions {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin-left: auto;
    }}
    .archive-toolbar select {{
      min-height: 34px;
      min-width: 140px;
      font-size: 13px;
      font-weight: 780;
      background: #fff;
    }}
    .archive-secondary-action {{
      min-height: 32px;
      padding: 5px 10px;
      border-color: #d6e4f5;
      background: #fff;
      color: #175cd3;
      font-size: 12px;
      font-weight: 800;
      white-space: nowrap;
    }}
    .minor-panel {{
      max-width: 1280px;
      margin-top: 16px;
      border: 1px dashed #cfd8e6;
      border-radius: 8px;
      padding: 10px 14px;
      background: #fbfcfe;
    }}
    .minor-panel summary {{
      color: #667085;
      cursor: pointer;
      font-size: 13px;
      font-weight: 760;
    }}
    .minor-panel[open] summary {{ color: #344054; }}
    .minor-panel .button {{
      min-height: 32px;
      padding: 5px 10px;
      font-size: 12px;
    }}
    .status {{
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 3px 10px;
      font-size: 12px;
      font-weight: 800;
    }}
	    .running {{ color: #175cd3; background: #eff6ff; }}
	    .done {{ color: var(--green); background: #ecfdf3; }}
	    .failed {{ color: var(--red); background: #fef3f2; }}
	    .interrupted {{ color: var(--amber); background: #fffbeb; }}
    pre {{
      white-space: pre-wrap;
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #111827;
      color: #e5e7eb;
      padding: 14px;
      max-width: 1100px;
      max-height: 360px;
      font-size: 12px;
    }}
    .error {{ color: var(--red); font-weight: 700; }}
    @media (max-width: 760px) {{
      main {{ padding: 22px; }}
      header, form {{ display: block; }}
      .settings-grid {{ grid-template-columns: 1fr; }}
      .settings-card.wide {{ grid-column: auto; }}
      .settings-group-head {{ display: block; }}
      label, .check {{ margin-top: 14px; }}
    }}
    @media (max-width: 1040px) and (min-width: 761px) {{
      .settings-grid {{ grid-template-columns: repeat(2, minmax(220px, 1fr)); }}
    }}
  </style>
</head>
<body>
  <main>{body}</main>
</body>
</html>"""
    return html_doc.encode("utf-8")


def manual_page(config: AppConfig, session: AuthSession | None = None, error: str = "") -> bytes:
    now = datetime.now(local_tz(config.timezone)).replace(second=0, microsecond=0)
    start = now - timedelta(days=7)
    error_html = f'<p class="error">{esc(error)}</p>' if error else ""
    source_hint = "先刷新 ClickHouse 增量索引，再按自定义周期查询生成 HTML 报告。" if config.use_clickhouse else "读取本机天擎 syslog，生成独立 HTML 报告。"
    body = f"""
    <header>
      <div>
        <h1>自定义周期报告生成</h1>
        <div class="muted">{esc(source_hint)}不覆盖日报、周报和首页。</div>
      </div>
	      <div class="actions">
	        <a class="button" href="/settings">策略管理</a>
	        <a class="button" href="/reports">历史报告</a>
	        <a class="button" href="/">当前报告首页</a>
	        <a class="button" href="/auth/logout">退出登录</a>
	      </div>
    </header>
    {error_html}
    <section class="panel">
      <form method="post" action="/api/generate">
        <div class="quick-ranges" aria-label="快捷周期">
          <strong>快捷周期</strong>
          <button type="button" data-range="today">今天</button>
          <button type="button" data-range="yesterday">昨天</button>
          <button type="button" data-range="last24h">最近24小时</button>
          <button type="button" data-range="last7d">最近7天</button>
          <button type="button" data-range="thisWeek">本周</button>
          <button type="button" data-range="lastWeek">上周</button>
          <button type="button" data-range="thisMonth">本月</button>
          <button type="button" data-range="lastMonth">上月</button>
        </div>
        <label>开始时间
          <input id="report-start" name="start" type="datetime-local" value="{esc(start.strftime('%Y-%m-%dT%H:%M'))}" required>
        </label>
        <label>结束时间
          <input id="report-end" name="end" type="datetime-local" value="{esc(now.strftime('%Y-%m-%dT%H:%M'))}" required>
        </label>
        <label>报告名称
          <input id="report-label" name="label" type="text" value="自定义审计报告" maxlength="60">
        </label>
        <div class="full actions">
          <button class="primary" type="submit">生成报告</button>
          <a class="button" href="/">返回首页</a>
        </div>
      </form>
    </section>
    <p class="muted">时间跨度限制为 {MAX_RANGE_DAYS} 天以内；同一时间只允许一个生成任务。符合规则的清单会全部写入报告，页面内分页展示。</p>
    <script>
      (function () {{
        var startInput = document.getElementById("report-start");
        var endInput = document.getElementById("report-end");
        var labelInput = document.getElementById("report-label");
        if (!startInput || !endInput) {{
          return;
        }}
        function pad(value) {{
          return String(value).padStart(2, "0");
        }}
        function toLocalInputValue(date) {{
          return [
            date.getFullYear(),
            pad(date.getMonth() + 1),
            pad(date.getDate())
          ].join("-") + "T" + [pad(date.getHours()), pad(date.getMinutes())].join(":");
        }}
        function startOfDay(date) {{
          return new Date(date.getFullYear(), date.getMonth(), date.getDate(), 0, 0, 0, 0);
        }}
        function addDays(date, days) {{
          var next = new Date(date.getTime());
          next.setDate(next.getDate() + days);
          return next;
        }}
        function startOfWeek(date) {{
          var day = date.getDay() || 7;
          return startOfDay(addDays(date, 1 - day));
        }}
        function startOfMonth(date) {{
          return new Date(date.getFullYear(), date.getMonth(), 1, 0, 0, 0, 0);
        }}
        function setRange(start, end, label) {{
          startInput.value = toLocalInputValue(start);
          endInput.value = toLocalInputValue(end);
          if (labelInput && (!labelInput.value || labelInput.value === "自定义审计报告" || /审计报告$/.test(labelInput.value))) {{
            labelInput.value = label + "审计报告";
          }}
        }}
        function rangeFor(name) {{
          var now = new Date();
          now.setSeconds(0, 0);
          var today = startOfDay(now);
          var thisWeek = startOfWeek(now);
          var thisMonth = startOfMonth(now);
          if (name === "today") {{
            return [today, now, "今天"];
          }}
          if (name === "yesterday") {{
            return [addDays(today, -1), today, "昨天"];
          }}
          if (name === "last24h") {{
            return [new Date(now.getTime() - 24 * 60 * 60 * 1000), now, "最近24小时"];
          }}
          if (name === "last7d") {{
            return [addDays(now, -7), now, "最近7天"];
          }}
          if (name === "thisWeek") {{
            return [thisWeek, now, "本周"];
          }}
          if (name === "lastWeek") {{
            return [addDays(thisWeek, -7), thisWeek, "上周"];
          }}
          if (name === "thisMonth") {{
            return [thisMonth, now, "本月"];
          }}
          if (name === "lastMonth") {{
            return [new Date(thisMonth.getFullYear(), thisMonth.getMonth() - 1, 1, 0, 0, 0, 0), thisMonth, "上月"];
          }}
          return null;
        }}
        Array.prototype.forEach.call(document.querySelectorAll(".quick-ranges button[data-range]"), function (button) {{
          button.addEventListener("click", function () {{
            var range = rangeFor(button.getAttribute("data-range"));
            if (range) {{
              setRange(range[0], range[1], range[2]);
            }}
          }});
        }});
      }})();
    </script>
"""
    return page_shell("自定义周期报告生成", body)


def job_page(config: AppConfig, job_id: str) -> bytes:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        log_path = config.report_dir / "jobs" / f"{job_id}.log"
        if log_path.exists():
            info = parse_job_log(log_path)
            output = main_output_for_job(config, job_id)
            status = str(info.get("status") or ("done" if output else "interrupted"))
            status_label = {"running": "生成中", "done": "已完成", "failed": "失败", "interrupted": "已中断/未知"}.get(status, status)
            result_html = f'<p><a class="button primary" href="{esc(report_url_for_path(config, output))}">打开生成的报告</a></p>' if output else ""
            cleanup_script = temporary_report_cleanup_script_for_path(config, output)
            log_tail = tail_text(log_path)
            body = f"""
    <header>
      <div>
        <h1>生成状态：{esc(job_id)}</h1>
        <div class="muted">统计周期：{esc(info.get('range', ''))}</div>
      </div>
      <div class="actions"><a class="button" href="/manual">自定义周期生成</a><a class="button" href="/">当前报告首页</a></div>
    </header>
    <section class="panel">
      <p><span class="status {esc(status)}">{esc(status_label)}</span></p>
      <p class="muted">报告模式：规则概览；输出页数：{esc(output_count_for_job(config, job_id))}</p>
      {result_html}
    </section>
    <h2>生成日志</h2>
    <pre>{esc(log_tail or '暂无日志。')}</pre>
    {cleanup_script}
"""
            return page_shell(f"生成状态 {job_id}", body, refresh_seconds=5 if status == "running" else None)
        body = f"""
    <header>
      <div>
        <h1>任务不存在</h1>
        <div class="muted">服务重启后仅保留已生成的 HTML 文件，任务状态内存会清空。</div>
      </div>
      <div class="actions"><a class="button" href="/manual">自定义周期生成</a><a class="button" href="/">当前报告首页</a></div>
    </header>
"""
        return page_shell("任务不存在", body)
    log_path = config.report_dir / "jobs" / job.log_name
    log_tail = tail_text(log_path)
    status_class = job.status
    status_label = {"running": "生成中", "done": "已完成", "failed": "失败"}.get(job.status, job.status)
    duration = ""
    if job.finished_at:
        duration = f"{int(job.finished_at - job.created_at)} 秒"
    elif job.created_at:
        duration = f"{int(time.time() - job.created_at)} 秒"
    result_html = ""
    cleanup_script = ""
    if job.status == "done":
        result_html = f'<p><a class="button primary" href="/{esc(job.output_name)}">打开生成的报告</a></p>'
        cleanup_script = temporary_report_cleanup_script_for_path(config, config.report_dir / job.output_name)
    elif job.status == "failed":
        result_html = f'<p class="error">{esc(job.error or "生成失败。")}</p>'
    body = f"""
    <header>
      <div>
        <h1>{esc(job.label)}</h1>
        <div class="muted">统计周期：{esc(job.start_text)} 至 {esc(job.end_text)}</div>
      </div>
      <div class="actions">
        <a class="button" href="/manual">自定义周期生成</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    <section class="panel">
      <p><span class="status {esc(status_class)}">{esc(status_label)}</span></p>
      <p class="muted">任务 ID：{esc(job.job_id)}；报告模式：规则概览；清单：符合规则全部显示；耗时：{esc(duration)}</p>
      {result_html}
    </section>
    <h2>生成日志</h2>
    <pre>{esc(log_tail or '暂无日志。')}</pre>
    {cleanup_script}
	"""
    return page_shell(job.label, body, refresh_seconds=5 if job.status == "running" else None)


def reports_page(config: AppConfig, session: AuthSession) -> bytes:
    cleanup_temporary_reports(config)
    entries = report_archive_entries(config, session)
    rows = []
    for entry in entries:
        period = str(entry["period"])
        rows.append(
            f'<tr data-report-period="{esc(period)}">'
            f"<td>{esc(entry['report_range'])}</td>"
            f"<td>{esc(period)}</td>"
            f"<td>{esc(entry['size'])}</td>"
            f"<td>{esc(entry['sidecars'])}</td>"
            f'<td><a class="button" href="{esc(entry["href"])}">打开</a></td>'
            "</tr>"
        )
    table = "".join(rows) if rows else '<tr><td colspan="5" class="muted">暂无定时报告归档。</td></tr>'
    body = f"""
    <header>
      <div>
        <h1>历史报告</h1>
        <div class="muted">仅展示日报、周报定时任务登记的正式归档；自定义周期和测试生成报告不进入历史报告，关闭临时报表页时自动清理。</div>
      </div>
      <div class="actions">
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    <section class="panel">
      <p>当前可见正式报告归档：共 {len(entries)} 份。仅展示全集团日报、周报正式归档。</p>
    </section>
    <div class="archive-toolbar">
      <div class="archive-toolbar-main">
        <label>报告周期
          <select id="report-period-filter">
            <option value="">全部正式报告</option>
            <option value="日报">日报</option>
            <option value="周报">周报</option>
          </select>
        </label>
        <span class="muted" id="report-period-filter-hint">优先查看已归档报告，临时生成仅用于特殊复核。</span>
      </div>
      <div class="archive-toolbar-actions">
        <a class="button archive-secondary-action" href="/manual" title="仅用于日报、周报无法覆盖的临时复核，不进入历史报告归档">临时自定义周期</a>
      </div>
    </div>
    <div class="table-wrap"><table>
      <thead><tr><th>报告日期/周期</th><th>类型</th><th>首页大小</th><th>明细页数</th><th>操作</th></tr></thead>
      <tbody>{table}</tbody>
    </table></div>
    <script>
      (function () {{
        var filter = document.getElementById("report-period-filter");
        var hint = document.getElementById("report-period-filter-hint");
        var rows = Array.prototype.slice.call(document.querySelectorAll("[data-report-period]"));
        function apply() {{
          var value = filter ? filter.value : "";
          var count = 0;
          rows.forEach(function (row) {{
            var show = !value || row.getAttribute("data-report-period") === value;
            row.style.display = show ? "" : "none";
            if (show) count += 1;
          }});
          if (hint) {{
            hint.textContent = value ? (value + "：当前显示 " + count + " 份正式归档") : ("全部正式报告：当前显示 " + count + " 份");
          }}
        }}
        if (filter) {{
          filter.addEventListener("change", apply);
          apply();
        }}
      }})();
    </script>
"""
    return page_shell("历史报告", body)


def jobs_page(config: AppConfig, session: AuthSession) -> bytes:
    entries = job_history_entries(config, session, limit=80)
    status_label = {"running": "生成中", "done": "已完成", "failed": "失败", "interrupted": "已中断/未知"}
    rows = []
    for entry in entries:
        status = str(entry.get("status") or "interrupted")
        output_link = f'<a class="button" href="{esc(entry["href"])}">打开报告</a>' if entry.get("href") else '<span class="muted">无输出</span>'
        log_link = f'<a class="button" href="/jobs/{esc(entry["job_id"])}">日志</a>'
        rows.append(
            "<tr>"
            f"<td>{esc(entry.get('created_at') or datetime.fromtimestamp(float(entry.get('mtime') or 0)).strftime('%Y-%m-%d %H:%M:%S'))}</td>"
            f'<td><span class="status {esc(status)}">{esc(status_label.get(status, status))}</span></td>'
            f"<td>{esc(entry.get('range', ''))}</td>"
            "<td>规则概览</td>"
            f"<td>{esc(entry.get('output_count', 0))}</td>"
            f"<td>{output_link} {log_link}</td>"
            f"<td>{esc(entry.get('error', ''))}</td>"
            "</tr>"
        )
    table = "".join(rows) if rows else '<tr><td colspan="7" class="muted">暂无生成任务。</td></tr>'
    body = f"""
    <header>
      <div>
        <h1>历史任务</h1>
        <div class="muted">从任务日志和输出文件反推状态；生成中任务离开页面不会中止。</div>
      </div>
      <div class="actions">
        <a class="button" href="/reports">历史报告</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    <section class="panel">
      <p>状态说明：有后台进程的是“生成中”；日志写入 status=done 的是“已完成”；没有完成标记、没有输出且进程已不存在的任务显示为“已中断/未知”。</p>
    </section>
    <div class="table-wrap"><table>
      <thead><tr><th>创建时间</th><th>状态</th><th>统计周期</th><th>报告模式</th><th>输出页数</th><th>操作</th><th>错误</th></tr></thead>
      <tbody>{table}</tbody>
    </table></div>
"""
    return page_shell("历史任务", body, refresh_seconds=5 if any(str(item.get("status")) == "running" for item in entries) else None)


def login_page(config: AppConfig, next_path: str = "/", error: str = "") -> tuple[bytes, str]:
    state = secrets.token_urlsafe(24)
    safe_next = normalize_login_next(next_path)
    redirect_uri = config.auth_callback_url or (config.public_base_url.rstrip("/") + "/auth/callback")
    try:
        auth_config = auth_proxy_request(config, "/auth/wecom/config")
        corp_id = str(auth_config.get("corp_id") or "")
        agent_id = str(auth_config.get("agent_id") or "")
    except Exception as exc:
        corp_id = ""
        agent_id = ""
        error = error or f"企业微信认证配置读取失败：{type(exc).__name__}"
    if corp_id and agent_id:
        params = {
            "appid": corp_id,
            "agentid": agent_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        qr_url = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect?" + urlencode(params)
        action_html = f'<a class="button primary" href="{esc(qr_url)}">企业微信扫码登录</a>'
    else:
        action_html = '<span class="error">企业微信认证暂不可用。</span>'
    error_html = f'<p class="error">{esc(error)}</p>' if error else ""
    body = f"""
    <header>
      <div>
        <h1>数据安全审计报告</h1>
        <div class="muted">请使用企业微信扫码认证后访问外发与解密审计报告。</div>
      </div>
    </header>
    {error_html}
    <section class="panel">
      <h2>企业微信认证</h2>
      <p class="muted">登录后按企业微信 userid 授权访问全集团审计报告；策略管理仅限固定管理员。</p>
      <div class="actions">{action_html}</div>
    </section>
"""
    state_cookie = f"{state}|{quote(safe_next, safe='')}"
    return page_shell("企业微信认证", body), state_cookie


def forbidden_page(message: str = "无权限访问该资源。") -> bytes:
    body = f"""
    <header>
      <div>
        <h1>访问受限</h1>
        <div class="muted">{esc(message)}</div>
      </div>
      <div class="actions"><a class="button" href="/auth/logout">退出登录</a><a class="button" href="/">返回首页</a></div>
    </header>
"""
    return page_shell("访问受限", body)


def iso_now(config: AppConfig) -> str:
    return datetime.now(local_tz(config.timezone)).isoformat(timespec="seconds")


def rule_doc(path: Path, description: str) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "updated_at": "", "description": description, "rules": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "updated_at": "", "description": description, "rules": []}
    if isinstance(data, list):
        data = {"version": 1, "updated_at": "", "description": description, "rules": data}
    if not isinstance(data, dict):
        data = {"version": 1, "updated_at": "", "description": description, "rules": []}
    rules = data.get("rules")
    if not isinstance(rules, list):
        data["rules"] = []
    data.setdefault("version", 1)
    data.setdefault("description", description)
    data.setdefault("updated_at", "")
    return data


def policy_alias_count(data: Any) -> int:
    if not isinstance(data, dict):
        return 0
    aliases = data.get("organization_aliases")
    return len(aliases) if isinstance(aliases, list) else 0


def existing_json_doc(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def backup_rule_doc(path: Path) -> None:
    if not path.exists():
        return
    backup_dir = path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = backup_dir / f"{path.name}.{stamp}.bak"
    backup_path.write_bytes(path.read_bytes())
    try:
        backup_path.chmod(0o640)
    except OSError:
        pass


def guard_policy_doc_write(path: Path, data: dict[str, Any]) -> None:
    if path.name != "audit_policy.json" or not path.exists():
        return
    existing = existing_json_doc(path)
    if policy_alias_count(existing) > 0 and policy_alias_count(data) == 0 and os.getenv("TIANQING_ALLOW_EMPTY_ORG_ALIASES") != "1":
        raise ValueError("拒绝保存：当前策略已有组织别名，不能被空组织别名表覆盖。")


def write_rule_doc(path: Path, data: dict[str, Any], config: AppConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    guard_policy_doc_write(path, data)
    backup_rule_doc(path)
    data["updated_at"] = iso_now(config)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    try:
        path.chmod(0o640 if path.name == "audit_policy.json" else 0o644)
    except OSError:
        pass


def keywords_path(config: AppConfig) -> Path:
    return config.keywords_file


def policy_path(config: AppConfig) -> Path:
    return config.policy_file


def exclusions_path(config: AppConfig) -> Path:
    return config.exclusions_file


def load_keyword_doc(config: AppConfig) -> dict[str, Any]:
    return rule_doc(keywords_path(config), "天擎外发审计敏感词策略。系统不内置敏感词，全部以本文件和策略管理页面为准。")


def load_policy_doc(config: AppConfig) -> dict[str, Any]:
    path = policy_path(config)
    if not path.exists():
        return {
            "version": 1,
            "description": "奇安信天擎安全审计策略。设计图纸后缀和敏感词一样由策略中心维护。",
            "design_suffixes": {"three_d": ["prt", "asm", "sldasm", "sldprt", "step"], "two_d": ["dwg"], "pcb_ecad": []},
            "critical_design_patterns": sanitize_critical_design_patterns(DEFAULT_CRITICAL_DESIGN_PATTERNS),
            "archive_suffixes": DEFAULT_ARCHIVE_SUFFIXES,
            "organization_aliases": [],
            "internal_targets": {"domains": ["daqo.com"], "networks": ["172.88.0.0/16", "172.188.0.0/16"]},
            "plm_login_audit": {
                "constrained_departments": DEFAULT_PLM_CONSTRAINED_DEPARTMENTS,
                "terminal_match_fields": DEFAULT_PLM_TERMINAL_MATCH_FIELDS,
            },
            "terminal_behavior_review": terminal_review.DEFAULT_REVIEW_POLICY,
            "auth": {
                "policy_admin_userids": DEFAULT_POLICY_ADMIN_USERIDS,
                "global_viewer_userids": [],
                "session_hours": 8,
            },
        }
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        loaded = {}
    if not isinstance(loaded, dict):
        loaded = {}
    loaded.setdefault("version", 1)
    loaded.setdefault("description", "奇安信天擎安全审计策略。")
    design = loaded.get("design_suffixes")
    if not isinstance(design, dict):
        design = {}
    design.setdefault("three_d", ["prt", "asm", "sldasm", "sldprt", "step"])
    design.setdefault("two_d", ["dwg"])
    design.setdefault("pcb_ecad", [])
    loaded["design_suffixes"] = design
    loaded["critical_design_patterns"] = sanitize_critical_design_patterns(loaded.get("critical_design_patterns"))
    archive_suffixes = loaded.get("archive_suffixes")
    if not isinstance(archive_suffixes, list):
        archive_suffixes = DEFAULT_ARCHIVE_SUFFIXES
    loaded["archive_suffixes"] = archive_suffixes
    organization_aliases = loaded.get("organization_aliases")
    if not isinstance(organization_aliases, list):
        organization_aliases = []
    loaded["organization_aliases"] = organization_aliases
    internal_targets = loaded.get("internal_targets")
    if not isinstance(internal_targets, dict):
        internal_targets = {}
    internal_targets.setdefault("domains", ["daqo.com"])
    internal_targets.setdefault("networks", ["172.88.0.0/16", "172.188.0.0/16"])
    loaded["internal_targets"] = internal_targets
    plm_login_audit = loaded.get("plm_login_audit")
    if not isinstance(plm_login_audit, dict):
        plm_login_audit = {}
    constrained_departments = plm_login_audit.get("constrained_departments")
    if not isinstance(constrained_departments, list):
        constrained_departments = DEFAULT_PLM_CONSTRAINED_DEPARTMENTS
    plm_login_audit["constrained_departments"] = normalize_unique_text_list(constrained_departments)
    match_fields = plm_login_audit.get("terminal_match_fields")
    if not isinstance(match_fields, list):
        match_fields = DEFAULT_PLM_TERMINAL_MATCH_FIELDS
    normalized_match_fields = [item for item in normalize_unique_text_list(match_fields) if item in DEFAULT_PLM_TERMINAL_MATCH_FIELDS]
    plm_login_audit["terminal_match_fields"] = normalized_match_fields or DEFAULT_PLM_TERMINAL_MATCH_FIELDS
    loaded["plm_login_audit"] = plm_login_audit
    terminal_behavior_review = loaded.get("terminal_behavior_review")
    if not isinstance(terminal_behavior_review, dict):
        terminal_behavior_review = {}
    loaded["terminal_behavior_review"] = terminal_review.normalized_review_policy(
        {"terminal_behavior_review": terminal_behavior_review}
    )
    auth = loaded.get("auth")
    if not isinstance(auth, dict):
        auth = {}
    auth.setdefault("policy_admin_userids", DEFAULT_POLICY_ADMIN_USERIDS)
    auth.setdefault("global_viewer_userids", [])
    auth.setdefault("session_hours", 8)
    loaded["auth"] = auth
    return loaded


def load_exclusion_doc(config: AppConfig) -> dict[str, Any]:
    return rule_doc(exclusions_path(config), "天擎外发审计排除策略。命中后不进入重点事件和行为异常分析，原始 syslog 不删除。")


def rule_enabled(rule: dict[str, Any]) -> bool:
    value = rule.get("enabled")
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "启用", "是"}


def form_enabled(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def form_list(value: str) -> list[str]:
    values = []
    for line in (value or "").replace("\r", "\n").split("\n"):
        for part in line.replace("，", ",").replace("；", ",").replace(";", ",").split(","):
            item = part.strip()
            if item:
                values.append(item)
    return values


def normalize_unique_text_list(value: Any) -> list[str]:
    source = value if isinstance(value, list) else form_list(str(value or ""))
    seen: set[str] = set()
    result: list[str] = []
    for raw in source:
        item = " ".join(str(raw or "").strip().split())
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def normalize_userids(value: str) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in form_list(value):
        userid = item.strip()
        if not userid or userid in seen:
            continue
        seen.add(userid)
        result.append(userid)
    return result


def normalize_suffixes(value: str) -> list[str]:
    seen: set[str] = set()
    suffixes: list[str] = []
    for item in form_list(value):
        ext = item.lower().lstrip(".")
        if not ext or not all(ch.isalnum() or ch == "_" for ch in ext) or len(ext) > 16:
            continue
        if ext in seen:
            continue
        seen.add(ext)
        suffixes.append(ext)
    return suffixes


def normalize_domains(value: str) -> list[str]:
    seen: set[str] = set()
    domains: list[str] = []
    for item in form_list(value):
        domain = item.strip().lower()
        domain = domain.removeprefix("http://").removeprefix("https://").split("/", 1)[0].split(":", 1)[0].strip("*. ")
        if not domain:
            continue
        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass
        if domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)
    return domains


def normalize_networks(value: str) -> list[str]:
    seen: set[str] = set()
    networks: list[str] = []
    for item in form_list(value):
        raw = item.strip()
        if not raw:
            continue
        if raw.count(".") == 1 and "/" not in raw:
            raw = f"{raw}.0.0/16"
        elif raw.count(".") == 2 and "/" not in raw:
            raw = f"{raw}.0/24"
        elif raw.count(".") == 3 and "/" not in raw:
            raw = f"{raw}/32"
        try:
            network = str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            continue
        if network in seen:
            continue
        seen.add(network)
        networks.append(network)
    return networks


def normalize_alias_text(value: Any) -> str:
    return " ".join(str(value if value is not None else "").replace("\u3000", " ").strip().split())


def normalize_organization_aliases(value: Any) -> list[dict[str, Any]]:
    rows = value if isinstance(value, list) else []
    result: list[dict[str, Any]] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        raw_org_path = normalize_alias_text(item.get("raw_org_path") or item.get("alias_path"))
        raw_company = normalize_alias_text(item.get("raw_company") or item.get("alias_company"))
        raw_department = normalize_alias_text(item.get("raw_department") or item.get("alias_department"))
        canonical_company = normalize_alias_text(item.get("canonical_company"))
        canonical_department = normalize_alias_text(item.get("canonical_department"))
        note = normalize_alias_text(item.get("note"))
        if not canonical_company or not (raw_org_path or raw_company):
            continue
        result.append(
            {
                "raw_org_path": raw_org_path,
                "raw_company": raw_company,
                "raw_department": raw_department,
                "canonical_company": canonical_company,
                "canonical_department": canonical_department,
                "enabled": policy_bool(item.get("enabled", True), True),
                "note": note,
            }
        )
    return result


ROOT_COMPANY_NAMES = {"大全集团"}
GROUP_FUNCTION_SUFFIXES = ("部", "中心", "办公室", "科", "处", "组", "室", "办")
COMPANY_NAME_MARKERS = ("公司", "集团", "股份", "科技", "电气", "箱变", "母线", "事业部")
ORG_ALIAS_HINTS = [
    (("西门子", "s8"), ("西门子", "低压配电柜事业部")),
]


def unique_join_text(values: Iterable[Any], sep: str = " / ") -> str:
    cleaned: list[str] = []
    for value in values:
        text = normalize_alias_text(value)
        if text and text not in cleaned:
            cleaned.append(text)
    return sep.join(cleaned)


def is_group_function_org(name: str) -> bool:
    text = normalize_alias_text(name)
    if not text:
        return False
    if any(marker in text for marker in COMPANY_NAME_MARKERS):
        return False
    return text.endswith(GROUP_FUNCTION_SUFFIXES)


def split_wecom_org_path(parts: list[str]) -> tuple[str, str, str]:
    cleaned = [normalize_alias_text(part) for part in parts if normalize_alias_text(part)]
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
    path_text = normalize_alias_text(item.get("department_path"))
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
    company = normalize_alias_text(item.get("company"))
    department = normalize_alias_text(item.get("department"))
    parts = [company] if company else []
    if department:
        parts.extend(part for part in [normalize_alias_text(part) for part in department.split("/")] if part)
    if parts:
        split_item = split_wecom_org_path(parts)
        return split_item[0], split_item[1]
    return company, department


def wecom_org_options(config: AppConfig) -> tuple[list[str], list[str]]:
    cache = load_wecom_user_cache(config)
    companies: set[str] = set()
    departments: set[str] = set()
    for item in cache.values():
        company, department = wecom_item_org_fields(item)
        if company:
            companies.add(company)
        if department:
            departments.add(department)
    return sorted(companies), sorted(departments)


def wecom_item_department_paths(item: dict[str, Any]) -> list[list[str]]:
    path_text = normalize_alias_text(item.get("department_path"))
    paths: list[list[str]] = []
    if path_text:
        for path in re.split(r"[;；]", path_text):
            parts = [normalize_alias_text(part) for part in path.split("/") if normalize_alias_text(part)]
            if parts:
                paths.append(parts)
    if paths:
        return paths
    company = normalize_alias_text(item.get("company"))
    department = normalize_alias_text(item.get("department"))
    parts = [company] if company else []
    if department:
        parts.extend(part for part in [normalize_alias_text(part) for part in department.split("/")] if part)
    return [parts] if parts else []


def build_wecom_org_tree(config: AppConfig) -> tuple[dict[str, Any], dict[str, int]]:
    cache = load_wecom_user_cache(config)
    root: dict[str, Any] = {"name": "", "children": {}, "direct_users": 0, "total_users": 0, "raw_paths": set()}
    path_users: dict[tuple[str, ...], set[str]] = {}
    raw_path_count = 0
    for userid, item in cache.items():
        for parts in wecom_item_department_paths(item):
            company, department, raw_path = split_wecom_org_path(parts)
            if not company:
                continue
            department_parts = [part for part in [normalize_alias_text(part) for part in department.split("/")] if part]
            key = tuple([company] + department_parts)
            path_users.setdefault(key, set()).add(userid)
            raw_path_count += 1
            node = root
            for part in key:
                children = node.setdefault("children", {})
                node = children.setdefault(part, {"name": part, "children": {}, "direct_users": 0, "total_users": 0, "raw_paths": set()})
                node.setdefault("raw_paths", set()).add(raw_path)
    for key, users in path_users.items():
        node = root
        for part in key:
            node = node["children"][part]
        node["direct_users"] = len(users)

    def fill_total(node: dict[str, Any]) -> int:
        total = int(node.get("direct_users") or 0)
        for child in node.get("children", {}).values():
            total += fill_total(child)
        node["total_users"] = total
        return total

    fill_total(root)
    return root, {"users": len(cache), "paths": len(path_users), "raw_paths": raw_path_count}


def org_tree_node_kind(parts: list[str], company: str, department: str) -> str:
    if not parts:
        return "根"
    if len(parts) == 1:
        return "集团公司" if parts[0] in ROOT_COMPANY_NAMES else "公司"
    if parts[0] in ROOT_COMPANY_NAMES:
        return "集团部门"
    return "部门"


def render_wecom_org_tree_rows(root: dict[str, Any]) -> str:
    rows: list[str] = []
    next_id = 0

    def walk(node: dict[str, Any], parts: list[str], level: int, ancestors: list[str]) -> None:
        nonlocal next_id
        if parts:
            node_id = f"org-node-{next_id}"
            next_id += 1
            company = parts[0]
            department = " / ".join(parts[1:])
            full_path = " / ".join(parts)
            kind = org_tree_node_kind(parts, company, department)
            has_children = bool(node.get("children"))
            raw_paths = sorted(str(item) for item in (node.get("raw_paths") or set()) if str(item))
            title_parts = [f"标准路径：{full_path}"]
            if raw_paths:
                title_parts.append("原始路径：" + "；".join(raw_paths[:8]))
                if len(raw_paths) > 8:
                    title_parts.append(f"等 {len(raw_paths)} 条")
            title = "；".join(title_parts)
            toggle = (
                f'<button type="button" class="org-tree-toggle" aria-expanded="true" data-toggle-node="{esc(node_id)}">▾</button>'
                if has_children
                else '<span class="org-tree-toggle org-tree-leaf">•</span>'
            )
            rows.append(
                f'<tr class="org-tree-row" data-node-id="{esc(node_id)}" data-ancestors="{esc(",".join(ancestors))}">'
                f'<td class="org-tree-path" title="{esc(title)}">'
                f'<span class="org-tree-indent" style="--level:{level}"></span>'
                f"{toggle}"
                f"{esc(parts[-1])}</td>"
                f'<td class="org-tree-company" title="{esc(company or "-")}">{esc(company or "-")}</td>'
                f'<td class="org-tree-dept" title="{esc(department or "-")}">{esc(department or "-")}</td>'
                f'<td class="org-tree-type"><span class="badge {"on" if kind in {"公司", "部门"} else "off"}">{esc(kind)}</span></td>'
                f'<td class="org-tree-count">{esc(node.get("total_users") or 0)}</td>'
                "</tr>"
            )
            ancestors = ancestors + [node_id]
        children = node.get("children") or {}
        ordered = sorted(children.values(), key=lambda item: (-int(item.get("total_users") or 0), str(item.get("name") or "")))
        for child in ordered:
            walk(child, parts + [str(child.get("name") or "")], level + (1 if parts else 0), ancestors)

    walk(root, [], 0, [])
    return "".join(rows) or '<tr><td colspan="5" class="muted">暂无企业微信组织缓存。</td></tr>'


def organization_tree_page(config: AppConfig) -> bytes:
    root, meta = build_wecom_org_tree(config)
    companies, departments = wecom_org_options(config)
    rows = render_wecom_org_tree_rows(root)
    body = f"""
    <header>
      <div>
        <h1>企业微信组织结构映射</h1>
        <div class="muted">这里按审计口径重组企业微信通讯录：顶层是标准公司，大全集团下面只显示集团本部部门，子公司和事业部公司独立展示。</div>
      </div>
      <div class="actions">
        <a class="button" href="/settings">策略中心</a>
        <a class="button" href="/settings/organization-aliases">组织别名关联</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    <section class="settings-grid">
      <div class="settings-card">
        <h3>通讯录人员</h3>
        <p class="metric">{esc(meta.get("users") or 0)} 人</p>
        <p class="muted">来自本机企业微信缓存。</p>
      </div>
      <div class="settings-card">
        <h3>标准组织路径</h3>
        <p class="metric">{esc(meta.get("paths") or 0)} 条</p>
        <p class="muted">按解析后的公司/部门路径去重。</p>
      </div>
      <div class="settings-card">
        <h3>标准公司候选</h3>
        <p class="metric">{len(companies)} 个</p>
        <p class="muted">由同一套解析逻辑生成，供组织别名下拉选择。</p>
      </div>
    </section>
    <section class="panel">
      <h2>解析规则说明</h2>
      <p class="muted">`大全集团` 下的二级组织如果是总裁办、董事会办公室、信息中心这类集团职能部门，标准公司保持为 `大全集团`；如果二级组织名称包含公司/集团/股份/科技/电气/箱变/母线/事业部等公司特征，则该二级组织本身作为标准公司。</p>
      <p class="muted">例如：`大全集团 / 镇江西门子母线有限公司低压配电柜事业部 / 技术部` 会解析为公司 `镇江西门子母线有限公司低压配电柜事业部`，部门 `技术部`。</p>
    </section>
    <section class="panel">
      <div class="settings-group-head">
        <div>
          <h2>标准组织结构树</h2>
          <p class="muted">鼠标悬停节点可查看对应的原始通讯录路径；点击箭头可展开或收起。</p>
        </div>
        <div class="actions">
          <button type="button" data-org-tree-action="expand">全部展开</button>
          <button type="button" data-org-tree-action="collapse">全部收起</button>
        </div>
      </div>
      <div class="table-wrap"><table class="org-tree-table"><thead><tr><th>企业微信组织节点</th><th>解析标准公司</th><th>解析标准部门</th><th>类型</th><th>人员数</th></tr></thead><tbody>{rows}</tbody></table></div>
    </section>
    <script>
    (function() {{
      var rows = Array.from(document.querySelectorAll(".org-tree-row"));
      var buttons = Array.from(document.querySelectorAll("button.org-tree-toggle[data-toggle-node]"));
      function refreshTree() {{
        var collapsed = new Set(buttons.filter(function(btn) {{
          return btn.getAttribute("aria-expanded") === "false";
        }}).map(function(btn) {{ return btn.getAttribute("data-toggle-node"); }}));
        rows.forEach(function(row) {{
          var ancestors = (row.getAttribute("data-ancestors") || "").split(",").filter(Boolean);
          row.hidden = ancestors.some(function(id) {{ return collapsed.has(id); }});
        }});
        buttons.forEach(function(btn) {{
          btn.textContent = btn.getAttribute("aria-expanded") === "false" ? "▸" : "▾";
        }});
      }}
      buttons.forEach(function(btn) {{
        btn.addEventListener("click", function() {{
          var open = btn.getAttribute("aria-expanded") !== "false";
          btn.setAttribute("aria-expanded", open ? "false" : "true");
          refreshTree();
        }});
      }});
      document.querySelectorAll("[data-org-tree-action]").forEach(function(btn) {{
        btn.addEventListener("click", function() {{
          var expand = btn.getAttribute("data-org-tree-action") === "expand";
          buttons.forEach(function(toggle) {{
            toggle.setAttribute("aria-expanded", expand ? "true" : "false");
          }});
          refreshTree();
        }});
      }});
      refreshTree();
    }})();
    </script>
"""
    return page_shell("企业微信组织结构映射", body)


def organization_alias_datalists(config: AppConfig) -> str:
    companies, departments = wecom_org_options(config)
    company_options = "".join(f'<option value="{esc(item)}"></option>' for item in companies)
    department_options = "".join(f'<option value="{esc(item)}"></option>' for item in departments)
    return f"""
    <datalist id="company-options">{company_options}</datalist>
    <datalist id="department-options">{department_options}</datalist>
"""


def clickhouse_args(config: AppConfig) -> argparse.Namespace:
    return argparse.Namespace(
        clickhouse_url=config.clickhouse_url,
        clickhouse_database=config.clickhouse_database,
        clickhouse_user=config.clickhouse_user,
        clickhouse_password=config.clickhouse_password,
        timeout=config.clickhouse_timeout,
    )


def decrypt_upload_dir() -> Path:
    return Path("/data/tianqing-audit/decrypt-records/uploads")


def encryption_terminal_upload_dir() -> Path:
    return Path("/data/tianqing-audit/encryption-terminals/uploads")


def decrypt_query(config: AppConfig, query: str) -> list[dict[str, Any]]:
    if not config.use_clickhouse:
        return []
    args = clickhouse_args(config)
    try:
        decrypt_records.ensure_decrypt_table(args)
        text = decrypt_records.clickhouse_request(args, query).decode("utf-8", errors="replace")
    except Exception:
        return []
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def encryption_terminal_query(config: AppConfig, query: str) -> list[dict[str, Any]]:
    if not config.use_clickhouse:
        return []
    args = clickhouse_args(config)
    try:
        encryption_terminals.ensure_terminal_table(args)
        text = decrypt_records.clickhouse_request(args, query).decode("utf-8", errors="replace")
    except Exception:
        return []
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def report_period_from_html(data: bytes) -> tuple[str, str] | None:
    text = data.decode("utf-8", errors="replace")
    patterns = [
        r"统计周期[：:]\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+至\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
        r"统计周期[：:]\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?)\s+至\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1).replace("T", " "), match.group(2).replace("T", " ")
    return None


def live_decrypt_url(path: str, start: datetime, end: datetime, **params: str) -> str:
    query: dict[str, str] = {
        "start": start.strftime("%Y-%m-%d %H:%M:%S"),
        "end": end.strftime("%Y-%m-%d %H:%M:%S"),
    }
    for key, value in params.items():
        if value:
            query[key] = value
    return path + "?" + urlencode(query)


def decrypt_latest_import_meta(config: AppConfig) -> dict[str, str]:
    rows = decrypt_query(
        config,
        """
SELECT
    max(import_time) AS latest_import_time,
    argMax(import_batch, import_time) AS latest_import_batch,
    argMax(source_file, import_time) AS latest_source_file,
    count() AS total_rows
FROM decrypt_records FINAL
FORMAT JSONEachRow
""",
    )
    if not rows:
        return {}
    row = rows[0]
    return {
        "latest_import_time": str(row.get("latest_import_time") or ""),
        "latest_import_batch": str(row.get("latest_import_batch") or ""),
        "latest_source_file": str(row.get("latest_source_file") or ""),
        "total_rows": str(row.get("total_rows") or "0"),
    }


def live_decrypt_meta_html(config: AppConfig) -> str:
    meta = decrypt_latest_import_meta(config)
    if not meta:
        return '<p class="note live-decrypt-meta">解密数据实时计算：当前未读取到解密记录导入批次。</p>'
    parts = [
        "解密数据实时计算",
        f"最近导入：{meta.get('latest_import_time') or '-'}",
        f"批次：{meta.get('latest_import_batch') or '-'}",
        f"源文件：{meta.get('latest_source_file') or '-'}",
        f"库内记录：{meta.get('total_rows') or '0'} 条",
    ]
    return f'<p class="note live-decrypt-meta">{"；".join(esc(part) for part in parts)}。</p>'


def live_decrypt_args(config: AppConfig) -> argparse.Namespace:
    return argparse.Namespace(
        use_clickhouse=config.use_clickhouse,
        clickhouse_url=config.clickhouse_url,
        clickhouse_database=config.clickhouse_database,
        clickhouse_user=config.clickhouse_user,
        clickhouse_password=config.clickhouse_password,
        clickhouse_timeout=config.clickhouse_timeout,
    )


def live_decrypt_policy_context(config: AppConfig) -> tuple[argparse.Namespace, Any, set[str]]:
    args = live_decrypt_args(config)
    tz = local_tz(config.timezone) or ZoneInfo("Asia/Shanghai") if ZoneInfo else None
    if tz is None:
        tz = report_gen.timezone(timedelta(hours=8))
    with RULES_LOCK:
        policy_doc = load_policy_doc(config)
    report_gen.configure_audit_policy(policy_doc)
    report_gen.bind_report_submodule_dependencies()
    internal_domains = set(report_gen.DEFAULT_INTERNAL_DOMAINS)
    internal_domains.update(report_gen.policy_internal_domains(policy_doc))
    return args, tz, internal_domains


def load_live_decrypt_analysis(
    config: AppConfig,
    start: datetime,
    end: datetime,
) -> report_gen.DecryptRiskAnalysis:
    args, tz, internal_domains = live_decrypt_policy_context(config)
    return report_gen.load_decrypt_risk_analysis(args, start, end, tz, [], internal_domains)


def live_decrypt_policy_fingerprint(config: AppConfig) -> str:
    with RULES_LOCK:
        policy_doc = load_policy_doc(config)
    return terminal_check_policy_fingerprint(policy_doc)


def live_decrypt_cache_key(config: AppConfig, start: datetime, end: datetime) -> tuple[str, str, str]:
    return (datetime_input_value(start), datetime_input_value(end), live_decrypt_policy_fingerprint(config))


def live_decrypt_prune_cache(now: float | None = None) -> None:
    now = time.time() if now is None else now
    for key, value in list(DECRYPT_ANALYSIS_CACHE.items()):
        if now - float(value.get("created_at") or 0) > DECRYPT_ANALYSIS_CACHE_TTL_SECONDS:
            event = value.get("event")
            DECRYPT_ANALYSIS_CACHE.pop(key, None)
            if hasattr(event, "set"):
                event.set()
    if len(DECRYPT_ANALYSIS_CACHE) <= DECRYPT_ANALYSIS_CACHE_MAX_ENTRIES:
        return
    ordered = sorted(DECRYPT_ANALYSIS_CACHE.items(), key=lambda item: float(item[1].get("created_at") or 0))
    for key, value in ordered[: max(0, len(DECRYPT_ANALYSIS_CACHE) - DECRYPT_ANALYSIS_CACHE_MAX_ENTRIES)]:
        event = value.get("event")
        DECRYPT_ANALYSIS_CACHE.pop(key, None)
        if hasattr(event, "set"):
            event.set()


def live_decrypt_clear_cache() -> None:
    with DECRYPT_ANALYSIS_CACHE_LOCK:
        for value in DECRYPT_ANALYSIS_CACHE.values():
            event = value.get("event")
            if hasattr(event, "set"):
                event.set()
        DECRYPT_ANALYSIS_CACHE.clear()


def live_decrypt_build_payload(config: AppConfig, start: datetime, end: datetime) -> dict[str, Any]:
    args, tz, internal_domains = live_decrypt_policy_context(config)
    analysis = report_gen.load_decrypt_risk_analysis(args, start, end, tz, [], internal_domains)
    links = live_decrypt_links(start, end)
    company_links = live_decrypt_company_links(analysis.records, start, end)
    html_text = report_gen.decrypt_risk_home_html(analysis, links, company_links, tz, end)
    html_text = html_text.replace('<div class="decrypt-card-grid">', live_decrypt_meta_html(config) + '<div class="decrypt-card-grid">', 1)
    return {
        "analysis": analysis,
        "home_html": html_text,
        "links": links,
        "company_links": company_links,
        "tz": tz,
        "built_at": time.time(),
    }


def live_decrypt_cache_entry(key: tuple[str, str, str]) -> dict[str, Any] | None:
    now = time.time()
    with DECRYPT_ANALYSIS_CACHE_LOCK:
        live_decrypt_prune_cache(now)
        entry = DECRYPT_ANALYSIS_CACHE.get(key)
        if entry and now - float(entry.get("created_at") or 0) <= DECRYPT_ANALYSIS_CACHE_TTL_SECONDS:
            return entry
    return None


def live_decrypt_cached_payload(
    config: AppConfig,
    start: datetime,
    end: datetime,
    *,
    wait_seconds: float = 0,
    build_if_missing: bool = True,
) -> dict[str, Any] | None:
    key = live_decrypt_cache_key(config, start, end)
    entry = live_decrypt_cache_entry(key)
    if entry and entry.get("status") == "ready":
        return entry.get("payload")
    if entry and entry.get("status") == "loading":
        event = entry.get("event")
        if hasattr(event, "wait") and wait_seconds > 0:
            event.wait(wait_seconds)
            entry = live_decrypt_cache_entry(key)
            if entry and entry.get("status") == "ready":
                return entry.get("payload")
        if not build_if_missing:
            return None
    if not build_if_missing:
        return None

    event = threading.Event()
    with DECRYPT_ANALYSIS_CACHE_LOCK:
        live_decrypt_prune_cache()
        existing = DECRYPT_ANALYSIS_CACHE.get(key)
        if existing and existing.get("status") == "ready":
            return existing.get("payload")
        if existing and existing.get("status") == "loading":
            event = existing.get("event")
            should_build = False
        else:
            DECRYPT_ANALYSIS_CACHE[key] = {"created_at": time.time(), "status": "loading", "event": event}
            should_build = True
    if not should_build:
        if hasattr(event, "wait") and wait_seconds > 0:
            event.wait(wait_seconds)
            entry = live_decrypt_cache_entry(key)
            if entry and entry.get("status") == "ready":
                return entry.get("payload")
        return None

    try:
        payload = live_decrypt_build_payload(config, start, end)
    except Exception as exc:
        with DECRYPT_ANALYSIS_CACHE_LOCK:
            DECRYPT_ANALYSIS_CACHE[key] = {
                "created_at": time.time(),
                "status": "error",
                "event": event,
                "error": f"{type(exc).__name__}: {str(exc)[:240]}",
            }
            event.set()
        raise
    with DECRYPT_ANALYSIS_CACHE_LOCK:
        DECRYPT_ANALYSIS_CACHE[key] = {
            "created_at": time.time(),
            "status": "ready",
            "event": event,
            "payload": payload,
        }
        event.set()
    return payload


def live_decrypt_warm_cache(config: AppConfig, start: datetime, end: datetime) -> None:
    try:
        live_decrypt_cached_payload(config, start, end, wait_seconds=0, build_if_missing=True)
    except Exception:
        return


def live_decrypt_schedule_warm_cache(config: AppConfig, start: datetime, end: datetime) -> None:
    key = live_decrypt_cache_key(config, start, end)
    with DECRYPT_ANALYSIS_CACHE_LOCK:
        live_decrypt_prune_cache()
        existing = DECRYPT_ANALYSIS_CACHE.get(key)
        if existing and existing.get("status") in {"loading", "ready"}:
            return
        event = threading.Event()
        DECRYPT_ANALYSIS_CACHE[key] = {"created_at": time.time(), "status": "loading", "event": event}

    def worker() -> None:
        try:
            payload = live_decrypt_build_payload(config, start, end)
        except Exception as exc:
            with DECRYPT_ANALYSIS_CACHE_LOCK:
                entry = DECRYPT_ANALYSIS_CACHE.get(key) or {}
                event_obj = entry.get("event") or event
                DECRYPT_ANALYSIS_CACHE[key] = {
                    "created_at": time.time(),
                    "status": "error",
                    "event": event_obj,
                    "error": f"{type(exc).__name__}: {str(exc)[:240]}",
                }
                if hasattr(event_obj, "set"):
                    event_obj.set()
            return
        with DECRYPT_ANALYSIS_CACHE_LOCK:
            entry = DECRYPT_ANALYSIS_CACHE.get(key) or {}
            event_obj = entry.get("event") or event
            DECRYPT_ANALYSIS_CACHE[key] = {
                "created_at": time.time(),
                "status": "ready",
                "event": event_obj,
                "payload": payload,
            }
            if hasattr(event_obj, "set"):
                event_obj.set()

    threading.Thread(target=worker, name="decrypt-analysis-cache-warm", daemon=True).start()


def live_decrypt_summary_rows(config: AppConfig, start: datetime, end: datetime) -> list[dict[str, Any]]:
    live_decrypt_policy_context(config)
    return decrypt_query(
        config,
        f"""
SELECT file_name, file_ext
FROM decrypt_records FINAL
WHERE isNotNull(apply_time)
  AND apply_time >= parseDateTime64BestEffort({decrypt_records.clickhouse_quote(start.isoformat())}, 3)
  AND apply_time < parseDateTime64BestEffort({decrypt_records.clickhouse_quote(end.isoformat())}, 3)
FORMAT JSONEachRow
""",
    )


def live_decrypt_sql_or(conditions: Iterable[str]) -> str:
    values = [condition for condition in conditions if condition]
    if not values:
        return "0"
    if len(values) == 1:
        return values[0]
    return "(" + " OR ".join(f"({condition})" for condition in values) + ")"


def live_decrypt_ext_has(exts: Iterable[str], ext_expr: str = "lowerUTF8(file_ext)") -> str:
    values = sorted({str(ext or "").strip().lower().lstrip(".") for ext in exts if str(ext or "").strip()})
    if not values:
        return "0"
    return f"has({report_gen.clickhouse_array_literal(values)}, {ext_expr})"


def live_decrypt_pattern_conditions(label: str, base_expr: str) -> list[str]:
    conditions: list[str] = []
    for pattern in report_gen.CRITICAL_DESIGN_PATTERNS:
        if str(pattern.get("label") or "").strip() != label:
            continue
        regex = str(pattern.get("regex") or "").strip()
        if not regex:
            continue
        conditions.append(f"match({base_expr}, {decrypt_records.clickhouse_quote(regex.lower())})")
    return conditions


def live_decrypt_sql_classifiers() -> dict[str, str]:
    base_expr = "replaceRegexpOne(lowerUTF8(file_name), '^.*[\\\\\\\\/]', '')"
    ext_expr = "lowerUTF8(file_ext)"
    structure_direct = live_decrypt_sql_or(live_decrypt_pattern_conditions(report_gen.CRITICAL_STRUCTURE_LABEL, base_expr))
    electrical_direct = live_decrypt_sql_or(live_decrypt_pattern_conditions(report_gen.CRITICAL_ELECTRICAL_LABEL, base_expr))
    standard_cond = f"(({structure_direct}) OR ({electrical_direct}))"
    return {
        "structure": structure_direct,
        "electrical": electrical_direct,
        "standard": standard_cond,
        "three_d": live_decrypt_ext_has(report_gen.CONTROLLED_3D_EXTS, ext_expr),
        "dwg": live_decrypt_ext_has(report_gen.CONTROLLED_2D_CAD_EXTS, ext_expr),
        "archive": live_decrypt_ext_has(report_gen.ARCHIVE_EXTS, ext_expr),
    }


def live_decrypt_bucket_expr(classifiers: dict[str, str]) -> str:
    structure_direct = classifiers["structure"]
    electrical_direct = classifiers["electrical"]
    standard_cond = classifiers["standard"]
    return (
        "multiIf("
        f"{structure_direct}, '结构', "
        f"(NOT ({structure_direct})) AND ({electrical_direct}), '电气', "
        f"(NOT ({standard_cond})) AND ({classifiers['three_d']}), '三维模型', "
        f"(NOT ({standard_cond})) AND ({classifiers['dwg']}), 'DWG图纸', "
        f"{classifiers['archive']}, '压缩包', "
        "'其他')"
    )


def live_decrypt_summary_counts(config: AppConfig, start: datetime, end: datetime) -> dict[str, int]:
    if not config.use_clickhouse:
        return {"records": 0, "standard": 0, "structure": 0, "electrical": 0, "three_d": 0, "dwg": 0, "archive": 0}
    args, _tz, _internal_domains = live_decrypt_policy_context(config)
    classifiers = live_decrypt_sql_classifiers()
    structure_direct = classifiers["structure"]
    electrical_direct = classifiers["electrical"]
    standard_cond = classifiers["standard"]
    three_d_ext = classifiers["three_d"]
    two_d_ext = classifiers["dwg"]
    archive_ext = classifiers["archive"]
    time_filter = (
        f"isNotNull(apply_time) "
        f"AND apply_time >= parseDateTime64BestEffort({decrypt_records.clickhouse_quote(start.isoformat())}, 3) "
        f"AND apply_time < parseDateTime64BestEffort({decrypt_records.clickhouse_quote(end.isoformat())}, 3)"
    )
    query = f"""
SELECT
  count() AS records,
  countIf({standard_cond}) AS standard,
  countIf({structure_direct}) AS structure,
  countIf((NOT ({structure_direct})) AND ({electrical_direct})) AS electrical,
  countIf((NOT ({standard_cond})) AND ({three_d_ext})) AS three_d,
  countIf((NOT ({standard_cond})) AND ({two_d_ext})) AS dwg,
  countIf({archive_ext}) AS archive
FROM decrypt_records FINAL
WHERE {time_filter}
FORMAT JSONEachRow
"""
    try:
        text = decrypt_records.clickhouse_request(args, query).decode("utf-8", errors="replace")
        row = json.loads(text.splitlines()[0]) if text.strip() else {}
    except Exception:
        return {"records": 0, "standard": 0, "structure": 0, "electrical": 0, "three_d": 0, "dwg": 0, "archive": 0}
    return {
        "records": int(row.get("records") or 0),
        "standard": int(row.get("standard") or 0),
        "structure": int(row.get("structure") or 0),
        "electrical": int(row.get("electrical") or 0),
        "three_d": int(row.get("three_d") or 0),
        "dwg": int(row.get("dwg") or 0),
        "archive": int(row.get("archive") or 0),
    }


def live_decrypt_trend_summary_html(config: AppConfig, start: datetime, end: datetime) -> str:
    if not config.use_clickhouse:
        return ""
    tz = local_tz(config.timezone)
    trend_end = end.astimezone(tz).date()
    days = [trend_end - timedelta(days=offset) for offset in range(29, -1, -1)]
    day_index = {item: idx for idx, item in enumerate(days)}
    args, _tz, _internal_domains = live_decrypt_policy_context(config)
    bucket_expr = live_decrypt_bucket_expr(live_decrypt_sql_classifiers())
    trend_start = datetime.combine(days[0], datetime.min.time(), tz)
    query = f"""
SELECT
  toDate(toTimeZone(apply_time, {decrypt_records.clickhouse_quote(config.timezone)})) AS day,
  {bucket_expr} AS bucket,
  raw_org_path,
  raw_company,
  raw_department,
  count() AS count
FROM decrypt_records FINAL
WHERE isNotNull(apply_time)
  AND apply_time >= parseDateTime64BestEffort({decrypt_records.clickhouse_quote(trend_start.isoformat())}, 3)
  AND apply_time < parseDateTime64BestEffort({decrypt_records.clickhouse_quote(end.isoformat())}, 3)
GROUP BY day, bucket, raw_org_path, raw_company, raw_department
FORMAT JSONEachRow
"""
    object_names = ["结构", "电气", "三维模型", "DWG图纸"]
    object_counts: dict[str, list[int]] = {name: [0 for _ in days] for name in object_names}
    company_daily: dict[str, list[int]] = {}
    company_totals: Counter = Counter()
    aliases = decrypt_records.normalize_aliases(load_policy_doc(config))
    try:
        rows = [json.loads(line) for line in decrypt_records.clickhouse_request(args, query).decode("utf-8", errors="replace").splitlines() if line.strip()]
    except Exception:
        return ""
    for row in rows:
        try:
            day_value = date.fromisoformat(str(row.get("day") or ""))
        except ValueError:
            continue
        idx = day_index.get(day_value)
        if idx is None:
            continue
        count = int(row.get("count") or 0)
        bucket = str(row.get("bucket") or "")
        if bucket in object_counts:
            object_counts[bucket][idx] += count
        company, _department, matched = decrypt_records.resolve_org_alias(
            str(row.get("raw_org_path") or ""),
            str(row.get("raw_company") or ""),
            str(row.get("raw_department") or ""),
            aliases,
        )
        company = str(company or "").strip()
        if matched and company and not company.startswith("未"):
            company_daily.setdefault(company, [0 for _ in days])[idx] += count
            company_totals[company] += count
    labels = [item.strftime("%m-%d") for item in days]
    object_colors = {
        "结构": "#7c3aed",
        "电气": "#b45309",
        "三维模型": "#be123c",
        "DWG图纸": "#2563eb",
    }
    object_series = [
        {"label": name, "current": values, "current_total": sum(values), "color": object_colors[name]}
        for name, values in object_counts.items()
        if sum(values) > 0
    ]
    company_series = [
        {
            "label": company,
            "current": company_daily.get(company, [0 for _ in days]),
            "current_total": sum(company_daily.get(company, [])),
            "color": report_gen.TREND_COLORS[idx % len(report_gen.TREND_COLORS)],
        }
        for idx, (company, _total) in enumerate(company_totals.most_common(5))
    ]
    if not object_series and not company_series:
        return ""
    object_chart = report_gen.trend_chart_html("解密对象趋势", object_series, labels, "近30天", "按天", include_small_multiples=False).replace(
        'class="trend-chart-card"', 'class="trend-chart-card decrypt-trend-card"', 1
    )
    organization_chart = report_gen.trend_chart_html("解密组织 Top5 趋势", company_series, labels, "近30天", "按近30天公司 Top5", include_small_multiples=False).replace(
        'class="trend-chart-card"', 'class="trend-chart-card decrypt-trend-card"', 1
    )
    return f"""
      <div class="decrypt-trend-panel">
        <div class="decrypt-trend-row" style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;align-items:stretch;">
          {object_chart}
          {organization_chart}
        </div>
      </div>
"""


def live_decrypt_company_matrix_summary_html(
    config: AppConfig,
    start: datetime,
    end: datetime,
    limit: int = 10,
) -> str:
    if not config.use_clickhouse:
        return ""
    args, _tz, _internal_domains = live_decrypt_policy_context(config)
    bucket_expr = live_decrypt_bucket_expr(live_decrypt_sql_classifiers())
    query = f"""
SELECT
  {bucket_expr} AS bucket,
  raw_org_path,
  raw_company,
  raw_department,
  count() AS count
FROM decrypt_records FINAL
WHERE isNotNull(apply_time)
  AND apply_time >= parseDateTime64BestEffort({decrypt_records.clickhouse_quote(start.isoformat())}, 3)
  AND apply_time < parseDateTime64BestEffort({decrypt_records.clickhouse_quote(end.isoformat())}, 3)
GROUP BY bucket, raw_org_path, raw_company, raw_department
FORMAT JSONEachRow
"""
    try:
        rows = [json.loads(line) for line in decrypt_records.clickhouse_request(args, query).decode("utf-8", errors="replace").splitlines() if line.strip()]
    except Exception:
        return ""

    aliases = decrypt_records.normalize_aliases(load_policy_doc(config))
    company_counts: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        company, _department, matched = decrypt_records.resolve_org_alias(
            str(row.get("raw_org_path") or ""),
            str(row.get("raw_company") or ""),
            str(row.get("raw_department") or ""),
            aliases,
        )
        company = str(company or "").strip()
        if not matched or not company or company.startswith("未"):
            continue
        bucket = str(row.get("bucket") or "其他")
        company_counts[company][bucket] += int(row.get("count") or 0)

    ordered = sorted(
        company_counts.items(),
        key=lambda item: (
            -sum(int(value or 0) for value in item[1].values()),
            -int(item[1].get("结构", 0) or 0) - int(item[1].get("电气", 0) or 0),
            item[0],
        ),
    )
    visible = ordered[:limit]
    if not visible:
        matrix_html = '<p class="empty">暂无已映射公司的解密记录。</p>'
    else:
        all_cell_counts: list[int] = []
        all_total_counts: list[int] = []
        for _company, counts in ordered:
            all_cell_counts.extend(int(counts.get(column, 0) or 0) for column in report_gen.DECRYPT_MATRIX_COLUMNS)
            all_total_counts.append(sum(int(value or 0) for value in counts.values()))
        cell_thresholds = report_gen.heat_thresholds_from_counts(all_cell_counts)
        total_thresholds = report_gen.heat_thresholds_from_counts(all_total_counts)
        headers = "".join(
            f'<th title="{esc(column)}">{esc({"三维模型": "三维", "DWG图纸": "DWG", "压缩包": "压缩"}.get(column, column))}</th>'
            for column in report_gen.DECRYPT_MATRIX_COLUMNS
        )
        rows_html: list[str] = []
        for company, counts in visible:
            total_count = sum(int(value or 0) for value in counts.values())
            total_href = live_decrypt_url("/api/decrypt-risk-detail", start, end, scope="company", company=company, bucket="__all__")
            label_inner = f"""
              <div class="org-matrix-label">
                <strong title="{esc(company)}">{esc(company)}</strong>
                <small>{esc(total_count)} 条记录</small>
              </div>
"""
            row_label = f'<a class="org-matrix-label-link" href="{esc(total_href)}" title="查看{esc(company)}解密记录">{label_inner}</a>'
            cells = [f'<th class="channel-name org-matrix-name" scope="row">{row_label}</th>']
            for column in report_gen.DECRYPT_MATRIX_COLUMNS:
                count = int(counts.get(column, 0) or 0)
                href = live_decrypt_url("/api/decrypt-risk-detail", start, end, scope="company", company=company, bucket=column)
                cells.append(
                    f"<td>{report_gen.matrix_number_html(count, href if count else '', f'查看{company} / {column} 解密记录', cell_thresholds)}</td>"
                )
            cells.append(
                f"<td>{report_gen.matrix_number_html(total_count, total_href, f'查看{company}全部解密记录', total_thresholds, total=True)}</td>"
            )
            rows_html.append("<tr>" + "".join(cells) + "</tr>")
        matrix_html = f"""
          <div class="channel-matrix-wrap organization-matrix-wrap decrypt-company-matrix-wrap">
            <table class="channel-matrix organization-matrix decrypt-company-matrix">
              <thead><tr><th>公司</th>{headers}<th>合计</th></tr></thead>
              <tbody>{"".join(rows_html)}</tbody>
            </table>
          </div>
"""
    all_href = live_decrypt_url("/api/decrypt-risk-detail", start, end, scope="all")
    return f"""
      <section class="decrypt-company-panel">
        <div class="org-panel-head">
          <span>Company Decrypt Risk</span>
          <a href="{esc(all_href)}">查看全部解密记录</a>
        </div>
        <h3>公司解密风险矩阵 Top10</h3>
        {matrix_html}
      </section>
"""


def live_decrypt_bucket_for_row(row: dict[str, Any]) -> str:
    file_name = str(row.get("file_name") or "")
    file_ext = str(row.get("file_ext") or report_gen.extension(file_name)).lower()
    labels = set(report_gen.critical_design_labels_for_name(file_name))
    if report_gen.CRITICAL_STRUCTURE_LABEL in labels:
        return "结构"
    if report_gen.CRITICAL_ELECTRICAL_LABEL in labels:
        return "电气"
    if file_ext in report_gen.CONTROLLED_3D_EXTS:
        return "三维模型"
    if file_ext in report_gen.CONTROLLED_2D_CAD_EXTS:
        return "DWG图纸"
    if file_ext in report_gen.ARCHIVE_EXTS:
        return "压缩包"
    return "其他"


def live_decrypt_object_counts(rows: list[dict[str, Any]]) -> Counter:
    counts: Counter = Counter()
    for row in rows:
        counts[live_decrypt_bucket_for_row(row)] += 1
    return counts


def live_decrypt_links(start: datetime, end: datetime) -> dict[str, str]:
    return {
        "all": live_decrypt_url("/api/decrypt-risk-detail", start, end, scope="all"),
        "standard": live_decrypt_url("/api/decrypt-risk-detail", start, end, scope="standard"),
        "structure": live_decrypt_url("/api/decrypt-risk-detail", start, end, scope="structure"),
        "electrical": live_decrypt_url("/api/decrypt-risk-detail", start, end, scope="electrical"),
        "three_d": live_decrypt_url("/api/decrypt-risk-detail", start, end, scope="three-d"),
        "dwg": live_decrypt_url("/api/decrypt-risk-detail", start, end, scope="dwg"),
        "linked": live_decrypt_url("/api/decrypt-risk-detail", start, end, scope="linked"),
        "unmatched": live_decrypt_url("/api/decrypt-risk-detail", start, end, scope="unmatched"),
    }


def live_decrypt_company_links(
    records: list[report_gen.DecryptRiskRecord],
    start: datetime,
    end: datetime,
) -> dict[tuple[str, str], str]:
    links: dict[tuple[str, str], str] = {}
    for company, company_records in report_gen.decrypt_company_groups(records).items():
        links[report_gen.decrypt_company_matrix_detail_key(company, "__all__")] = live_decrypt_url(
            "/api/decrypt-risk-detail", start, end, scope="company", company=company, bucket="__all__"
        )
        buckets = {record.object_bucket for record in company_records}
        for bucket in buckets:
            links[report_gen.decrypt_company_matrix_detail_key(company, bucket)] = live_decrypt_url(
                "/api/decrypt-risk-detail", start, end, scope="company", company=company, bucket=bucket
            )
    return links


def live_decrypt_fragment(config: AppConfig, start: datetime, end: datetime) -> bytes:
    payload = live_decrypt_cached_payload(config, start, end, wait_seconds=60, build_if_missing=True)
    if not payload:
        raise RuntimeError("解密分析缓存尚未生成完成")
    return str(payload.get("home_html") or "").encode("utf-8")


def live_decrypt_summary_fragment(config: AppConfig, start: datetime, end: datetime) -> bytes:
    counts = live_decrypt_summary_counts(config, start, end)
    links = live_decrypt_links(start, end)
    trend_html = live_decrypt_trend_summary_html(config, start, end)
    company_matrix_html = live_decrypt_company_matrix_summary_html(config, start, end)
    structure = int(counts.get("structure", 0) or 0)
    electrical = int(counts.get("electrical", 0) or 0)
    standard = int(counts.get("standard", 0) or 0)
    three_d = int(counts.get("three_d", 0) or 0)
    dwg = int(counts.get("dwg", 0) or 0)
    archive = int(counts.get("archive", 0) or 0)
    conclusions = [
        f"本期一级风险为标准图纸解密 {standard} 条，其中结构 {structure} 条、电气 {electrical} 条；该口径与下方结构/电气卡片及标准图纸明细一致。",
        f"普通对象作为辅助复核：三维模型 {three_d} 条、DWG图纸 {dwg} 条、压缩包 {archive} 条；不计入本模块一级风险汇总。",
        "首页打开后同步预热完整流转链路和全部解密记录；点击下钻优先命中缓存。",
    ]
    overview = f"""
    <section id="decrypt-risk-overview" class="section-block risk-overview-shell decrypt-overview-shell">
      <div class="section-title-row">
        <div>
          <span class="section-eyebrow">Rule Overview</span>
          <h2>加密软件解密规则风险概览</h2>
          <p>首页先按本周期文件名、后缀和组织做轻量聚合，同时预热完整流转链路和下钻明细缓存。</p>
        </div>
      </div>
      <div class="risk-overview-hero">
        <div class="risk-overview-conclusions">
          <span>管理结论</span>
          <ul>{"".join(f"<li>{esc(item)}</li>" for item in conclusions)}</ul>
        </div>
      </div>
    </section>
"""

    def card(label: str, value: Any, note: str, href: str | None, tone: str) -> str:
        inner = f"""
        <div class="decrypt-mini-card-main">
          <span>{esc(label)}</span>
          <strong>{esc(value)}</strong>
        </div>
        <em>{esc(note)}</em>
    """
        if href:
            return f'<a class="decrypt-mini-card decrypt-mini-card-{esc(tone)}" href="{esc(href)}" title="{esc(note)}">{inner}</a>'
        return f'<div class="decrypt-mini-card decrypt-mini-card-{esc(tone)}" title="{esc(note)}">{inner}</div>'

    cards = [
        card("标准图纸解密总数", standard, "结构/电气/标准图纸解密，原则上不应发生", links.get("standard"), "red"),
        card("结构", structure, "结构标准方案解密记录", links.get("structure"), "violet"),
        card("电气", electrical, "电气标准方案解密记录", links.get("electrical"), "amber"),
        card("三维模型", three_d, "PRT/ASM/SLDASM/SLDPRT/STEP 解密记录", links.get("three_d"), "blue"),
        card("DWG图纸", dwg, "DWG 图纸解密记录", links.get("dwg"), "slate"),
        card("发现后续流转", "打开即预热", "首页打开后同步预热解密记录与天擎审计事件的后续流转链路", links.get("linked"), "red"),
    ]
    return (overview + f'<div class="decrypt-card-grid">{"".join(cards)}</div>' + trend_html + company_matrix_html).encode("utf-8")


def filter_live_decrypt_records(
    records: list[report_gen.DecryptRiskRecord],
    scope: str,
    company: str = "",
    bucket: str = "",
) -> list[report_gen.DecryptRiskRecord]:
    if scope == "standard":
        return report_gen.decrypt_standard_records(records)
    if scope == "structure":
        return [record for record in records if record.object_bucket == "结构"]
    if scope == "electrical":
        return [record for record in records if record.object_bucket == "电气"]
    if scope == "three-d":
        return [record for record in records if record.object_bucket == "三维模型"]
    if scope == "dwg":
        return [record for record in records if record.object_bucket == "DWG图纸"]
    if scope == "linked":
        return [record for record in records if report_gen.decrypt_has_followup(record)]
    if scope == "unmatched":
        return [record for record in records if not record.org_matched]
    if scope == "company":
        matched = [record for record in records if report_gen.decrypt_company_label(record) == company]
        if bucket and bucket != "__all__":
            matched = [record for record in matched if record.object_bucket == bucket]
        return matched
    return records


def live_decrypt_detail_page(config: AppConfig, start: datetime, end: datetime, params: dict[str, list[str]]) -> bytes:
    payload = live_decrypt_cached_payload(config, start, end, wait_seconds=60, build_if_missing=True)
    if not payload:
        raise RuntimeError("解密分析缓存尚未生成完成")
    analysis = payload.get("analysis")
    tz = payload.get("tz")
    if analysis is None or tz is None:
        raise RuntimeError("解密分析缓存无效")
    scope = (params.get("scope") or ["all"])[-1]
    company = (params.get("company") or [""])[-1]
    bucket = (params.get("bucket") or [""])[-1]
    cache_key = (scope, company, bucket)
    with DECRYPT_ANALYSIS_CACHE_LOCK:
        detail_cache = payload.setdefault("detail_html_cache", {})
        cached_html = detail_cache.get(cache_key) if isinstance(detail_cache, dict) else None
    if cached_html is not None:
        return str(cached_html).encode("utf-8")
    records = filter_live_decrypt_records(analysis.records, scope, company, bucket)
    title_map = {
        "all": "解密图纸风险追踪",
        "standard": "标准图纸解密明细",
        "structure": "结构解密明细",
        "electrical": "电气解密明细",
        "three-d": "三维模型解密明细",
        "dwg": "DWG图纸解密明细",
        "linked": "解密文件流转链路明细",
        "unmatched": "组织映射待完善明细",
    }
    title = title_map.get(scope, "解密图纸风险追踪")
    if scope == "company":
        title = f"公司解密风险明细：{company or '-'}"
        if bucket and bucket != "__all__":
            title += f" / {bucket}"
    report_period = f"{start.strftime('%Y-%m-%d %H:%M:%S')} 至 {end.strftime('%Y-%m-%d %H:%M:%S')}"
    note = "本页为实时计算结果，打开时按当前解密数据库和当前组织别名策略重新生成；追踪窗口为申请时间后30天。"
    html_text = report_gen.build_decrypt_risk_detail_page(
        title,
        records,
        tz,
        report_period,
        "ClickHouse:tianqing.decrypt_records + audit_events",
        note,
    )
    with DECRYPT_ANALYSIS_CACHE_LOCK:
        detail_cache = payload.setdefault("detail_html_cache", {})
        if isinstance(detail_cache, dict) and len(detail_cache) < 24:
            detail_cache[cache_key] = html_text
    return html_text.encode("utf-8")


def live_decrypt_warmup_json(config: AppConfig, start: datetime, end: datetime) -> bytes:
    started_at = time.time()
    payload = live_decrypt_cached_payload(config, start, end, wait_seconds=60, build_if_missing=True)
    if not payload:
        raise RuntimeError("解密分析缓存尚未生成完成")
    analysis = payload.get("analysis")
    records_count = len(getattr(analysis, "records", []) or [])
    warmed_details: list[str] = []
    for scope in ["all", "standard", "structure", "electrical", "three-d", "dwg", "linked"]:
        live_decrypt_detail_page(config, start, end, {"scope": [scope]})
        warmed_details.append(scope)
    company_groups = report_gen.decrypt_company_groups(getattr(analysis, "records", []) or [])
    ordered_companies = sorted(
        company_groups.items(),
        key=lambda item: (
            -len(item[1]),
            -sum(1 for record in item[1] if getattr(record, "object_bucket", "") in {"结构", "电气"}),
            item[0],
        ),
    )
    for company, _records in ordered_companies[:10]:
        live_decrypt_detail_page(config, start, end, {"scope": ["company"], "company": [company], "bucket": ["__all__"]})
        warmed_details.append(f"company:{company}")
    elapsed = round(time.time() - started_at, 3)
    return json.dumps(
        {
            "status": "ready",
            "records": records_count,
            "warmed_details": warmed_details,
            "elapsed": elapsed,
        },
        ensure_ascii=False,
    ).encode("utf-8")


def live_decrypt_loading_placeholder_html(start: datetime, end: datetime) -> str:
    return f"""
<div class="live-decrypt-stage" aria-live="polite">
  <div class="live-decrypt-stage-head">
    <div>
      <span>Decrypt Audit</span>
      <strong>加密软件解密审计正在刷新</strong>
      <p>统计周期：{esc(start.strftime('%Y-%m-%d %H:%M'))} 至 {esc(end.strftime('%Y-%m-%d %H:%M'))}。先刷新一级风险数字，随后补齐趋势、公司矩阵和流转链路。</p>
    </div>
    <em>实时计算</em>
  </div>
  <div class="live-decrypt-stage-grid">
    <i></i><i></i><i></i><i></i><i></i><i></i>
  </div>
  <div class="live-decrypt-stage-bar" aria-hidden="true"></div>
</div>
"""


def inject_live_decrypt_loader(data: bytes, config: AppConfig) -> bytes:
    if b'id="decrypt-risk-tracking"' not in data or b'id="tq-live-decrypt-loader"' in data:
        return data
    period = report_period_from_html(data)
    if not period:
        return data
    try:
        start = parse_local_datetime(period[0], config.timezone)
        end = parse_local_datetime(period[1], config.timezone)
    except ValueError:
        return data
    summary_url = live_decrypt_url("/api/decrypt-risk-summary-fragment", start, end)
    warmup_url = live_decrypt_url("/api/decrypt-risk-warmup", start, end)
    prehide_style = """
<style id="tq-live-decrypt-prehide">
  #decrypt-risk-overview[data-live-decrypt-state="loading"] {
    display: none !important;
  }
  #decrypt-risk-tracking .live-decrypt-inline-status {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0 0 12px;
    color: #475467;
    font-size: 13px;
    font-weight: 760;
  }
  #decrypt-risk-tracking .live-decrypt-inline-status::before {
    content: "";
    width: 7px;
    height: 7px;
    border-radius: 999px;
    background: #175cd3;
    box-shadow: 11px 0 0 rgba(23, 92, 211, .38), 22px 0 0 rgba(23, 92, 211, .18);
    animation: liveDecryptDots 1.05s infinite ease-in-out;
  }
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .rename-empty,
  #decrypt-risk-tracking[data-live-decrypt-state="summary"] .rename-empty {
    display: none !important;
  }
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-card-grid strong,
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-card-grid span,
  #decrypt-risk-tracking[data-live-decrypt-state="summary"] .decrypt-trend-panel .trend-legend-item strong,
  #decrypt-risk-tracking[data-live-decrypt-state="summary"] .decrypt-trend-panel .trend-axis-label,
  #decrypt-risk-tracking[data-live-decrypt-state="summary"] .decrypt-company-matrix .matrix-count,
  #decrypt-risk-tracking[data-live-decrypt-state="summary"] .decrypt-company-matrix .matrix-total,
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-trend-panel .trend-legend-item strong,
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-trend-panel .trend-axis-label,
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-company-matrix .matrix-count,
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-company-matrix .matrix-total {
    position: relative;
    color: transparent !important;
  }
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-card-grid strong::after,
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-card-grid span::after,
  #decrypt-risk-tracking[data-live-decrypt-state="summary"] .decrypt-trend-panel .trend-legend-item strong::after,
  #decrypt-risk-tracking[data-live-decrypt-state="summary"] .decrypt-trend-panel .trend-axis-label::after,
  #decrypt-risk-tracking[data-live-decrypt-state="summary"] .decrypt-company-matrix .matrix-count::after,
  #decrypt-risk-tracking[data-live-decrypt-state="summary"] .decrypt-company-matrix .matrix-total::after,
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-trend-panel .trend-legend-item strong::after,
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-trend-panel .trend-axis-label::after,
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-company-matrix .matrix-count::after,
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-company-matrix .matrix-total::after {
    content: "...";
    position: absolute;
    inset: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: #175cd3;
    font-weight: 900;
    letter-spacing: 1px;
    animation: liveDecryptTextDots 1.05s infinite steps(3, end);
  }
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-trend-panel .trend-line,
  #decrypt-risk-tracking[data-live-decrypt-state="summary"] .decrypt-trend-panel .trend-line {
    opacity: .36;
    stroke-dasharray: 4 8;
    animation: liveDecryptLine 1.6s linear infinite;
  }
  #decrypt-risk-tracking[data-live-decrypt-state="loading"] .decrypt-trend-panel .trend-point-hit,
  #decrypt-risk-tracking[data-live-decrypt-state="summary"] .decrypt-trend-panel .trend-point-hit {
    opacity: 0;
  }
  @keyframes liveDecryptDots {
    0%, 100% { box-shadow: 11px 0 0 rgba(23, 92, 211, .38), 22px 0 0 rgba(23, 92, 211, .18); }
    33% { box-shadow: 11px 0 0 #175cd3, 22px 0 0 rgba(23, 92, 211, .38); }
    66% { box-shadow: 11px 0 0 rgba(23, 92, 211, .38), 22px 0 0 #175cd3; }
  }
  @keyframes liveDecryptTextDots {
    0%, 100% { opacity: .38; }
    50% { opacity: 1; }
  }
  @keyframes liveDecryptLine {
    to { stroke-dashoffset: -24; }
  }
</style>
"""
    script = f"""
<script id="tq-live-decrypt-loader">
(function() {{
  var summaryUrl = {json.dumps(summary_url, ensure_ascii=False)};
  var warmupUrl = {json.dumps(warmup_url, ensure_ascii=False)};
  function removePrehide() {{
    var style = document.getElementById("tq-live-decrypt-prehide");
    if (style && style.parentNode) {{
      style.parentNode.removeChild(style);
    }}
  }}
  function loadLiveDecrypt() {{
    var section = document.getElementById("decrypt-risk-tracking");
    if (!section || section.getAttribute("data-live-decrypt-loaded") === "1") return;
    var overview = document.getElementById("decrypt-risk-overview");
    section.setAttribute("data-live-decrypt-loaded", "1");
    section.setAttribute("data-live-decrypt-state", "loading");
    if (overview) {{
      overview.setAttribute("data-live-decrypt-state", "loading");
    }}
    var status = section.querySelector(".live-decrypt-inline-status");
    if (!status) {{
      status = document.createElement("p");
      status.className = "live-decrypt-inline-status";
      status.textContent = "解密审计数字实时刷新中";
      section.insertBefore(status, section.firstChild);
    }}
    var summaryApplied = false;
    var summaryDone = false;
    var warmupDone = false;
    var warmupError = "";
    function refreshStatus() {{
      if (!status || !status.parentNode) return;
      if (summaryDone && warmupDone) {{
        status.textContent = "解密审计数字、趋势、公司矩阵和完整下钻缓存已刷新";
      }} else if (summaryDone && warmupError) {{
        status.textContent = "解密审计数字、趋势和公司矩阵已刷新；完整下钻缓存预热失败：" + warmupError;
      }} else if (summaryDone) {{
        status.textContent = "解密审计数字、趋势和公司矩阵已刷新；完整下钻缓存计算中";
      }} else if (warmupDone) {{
        status.textContent = "完整下钻缓存已刷新；首页数字刷新中";
      }} else {{
        status.textContent = "解密审计数字和完整下钻缓存同步刷新中";
      }}
    }}
    function applySummary(html) {{
      var wrapper = document.createElement("div");
      wrapper.innerHTML = html;
      var freshOverview = wrapper.querySelector("#decrypt-risk-overview");
      var oldOverview = document.getElementById("decrypt-risk-overview");
      if (freshOverview && oldOverview) {{
        oldOverview.replaceWith(freshOverview);
      }} else if (oldOverview) {{
        oldOverview.removeAttribute("data-live-decrypt-state");
      }}
      var freshCards = wrapper.querySelector(".decrypt-card-grid");
      var oldCards = section.querySelector(".decrypt-card-grid");
      if (freshCards && oldCards) {{
        oldCards.replaceWith(freshCards);
      }}
      var anchor = section.querySelector(".decrypt-card-grid");
      var freshTrend = wrapper.querySelector(".decrypt-trend-panel");
      var freshCompany = wrapper.querySelector(".decrypt-company-panel");
      Array.prototype.forEach.call(section.querySelectorAll(".decrypt-trend-panel, .decrypt-company-panel, .rename-empty"), function(node) {{
        if (node && node.parentNode) node.parentNode.removeChild(node);
      }});
      function insertAfter(reference, node) {{
        if (!node) return reference;
        if (reference && reference.parentNode) {{
          reference.parentNode.insertBefore(node, reference.nextSibling);
          return node;
        }}
        section.appendChild(node);
        return node;
      }}
      anchor = insertAfter(anchor, freshTrend);
      anchor = insertAfter(anchor, freshCompany);
      if (freshOverview || freshCards || freshTrend || freshCompany) {{
        section.setAttribute("data-live-decrypt-state", "ready");
        removePrehide();
        summaryDone = true;
        refreshStatus();
        summaryApplied = true;
      }}
    }}
    function showError(err) {{
      removePrehide();
      var overview = document.getElementById("decrypt-risk-overview");
      if (overview) {{
        overview.removeAttribute("data-live-decrypt-state");
      }}
      section.removeAttribute("data-live-decrypt-state");
      if (summaryApplied) {{
        var error = document.createElement("p");
        error.className = "note";
        error.textContent = "解密数字刷新失败：" + err.message;
        section.appendChild(error);
      }} else {{
        if (status && status.parentNode) {{
          status.textContent = "解密实时计算暂不可用，当前显示归档快照：" + err.message;
        }} else {{
          var error = document.createElement("p");
          error.className = "note";
          error.textContent = "解密实时计算暂不可用，当前显示归档快照：" + err.message;
          section.insertBefore(error, section.firstChild);
        }}
      }}
    }}
    function fetchHtml(url) {{
      return fetch(url, {{credentials: "same-origin", cache: "no-store"}})
        .then(function(resp) {{
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        return resp.text();
      }});
    }}
    function fetchJson(url) {{
      return fetch(url, {{credentials: "same-origin", cache: "no-store"}})
        .then(function(resp) {{
          if (!resp.ok) throw new Error("HTTP " + resp.status);
          return resp.json();
        }});
    }}
    refreshStatus();
    fetchJson(warmupUrl)
      .then(function(data) {{
        warmupDone = true;
        section.setAttribute("data-live-decrypt-warmup", "ready");
        refreshStatus();
      }})
      .catch(function(err) {{
        warmupError = err.message || "unknown";
        section.setAttribute("data-live-decrypt-warmup", "error");
        refreshStatus();
      }});
    fetchHtml(summaryUrl)
      .then(applySummary)
      .catch(showError);
  }}
  if (document.readyState === "loading") {{
    document.addEventListener("DOMContentLoaded", loadLiveDecrypt);
  }} else {{
    loadLiveDecrypt();
  }}
}})();
</script>
"""
    text = data.decode("utf-8", errors="replace")
    if 'id="tq-live-decrypt-prehide"' not in text:
        text = text.replace("</head>", prehide_style + "</head>", 1)
    def mark_live_decrypt_loading(match: re.Match[str]) -> str:
        open_tag = match.group(1)
        if "data-live-decrypt-state=" in open_tag:
            return open_tag
        return open_tag[:-1] + ' data-live-decrypt-state="loading">'

    for section_id in ["decrypt-risk-overview", "decrypt-risk-tracking"]:
        text = re.sub(
            rf'(<section\b(?=[^>]*\bid="{section_id}")[^>]*>)',
            mark_live_decrypt_loading,
            text,
            count=1,
            flags=re.IGNORECASE,
        )
    text = text.replace("</body>", script + "</body>", 1)
    return text.encode("utf-8")


def decrypt_import_batches(config: AppConfig, limit: int = 20) -> list[dict[str, Any]]:
    return decrypt_query(
        config,
        f"""
SELECT
    import_batch,
    anyLast(source_file) AS source_file,
    min(import_time) AS import_time,
    count() AS rows,
    uniqExact(raw_org_path) AS orgs,
    sum(file_ext IN ('prt','asm','sldasm','sldprt','step','dwg')) AS design_rows
FROM decrypt_records FINAL
GROUP BY import_batch
ORDER BY import_time DESC
LIMIT {int(limit)}
FORMAT JSONEachRow
""",
    )


def encryption_terminal_batches(config: AppConfig, limit: int = 20) -> list[dict[str, Any]]:
    trust_condition = encryption_terminal_trust_condition()
    return encryption_terminal_query(
        config,
        f"""
SELECT
    import_batch,
    anyLast(source_file) AS source_file,
    min(import_time) AS import_time,
    count() AS rows,
    uniqExactIf(tuple(ip_address, computer_name), notEmpty(ip_address) AND notEmpty(computer_name)) AS terminal_keys,
    uniqExactIf(tuple(ip_address, computer_name), {trust_condition}) AS trusted_terminal_keys,
    uniqExactIf(ip_address, notEmpty(ip_address)) AS ips,
    uniqExactIf(ip_address, {trust_condition}) AS trusted_ips,
    countIf(NOT ({trust_condition})) AS excluded_rows,
    countIf((isNull(last_seen) OR last_seen < now('Asia/Shanghai') - INTERVAL {ENCRYPTION_TERMINAL_TRUST_DAYS} DAY) AND notEmpty(ip_address) AND notEmpty(computer_name)) AS expired_rows,
    uniqExactIf(company, notEmpty(company)) AS companies
FROM encryption_terminal_inventory FINAL
GROUP BY import_batch
ORDER BY import_time DESC
LIMIT {int(limit)}
FORMAT JSONEachRow
""",
    )


def latest_encryption_terminal_pool(config: AppConfig) -> dict[str, Any]:
    trust_condition = encryption_terminal_trust_condition()
    rows = encryption_terminal_query(
        config,
        f"""
SELECT
    import_batch,
    anyLast(source_file) AS source_file,
    max(import_time) AS import_time,
    count() AS rows,
    uniqExactIf(tuple(ip_address, computer_name), notEmpty(ip_address) AND notEmpty(computer_name)) AS terminal_keys,
    uniqExactIf(tuple(ip_address, computer_name), {trust_condition}) AS trusted_terminal_keys,
    uniqExactIf(ip_address, notEmpty(ip_address)) AS ips,
    uniqExactIf(ip_address, {trust_condition}) AS trusted_ips,
    countIf(NOT ({trust_condition})) AS excluded_rows,
    countIf((isNull(last_seen) OR last_seen < now('Asia/Shanghai') - INTERVAL {ENCRYPTION_TERMINAL_TRUST_DAYS} DAY) AND notEmpty(ip_address) AND notEmpty(computer_name)) AS expired_rows,
    uniqExactIf(company, notEmpty(company)) AS companies
FROM encryption_terminal_inventory FINAL
GROUP BY import_batch
ORDER BY import_time DESC
LIMIT 1
FORMAT JSONEachRow
""",
    )
    if not rows or int(rows[0].get("rows") or 0) <= 0:
        return {}
    return rows[0]


def latest_encryption_terminal_batch(config: AppConfig) -> str:
    pool = latest_encryption_terminal_pool(config)
    return str(pool.get("import_batch") or "") if pool else ""


def encryption_terminal_duplicates(config: AppConfig, batch_id: str, limit: int = 80) -> list[dict[str, Any]]:
    if not batch_id:
        return []
    quoted_batch = decrypt_records.clickhouse_quote(batch_id)
    trust_condition = encryption_terminal_trust_condition()
    trust_status_sql = encryption_terminal_trust_status_sql()
    return encryption_terminal_query(
        config,
        f"""
SELECT
    t.ip_address AS ip_address,
    t.computer_name,
    t.mac_address,
    t.user_name,
    t.user_account,
    t.company,
    t.department,
    t.os_version,
    t.client_version,
    t.encryption_status,
    t.last_seen,
    t.is_trusted,
    t.trust_status,
    d.ip_rows,
    d.terminal_keys
FROM
(
    SELECT
        ip_address,
        computer_name,
        mac_address,
        user_name,
        user_account,
        company,
        department,
        os_version,
        client_version,
        encryption_status,
        last_seen,
        if({trust_condition}, 1, 0) AS is_trusted,
        {trust_status_sql} AS trust_status
    FROM encryption_terminal_inventory FINAL
    WHERE import_batch = {quoted_batch} AND {trust_condition}
) AS t
INNER JOIN
(
    SELECT
        ip_address,
        count() AS ip_rows,
        uniqExactIf(tuple(ip_address, computer_name), notEmpty(computer_name)) AS terminal_keys
    FROM encryption_terminal_inventory FINAL
    WHERE import_batch = {quoted_batch} AND {trust_condition}
    GROUP BY ip_address
    HAVING ip_rows > 1
) AS d USING ip_address
ORDER BY
    toUInt16OrZero(splitByChar('.', ip_address)[1]),
    toUInt16OrZero(splitByChar('.', ip_address)[2]),
    toUInt16OrZero(splitByChar('.', ip_address)[3]),
    toUInt16OrZero(splitByChar('.', ip_address)[4]),
    computer_name,
    mac_address
LIMIT {int(limit)}
FORMAT JSONEachRow
""",
    )


def encryption_terminal_duplicate_ip_count(config: AppConfig, batch_id: str) -> int:
    if not batch_id:
        return 0
    quoted_batch = decrypt_records.clickhouse_quote(batch_id)
    trust_condition = encryption_terminal_trust_condition()
    rows = encryption_terminal_query(
        config,
        f"""
SELECT count() AS rows
FROM
(
    SELECT ip_address
    FROM encryption_terminal_inventory FINAL
    WHERE import_batch = {quoted_batch} AND {trust_condition}
    GROUP BY ip_address
    HAVING count() > 1
)
FORMAT JSONEachRow
""",
    )
    return int(rows[0].get("rows") or 0) if rows else 0


def encryption_terminal_count(
    config: AppConfig,
    batch_id: str,
    duplicate_ip_only: bool = False,
    trust_state: str = "all",
) -> int:
    if not batch_id:
        return 0
    quoted_batch = decrypt_records.clickhouse_quote(batch_id)
    trust_condition = encryption_terminal_trust_condition()
    state_filter = ""
    if trust_state == "trusted":
        state_filter = f"AND {trust_condition}"
    elif trust_state == "excluded":
        state_filter = f"AND NOT ({trust_condition})"
    duplicate_filter = ""
    if duplicate_ip_only:
        duplicate_filter = f"""
AND ip_address IN (
    SELECT ip_address
    FROM encryption_terminal_inventory FINAL
    WHERE import_batch = {quoted_batch} AND {trust_condition}
    GROUP BY ip_address
    HAVING count() > 1
)
"""
    rows = encryption_terminal_query(
        config,
        f"""
SELECT count() AS rows
FROM encryption_terminal_inventory FINAL
WHERE import_batch = {quoted_batch}
{state_filter}
{duplicate_filter}
FORMAT JSONEachRow
""",
    )
    return int(rows[0].get("rows") or 0) if rows else 0


def encryption_terminal_records(
    config: AppConfig,
    batch_id: str,
    page: int = 1,
    page_size: int = 100,
    duplicate_ip_only: bool = False,
    trust_state: str = "all",
) -> list[dict[str, Any]]:
    if not batch_id:
        return []
    page = max(1, int(page or 1))
    page_size = min(200, max(50, int(page_size or 100)))
    offset = (page - 1) * page_size
    quoted_batch = decrypt_records.clickhouse_quote(batch_id)
    trust_condition = encryption_terminal_trust_condition()
    trust_status_sql = encryption_terminal_trust_status_sql()
    mac_key_sql = encryption_terminal_mac_key_sql()
    state_filter = ""
    if trust_state == "trusted":
        state_filter = f"AND {trust_condition}"
    elif trust_state == "excluded":
        state_filter = f"AND NOT ({trust_condition})"
    duplicate_filter = ""
    if duplicate_ip_only:
        duplicate_filter = f"""
AND ip_address IN (
    SELECT ip_address
    FROM encryption_terminal_inventory FINAL
    WHERE import_batch = {quoted_batch} AND {trust_condition}
    GROUP BY ip_address
    HAVING count() > 1
)
"""
    return encryption_terminal_query(
        config,
        f"""
SELECT
    t.ip_address AS ip_address,
    t.computer_name,
    t.mac_address,
    t.user_name,
    t.user_account,
    t.company,
    t.department,
    t.os_version,
    t.client_version,
    t.encryption_status,
    t.last_seen,
    t.is_trusted,
    t.trust_status,
    ifNull(d.ip_rows, 0) AS ip_rows,
    ifNull(m.trusted_mac_rows, 0) AS trusted_mac_rows,
    ifNull(m.trusted_mac_refs, '') AS trusted_mac_refs
FROM
(
    SELECT
        ip_address,
        computer_name,
        mac_address,
        user_name,
        user_account,
        company,
        department,
        os_version,
        client_version,
        encryption_status,
        last_seen,
        if({trust_condition}, 1, 0) AS is_trusted,
        {trust_status_sql} AS trust_status,
        {mac_key_sql} AS mac_key
    FROM encryption_terminal_inventory FINAL
    WHERE import_batch = {quoted_batch}
    {state_filter}
    {duplicate_filter}
) AS t
LEFT JOIN
(
    SELECT ip_address, count() AS ip_rows
    FROM encryption_terminal_inventory FINAL
    WHERE import_batch = {quoted_batch} AND {trust_condition}
    GROUP BY ip_address
) AS d USING ip_address
LEFT JOIN
(
    SELECT
        {mac_key_sql} AS mac_key,
        count() AS trusted_mac_rows,
        arrayStringConcat(groupUniqArray(concat(ip_address, ' / ', computer_name)), '；') AS trusted_mac_refs
    FROM encryption_terminal_inventory FINAL
    WHERE import_batch = {quoted_batch} AND {trust_condition} AND notEmpty({mac_key_sql})
    GROUP BY mac_key
) AS m USING mac_key
ORDER BY
    toUInt16OrZero(splitByChar('.', ip_address)[1]),
    toUInt16OrZero(splitByChar('.', ip_address)[2]),
    toUInt16OrZero(splitByChar('.', ip_address)[3]),
    toUInt16OrZero(splitByChar('.', ip_address)[4]),
    computer_name,
    mac_address
LIMIT {page_size} OFFSET {offset}
FORMAT JSONEachRow
""",
    )


def decrypt_org_candidates(config: AppConfig, policy_doc: dict[str, Any], limit: int = 80) -> list[dict[str, Any]]:
    aliases = decrypt_records.normalize_aliases(policy_doc)
    candidates = decrypt_query(
        config,
        f"""
SELECT raw_org_path, raw_company, raw_department, count() AS rows
FROM decrypt_records FINAL
GROUP BY raw_org_path, raw_company, raw_department
ORDER BY rows DESC
LIMIT {int(limit) * 3}
FORMAT JSONEachRow
""",
    )
    unresolved: list[dict[str, Any]] = []
    for row in candidates:
        raw_org_path = normalize_alias_text(row.get("raw_org_path"))
        raw_company = normalize_alias_text(row.get("raw_company"))
        raw_department = normalize_alias_text(row.get("raw_department"))
        _company, _department, matched = decrypt_records.resolve_org_alias(raw_org_path, raw_company, raw_department, aliases)
        if matched:
            continue
        row["suggestions"] = organization_alias_suggestions(config, raw_company)
        unresolved.append(row)
        if len(unresolved) >= limit:
            break
    return unresolved


def decrypt_all_orgs(config: AppConfig, policy_doc: dict[str, Any], limit: int = 5000) -> list[dict[str, Any]]:
    aliases = decrypt_records.normalize_aliases(policy_doc)
    rows = decrypt_query(
        config,
        f"""
SELECT raw_org_path, raw_company, raw_department, count() AS rows
FROM decrypt_records FINAL
GROUP BY raw_org_path, raw_company, raw_department
ORDER BY rows DESC
LIMIT {int(limit)}
FORMAT JSONEachRow
""",
    )
    result: list[dict[str, Any]] = []
    for row in rows:
        raw_org_path = normalize_alias_text(row.get("raw_org_path"))
        raw_company = normalize_alias_text(row.get("raw_company"))
        raw_department = normalize_alias_text(row.get("raw_department"))
        company, department, matched = decrypt_records.resolve_org_alias(raw_org_path, raw_company, raw_department, aliases)
        row["canonical_company"] = company
        row["canonical_department"] = department
        row["matched"] = matched
        result.append(row)
    return result


def compact_org_name(value: str) -> str:
    return re.sub(r"[\s（）()有限公司股份集团\-_/]", "", normalize_alias_text(value).lower())


def organization_alias_suggestions(config: AppConfig, raw_company: str, limit: int = 5) -> list[str]:
    raw = normalize_alias_text(raw_company)
    if not raw:
        return []
    compact_raw = compact_org_name(raw)
    companies, _departments = wecom_org_options(config)
    scored: list[tuple[int, str]] = []
    for company in companies:
        compact_company = compact_org_name(company)
        score = 0
        if raw == company:
            score = 100
        elif raw in company or company in raw:
            score = 85
        elif compact_raw and (compact_raw in compact_company or compact_company in compact_raw):
            score = 70
        for raw_terms, company_terms in ORG_ALIAS_HINTS:
            if all(term in compact_raw for term in raw_terms) and all(term in compact_company for term in company_terms):
                score = max(score, 90)
        if score:
            scored.append((score, company))
    return [company for _score, company in sorted(scored, key=lambda item: (-item[0], item[1]))[:limit]]


def safe_upload_filename(filename: str) -> str:
    name = Path(filename or "decrypt-records.xlsx").name.strip()
    name = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff._()（） -]+", "_", name)
    name = re.sub(r"\s+", " ", name).strip(" .")
    return (name or "decrypt-records.xlsx")[:160]


def organization_alias_from_form(form: dict[str, str], default_enabled: bool = True) -> dict[str, Any]:
    enabled = form.get("enabled") == "1" if "enabled" in form else default_enabled
    return {
        "raw_org_path": normalize_alias_text(form.get("raw_org_path")),
        "raw_company": normalize_alias_text(form.get("raw_company")),
        "raw_department": normalize_alias_text(form.get("raw_department")),
        "canonical_company": normalize_alias_text(form.get("canonical_company")),
        "canonical_department": normalize_alias_text(form.get("canonical_department")),
        "enabled": enabled,
        "note": normalize_alias_text(form.get("note")),
    }


def unique_rules(rules: list[dict[str, Any]], key_name: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for rule in rules:
        key = str(rule.get(key_name) or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(rule)
    return unique


def keyword_editor_text(rules: list[dict[str, Any]]) -> str:
    keywords: list[str] = []
    for rule in rules:
        keyword = str(rule.get("keyword") or "").strip()
        if not keyword:
            continue
        keywords.append(keyword)
    return ", ".join(keywords)


def parse_keyword_editor_text(text: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_item in form_list(text):
        line = raw_item.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("|")]
        keyword = parts[0] if parts else ""
        if not keyword:
            continue
        dedupe_key = keyword.lower()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        scope = parts[2] if len(parts) > 2 and parts[2] else "both"
        match_type = parts[3] if len(parts) > 3 and parts[3] else "contains"
        if scope not in {"both", "risk", "leadership"}:
            scope = "both"
        if match_type not in {"contains", "regex"}:
            match_type = "contains"
        rules.append(
            {
                "enabled": True,
                "keyword": keyword,
                "category": parts[1] if len(parts) > 1 else "",
                "scope": scope,
                "match_type": match_type,
                "note": parts[4] if len(parts) > 4 else "",
            }
        )
    return rules


def userids_editor_text(userids: list[str]) -> str:
    return ", ".join(str(item).strip() for item in userids if str(item).strip())


def auth_user_rows(config: AppConfig, userids: list[str]) -> str:
    cache = load_wecom_user_cache(config)
    rows = []
    for userid in userids:
        item = cache.get(str(userid).strip(), {})
        company, department = wecom_item_org_fields(item)
        rows.append(
            "<tr>"
            f"<td>{esc(userid)}</td>"
            f"<td>{esc(item.get('name') or '-')}</td>"
            f"<td>{esc(company or '-')}</td>"
            f"<td>{esc(department or '-')}</td>"
            f"<td>{esc(item.get('status') or '-')}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="5" class="muted">暂无账号。</td></tr>'


def settings_page(config: AppConfig) -> bytes:
    keyword_doc = load_keyword_doc(config)
    policy_doc = load_policy_doc(config)
    exclusion_doc = load_exclusion_doc(config)
    keywords = [rule for rule in keyword_doc.get("rules", []) if isinstance(rule, dict)]
    design = policy_doc.get("design_suffixes") if isinstance(policy_doc.get("design_suffixes"), dict) else {}
    internal_targets = policy_doc.get("internal_targets") if isinstance(policy_doc.get("internal_targets"), dict) else {}
    plm_login_audit = policy_doc.get("plm_login_audit") if isinstance(policy_doc.get("plm_login_audit"), dict) else {}
    organization_aliases = normalize_organization_aliases(policy_doc.get("organization_aliases"))
    three_d = design.get("three_d") or []
    two_d = design.get("two_d") or []
    critical_patterns = [item for item in policy_doc.get("critical_design_patterns", []) if isinstance(item, dict) and item.get("enabled", True)]
    archive_suffixes = policy_doc.get("archive_suffixes") if isinstance(policy_doc.get("archive_suffixes"), list) else []
    internal_domains = internal_targets.get("domains") or []
    internal_networks = internal_targets.get("networks") or []
    plm_departments = normalize_unique_text_list(plm_login_audit.get("constrained_departments") or DEFAULT_PLM_CONSTRAINED_DEPARTMENTS)
    exclusions = [rule for rule in exclusion_doc.get("rules", []) if isinstance(rule, dict)]
    auth = auth_policy(config)
    wecom_companies, _wecom_departments = wecom_org_options(config)
    recent_decrypt_batches = decrypt_import_batches(config, 1)
    decrypt_metric = "未导入"
    if recent_decrypt_batches:
        decrypt_metric = f"{int(recent_decrypt_batches[0].get('rows') or 0)} 条"
    terminal_pool = latest_encryption_terminal_pool(config)
    terminal_metric = "未导入"
    if terminal_pool:
        terminal_metric = f"{int(terminal_pool.get('trusted_terminal_keys') or 0)} 个授信终端键"
    body = f"""
    <header>
      <div>
        <h1>审计策略管理</h1>
        <div class="muted">敏感词、二维/三维图纸后缀、内部目标和软件同步排除都在这里维护；报表生成会按当前策略自动刷新 ClickHouse 派生索引。</div>
      </div>
      <div class="actions">
        <a class="button" href="/manual">自定义生成</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    <section class="settings-groups">
      <div class="settings-group">
        <div class="settings-group-head">
          <div>
            <p class="settings-group-kicker">RULES</p>
            <h2>文件识别规则</h2>
            <p class="muted">定义哪些附件对象进入审计矩阵，包括敏感名称、图纸、最高预警对象和压缩包。</p>
          </div>
        </div>
        <div class="settings-grid">
      <div class="settings-card">
        <h3>敏感词策略</h3>
        <p class="metric">{len(keywords)} 条</p>
        <p class="muted">逗号分隔集中维护，保存即覆盖当前敏感词策略。</p>
        <div class="actions"><a class="button primary" href="/settings/keywords">维护敏感词</a></div>
      </div>
      <div class="settings-card">
        <h3>图纸后缀策略</h3>
        <p class="metric">三维 {len(three_d)} / 二维 {len(two_d)}</p>
        <p class="muted">图纸后缀是强管控触发条件，不依赖敏感词命中。</p>
        <div class="actions"><a class="button primary" href="/settings/policy">维护图纸后缀</a></div>
      </div>
      <div class="settings-card">
        <h3>最高预警对象</h3>
        <p class="metric">{len(critical_patterns)} 类</p>
        <p class="muted">结构、电气、标准图纸优先于普通图纸对象。</p>
        <div class="actions"><a class="button primary" href="/settings/policy">查看规则</a></div>
      </div>
      <div class="settings-card">
        <h3>压缩包后缀策略</h3>
        <p class="metric">{len(archive_suffixes)} 个</p>
        <p class="muted">压缩包作为矩阵审计对象，替代原“其他”列。</p>
        <div class="actions"><a class="button primary" href="/settings/archive-suffixes">维护压缩包后缀</a></div>
      </div>
        </div>
      </div>

      <div class="settings-group">
        <div class="settings-group-head">
          <div>
            <p class="settings-group-kicker">NOISE CONTROL</p>
            <h2>内部目标与降噪</h2>
            <p class="muted">维护内部系统、内部网段和已知正常软件行为，降低首页和矩阵噪音。</p>
          </div>
        </div>
        <div class="settings-grid">
      <div class="settings-card">
        <h3>内部目标策略</h3>
        <p class="metric">域名 {len(internal_domains)} / 网段 {len(internal_networks)}</p>
        <p class="muted">维护不按外部目标统计的内部系统网段/域名。</p>
        <div class="actions"><a class="button primary" href="/settings/internal-targets">维护内部目标</a></div>
      </div>
      <div class="settings-card">
        <h3>排除策略</h3>
        <p class="metric">共 {len(exclusions)} 条，启用 {sum(1 for rule in exclusions if rule_enabled(rule))} 条</p>
        <p class="muted">用于搜狗输入法同步、浏览器配置同步等已知软件行为降噪；原始 syslog 不删除。</p>
        <div class="actions"><a class="button primary" href="/settings/exclusions">维护排除策略</a></div>
      </div>
        </div>
      </div>

      <div class="settings-group">
        <div class="settings-group-head">
          <div>
            <p class="settings-group-kicker">DATA SOURCES</p>
            <h2>解密与 PLM 数据源</h2>
            <p class="muted">维护加密软件解密记录、合规终端池和 PLM 登录审计的强约束部门。</p>
          </div>
        </div>
        <div class="settings-grid">
      <div class="settings-card">
        <h3>解密记录导入</h3>
        <p class="metric">{esc(decrypt_metric)}</p>
        <p class="muted">上传加密软件解密/外发申请 Excel，独立追踪标准图纸解密风险。</p>
        <div class="actions"><a class="button primary" href="/settings/decrypt-records">上传解密记录</a></div>
      </div>
      <div class="settings-card">
        <h3>加密终端列表</h3>
        <p class="metric">{esc(terminal_metric)}</p>
        <p class="muted">上传加密软件终端清单，最新批次中 7 天内在线的 IP+计算机名作为 PLM 授信终端池来源。</p>
        <div class="actions"><a class="button primary" href="/settings/encryption-terminals">上传终端列表</a></div>
      </div>
      <div class="settings-card">
        <h3>PLM登录审计策略</h3>
        <p class="metric">{len(plm_departments)} 个部门</p>
        <p class="muted">仅跟踪强约束部门账号；登录终端不在 7 天内在线的加密终端池时判一级风险。</p>
        <div class="actions"><a class="button primary" href="/settings/plm-login">维护PLM策略</a></div>
      </div>
      <div class="settings-card">
        <h3>风险终端复核策略</h3>
        <p class="metric">{'启用' if terminal_review.normalized_review_policy(policy_doc).get('enabled', True) else '关闭'}</p>
        <p class="muted">候选只保留标准图纸、大于100MB压缩包、普通图纸高频和敏感文件高频，人工确认后才进报告。</p>
        <div class="actions"><a class="button primary" href="/settings/terminal-behavior-review">维护核查阈值</a></div>
      </div>
        </div>
      </div>

      <div class="settings-group">
        <div class="settings-group-head">
          <div>
            <p class="settings-group-kicker">IDENTITY</p>
            <h2>组织与身份映射</h2>
            <p class="muted">统一企业微信通讯录、解密记录原始组织和审计报告中的公司部门口径。</p>
          </div>
        </div>
        <div class="settings-grid">
      <div class="settings-card">
        <h3>组织别名关联</h3>
        <p class="metric">{len(organization_aliases)} 条</p>
        <p class="muted">维护解密表原始组织到标准公司/部门的归一映射。</p>
        <div class="actions"><a class="button primary" href="/settings/organization-aliases">维护组织别名</a></div>
      </div>
      <div class="settings-card">
        <h3>组织结构映射</h3>
        <p class="metric">{len(wecom_companies)} 个公司</p>
        <p class="muted">树状查看企业微信路径会被解析到哪个标准公司/部门。</p>
        <div class="actions"><a class="button primary" href="/settings/organization-tree">查看映射树</a></div>
      </div>
        </div>
      </div>

      <div class="settings-group">
        <div class="settings-group-head">
          <div>
            <p class="settings-group-kicker">SYSTEM</p>
            <h2>系统能力与访问控制</h2>
            <p class="muted">维护全集团审计报告访问权限和系统级策略。</p>
          </div>
        </div>
        <div class="settings-grid">
      <div class="settings-card">
        <h3>认证与报表查看</h3>
        <p class="metric">查看用户 {len(auth["global_viewer_userids"])}</p>
        <p class="muted">策略管理员固定 userid=10056。</p>
        <p class="muted">授权用户登录后查看全集团审计报告。</p>
        <div class="actions"><a class="button primary" href="/settings/auth">维护认证权限</a></div>
      </div>
        </div>
      </div>
    </section>
"""
    return page_shell("审计策略管理", body)


def datetime_input_value(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M")


def terminal_check_policy_fingerprint(policy_doc: dict[str, Any]) -> str:
    payload = {key: value for key, value in policy_doc.items() if key != "updated_at"}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def terminal_check_cache_key(policy_doc: dict[str, Any], start: datetime, end: datetime) -> tuple[str, str, str]:
    return (datetime_input_value(start), datetime_input_value(end), terminal_check_policy_fingerprint(policy_doc))


def attach_terminal_review_state(
    candidates: list[terminal_review.TerminalBehaviorCandidate],
    reviews: list[terminal_review.TerminalBehaviorReview],
) -> None:
    existing = {review.candidate_id: review for review in reviews}
    for candidate in candidates:
        candidate.existing_status = ""
        candidate.existing_review_time = ""
        candidate.existing_conclusion = ""
        candidate.existing_notes = ""
        candidate.existing_owner_department = ""
        candidate.existing_due_date = ""
        review = existing.get(candidate.candidate_id)
        if review:
            candidate.existing_status = review.status
            candidate.existing_review_time = review.review_time
            candidate.existing_conclusion = review.conclusion
            candidate.existing_notes = review.notes
            candidate.existing_owner_department = review.owner_department
            candidate.existing_due_date = review.due_date


def terminal_check_prune_cache(now: float | None = None) -> None:
    now = time.time() if now is None else now
    for key, value in list(TERMINAL_CHECK_CACHE.items()):
        if now - float(value.get("created_at") or 0) > TERMINAL_CHECK_CACHE_TTL_SECONDS:
            event = value.get("event")
            TERMINAL_CHECK_CACHE.pop(key, None)
            if hasattr(event, "set"):
                event.set()
    if len(TERMINAL_CHECK_CACHE) <= TERMINAL_CHECK_CACHE_MAX_ENTRIES:
        return
    ordered = sorted(TERMINAL_CHECK_CACHE.items(), key=lambda item: float(item[1].get("created_at") or 0))
    for key, value in ordered[: max(0, len(TERMINAL_CHECK_CACHE) - TERMINAL_CHECK_CACHE_MAX_ENTRIES)]:
        event = value.get("event")
        TERMINAL_CHECK_CACHE.pop(key, None)
        if hasattr(event, "set"):
            event.set()


def terminal_check_payload(
    candidates: list[terminal_review.TerminalBehaviorCandidate],
    reviews: list[terminal_review.TerminalBehaviorReview],
) -> dict[str, Any]:
    attach_terminal_review_state(candidates, reviews)
    return {
        "candidates": candidates,
        "reviews": reviews,
        "by_id": {candidate.candidate_id: candidate for candidate in candidates},
    }


def terminal_check_build_payload(config: AppConfig, policy_doc: dict[str, Any], start: datetime, end: datetime) -> dict[str, Any]:
    candidates = terminal_review.generate_candidates(config, policy_doc, start, end)
    reviews = terminal_review.fetch_reviews(config, start, end, include_all_status=True)
    return terminal_check_payload(candidates, reviews)


def terminal_check_cache_entry(key: tuple[str, str, str]) -> dict[str, Any] | None:
    now = time.time()
    with TERMINAL_CHECK_CACHE_LOCK:
        terminal_check_prune_cache(now)
        entry = TERMINAL_CHECK_CACHE.get(key)
        if entry and now - float(entry.get("created_at") or 0) <= TERMINAL_CHECK_CACHE_TTL_SECONDS:
            return entry
    return None


def terminal_check_put_cache(
    policy_doc: dict[str, Any],
    start: datetime,
    end: datetime,
    candidates: list[terminal_review.TerminalBehaviorCandidate],
    reviews: list[terminal_review.TerminalBehaviorReview],
) -> dict[str, Any]:
    payload = terminal_check_payload(candidates, reviews)
    key = terminal_check_cache_key(policy_doc, start, end)
    value = {
        "created_at": time.time(),
        "status": "ready",
        "payload": payload,
    }
    with TERMINAL_CHECK_CACHE_LOCK:
        terminal_check_prune_cache(value["created_at"])
        existing = TERMINAL_CHECK_CACHE.get(key) or {}
        event = existing.get("event")
        if hasattr(event, "set"):
            value["event"] = event
        TERMINAL_CHECK_CACHE[key] = value
        if hasattr(event, "set"):
            event.set()
    return payload


def terminal_check_cached_data(
    config: AppConfig,
    policy_doc: dict[str, Any],
    start: datetime,
    end: datetime,
    *,
    wait_seconds: float = 0,
    build_if_missing: bool = True,
) -> dict[str, Any] | None:
    key = terminal_check_cache_key(policy_doc, start, end)
    entry = terminal_check_cache_entry(key)
    if entry and entry.get("status") == "ready":
        return entry.get("payload")
    if entry and entry.get("status") == "loading":
        event = entry.get("event")
        if hasattr(event, "wait") and wait_seconds > 0:
            event.wait(wait_seconds)
            entry = terminal_check_cache_entry(key)
            if entry and entry.get("status") == "ready":
                return entry.get("payload")
            if entry and entry.get("status") == "error" and build_if_missing:
                raise RuntimeError(str(entry.get("error") or "候选生成失败"))
        return None
    if not build_if_missing:
        return None

    event = threading.Event()
    with TERMINAL_CHECK_CACHE_LOCK:
        terminal_check_prune_cache()
        existing = TERMINAL_CHECK_CACHE.get(key)
        if existing and existing.get("status") == "ready":
            return existing.get("payload")
        if existing and existing.get("status") == "loading":
            event = existing.get("event")
            should_build = False
        else:
            TERMINAL_CHECK_CACHE[key] = {"created_at": time.time(), "status": "loading", "event": event}
            should_build = True
    if not should_build:
        if hasattr(event, "wait") and wait_seconds > 0:
            event.wait(wait_seconds)
            entry = terminal_check_cache_entry(key)
            if entry and entry.get("status") == "ready":
                return entry.get("payload")
            if entry and entry.get("status") == "error":
                raise RuntimeError(str(entry.get("error") or "候选生成失败"))
        return None

    try:
        payload = terminal_check_build_payload(config, policy_doc, start, end)
    except Exception as exc:
        with TERMINAL_CHECK_CACHE_LOCK:
            TERMINAL_CHECK_CACHE[key] = {
                "created_at": time.time(),
                "status": "error",
                "event": event,
                "error": f"{type(exc).__name__}: {str(exc)[:240]}",
            }
            event.set()
        raise
    with TERMINAL_CHECK_CACHE_LOCK:
        TERMINAL_CHECK_CACHE[key] = {
            "created_at": time.time(),
            "status": "ready",
            "event": event,
            "payload": payload,
        }
        event.set()
    return payload


def terminal_check_schedule_warm_cache(config: AppConfig, policy_doc: dict[str, Any], start: datetime, end: datetime) -> None:
    key = terminal_check_cache_key(policy_doc, start, end)
    with TERMINAL_CHECK_CACHE_LOCK:
        terminal_check_prune_cache()
        existing = TERMINAL_CHECK_CACHE.get(key)
        if existing and existing.get("status") in {"loading", "ready"}:
            return
        event = threading.Event()
        TERMINAL_CHECK_CACHE[key] = {"created_at": time.time(), "status": "loading", "event": event}

    def worker() -> None:
        try:
            payload = terminal_check_build_payload(config, policy_doc, start, end)
        except Exception as exc:
            with TERMINAL_CHECK_CACHE_LOCK:
                entry = TERMINAL_CHECK_CACHE.get(key) or {}
                event_obj = entry.get("event") or event
                TERMINAL_CHECK_CACHE[key] = {
                    "created_at": time.time(),
                    "status": "error",
                    "event": event_obj,
                    "error": f"{type(exc).__name__}: {str(exc)[:240]}",
                }
                if hasattr(event_obj, "set"):
                    event_obj.set()
            return
        with TERMINAL_CHECK_CACHE_LOCK:
            entry = TERMINAL_CHECK_CACHE.get(key) or {}
            event_obj = entry.get("event") or event
            TERMINAL_CHECK_CACHE[key] = {
                "created_at": time.time(),
                "status": "ready",
                "event": event_obj,
                "payload": payload,
            }
            if hasattr(event_obj, "set"):
                event_obj.set()

    threading.Thread(target=worker, name="terminal-check-cache-warm", daemon=True).start()


def terminal_check_clear_cache() -> None:
    with TERMINAL_CHECK_CACHE_LOCK:
        for value in TERMINAL_CHECK_CACHE.values():
            event = value.get("event")
            if hasattr(event, "set"):
                event.set()
        TERMINAL_CHECK_CACHE.clear()


def terminal_check_period_from_params(config: AppConfig, params: dict[str, list[str]]) -> tuple[datetime, datetime, str]:
    tz = local_tz(config.timezone)
    now = datetime.now(tz) if tz else datetime.now()
    preset = (params.get("preset") or ["today"])[-1]
    if preset == "yesterday":
        day = (now - timedelta(days=1)).date()
        return datetime.combine(day, datetime.min.time(), tz), datetime.combine(day + timedelta(days=1), datetime.min.time(), tz), preset
    if preset == "week":
        start_day = now.date() - timedelta(days=now.weekday())
        return datetime.combine(start_day, datetime.min.time(), tz), now, preset
    if preset == "custom":
        try:
            start = parse_local_datetime((params.get("start") or [""])[-1], config.timezone)
            end = parse_local_datetime((params.get("end") or [""])[-1], config.timezone)
            if end > start:
                return start, end, preset
        except ValueError:
            pass
    day = now.date()
    return datetime.combine(day, datetime.min.time(), tz), now, "today"


def terminal_review_status_options(selected: str = "待核查") -> str:
    return "".join(
        f'<option value="{esc(status)}"{" selected" if status == selected else ""}>{esc(status)}</option>'
        for status in terminal_review.REVIEW_STATUSES
    )


def terminal_check_css() -> str:
    return """
<style>
  .terminal-check-hero {
    border: 1px solid #d8e4f2;
    border-radius: 16px;
    padding: 18px 20px 16px;
    background: linear-gradient(180deg, #ffffff 0%, #fbfdff 100%);
    box-shadow: 0 12px 28px rgba(23, 32, 51, 0.05);
  }
  .terminal-check-scope {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    margin-top: 10px;
    padding-top: 12px;
    border-top: 1px solid #e7eef7;
  }
  .terminal-check-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    margin: 14px 0;
  }
  .terminal-check-chip {
    border: 1px solid #dbe6f3;
    border-radius: 10px;
    padding: 13px 14px;
    background: #fff;
  }
  .terminal-check-chip span {
    display: block;
    color: #667085;
    font-size: 12px;
    font-weight: 800;
  }
  .terminal-check-chip strong {
    display: block;
    margin-top: 4px;
    color: #122033;
    font-size: 25px;
    line-height: 1;
    font-weight: 900;
  }
  .terminal-check-review-form {
    display: block;
    width: 100%;
  }
  .terminal-check-section {
    margin-top: 18px;
  }
  .terminal-check-section-head {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 16px;
    width: 100%;
    margin: 0 0 12px;
    border-bottom: 1px solid #e6edf5;
    padding-bottom: 12px;
  }
  .terminal-check-section-head h2 {
    margin: 0;
    font-size: 19px;
    font-weight: 860;
    color: #122033;
  }
  .terminal-check-section-head p {
    margin: 5px 0 0;
  }
  .terminal-check-section-head .actions {
    margin: 0;
    flex: 0 0 auto;
  }
  .terminal-check-matrix-wrap {
    width: 100%;
    overflow-x: hidden;
    border: 1px solid #d8e4f2;
    border-radius: 13px;
    background: #fff;
  }
  .terminal-check-matrix {
    width: 100%;
    table-layout: fixed;
    border-collapse: collapse;
    font-size: 12px;
    background: #fff;
  }
  .terminal-check-matrix col.rank-col { width: 34px; }
  .terminal-check-matrix col.company-col { width: 96px; }
  .terminal-check-matrix col.department-col { width: 82px; }
  .terminal-check-matrix col.person-col { width: 74px; }
  .terminal-check-matrix col.ip-col { width: 94px; }
  .terminal-check-matrix col.number-col { width: 30px; }
  .terminal-check-matrix col.total-col { width: 44px; }
  .terminal-check-matrix col.action-col { width: 76px; }
  .terminal-check-matrix th,
  .terminal-check-matrix td {
    padding: 10px 3px;
    line-height: 1.24;
    text-align: center;
    vertical-align: middle;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .terminal-check-matrix thead th {
    color: #43546c;
    background: #f6f9fd;
    font-size: 10.5px;
    line-height: 1.15;
    font-weight: 820;
    white-space: normal;
  }
  .terminal-check-matrix .channel-head {
    background: #eaf3ff;
    border-left: 1px solid #d8e4f2;
    border-right: 1px solid #d8e4f2;
    font-weight: 860;
  }
  .terminal-check-matrix .identity-cell {
    text-align: left;
    color: #172033;
    font-weight: 720;
  }
  .terminal-check-matrix .ip-cell {
    text-align: left;
    color: #344054;
    font-weight: 500;
  }
  .terminal-check-matrix .rank-cell {
    color: #667085;
    font-weight: 780;
  }
  .terminal-check-matrix .matrix-zero {
    color: #c3cedb;
    font-size: 11px;
    font-weight: 740;
  }
  .terminal-check-matrix .matrix-count,
  .terminal-check-matrix .matrix-total {
    display: inline-flex;
    min-width: 24px;
    min-height: 22px;
    align-items: center;
    justify-content: center;
    border-radius: 999px;
    padding: 2px 6px;
    font-size: 12px;
    font-weight: 860;
    text-decoration: none;
    border-bottom: 0;
  }
  .terminal-check-matrix .matrix-total {
    border-radius: 8px;
  }
  .terminal-check-matrix .matrix-heat-low { background: #edf7f2; color: #24754f; }
  .terminal-check-matrix .matrix-heat-mid { background: #fff7df; color: #a15c00; }
  .terminal-check-matrix .matrix-heat-high { background: #fff0e8; color: #c2410c; }
  .terminal-check-matrix .matrix-heat-critical { background: #fee4e2; color: #b42318; }
  .terminal-check-matrix .review-action-cell {
    overflow: visible;
  }
  .terminal-check-action {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-height: 28px;
    width: 66px;
    border-radius: 999px;
    border: 1px solid #d8e4f2;
    padding: 4px 8px;
    background: #fff;
    color: #175cd3;
    font-size: 12px;
    font-weight: 820;
    white-space: nowrap;
  }
  .terminal-check-action.has-value {
    border-color: #9ed4c0;
    background: #f0fbf6;
    color: #067647;
  }
  .terminal-check-action.status-reviewed {
    border-color: #f4bf7a;
    background: #fff7e8;
    color: #b54708;
  }
  .terminal-check-hidden {
    display: none;
  }
  .terminal-check-live-status {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 16px 0 4px;
    color: #475467;
    font-size: 13px;
    font-weight: 760;
  }
  .terminal-check-live-status::before {
    content: "";
    width: 7px;
    height: 7px;
    border-radius: 999px;
    background: #175cd3;
    box-shadow: 11px 0 0 rgba(23, 92, 211, .38), 22px 0 0 rgba(23, 92, 211, .18);
    animation: terminalCheckDots 1.05s infinite ease-in-out;
  }
  .terminal-check-dot-value {
    position: relative;
    display: inline-flex;
    min-width: 22px;
    min-height: 20px;
    align-items: center;
    justify-content: center;
    color: transparent !important;
  }
  .terminal-check-dot-value::after {
    content: "...";
    position: absolute;
    inset: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: #175cd3;
    font-weight: 900;
    letter-spacing: 1px;
    animation: terminalCheckTextDots 1.05s infinite ease-in-out;
  }
  .terminal-check-skeleton-text {
    display: block;
    width: 72%;
    height: 10px;
    margin: 0 auto;
    border-radius: 999px;
    background: linear-gradient(110deg, #edf3fb 8%, #f8fbff 28%, #edf3fb 46%);
    background-size: 220% 100%;
    animation: terminalCheckShimmer 1.35s ease-in-out infinite;
  }
  .terminal-check-skeleton-text.short { width: 46%; }
  .terminal-check-live[data-terminal-check-loading="1"] .terminal-check-chip strong,
  .terminal-check-live[data-terminal-check-loading="1"] .terminal-check-chip span {
    position: relative;
    color: transparent !important;
  }
  .terminal-check-live[data-terminal-check-loading="1"] .terminal-check-chip strong::after {
    content: "...";
    position: absolute;
    inset: 0;
    display: inline-flex;
    align-items: center;
    color: #175cd3;
    font-weight: 900;
    letter-spacing: 1px;
    animation: terminalCheckTextDots 1.05s infinite ease-in-out;
  }
  .terminal-check-live[data-terminal-check-loading="1"] .terminal-check-chip span::after {
    content: attr(data-loading-label);
    position: absolute;
    inset: 0;
    display: inline-flex;
    align-items: center;
    color: #667085;
  }
  .terminal-check-loading {
    margin-top: 18px;
    border: 1px solid #d8e4f2;
    border-radius: 14px;
    padding: 22px;
    background: linear-gradient(180deg, #ffffff 0%, #f7fbff 100%);
    color: #43546c;
    box-shadow: 0 12px 26px rgba(23, 32, 51, 0.045);
  }
  .terminal-check-loading strong {
    display: block;
    margin-bottom: 6px;
    color: #122033;
    font-size: 17px;
    font-weight: 880;
  }
  .terminal-check-loading-bar {
    width: 100%;
    height: 7px;
    margin-top: 14px;
    overflow: hidden;
    border-radius: 999px;
    background: #e8f0fa;
  }
  .terminal-check-loading-bar::after {
    content: "";
    display: block;
    width: 38%;
    height: 100%;
    border-radius: inherit;
    background: linear-gradient(90deg, #2f80ed, #8ec5ff);
    animation: terminalCheckLoading 1.25s ease-in-out infinite;
  }
  @keyframes terminalCheckLoading {
    0% { transform: translateX(-105%); }
    100% { transform: translateX(275%); }
  }
  @keyframes terminalCheckDots {
    0%, 100% { box-shadow: 11px 0 0 rgba(23, 92, 211, .38), 22px 0 0 rgba(23, 92, 211, .18); }
    33% { box-shadow: 11px 0 0 #175cd3, 22px 0 0 rgba(23, 92, 211, .38); }
    66% { box-shadow: 11px 0 0 rgba(23, 92, 211, .38), 22px 0 0 #175cd3; }
  }
  @keyframes terminalCheckTextDots {
    0%, 100% { opacity: .42; }
    50% { opacity: 1; }
  }
  @keyframes terminalCheckShimmer {
    0% { background-position: 180% 0; }
    100% { background-position: -60% 0; }
  }
  @media (max-width: 980px) {
    .terminal-check-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .terminal-check-section-head { align-items: flex-start; flex-direction: column; }
  }
</style>
<script>
  (function () {
    var statuses = ["待核查", "异常待整改", "正常业务", "误报", "继续观察", "已闭环", "不纳入报告"];
    function markSelected(row) {
      var selected = row.querySelector(".terminal-check-selected");
      if (selected) selected.disabled = false;
    }
    function updateStatusButton(button, value) {
      button.textContent = value || "待核查";
      button.classList.toggle("status-reviewed", value && value !== "待核查");
      button.title = "点击切换核查状态";
    }
    function updateResultButton(button, value) {
      button.textContent = value ? "已填写" : "填写";
      button.classList.toggle("has-value", !!value);
      button.title = value || "点击填写核查结果";
    }
    document.addEventListener("click", function (event) {
      var statusButton = event.target.closest(".terminal-status-button");
      if (statusButton) {
        var row = statusButton.closest("tr");
        var input = row.querySelector("input[data-review-field='status']");
        var current = input.value || "待核查";
        var next = statuses[(Math.max(0, statuses.indexOf(current)) + 1) % statuses.length];
        input.value = next;
        updateStatusButton(statusButton, next);
        markSelected(row);
        return;
      }
      var resultButton = event.target.closest(".terminal-result-button");
      if (resultButton) {
        var row = resultButton.closest("tr");
        var input = row.querySelector("input[data-review-field='conclusion']");
        var value = window.prompt("填写核查结果", input.value || "");
        if (value === null) return;
        input.value = value.trim();
        updateResultButton(resultButton, input.value);
        markSelected(row);
      }
    });
  })();
</script>
"""


def terminal_check_metrics_html(candidates: list[terminal_review.TerminalBehaviorCandidate], reviews: list[terminal_review.TerminalBehaviorReview]) -> str:
    type_counts = Counter(candidate.anomaly_type for candidate in candidates)
    report_reviews = [review for review in reviews if review.include_in_report]
    chips = [
        ("候选异常终端", len(candidates)),
        ("已人工确认", len(reviews)),
        ("进入报告", len(report_reviews)),
        ("最高频类型", type_counts.most_common(1)[0][0] if type_counts else "-"),
    ]
    return '<div class="terminal-check-grid">' + "".join(
        f'<div class="terminal-check-chip"><span>{esc(label)}</span><strong>{esc(value)}</strong></div>' for label, value in chips
    ) + "</div>"


def terminal_check_loading_metrics_html() -> str:
    labels = ["候选异常终端", "已人工确认", "进入报告", "最高频类型"]
    return '<div class="terminal-check-grid">' + "".join(
        f'<div class="terminal-check-chip"><span data-loading-label="{esc(label)}">{esc(label)}</span><strong>...</strong></div>'
        for label in labels
    ) + "</div>"


def terminal_check_short_label(value: str) -> str:
    alias = report_gen.HTML_DISPLAY_LABEL_ALIASES.get(value, value)
    return report_gen.ORG_MATRIX_OBJECT_SHORT_LABELS.get(alias, report_gen.ORG_MATRIX_OBJECT_SHORT_LABELS.get(value, alias))


def terminal_check_matrix_count(candidate: terminal_review.TerminalBehaviorCandidate, channel: str, bucket: str) -> int:
    return int((candidate.matrix_counts or {}).get(f"{channel}\u241f{bucket}", 0) or 0)


def terminal_check_audit_event_from_row(row: dict[str, Any], tz: Any) -> report_gen.AuditEvent:
    event = report_gen.AuditEvent(
        event_id=str(row.get("event_id") or ""),
        ts=report_gen.parse_clickhouse_ts(row.get("ts"), tz) or row.get("parsed_ts"),
        topic=str(row.get("topic") or ""),
        channel=str(row.get("channel") or ""),
        person=str(row.get("person") or ""),
        account="",
        client_name=str(row.get("client_name") or ""),
        client_ip=str(row.get("client_ip") or ""),
        department=str(row.get("department") or ""),
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
        reasons=[str(item) for item in row.get("reasons") or []],
        resolved_person=str(row.get("resolved_person") or row.get("person") or ""),
        resolved_company=str(row.get("company") or ""),
        resolved_department=str(row.get("department") or ""),
        level=str(row.get("level") or "LOW"),
    )
    return event


def terminal_candidates_table(candidates: list[terminal_review.TerminalBehaviorCandidate], start: datetime, end: datetime) -> str:
    if not candidates:
        return '<p class="muted">当前周期暂无候选异常终端。</p>'
    start_value = datetime_input_value(start)
    end_value = datetime_input_value(end)
    base_channels = list(report_gen.CHANNEL_MATRIX_BASE_ROWS)
    dynamic_channels = sorted({channel for candidate in candidates for channel in candidate.channels if channel and channel not in base_channels})
    channels = base_channels + dynamic_channels
    columns = list(report_gen.CHANNEL_MATRIX_COLUMNS)
    detail_base = f"/terminal-check/events?preset=custom&start={quote(start_value)}&end={quote(end_value)}"
    channel_headers = "".join(
        f'<th class="channel-head" colspan="{len(columns)}" title="{esc(channel)}">{esc(report_gen.CHANNEL_MATRIX_SHORT_LABELS.get(channel, channel))}</th>'
        for channel in channels
    )
    object_headers = "".join(
        f'<th title="{esc(channel)} / {esc(column)}">{esc(terminal_check_short_label(column))}</th>'
        for channel in channels
        for column in columns
    )
    colgroup = (
        '<colgroup>'
        '<col class="rank-col"><col class="company-col"><col class="department-col"><col class="person-col"><col class="ip-col">'
        + "".join('<col class="number-col">' for _ in range(len(channels) * len(columns)))
        + '<col class="total-col"><col class="action-col"><col class="action-col">'
        '</colgroup>'
    )
    all_counts = [
        terminal_check_matrix_count(candidate, channel, column)
        for candidate in candidates
        for channel in channels
        for column in columns
    ]
    total_counts = [sum(terminal_check_matrix_count(candidate, channel, column) for channel in channels for column in columns) for candidate in candidates]
    count_thresholds = report_gen.heat_thresholds_from_counts(all_counts)
    total_thresholds = report_gen.heat_thresholds_from_counts(total_counts)
    rows: list[str] = []
    for idx, candidate in enumerate(candidates, 1):
        selected_disabled = "" if candidate.existing_status else " disabled"
        status = candidate.existing_status or "待核查"
        status_class = " status-reviewed" if status != "待核查" else ""
        result_class = " has-value" if candidate.existing_conclusion else ""
        detail_href = f"{detail_base}&candidate_id={quote(candidate.candidate_id)}"
        matrix_cells: list[str] = []
        for channel in channels:
            for column in columns:
                count = terminal_check_matrix_count(candidate, channel, column)
                title = f"{candidate.company or '-'} / {candidate.person or '-'}：{channel} / {column}明细"
                matrix_cells.append(f"<td>{report_gen.matrix_number_html(count, detail_href if count else '', title, count_thresholds)}</td>")
        total_count = int(total_counts[idx - 1] or candidate.event_count or 0)
        rows.append(
            f"""
<tr>
  <td class="rank-cell">{idx}</td>
  <td class="identity-cell" title="{esc(candidate.company)}">{esc(candidate.company or "-")}</td>
  <td class="identity-cell" title="{esc(candidate.department)}">{esc(candidate.department or "-")}</td>
  <td class="identity-cell" title="{esc(candidate.person)}">{esc(candidate.person or "-")}</td>
  <td class="ip-cell" title="{esc(candidate.client_ip)}">{esc(candidate.client_ip or "-")}</td>
  {''.join(matrix_cells)}
  <td>{report_gen.matrix_number_html(total_count, detail_href, "查看该候选终端明细", total_thresholds, total=True)}</td>
  <td class="review-action-cell">
    <input class="terminal-check-selected terminal-check-hidden" type="hidden" name="candidate__{esc(candidate.candidate_id)}" value="1"{selected_disabled}>
    <input class="terminal-check-hidden" data-review-field="status" type="hidden" name="status__{esc(candidate.candidate_id)}" value="{esc(status)}">
    <button class="terminal-check-action terminal-status-button{status_class}" type="button">{esc(status)}</button>
  </td>
  <td class="review-action-cell">
    <input class="terminal-check-hidden" data-review-field="conclusion" type="hidden" name="conclusion__{esc(candidate.candidate_id)}" value="{esc(candidate.existing_conclusion)}">
    <button class="terminal-check-action terminal-result-button{result_class}" type="button" title="{esc(candidate.existing_conclusion or '点击填写核查结果')}">{esc('已填写' if candidate.existing_conclusion else '填写')}</button>
  </td>
</tr>"""
        )
    return f"""
<div class="terminal-check-matrix-wrap">
  <table class="terminal-check-matrix" data-matrix-data-cols="{len(channels) * len(columns)}">
    {colgroup}
    <thead>
      <tr>
        <th rowspan="2">#</th>
        <th rowspan="2">公司</th>
        <th rowspan="2">部门</th>
        <th rowspan="2">使用人</th>
        <th rowspan="2">IP地址</th>
        {channel_headers}
        <th rowspan="2">合计</th>
        <th rowspan="2">核查状态</th>
        <th rowspan="2">核查结果</th>
      </tr>
      <tr>{object_headers}</tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>
"""


def terminal_check_matrix_colgroup(channels: list[str], columns: list[str]) -> str:
    return (
        '<colgroup>'
        '<col class="rank-col"><col class="company-col"><col class="department-col"><col class="person-col"><col class="ip-col">'
        + "".join('<col class="number-col">' for _ in range(len(channels) * len(columns)))
        + '<col class="total-col"><col class="action-col"><col class="action-col">'
        '</colgroup>'
    )


def terminal_check_matrix_headers(channels: list[str], columns: list[str]) -> tuple[str, str]:
    channel_headers = "".join(
        f'<th class="channel-head" colspan="{len(columns)}" title="{esc(channel)}">{esc(report_gen.CHANNEL_MATRIX_SHORT_LABELS.get(channel, channel))}</th>'
        for channel in channels
    )
    object_headers = "".join(
        f'<th title="{esc(channel)} / {esc(column)}">{esc(terminal_check_short_label(column))}</th>'
        for channel in channels
        for column in columns
    )
    return channel_headers, object_headers


def terminal_candidates_loading_table(row_count: int = 8) -> str:
    channels = list(report_gen.CHANNEL_MATRIX_BASE_ROWS)
    columns = list(report_gen.CHANNEL_MATRIX_COLUMNS)
    channel_headers, object_headers = terminal_check_matrix_headers(channels, columns)
    colgroup = terminal_check_matrix_colgroup(channels, columns)
    matrix_cell_count = len(channels) * len(columns)
    rows: list[str] = []
    for idx in range(1, row_count + 1):
        matrix_cells = "".join('<td><span class="terminal-check-dot-value">...</span></td>' for _ in range(matrix_cell_count))
        rows.append(
            f"""
<tr>
  <td class="rank-cell">{idx}</td>
  <td class="identity-cell"><span class="terminal-check-skeleton-text"></span></td>
  <td class="identity-cell"><span class="terminal-check-skeleton-text short"></span></td>
  <td class="identity-cell"><span class="terminal-check-skeleton-text short"></span></td>
  <td class="ip-cell"><span class="terminal-check-skeleton-text"></span></td>
  {matrix_cells}
  <td><span class="terminal-check-dot-value">...</span></td>
  <td class="review-action-cell"><span class="terminal-check-action">待核查</span></td>
  <td class="review-action-cell"><span class="terminal-check-action">填写</span></td>
</tr>"""
        )
    return f"""
<div class="terminal-check-matrix-wrap">
  <table class="terminal-check-matrix" data-matrix-data-cols="{matrix_cell_count}">
    {colgroup}
    <thead>
      <tr>
        <th rowspan="2">#</th>
        <th rowspan="2">公司</th>
        <th rowspan="2">部门</th>
        <th rowspan="2">使用人</th>
        <th rowspan="2">IP地址</th>
        {channel_headers}
        <th rowspan="2">合计</th>
        <th rowspan="2">核查状态</th>
        <th rowspan="2">核查结果</th>
      </tr>
      <tr>{object_headers}</tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>
"""


def terminal_reviews_table(reviews: list[terminal_review.TerminalBehaviorReview]) -> str:
    if not reviews:
        return '<p class="muted">当前周期暂无已保存核查记录。</p>'
    rows = []
    for review in reviews:
        rows.append(
            f"""
<tr>
  <td>{esc(review.event_start[:19])}</td>
  <td title="{esc(review.anomaly_type)}">{esc(review.anomaly_type)}</td>
  <td>{esc(review.company)}<br><span class="muted">{esc(review.department)}</span></td>
  <td>{esc(review.person)}</td>
  <td>{esc(review.client_ip)}</td>
  <td>{esc(review.event_count)}</td>
  <td><span class="terminal-check-action status-reviewed">{esc(review.status)}</span></td>
  <td class="compact" title="{esc(review.conclusion)}">{esc(review.conclusion or "-")}</td>
  <td>{esc(review.reviewer_name or review.reviewer_userid)}<br><span class="muted">{esc(review.review_time[:19])}</span></td>
  <td>{esc('是' if review.include_in_report else '否')}</td>
</tr>"""
        )
    return f"""
<div class="table-wrap">
  <table class="terminal-check-table">
    <thead><tr><th>事件时间</th><th>入选原因</th><th>公司/部门</th><th>使用人</th><th>IP地址</th><th>事件数</th><th>核查状态</th><th>核查结果</th><th>审核人</th><th>进入报告</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>
"""


def terminal_reviews_loading_table(row_count: int = 3) -> str:
    rows = []
    for _idx in range(row_count):
        rows.append(
            """
<tr>
  <td><span class="terminal-check-skeleton-text"></span></td>
  <td><span class="terminal-check-skeleton-text"></span></td>
  <td><span class="terminal-check-skeleton-text"></span></td>
  <td><span class="terminal-check-skeleton-text short"></span></td>
  <td><span class="terminal-check-skeleton-text"></span></td>
  <td><span class="terminal-check-dot-value">...</span></td>
  <td><span class="terminal-check-action">待核查</span></td>
  <td><span class="terminal-check-skeleton-text short"></span></td>
  <td><span class="terminal-check-skeleton-text"></span></td>
  <td><span class="terminal-check-dot-value">...</span></td>
</tr>"""
        )
    return f"""
<div class="table-wrap">
  <table class="terminal-check-table">
    <thead><tr><th>事件时间</th><th>入选原因</th><th>公司/部门</th><th>使用人</th><th>IP地址</th><th>事件数</th><th>核查状态</th><th>核查结果</th><th>审核人</th><th>进入报告</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>
"""


def terminal_check_work_area_html(
    candidates: list[terminal_review.TerminalBehaviorCandidate],
    reviews: list[terminal_review.TerminalBehaviorReview],
    start: datetime,
    end: datetime,
    summary_only: bool = False,
) -> str:
    wrapper_attr = ' data-terminal-check-summary="1"' if summary_only else ' data-terminal-check-ready="1"'
    save_button = (
        '<button class="primary" type="button" disabled title="证据明细正在后台补齐，完成后可保存复核结果">证据补齐后可保存</button>'
        if summary_only
        else '<button class="primary" type="submit">保存核查结果</button>'
    )
    note = (
        "矩阵数字已按 ClickHouse 聚合快速刷新；证据明细和保存能力正在后台补齐。"
        if summary_only
        else "矩阵口径与报告首页终端风险保持一致；点击“核查状态”切换状态，点击“核查结果”填写结论。"
    )
    saved_note = "已保存记录已刷新；候选证据补齐完成后可下钻查看。" if summary_only else "周报按事件发生时间自动汇总本周期已进入报告的核查记录。"
    return f"""
<div{wrapper_attr}>
  {terminal_check_metrics_html(candidates, reviews)}
  <form class="terminal-check-review-form" method="post" action="/terminal-check/review">
    <input type="hidden" name="start" value="{esc(datetime_input_value(start))}">
    <input type="hidden" name="end" value="{esc(datetime_input_value(end))}">
    <section class="terminal-check-section">
      <div class="terminal-check-section-head">
        <div>
          <h2>候选异常终端</h2>
          <p class="muted">{esc(note)}</p>
        </div>
        <div class="actions">{save_button}</div>
      </div>
      {terminal_candidates_table(candidates, start, end)}
    </section>
  </form>
  <section>
    <h2>已保存核查记录</h2>
    <p class="muted">{esc(saved_note)}</p>
    {terminal_reviews_table(reviews)}
  </section>
</div>
"""


def terminal_check_loading_html(start: datetime, end: datetime) -> str:
    return f"""
<div class="terminal-check-live" data-terminal-check-loading="1">
  <p class="terminal-check-live-status">风险终端候选正在计算，矩阵结构已就绪，数字和候选行稍后自动刷新</p>
  {terminal_check_loading_metrics_html()}
  <form class="terminal-check-review-form" method="post" action="/terminal-check/review" aria-busy="true">
    <input type="hidden" name="start" value="{esc(datetime_input_value(start))}">
    <input type="hidden" name="end" value="{esc(datetime_input_value(end))}">
    <section class="terminal-check-section">
      <div class="terminal-check-section-head">
        <div>
          <h2>候选异常终端</h2>
          <p class="muted">候选按当前报告周期后台聚合；完成后可点击矩阵数字查看证据并保存核查结果。</p>
        </div>
        <div class="actions"><button class="primary" type="button" disabled>保存核查结果</button></div>
      </div>
      {terminal_candidates_loading_table()}
    </section>
  </form>
  <section>
    <h2>已保存核查记录</h2>
    <p class="muted">已保存记录会随候选计算一起刷新。</p>
    {terminal_reviews_loading_table()}
  </section>
</div>
"""


def terminal_check_error_html(message: str) -> str:
    return f"""
<div class="terminal-check-loading">
  <strong>风险终端候选生成失败</strong>
  <div class="badge off danger">{esc(message)}</div>
  <p class="muted">请刷新页面重试；如果仍失败，需要检查 ClickHouse 或审计底稿查询。</p>
</div>
"""


def terminal_check_fragment_url(start: datetime, end: datetime) -> str:
    return "/api/terminal-check-fragment?" + urlencode(
        {"preset": "custom", "start": datetime_input_value(start), "end": datetime_input_value(end)}
    )


def terminal_check_fragment_html(config: AppConfig, start: datetime, end: datetime) -> bytes:
    policy_doc = load_policy_doc(config)
    key = terminal_check_cache_key(policy_doc, start, end)
    entry = terminal_check_cache_entry(key)
    if entry and entry.get("status") == "ready":
        payload = entry.get("payload") or {}
        return terminal_check_work_area_html(payload.get("candidates") or [], payload.get("reviews") or [], start, end).encode("utf-8")
    if entry and entry.get("status") == "error":
        return terminal_check_error_html(str(entry.get("error") or "候选生成失败")).encode("utf-8")
    try:
        candidates = terminal_review.generate_candidate_summaries(config, policy_doc, start, end)
        reviews = terminal_review.fetch_reviews(config, start, end, include_all_status=True)
        html_text = terminal_check_work_area_html(candidates, reviews, start, end, summary_only=True)
    except Exception:
        html_text = terminal_check_loading_html(start, end)
    terminal_check_schedule_warm_cache(config, policy_doc, start, end)
    return html_text.encode("utf-8")


def terminal_check_loader_script(start: datetime, end: datetime) -> str:
    fragment_url = terminal_check_fragment_url(start, end)
    fragment_url_json = json.dumps(fragment_url, ensure_ascii=False).replace("</", "<\\/")
    return f"""
<script id="terminal-check-loader">
  (function () {{
    var target = document.getElementById("terminal-check-dynamic");
    if (!target) return;
    var url = {fragment_url_json};
    var timer = null;
    function renderError(message) {{
      target.innerHTML = '<div class="terminal-check-loading"><strong>风险终端候选加载失败</strong><div class="badge off danger">' +
        message.replace(/[&<>"']/g, function (ch) {{ return ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[ch]; }}) +
        '</div><p class="muted">请刷新页面重试。</p></div>';
    }}
    function load() {{
      window.clearTimeout(timer);
      fetch(url, {{ credentials: "same-origin", cache: "no-store" }})
        .then(function (response) {{
          if (!response.ok) throw new Error("HTTP " + response.status);
          return response.text();
        }})
        .then(function (html) {{
          target.innerHTML = html;
          if (target.querySelector("[data-terminal-check-loading='1'],[data-terminal-check-summary='1']")) {{
            timer = window.setTimeout(load, 2000);
          }}
        }})
        .catch(function (error) {{
          renderError(error && error.message ? error.message : "加载失败");
        }});
    }}
    if (target.querySelector("[data-terminal-check-ready='1']")) {{
      return;
    }}
    if (target.querySelector("[data-terminal-check-summary='1']")) {{
      timer = window.setTimeout(load, 2000);
    }} else {{
      load();
    }}
  }})();
</script>
"""


def terminal_check_page(config: AppConfig, session: AuthSession, params: dict[str, list[str]] | None = None, message: str = "", error: str = "") -> bytes:
    params = params or {}
    start, end, preset = terminal_check_period_from_params(config, params)
    policy_doc = load_policy_doc(config)
    initial_fragment = terminal_check_fragment_html(config, start, end).decode("utf-8")
    body = f"""
    <header>
      <div>
        <h1>风险终端复核</h1>
        <div class="muted">按当前报告周期提取一级风险与终端高频明细候选，人工确认后进入日报/周报核查记录。</div>
      </div>
      <div class="actions">
        <a class="button" href="/">当前报告首页</a>
        <a class="button" href="/settings">策略管理</a>
      </div>
    </header>
    {terminal_check_css()}
    <section class="terminal-check-hero">
      <div>
        <h2 style="margin:0;font-size:19px;">核查候选概览</h2>
        <p class="muted">当前页面不提供独立周期选择，默认跟随报表入口传入的统计周期。</p>
      </div>
      <div class="terminal-check-scope">
        <span class="muted">当前周期：{esc(start.strftime('%Y-%m-%d %H:%M'))} 至 {esc(end.strftime('%Y-%m-%d %H:%M'))}</span>
        <span class="muted">点击矩阵数字查看对应候选终端证据。</span>
      </div>
      {f'<p class="badge on">{esc(message)}</p>' if message else ''}
      {f'<p class="badge off danger">{esc(error)}</p>' if error else ''}
    </section>
    <section id="terminal-check-dynamic">{initial_fragment}</section>
    {terminal_check_loader_script(start, end)}
"""
    return page_shell("风险终端复核", body)


def terminal_check_events_page(config: AppConfig, params: dict[str, list[str]]) -> bytes:
    start, end, _preset = terminal_check_period_from_params(config, params)
    candidate_id = (params.get("candidate_id") or [""])[-1]
    detail_events: list[report_gen.AuditEvent] = []
    title = "异常终端候选证据"
    if candidate_id:
        cached_data = terminal_check_cached_data(config, load_policy_doc(config), start, end, wait_seconds=90)
        candidate = (cached_data or {}).get("by_id", {}).get(candidate_id)
        if candidate:
            title = f"{candidate.anomaly_type} / {candidate.client_ip}"
            tz = local_tz(config.timezone)
            detail_events = [terminal_check_audit_event_from_row(row, tz) for row in candidate.evidence_events]
    table_html = (
        '<p class="muted">未找到候选证据，可能候选周期已变化。</p>'
        if not detail_events
        else report_gen.event_detail_table_html(detail_events, local_tz(config.timezone), page_size=50)
    )
    body = f"""
    <header>
      <div><h1>{esc(title)}</h1><div class="muted">本页直接复用报表重点明细事件与报表同款清单渲染，不再单独查询 ClickHouse 拼接简表。</div></div>
      <div class="actions"><a class="button" href="/terminal-check?start={esc(datetime_input_value(start))}&end={esc(datetime_input_value(end))}&preset=custom">返回复核工作台</a></div>
    </header>
    {table_html}
"""
    return page_shell(title, body)


def terminal_behavior_policy_page(config: AppConfig, message: str = "", error: str = "") -> bytes:
    doc = load_policy_doc(config)
    policy = terminal_review.normalized_review_policy(doc)
    field_labels = [
        ("other_drawing_min_events", "普通图纸流转阈值"),
        ("sensitive_name_min_events", "敏感文件流转阈值"),
        ("candidate_limit", "候选列表上限"),
    ]
    inputs = "".join(
        f'<label>{esc(label)}<input type="number" min="0" name="{esc(key)}" value="{esc(policy.get(key, terminal_review.DEFAULT_REVIEW_POLICY[key]))}"></label>'
        for key, label in field_labels
    )
    body = f"""
    <header>
      <div><h1>风险终端复核策略</h1><div class="muted">候选只取标准图纸流转、大于100MB压缩包流转、普通图纸超过阈值、敏感文件超过阈值四类；同一终端同一周期只生成一条候选。</div></div>
      <div class="actions"><a class="button" href="/settings">策略中心</a><a class="button" href="/terminal-check">复核工作台</a></div>
    </header>
    {f'<p class="badge on">{esc(message)}</p>' if message else ''}
    {f'<p class="badge off danger">{esc(error)}</p>' if error else ''}
    <form method="post" action="/settings/terminal-behavior-review/save">
      <label>启用状态
        <select name="enabled">
          <option value="1"{" selected" if policy.get("enabled", True) else ""}>启用</option>
          <option value="0"{" selected" if not policy.get("enabled", True) else ""}>关闭</option>
        </select>
      </label>
      {inputs}
      <p class="muted full">当前口径：标准图纸和大于100MB压缩包经邮件、IM、外部站点上传或外设拷贝等通道流转即入候选；普通三维/DWG 图纸默认超过 100 条入候选；敏感名称文件默认超过 1000 条入候选。</p>
      <div class="actions"><button class="primary" type="submit">保存复核策略</button></div>
    </form>
"""
    return page_shell("风险终端复核策略", body)


def keywords_page(config: AppConfig, message: str = "") -> bytes:
    doc = load_keyword_doc(config)
    rules = [rule for rule in doc.get("rules", []) if isinstance(rule, dict)]
    rows = []
    for rule in rules:
        rows.append(
            "<tr>"
            f"<td>{esc(rule.get('keyword', ''))}</td>"
            f"<td>{esc(rule.get('category', '') or '-')}</td>"
            "</tr>"
        )
    table = "".join(rows) or '<tr><td colspan="2" class="muted">暂无敏感词。</td></tr>'
    editor_text = keyword_editor_text(rules)
    msg = f'<p class="muted">{esc(message)}</p>' if message else ""
    body = f"""
    <header>
      <div>
        <h1>敏感词策略</h1>
        <div class="muted">系统不内置敏感词；当前全部来自 {esc(keywords_path(config))}。</div>
      </div>
      <div class="actions">
        <a class="button" href="/settings">策略中心</a>
        <a class="button" href="/manual">自定义生成</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    {msg}
    <section class="panel">
      <h2>编辑敏感词</h2>
      <form method="post" action="/settings/keywords/save">
        <label class="full">敏感词，逗号分隔；需要分类时可写成“关键词|财务”
          <textarea name="keywords" spellcheck="false" placeholder="借款合同, 授信资料, 征信报告, 报价成本, 工资, 审计报告">{esc(editor_text)}</textarea>
        </label>
        <p class="muted full">保存后覆盖当前敏感词列表；系统不再内置基础词。分类不是必填，确实需要时建议使用财务、质量、技术、采购、人事等业务分类。</p>
        <div class="full actions"><button class="primary" type="submit">保存覆盖</button></div>
      </form>
    </section>
    <h2>保存预览</h2>
    <div class="table-wrap"><table><thead><tr><th>关键词</th><th>分类</th></tr></thead><tbody>{table}</tbody></table></div>
"""
    return page_shell("敏感词策略", body)


def critical_pattern_examples_html(item: dict[str, Any], field: str) -> str:
    default = next((row for row in DEFAULT_CRITICAL_DESIGN_PATTERNS if row.get("key") == item.get("key")), {})
    values = item.get(field)
    if not isinstance(values, list):
        values = default.get(field)
    examples = [str(value).strip() for value in values or [] if str(value).strip()]
    if not examples:
        return '<span class="muted">-</span>'
    return '<div class="example-list">' + "".join(f"<code>{esc(value)}</code>" for value in examples) + "</div>"


def policy_page(config: AppConfig, message: str = "") -> bytes:
    doc = load_policy_doc(config)
    design = doc.get("design_suffixes") if isinstance(doc.get("design_suffixes"), dict) else {}
    three_d = ", ".join(str(item).lstrip(".") for item in design.get("three_d", []) if str(item).strip())
    two_d = ", ".join(str(item).lstrip(".") for item in design.get("two_d", []) if str(item).strip())
    critical_patterns = [item for item in doc.get("critical_design_patterns", []) if isinstance(item, dict)]
    critical_rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('label') or item.get('key') or '-')}</td>"
        f"<td>{esc('启用' if item.get('enabled', True) else '停用')}</td>"
        f"<td>{esc(item.get('description') or '-')}</td>"
        f"<td>{critical_pattern_examples_html(item, 'match_examples')}</td>"
        f"<td>{critical_pattern_examples_html(item, 'miss_examples')}</td>"
        f"<td><code class=\"regex-code\">{esc(item.get('regex') or '-')}</code></td>"
        "</tr>"
        for item in critical_patterns
    ) or '<tr><td colspan="6" class="muted">暂无最高预警对象规则。</td></tr>'
    msg = f'<p class="muted">{esc(message)}</p>' if message else ""
    body = f"""
    <header>
      <div>
        <h1>图纸后缀策略</h1>
        <div class="muted">图纸后缀属于强管控策略，命中后进入重点复核，不依赖敏感词。</div>
      </div>
      <div class="actions">
        <a class="button" href="/settings">策略中心</a>
        <a class="button" href="/manual">自定义生成</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    {msg}
    <section class="panel">
      <h2>编辑图纸后缀</h2>
      <form method="post" action="/settings/policy/save">
        <label class="full">三维模型后缀，逗号分隔
          <textarea name="three_d" spellcheck="false" placeholder="prt, asm, sldasm, sldprt, step">{esc(three_d)}</textarea>
        </label>
        <label class="full">二维图纸后缀，逗号分隔
          <textarea name="two_d" spellcheck="false" placeholder="dwg">{esc(two_d)}</textarea>
        </label>
        <p class="muted full">保存后，下一次报告生成会自动重建 ClickHouse 派生事件索引，原始 syslog 不会被修改。</p>
        <div class="full actions"><button class="primary" type="submit">保存覆盖</button></div>
      </form>
    </section>
    <section class="panel">
      <h2>最高预警对象规则</h2>
      <p class="muted">命中后优先于普通三维模型和 DWG 图纸，进入最高预警对象；压缩包内部文件不解析。</p>
      <div class="table-wrap"><table class="critical-rule-table"><thead><tr><th>对象</th><th>状态</th><th>规则说明</th><th>命中示例</th><th>不命中示例</th><th>正则</th></tr></thead><tbody>{critical_rows}</tbody></table></div>
    </section>
"""
    return page_shell("图纸后缀策略", body)


def internal_targets_page(config: AppConfig, message: str = "") -> bytes:
    doc = load_policy_doc(config)
    internal_targets = doc.get("internal_targets") if isinstance(doc.get("internal_targets"), dict) else {}
    internal_domains = ", ".join(str(item).strip() for item in internal_targets.get("domains", []) if str(item).strip())
    internal_networks = ", ".join(str(item).strip() for item in internal_targets.get("networks", []) if str(item).strip())
    msg = f'<p class="muted">{esc(message)}</p>' if message else ""
    body = f"""
    <header>
      <div>
        <h1>内部目标策略</h1>
        <div class="muted">维护内部系统域名和网段，命中后不按外部站点上传或高风险外联目标统计。</div>
      </div>
      <div class="actions">
        <a class="button" href="/settings">策略中心</a>
        <a class="button" href="/manual">自定义生成</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    {msg}
    <section class="panel">
      <h2>编辑内部目标</h2>
      <form method="post" action="/settings/internal-targets/save">
        <label class="full">内部域名，逗号分隔
          <textarea name="internal_domains" spellcheck="false" placeholder="daqo.com, oa.daqo.com">{esc(internal_domains)}</textarea>
        </label>
        <label class="full">内部网段，CIDR 或简写，逗号分隔
          <textarea name="internal_networks" spellcheck="false" placeholder="172.88.0.0/16, 172.188.0.0/16">{esc(internal_networks)}</textarea>
        </label>
        <p class="muted full">支持 CIDR，也支持简写：172.188 会保存为 172.188.0.0/16，172.16.20 会保存为 172.16.20.0/24。原始 syslog 和 ClickHouse 底稿不删除。</p>
        <div class="full actions"><button class="primary" type="submit">保存覆盖</button></div>
      </form>
    </section>
"""
    return page_shell("内部目标策略", body)


def archive_suffixes_page(config: AppConfig, message: str = "") -> bytes:
    doc = load_policy_doc(config)
    suffixes = doc.get("archive_suffixes") if isinstance(doc.get("archive_suffixes"), list) else DEFAULT_ARCHIVE_SUFFIXES
    archive_text = ", ".join(str(item).lstrip(".") for item in suffixes if str(item).strip())
    msg = f'<p class="muted">{esc(message)}</p>' if message else ""
    body = f"""
    <header>
      <div>
        <h1>压缩包后缀策略</h1>
        <div class="muted">压缩包作为独立审计对象进入矩阵，替代原“其他”列。</div>
      </div>
      <div class="actions">
        <a class="button" href="/settings">策略中心</a>
        <a class="button" href="/manual">自定义生成</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    {msg}
    <section class="panel">
      <h2>编辑压缩包后缀</h2>
      <form method="post" action="/settings/archive-suffixes/save">
        <label class="full">压缩包后缀，逗号分隔
          <textarea name="archive_suffixes" spellcheck="false" placeholder="zip, rar, 7z, tar, gz, tgz">{esc(archive_text)}</textarea>
        </label>
        <p class="muted full">保存后，下一次报告生成会按这些后缀识别压缩包矩阵对象；普通非图纸、非敏感名、非压缩包文件不进入矩阵对象统计。</p>
        <div class="full actions"><button class="primary" type="submit">保存覆盖</button></div>
      </form>
    </section>
"""
    return page_shell("压缩包后缀策略", body)


def plm_login_policy_page(config: AppConfig, message: str = "", error: str = "") -> bytes:
    doc = load_policy_doc(config)
    plm = doc.get("plm_login_audit") if isinstance(doc.get("plm_login_audit"), dict) else {}
    departments = normalize_unique_text_list(plm.get("constrained_departments") or DEFAULT_PLM_CONSTRAINED_DEPARTMENTS)
    terminal_match_fields = normalize_unique_text_list(plm.get("terminal_match_fields") or DEFAULT_PLM_TERMINAL_MATCH_FIELDS)
    department_text = ", ".join(departments)
    msg = f'<p class="muted">{esc(message)}</p>' if message else ""
    err = f'<p class="note error">{esc(error)}</p>' if error else ""
    body = f"""
    <header>
      <div>
        <h1>PLM登录审计策略</h1>
        <div class="muted">定义需要强制使用 7 天内在线的加密终端授信池登录 PLM 的部门范围。</div>
      </div>
      <div class="actions">
        <a class="button" href="/settings">策略中心</a>
        <a class="button" href="/settings/encryption-terminals">加密终端列表</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    {msg}
    {err}
    <section class="panel">
      <h2>强约束部门</h2>
      <form method="post" action="/settings/plm-login/save">
        <label class="full">部门名称，逗号分隔
          <textarea name="constrained_departments" spellcheck="false" placeholder="技术部, 研发部, 工艺部">{esc(department_text)}</textarea>
        </label>
        <p class="muted full">PLM账号匹配到企业微信通讯录，且部门命中该列表时，登录 IP + 计算机名不在最新加密终端授信池内即判一级风险；最后在线超过 {ENCRYPTION_TERMINAL_TRUST_DAYS} 天的终端视为加密失效，不进入授信池。列表外部门暂不跟踪。</p>
        <div class="full actions"><button class="primary" type="submit">保存覆盖</button></div>
      </form>
    </section>
    <section class="panel">
      <h2>当前口径</h2>
      <p class="muted">授信终端键：{esc(' + '.join(terminal_match_fields))}；有效条件：最后在线时间在 {ENCRYPTION_TERMINAL_TRUST_DAYS} 天内。PLM 登录接口接入后会按该键匹配最新加密终端批次。</p>
      <div class="table-wrap"><table><thead><tr><th>部门</th><th>规则</th></tr></thead><tbody>{"".join(f"<tr><td>{esc(item)}</td><td>登录IP+计算机名不在7天内在线授信终端池判一级风险</td></tr>" for item in departments) or '<tr><td colspan="2" class="muted">暂无强约束部门。</td></tr>'}</tbody></table></div>
    </section>
"""
    return page_shell("PLM登录审计策略", body)


def decrypt_records_page(config: AppConfig, message: str = "", error: str = "") -> bytes:
    batches = decrypt_import_batches(config, 30)
    rows = []
    for item in batches:
        rows.append(
            "<tr>"
            f"<td>{esc(item.get('import_batch') or '-')}</td>"
            f"<td>{esc(item.get('source_file') or '-')}</td>"
            f"<td>{esc(item.get('import_time') or '-')}</td>"
            f"<td>{esc(item.get('rows') or 0)}</td>"
            f"<td>{esc(item.get('design_rows') or 0)}</td>"
            f"<td>{esc(item.get('orgs') or 0)}</td>"
            "</tr>"
        )
    batch_table = "".join(rows) or '<tr><td colspan="6" class="muted">暂无导入批次。</td></tr>'
    msg = f'<p class="muted">{esc(message)}</p>' if message else ""
    error_html = f'<p class="error">{esc(error)}</p>' if error else ""
    body = f"""
    <header>
      <div>
        <h1>解密记录导入</h1>
        <div class="muted">上传加密软件导出的 .xlsx 解密/外发申请记录；导入后用于独立追踪标准图纸解密风险。</div>
      </div>
      <div class="actions">
        <a class="button" href="/settings">策略中心</a>
        <a class="button" href="/settings/organization-aliases">组织别名关联</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    {msg}
    {error_html}
    <section class="panel">
      <h2>上传 Excel</h2>
      <form method="post" action="/settings/decrypt-records/upload" enctype="multipart/form-data">
        <label class="full">解密记录 .xlsx 文件
          <input name="decrypt_file" type="file" multiple accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet">
        </label>
        <p class="muted full">支持一次选择多个 .xlsx；每个文件单独生成导入批次，重复上传会按业务指纹去重，不会放大趋势统计。上传文件保存到非 Web 目录作为审计证据。</p>
        <div class="full actions"><button class="primary" type="submit">批量上传并导入</button></div>
      </form>
    </section>
    <section class="panel">
      <h2>最近导入批次</h2>
      <div class="table-wrap"><table><thead><tr><th>批次</th><th>源文件</th><th>导入时间</th><th>记录数</th><th>图纸记录</th><th>组织数</th></tr></thead><tbody>{batch_table}</tbody></table></div>
    </section>
"""
    return page_shell("解密记录导入", body)


def parse_settings_page_params(params: dict[str, list[str]] | None) -> tuple[int, int, int, bool]:
    params = params or {}
    try:
        trusted_page = int((params.get("trusted_page") or params.get("page") or ["1"])[-1] or "1")
    except ValueError:
        trusted_page = 1
    try:
        excluded_page = int((params.get("excluded_page") or ["1"])[-1] or "1")
    except ValueError:
        excluded_page = 1
    try:
        page_size = int((params.get("page_size") or ["100"])[-1] or "100")
    except ValueError:
        page_size = 100
    if page_size not in {50, 100, 200}:
        page_size = 100
    duplicate_ip_only = str((params.get("duplicate_ip") or [""])[-1]).lower() in {"1", "true", "yes", "on"}
    return max(1, trusted_page), max(1, excluded_page), page_size, duplicate_ip_only


def encryption_terminals_page(
    config: AppConfig,
    message: str = "",
    error: str = "",
    params: dict[str, list[str]] | None = None,
) -> bytes:
    batches = encryption_terminal_batches(config, 30)
    latest_pool = latest_encryption_terminal_pool(config)
    latest_batch = str(latest_pool.get("import_batch") or "") if latest_pool else ""
    trusted_page, excluded_page, page_size, duplicate_ip_only = parse_settings_page_params(params)
    trusted_total = encryption_terminal_count(config, latest_batch, duplicate_ip_only, "trusted")
    excluded_total = encryption_terminal_count(config, latest_batch, False, "excluded")
    trusted_page_count = max(1, (trusted_total + page_size - 1) // page_size)
    excluded_page_count = max(1, (excluded_total + page_size - 1) // page_size)
    trusted_page = min(trusted_page, trusted_page_count)
    excluded_page = min(excluded_page, excluded_page_count)
    trusted_records = encryption_terminal_records(config, latest_batch, trusted_page, page_size, duplicate_ip_only, "trusted")
    excluded_records = encryption_terminal_records(config, latest_batch, excluded_page, page_size, False, "excluded")
    duplicate_ip_count = encryption_terminal_duplicate_ip_count(config, latest_batch)
    duplicate_record_count = encryption_terminal_count(config, latest_batch, True, "trusted")
    rows = []
    for item in batches:
        rows.append(
            "<tr>"
            f"<td>{esc(item.get('import_batch') or '-')}</td>"
            f"<td>{esc(item.get('source_file') or '-')}</td>"
            f"<td>{esc(item.get('import_time') or '-')}</td>"
            f"<td>{esc(item.get('rows') or 0)}</td>"
            f"<td>{esc(item.get('trusted_terminal_keys') or 0)}</td>"
            f"<td>{esc(item.get('terminal_keys') or 0)}</td>"
            f"<td>{esc(item.get('trusted_ips') or 0)}</td>"
            f"<td>{esc(item.get('ips') or 0)}</td>"
            f"<td>{esc(item.get('excluded_rows') or item.get('expired_rows') or 0)}</td>"
            f"<td>{esc(item.get('companies') or 0)}</td>"
            "</tr>"
        )
    batch_table = "".join(rows) or '<tr><td colspan="10" class="muted">暂无导入批次。</td></tr>'
    trusted_html = []
    for item in trusted_records:
        ip_rows = int(item.get("ip_rows") or 0)
        duplicate_badge = f'<span class="mini-badge danger">重复 {ip_rows}</span>' if ip_rows > 1 else '<span class="mini-badge">唯一</span>'
        row_class = ' class="duplicate-ip-row"' if ip_rows > 1 else ""
        trusted_html.append(
            f"<tr{row_class}>"
            f"<td>{esc(item.get('ip_address') or '-')}</td>"
            f"<td>{esc(item.get('computer_name') or '-')}</td>"
            f"<td>{duplicate_badge}</td>"
            f"<td>{esc(item.get('mac_address') or '-')}</td>"
            f"<td>{esc(item.get('user_name') or '-')}</td>"
            f"<td>{esc(item.get('user_account') or '-')}</td>"
            f"<td>{esc(item.get('company') or '-')}</td>"
            f"<td>{esc(item.get('department') or '-')}</td>"
            f"<td>{esc(item.get('os_version') or '-')}</td>"
            f"<td>{esc(item.get('client_version') or '-')}</td>"
            f"<td>{esc(item.get('encryption_status') or '-')}</td>"
            f"<td>{esc(item.get('last_seen') or '-')}</td>"
            "</tr>"
        )
    trusted_table = "".join(trusted_html) or '<tr><td colspan="12" class="muted">暂无授信终端记录。</td></tr>'
    excluded_html = []
    for item in excluded_records:
        trusted_mac_rows = int(item.get("trusted_mac_rows") or 0)
        mac_value = str(item.get("mac_address") or "").strip()
        if not mac_value:
            mac_check = '<span class="mini-badge warn">无MAC</span>'
        elif trusted_mac_rows > 0:
            refs = esc(item.get("trusted_mac_refs") or "")
            mac_check = f'<span class="mini-badge danger" title="{refs}">授信MAC重复 {trusted_mac_rows}</span>'
        else:
            mac_check = '<span class="mini-badge">未重复</span>'
        excluded_html.append(
            "<tr>"
            f"<td>{esc(item.get('ip_address') or '-')}</td>"
            f"<td>{esc(item.get('computer_name') or '-')}</td>"
            f"<td>{esc(item.get('mac_address') or '-')}</td>"
            f"<td>{esc(item.get('user_name') or '-')}</td>"
            f"<td>{esc(item.get('user_account') or '-')}</td>"
            f"<td>{esc(item.get('company') or '-')}</td>"
            f"<td>{esc(item.get('department') or '-')}</td>"
            f"<td>{esc(item.get('os_version') or '-')}</td>"
            f"<td>{esc(item.get('client_version') or '-')}</td>"
            f"<td>{esc(item.get('encryption_status') or '-')}</td>"
            f"<td>{esc(item.get('last_seen') or '-')}</td>"
            f'<td><span class="mini-badge danger">{esc(item.get("trust_status") or "不进入授信池")}</span></td>'
            f"<td>{mac_check}</td>"
            "</tr>"
        )
    excluded_table = "".join(excluded_html) or '<tr><td colspan="13" class="muted">暂无排除记录。</td></tr>'
    def list_url(
        target_trusted_page: int | None = None,
        target_excluded_page: int | None = None,
        size: int | None = None,
        duplicate: bool | None = None,
    ) -> str:
        query = {
            "trusted_page": str(max(1, target_trusted_page if target_trusted_page is not None else trusted_page)),
            "excluded_page": str(max(1, target_excluded_page if target_excluded_page is not None else excluded_page)),
            "page_size": str(size if size is not None else page_size),
        }
        if duplicate if duplicate is not None else duplicate_ip_only:
            query["duplicate_ip"] = "1"
        return "/settings/encryption-terminals?" + urlencode(query)

    mode_actions = (
        f'<a class="button {"primary" if not duplicate_ip_only else ""}" href="{esc(list_url(1, 1, page_size, False))}">授信池全部</a>'
        f'<a class="button {"primary" if duplicate_ip_only else ""}" href="{esc(list_url(1, 1, page_size, True))}">仅重复IP</a>'
    )
    size_actions = "".join(
        f'<a class="button {"primary" if page_size == size else ""}" href="{esc(list_url(1, 1, size, duplicate_ip_only))}">{size}/页</a>'
        for size in (50, 100, 200)
    )
    trusted_prev_link = list_url(trusted_page - 1, excluded_page, page_size, duplicate_ip_only)
    trusted_next_link = list_url(trusted_page + 1, excluded_page, page_size, duplicate_ip_only)
    trusted_pager_actions = (
        (f'<a class="button" href="{esc(trusted_prev_link)}">上一页</a>' if trusted_page > 1 else '<span class="mini-badge">上一页</span>')
        + (f'<a class="button" href="{esc(trusted_next_link)}">下一页</a>' if trusted_page < trusted_page_count else '<span class="mini-badge">下一页</span>')
    )
    excluded_prev_link = list_url(trusted_page, excluded_page - 1, page_size, duplicate_ip_only)
    excluded_next_link = list_url(trusted_page, excluded_page + 1, page_size, duplicate_ip_only)
    excluded_pager_actions = (
        (f'<a class="button" href="{esc(excluded_prev_link)}">上一页</a>' if excluded_page > 1 else '<span class="mini-badge">上一页</span>')
        + (f'<a class="button" href="{esc(excluded_next_link)}">下一页</a>' if excluded_page < excluded_page_count else '<span class="mini-badge">下一页</span>')
    )
    pool_text = "尚未导入终端列表"
    if latest_pool:
        pool_text = (
            f"最新批次 {latest_pool.get('import_batch') or '-'}："
            f"{int(latest_pool.get('trusted_terminal_keys') or 0)} 个授信终端键，"
            f"{int(latest_pool.get('trusted_ips') or 0)} 个授信 IP；"
            f"{int(latest_pool.get('terminal_keys') or 0)} 个全部终端键，"
            f"{int(latest_pool.get('ips') or 0)} 个全部 IP，"
            f"{int(latest_pool.get('excluded_rows') or latest_pool.get('expired_rows') or 0)} 条排除记录，"
            f"{int(latest_pool.get('rows') or 0)} 条终端记录。"
        )
    msg = f'<p class="muted">{esc(message)}</p>' if message else ""
    error_html = f'<p class="error">{esc(error)}</p>' if error else ""
    body = f"""
    <header>
      <div>
        <h1>加密终端列表导入</h1>
        <div class="muted">上传加密软件终端清单 .xlsx；最新导入批次中 7 天内在线的 IP + 计算机名作为授信终端池来源。</div>
      </div>
      <div class="actions">
        <a class="button" href="/settings">策略中心</a>
        <a class="button" href="/settings/decrypt-records">解密记录导入</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    {msg}
    {error_html}
    <section class="panel">
      <h2>当前授信终端池来源</h2>
      <p class="metric">{esc(pool_text)}</p>
      <p class="muted">该页面只维护数据源。PLM 登录审计等模块后续会读取最新批次中 `IP地址 + 计算机名` 且最后在线时间在 {ENCRYPTION_TERMINAL_TRUST_DAYS} 天内的记录作为授信终端键；超过 {ENCRYPTION_TERMINAL_TRUST_DAYS} 天未在线视为加密失效，不进入授信池。若 PLM 登录记录缺少计算机名，应单独标记为待复核，不按纯 IP 自动放行。</p>
    </section>
    <section class="panel">
      <div class="settings-toolbar">
        <div>
          <h2>授信 IP 池</h2>
          <p class="muted">只展示最后在线时间在 {ENCRYPTION_TERMINAL_TRUST_DAYS} 天内，且同时具备 IP 地址和计算机名的终端；重复 IP 仅按授信池计算。</p>
        </div>
        <div class="actions">{mode_actions}{size_actions}</div>
      </div>
      <p class="muted"><span class="mini-badge">授信记录 {trusted_total}</span> <span class="mini-badge">授信池重复IP {duplicate_ip_count}</span> <span class="mini-badge">重复记录 {duplicate_record_count}</span></p>
      <div class="table-wrap"><table><thead><tr><th>IP地址</th><th>计算机名</th><th>IP状态</th><th>MAC地址</th><th>使用人</th><th>账号</th><th>公司</th><th>部门</th><th>操作系统</th><th>客户端版本</th><th>加密状态</th><th>最后在线</th></tr></thead><tbody>{trusted_table}</tbody></table></div>
      <div class="pager">
        <span>授信池第 {trusted_page} / {trusted_page_count} 页，每页 {page_size} 条</span>
        <div class="actions">{trusted_pager_actions}</div>
      </div>
    </section>
    <section class="panel">
      <div class="settings-toolbar">
        <div>
          <h2>排除 IP / 终端</h2>
          <p class="muted">不进入授信池的最新批次记录，最后一列给出排除原因，例如最后在线超过 {ENCRYPTION_TERMINAL_TRUST_DAYS} 天、缺少 IP 或缺少计算机名。</p>
        </div>
        <span class="mini-badge danger">排除记录 {excluded_total}</span>
      </div>
      <div class="table-wrap"><table><thead><tr><th>IP地址</th><th>计算机名</th><th>MAC地址</th><th>使用人</th><th>账号</th><th>公司</th><th>部门</th><th>操作系统</th><th>客户端版本</th><th>加密状态</th><th>最后在线</th><th>备注原因</th><th>授信MAC检查</th></tr></thead><tbody>{excluded_table}</tbody></table></div>
      <div class="pager">
        <span>排除池第 {excluded_page} / {excluded_page_count} 页，每页 {page_size} 条</span>
        <div class="actions">{excluded_pager_actions}</div>
      </div>
    </section>
    <section class="panel">
      <h2>上传 Excel</h2>
      <form method="post" action="/settings/encryption-terminals/upload" enctype="multipart/form-data">
        <label class="full">终端列表 .xlsx 文件
          <input name="terminal_file" type="file" multiple accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet">
        </label>
        <p class="muted full">支持一次选择多个 .xlsx；系统会识别常见表头：IP地址、MAC地址、计算机名、使用人、账号、公司、部门、操作系统、客户端版本、状态、最后在线时间。重复上传会按终端记录指纹去重。</p>
        <div class="full actions"><button class="primary" type="submit">批量上传并导入</button></div>
      </form>
    </section>
    <section class="panel">
      <h2>最近导入批次</h2>
      <div class="table-wrap"><table><thead><tr><th>批次</th><th>源文件</th><th>导入时间</th><th>终端记录</th><th>授信终端键</th><th>全部终端键</th><th>授信IP</th><th>全部IP</th><th>排除记录</th><th>公司数</th></tr></thead><tbody>{batch_table}</tbody></table></div>
    </section>
"""
    return page_shell("加密终端列表导入", body)


def alias_row_form(idx: int, item: dict[str, Any]) -> str:
    enabled = policy_bool(item.get("enabled", True), True)
    form_id = f"alias-update-{idx}"
    delete_form_id = f"alias-delete-{idx}"
    return (
        "<tr>"
        f'<td class="alias-path-col"><input form="{form_id}" name="raw_org_path" value="{esc(item.get("raw_org_path") or "")}" placeholder="大全集团/公司/部门"></td>'
        f'<td class="alias-company-col"><input form="{form_id}" name="raw_company" value="{esc(item.get("raw_company") or "")}" placeholder="原始公司"></td>'
        f'<td class="alias-dept-col"><input form="{form_id}" name="raw_department" value="{esc(item.get("raw_department") or "")}" placeholder="原始部门"></td>'
        f'<td class="alias-company-col"><input form="{form_id}" name="canonical_company" list="company-options" value="{esc(item.get("canonical_company") or "")}" placeholder="标准公司"></td>'
        f'<td class="alias-dept-col"><input form="{form_id}" name="canonical_department" list="department-options" value="{esc(item.get("canonical_department") or "")}" placeholder="标准部门"></td>'
        f'<td class="alias-note-col"><input form="{form_id}" name="note" value="{esc(item.get("note") or "")}" placeholder="备注"></td>'
        f'<td class="alias-status-col"><label><input form="{form_id}" type="checkbox" name="enabled" value="1" {"checked" if enabled else ""}> 启用</label></td>'
        '<td class="actions alias-action-col">'
        f'<form id="{form_id}" class="inline-form" method="post" action="/settings/organization-aliases/update"><input type="hidden" name="idx" value="{idx}"></form>'
        f'<button form="{form_id}" type="submit">修改</button> '
        f'<form id="{delete_form_id}" class="inline-form" method="post" action="/settings/organization-aliases/delete"><input type="hidden" name="idx" value="{idx}"></form>'
        f'<button form="{delete_form_id}" class="danger" type="submit">删除</button>'
        "</td></tr>"
    )


def organization_aliases_page(config: AppConfig, message: str = "", error: str = "") -> bytes:
    doc = load_policy_doc(config)
    aliases = normalize_organization_aliases(doc.get("organization_aliases"))
    alias_rows = "".join(alias_row_form(idx, item) for idx, item in enumerate(aliases)) or '<tr><td colspan="8" class="muted">暂无组织别名。</td></tr>'
    all_orgs = decrypt_all_orgs(config, doc)
    matched_orgs = sum(1 for item in all_orgs if item.get("matched"))
    all_org_rows = []
    for item in all_orgs:
        matched = bool(item.get("matched"))
        all_org_rows.append(
            "<tr>"
            f'<td class="alias-path-col" title="{esc(item.get("raw_org_path") or "")}">{esc(item.get("raw_org_path") or "-")}</td>'
            f'<td class="alias-company-col">{esc(item.get("raw_company") or "-")}</td>'
            f'<td class="alias-dept-col">{esc(item.get("raw_department") or "-")}</td>'
            f'<td class="alias-count-col">{esc(item.get("rows") or 0)}</td>'
            f'<td class="alias-company-col">{esc(item.get("canonical_company") or "-")}</td>'
            f'<td class="alias-dept-col">{esc(item.get("canonical_department") or "-")}</td>'
            f'<td class="alias-status-col"><span class="badge {"on" if matched else "off"}">{"已映射" if matched else "待完善"}</span></td>'
            "</tr>"
        )
    all_org_table = "".join(all_org_rows) or '<tr><td colspan="7" class="muted">暂无解密记录原始组织。</td></tr>'
    candidates = decrypt_org_candidates(config, doc, 80)
    candidate_rows = []
    for idx, item in enumerate(candidates):
        form_id = f"alias-candidate-{idx}"
        suggestions = item.get("suggestions") or []
        suggestion_text = "、".join(str(value) for value in suggestions) or "无明显候选"
        candidate_rows.append(
            "<tr>"
            f'<td class="alias-path-col" title="{esc(item.get("raw_org_path") or "")}">{esc(item.get("raw_org_path") or "-")}</td>'
            f'<td class="alias-company-col">{esc(item.get("raw_company") or "-")}</td>'
            f'<td class="alias-dept-col">{esc(item.get("raw_department") or "-")}</td>'
            f'<td class="alias-count-col">{esc(item.get("rows") or 0)}</td>'
            f'<td class="alias-company-col" title="{esc(suggestion_text)}">{esc(suggestion_text)}</td>'
            f'<td class="alias-company-col"><input form="{form_id}" name="canonical_company" list="company-options" placeholder="标准公司" value="{esc(suggestions[0] if len(suggestions) == 1 else "")}"></td>'
            f'<td class="alias-dept-col"><input form="{form_id}" name="canonical_department" list="department-options" placeholder="标准部门" value="{esc(item.get("raw_department") or "")}"></td>'
            '<td class="alias-action-col">'
            f'<form id="{form_id}" class="inline-form" method="post" action="/settings/organization-aliases/add">'
            f'<input type="hidden" name="raw_org_path" value="{esc(item.get("raw_org_path") or "")}">'
            f'<input type="hidden" name="raw_company" value="{esc(item.get("raw_company") or "")}">'
            f'<input type="hidden" name="raw_department" value="{esc(item.get("raw_department") or "")}">'
            '</form>'
            f'<button form="{form_id}" type="submit">确认映射</button></td></tr>'
        )
    candidate_table = "".join(candidate_rows) or '<tr><td colspan="8" class="muted">暂无待确认组织。</td></tr>'
    msg = f'<p class="muted">{esc(message)}</p>' if message else ""
    error_html = f'<p class="error">{esc(error)}</p>' if error else ""
    body = f"""
    <header>
      <div>
        <h1>组织别名关联</h1>
        <div class="muted">维护解密表原始组织到标准公司/部门的映射；保存后后续导入和历史报告重新生成都会自动归一。</div>
      </div>
      <div class="actions">
        <a class="button" href="/settings">策略中心</a>
        <a class="button" href="/settings/decrypt-records">解密记录导入</a>
        <a class="button" href="/settings/organization-tree">组织结构映射</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    {organization_alias_datalists(config)}
    {msg}
    {error_html}
    <section class="settings-grid">
      <div class="settings-card">
        <h3>底稿原始组织</h3>
        <p class="metric">{len(all_orgs)} 个</p>
        <p class="muted">来自已导入解密记录，不代表企业微信全量通讯录。</p>
      </div>
      <div class="settings-card">
        <h3>已映射组织</h3>
        <p class="metric">{matched_orgs} 个</p>
        <p class="muted">命中启用状态的组织别名映射。</p>
      </div>
      <div class="settings-card">
        <h3>待完善组织</h3>
        <p class="metric">{max(0, len(all_orgs) - matched_orgs)} 个</p>
        <p class="muted">未确认组织会进入报告“组织映射待完善”。</p>
      </div>
    </section>
    <section class="panel">
      <h2>新增组织别名</h2>
      <form method="post" action="/settings/organization-aliases/add">
        <label class="full">原始所属部门完整值
          <input name="raw_org_path" placeholder="大全集团/西门子母线/技术部">
        </label>
        <label>原始公司
          <input name="raw_company" placeholder="西门子母线">
        </label>
        <label>原始部门
          <input name="raw_department" placeholder="技术部">
        </label>
        <label>标准公司
          <input name="canonical_company" list="company-options" placeholder="镇江西门子母线有限公司">
        </label>
        <label>标准部门
          <input name="canonical_department" list="department-options" placeholder="技术部">
        </label>
        <label class="full">备注
          <input name="note" placeholder="人工确认">
        </label>
        <div class="full actions"><button class="primary" type="submit">新增映射</button></div>
      </form>
    </section>
    <section class="panel">
      <h2>解密记录原始组织全量</h2>
      <p class="muted">这里展示当前 ClickHouse 解密记录底稿中出现过的全部原始组织组合；未来上传新 Excel 后，如果出现新组织，会自动进入这里和“未确认组织候选”。</p>
      <div class="table-wrap alias-table-wrap"><table class="alias-table"><thead><tr><th class="alias-path-col">原始所属部门</th><th class="alias-company-col">原始公司</th><th class="alias-dept-col">原始部门</th><th class="alias-count-col">记录数</th><th class="alias-company-col">映射公司</th><th class="alias-dept-col">映射部门</th><th class="alias-status-col">状态</th></tr></thead><tbody>{all_org_table}</tbody></table></div>
    </section>
    <section class="panel">
      <h2>未确认组织候选</h2>
      <p class="muted">候选只辅助填写，不自动归责；多候选时必须人工选择标准公司。</p>
      <div class="table-wrap alias-table-wrap"><table class="alias-table"><thead><tr><th class="alias-path-col">原始所属部门</th><th class="alias-company-col">原始公司</th><th class="alias-dept-col">原始部门</th><th class="alias-count-col">记录数</th><th class="alias-company-col">候选标准公司</th><th class="alias-company-col">标准公司</th><th class="alias-dept-col">标准部门</th><th class="alias-action-col">操作</th></tr></thead><tbody>{candidate_table}</tbody></table></div>
    </section>
    <section class="panel">
      <h2>已保存组织别名</h2>
      <div class="table-wrap alias-table-wrap"><table class="alias-table"><thead><tr><th class="alias-path-col">原始所属部门</th><th class="alias-company-col">原始公司</th><th class="alias-dept-col">原始部门</th><th class="alias-company-col">标准公司</th><th class="alias-dept-col">标准部门</th><th class="alias-note-col">备注</th><th class="alias-status-col">状态</th><th class="alias-action-col">操作</th></tr></thead><tbody>{alias_rows}</tbody></table></div>
    </section>
"""
    return page_shell("组织别名关联", body)


def auth_settings_page(config: AppConfig, message: str = "", error: str = "") -> bytes:
    auth = auth_policy(config)
    msg = f'<p class="muted">{esc(message)}</p>' if message else ""
    error_html = f'<p class="error">{esc(error)}</p>' if error else ""
    body = f"""
    <header>
      <div>
        <h1>认证与报表查看</h1>
        <div class="muted">企业微信扫码登录后按角色授权；授权查看用户只能查看全集团审计报告，策略管理仅 10056 可访问。</div>
      </div>
      <div class="actions">
        <a class="button" href="/settings">策略中心</a>
        <a class="button" href="/manual">自定义生成</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    {msg}
    {error_html}
    <section class="panel">
      <h2>编辑认证权限</h2>
      <form method="post" action="/settings/auth/save">
        <p class="muted full">策略管理固定仅允许 userid={esc(FIXED_POLICY_ADMIN_USERID)} 访问；这里维护允许登录查看全集团报告的账号。</p>
        <label class="full">集团报表查看 userid，逗号分隔
          <textarea name="global_viewer_userids" spellcheck="false" placeholder="例如：10001, 10002">{esc(userids_editor_text(auth["global_viewer_userids"]))}</textarea>
        </label>
        <label>会话有效期，小时
          <input name="session_hours" type="number" min="1" max="24" value="{esc(auth["session_hours"])}">
        </label>
        <p class="muted full">保存后立即生效；被移除账号下一次请求会失效。</p>
        <div class="full actions"><button class="primary" type="submit">保存覆盖</button></div>
      </form>
    </section>
    <h2>策略管理员</h2>
    <div class="table-wrap"><table><thead><tr><th>userid</th><th>姓名</th><th>公司</th><th>部门</th><th>状态</th></tr></thead><tbody>{auth_user_rows(config, [FIXED_POLICY_ADMIN_USERID])}</tbody></table></div>
    <h2>集团报表查看用户</h2>
    <div class="table-wrap"><table><thead><tr><th>userid</th><th>姓名</th><th>公司</th><th>部门</th><th>状态</th></tr></thead><tbody>{auth_user_rows(config, auth["global_viewer_userids"])}</tbody></table></div>
"""
    return page_shell("认证与报表查看", body)


def exclusions_page(config: AppConfig, message: str = "") -> bytes:
    doc = load_exclusion_doc(config)
    rules = [rule for rule in doc.get("rules", []) if isinstance(rule, dict)]
    rows = []
    for idx, rule in enumerate(rules):
        enabled = rule_enabled(rule)
        rows.append(
            "<tr>"
            f'<td><span class="badge {"on" if enabled else "off"}">{"启用" if enabled else "停用"}</span></td>'
            f"<td>{esc(rule.get('rule_name', ''))}</td>"
            f"<td>{esc(rule.get('topic', '*'))}</td>"
            f"<td>{esc('; '.join(rule.get('target_contains') or []))}</td>"
            f"<td>{esc('; '.join(rule.get('file_contains') or []))}<br>{esc('; '.join(rule.get('file_regex') or []))}</td>"
            f"<td>{esc(rule.get('note', ''))}</td>"
            '<td>'
            f'<form class="inline-form" method="post" action="/settings/exclusions/toggle"><input type="hidden" name="idx" value="{idx}"><button type="submit">{"停用" if enabled else "启用"}</button></form> '
            f'<form class="inline-form" method="post" action="/settings/exclusions/delete"><input type="hidden" name="idx" value="{idx}"><button class="danger" type="submit">删除</button></form>'
            "</td>"
            "</tr>"
        )
    table = "".join(rows) or '<tr><td colspan="7" class="muted">暂无排除策略。</td></tr>'
    msg = f'<p class="muted">{esc(message)}</p>' if message else ""
    body = f"""
    <header>
      <div>
        <h1>排除策略</h1>
        <div class="muted">用于已知软件同步降噪。命中后不进入报表分析，但不删除原始 syslog。</div>
      </div>
      <div class="actions">
        <a class="button" href="/settings">策略中心</a>
        <a class="button" href="/manual">自定义生成</a>
        <a class="button" href="/">当前报告首页</a>
      </div>
    </header>
    {msg}
    <section class="panel">
      <h2>新增排除策略</h2>
      <form method="post" action="/settings/exclusions/add">
        <label>规则名称<input name="rule_name" required maxlength="80" placeholder="如：搜狗输入法词库同步"></label>
        <label>日志类型
          <select name="topic">
            <option value="file_audit">file_audit</option>
            <option value="im_audit">im_audit</option>
            <option value="mail_audit">mail_audit</option>
            <option value="*">全部</option>
          </select>
        </label>
        <label class="full">目标包含，多个用分号或换行分隔<textarea name="target_contains" placeholder="profile.pinyin.sogou.com&#10;pc.profile.pinyin.sogou.com"></textarea></label>
        <label class="full">文件名包含，多个用分号或换行分隔<textarea name="file_contains" placeholder="sgim_"></textarea></label>
        <label class="full">文件名正则，多个用分号或换行分隔<textarea name="file_regex" placeholder="^(sgim_.*\\.zip|config\\.zip|configmd5\\.bin)$"></textarea></label>
        <label class="full">进程包含，可选<textarea name="process_contains"></textarea></label>
        <label class="full">备注<input name="note" maxlength="220"></label>
        <div class="full actions"><button class="primary" type="submit">新增排除策略</button></div>
      </form>
    </section>
    <h2>当前规则</h2>
    <div class="table-wrap"><table><thead><tr><th>状态</th><th>规则</th><th>类型</th><th>目标</th><th>文件条件</th><th>备注</th><th>操作</th></tr></thead><tbody>{table}</tbody></table></div>
"""
    return page_shell("排除策略", body)


def parse_content_disposition(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if "=" not in part:
            result.setdefault("_type", part.lower())
            continue
        key, raw = part.split("=", 1)
        result[key.strip().lower()] = raw.strip().strip('"')
    return result


def parse_multipart_form(content_type: str, body: bytes) -> tuple[dict[str, str], dict[str, list[dict[str, Any]]]]:
    match = re.search(r"boundary=(?P<boundary>[^;]+)", content_type)
    if not match:
        return {}, {}
    boundary = match.group("boundary").strip().strip('"').encode("utf-8")
    delimiter = b"--" + boundary
    form: dict[str, str] = {}
    files: dict[str, list[dict[str, Any]]] = {}
    for part in body.split(delimiter):
        if not part or part in {b"--\r\n", b"--", b"\r\n"}:
            continue
        part = part.strip(b"\r\n")
        if part.endswith(b"--"):
            part = part[:-2].rstrip(b"\r\n")
        if b"\r\n\r\n" not in part:
            continue
        header_blob, content = part.split(b"\r\n\r\n", 1)
        headers: dict[str, str] = {}
        for line in header_blob.decode("utf-8", errors="replace").split("\r\n"):
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        disposition = parse_content_disposition(headers.get("content-disposition", ""))
        name = disposition.get("name", "")
        if not name:
            continue
        filename = disposition.get("filename", "")
        if filename:
            files.setdefault(name, []).append(
                {
                "filename": filename,
                "content": content,
                "content_type": headers.get("content-type", "application/octet-stream"),
                }
            )
        else:
            form[name] = content.decode("utf-8", errors="replace")
    return form, files


class ReportHandler(BaseHTTPRequestHandler):
    server_version = "TianqingReportWeb/1.0"

    @property
    def config(self) -> AppConfig:
        return self.server.config  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        print("%s - - [%s] %s" % (self.client_address[0], self.log_date_time_string(), fmt % args), flush=True)

    def cookie_value(self, name: str) -> str:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        if name in cookie:
            return cookie[name].value
        return ""

    def current_session(self) -> AuthSession | None:
        sid = self.cookie_value(AUTH_COOKIE_NAME)
        if not sid:
            return None
        now = time.time()
        with SESSIONS_LOCK:
            session = SESSIONS.get(sid)
            if not session:
                SESSIONS.update(read_persisted_sessions(self.config, now))
                session = SESSIONS.get(sid)
            if not session or session.expires_at <= now:
                if sid in SESSIONS:
                    del SESSIONS[sid]
                    write_sessions_locked(self.config)
                return None
        if not session_is_allowed(self.config, session):
            with SESSIONS_LOCK:
                SESSIONS.pop(sid, None)
                write_sessions_locked(self.config)
            return None
        return session

    def login_redirect(self, next_path: str | None = None) -> None:
        location = "/auth/login"
        if next_path:
            location += "?" + urlencode({"next": normalize_login_next(next_path)})
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()

    def host_name(self) -> str:
        host = (self.headers.get("Host") or "").split(":", 1)[0].strip().lower()
        return host

    def redirect_canonical_host(self, parsed: Any, status: HTTPStatus = HTTPStatus.SEE_OTHER) -> bool:
        host = self.host_name()
        if not host or host in CANONICAL_HOSTS:
            return False
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        self.send_response(status)
        self.send_header("Location", public_redirect_url(self.config, target))
        self.end_headers()
        return True

    def send_forbidden(self, message: str = "无权限访问该资源。") -> None:
        self.send_html(forbidden_page(message), HTTPStatus.FORBIDDEN)

    def require_session(self, parsed_path: str) -> AuthSession | None:
        session = self.current_session()
        if session:
            return session
        self.login_redirect(parsed_path or "/")
        return None

    @staticmethod
    def request_next_path(parsed: Any) -> str:
        next_path = parsed.path or "/"
        if parsed.query:
            next_path += "?" + parsed.query
        return next_path

    def require_admin(self, session: AuthSession) -> bool:
        if session.role == "admin":
            return True
        self.send_forbidden("策略管理仅允许 userid=10056 访问。")
        return False

    def csrf_ok(self, form: dict[str, str], session: AuthSession) -> bool:
        token = form.get("csrf_token") or self.headers.get("X-CSRF-Token", "")
        return bool(token and hmac.compare_digest(token, session.csrf_token))

    def same_origin_request(self) -> bool:
        host = self.host_name()
        allowed_hosts = {item for item in CANONICAL_HOSTS if item}
        if host:
            allowed_hosts.add(host)
        for attr in ("Origin", "Referer"):
            value = self.headers.get(attr, "")
            if not value:
                continue
            parsed = urlparse(value)
            ref_host = (parsed.hostname or "").lower()
            if ref_host in allowed_hosts:
                return True
        return False

    def csrf_upload_fallback_ok(self, path: str, session: AuthSession) -> bool:
        upload_paths = {"/settings/decrypt-records/upload", "/settings/encryption-terminals/upload"}
        if path not in upload_paths or session.role != "admin":
            return False
        content_type = self.headers.get("Content-Type", "")
        return content_type.startswith("multipart/form-data") and self.same_origin_request()

    def inject_csrf(self, data: bytes) -> bytes:
        session = self.current_session()
        if not session:
            return data
        text = data.decode("utf-8", errors="replace")
        hidden = f'<input type="hidden" name="csrf_token" value="{esc(session.csrf_token)}">'
        text = re.sub(r"(<form\b[^>]*method=[\"']post[\"'][^>]*>)", r"\1" + hidden, text, flags=re.IGNORECASE)
        if 'name="csrf-token"' not in text:
            meta = f'<meta name="csrf-token" content="{esc(session.csrf_token)}">'
            text = text.replace("<head>", "<head>" + meta, 1)
        if "data-csrf-form-guard" not in text:
            script = """
<script data-csrf-form-guard>
(function(){
  var meta = document.querySelector('meta[name="csrf-token"]');
  if (!meta) return;
  var token = meta.getAttribute('content') || '';
  if (!token) return;
  document.addEventListener('submit', function(event) {
    var form = event.target;
    if (!form || !form.matches || !form.matches('form')) return;
    var method = (form.getAttribute('method') || 'get').toLowerCase();
    if (method !== 'post') return;
    var input = form.querySelector('input[name="csrf_token"]');
    if (!input) {
      input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'csrf_token';
      form.appendChild(input);
    }
    input.value = token;
  }, true);
})();
</script>
"""
            text = text.replace("</body>", script + "</body>", 1)
        return text.encode("utf-8")

    def send_html(self, data: bytes, status: HTTPStatus = HTTPStatus.OK) -> None:
        session = self.current_session()
        if status == HTTPStatus.OK:
            data = self.inject_csrf(data)
        data = inject_identity_bar(data, session)
        request_path = urlparse(self.path).path
        if status == HTTPStatus.OK and request_path in {"", "/", "/manual"}:
            data = inject_job_status_bar(data, self.config, session)
        data = inject_event_table_sorting(data)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def parse_request_form(self, parsed_path: str) -> tuple[dict[str, str], dict[str, list[dict[str, Any]]]] | None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        content_type = self.headers.get("Content-Type", "")
        upload_paths = {"/settings/decrypt-records/upload", "/settings/encryption-terminals/upload"}
        limit = MAX_UPLOAD_POST_BYTES if parsed_path in upload_paths and content_type.startswith("multipart/form-data") else MAX_POST_BYTES
        if length > limit:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return None
        body = self.rfile.read(length)
        if content_type.startswith("multipart/form-data"):
            return parse_multipart_form(content_type, body)
        raw = body.decode("utf-8", errors="replace")
        return {key: values[-1] for key, values in parse_qs(raw, keep_blank_values=True).items()}, {}

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if self.redirect_canonical_host(parsed):
            return
        if parsed.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            return
        if parsed.path == "/auth/login":
            params = parse_qs(parsed.query)
            next_path = (params.get("next") or ["/"])[-1]
            data, state_cookie = login_page(self.config, next_path)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", auth_cookie_header(self.config, AUTH_STATE_COOKIE_NAME, state_cookie, 600))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            return
        if parsed.path in {"/auth/callback", "/audit/auth/callback"}:
            self.handle_auth_callback(parsed)
            return
        if parsed.path == "/auth/logout":
            sid = self.cookie_value(AUTH_COOKIE_NAME)
            if sid:
                with SESSIONS_LOCK:
                    SESSIONS.pop(sid, None)
                    write_sessions_locked(self.config)
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/auth/login")
            self.send_header("Set-Cookie", auth_cookie_header(self.config, AUTH_COOKIE_NAME, "", 0))
            self.end_headers()
            return
        session = self.require_session(self.request_next_path(parsed))
        if not session:
            return
        if parsed.path == "/manual":
            self.send_html(manual_page(self.config, session))
            return
        if parsed.path == "/reports":
            self.send_html(reports_page(self.config, session))
            return
        if parsed.path == "/terminal-check":
            if session.role not in {"admin", "global"}:
                self.send_forbidden("仅授权查看全集团报告的用户可以进行风险终端复核。")
                return
            self.send_html(terminal_check_page(self.config, session, parse_qs(parsed.query)))
            return
        if parsed.path == "/terminal-check/events":
            if session.role not in {"admin", "global"}:
                self.send_forbidden("仅授权查看全集团报告的用户可以查看风险终端复核证据。")
                return
            self.send_html(terminal_check_events_page(self.config, parse_qs(parsed.query)))
            return
        if parsed.path == "/api/terminal-check-fragment":
            if session.role not in {"admin", "global"}:
                self.send_forbidden("仅授权查看全集团报告的用户可以进行风险终端复核。")
                return
            try:
                start, end, _preset = terminal_check_period_from_params(self.config, parse_qs(parsed.query))
            except Exception as exc:
                self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
                return
            data = terminal_check_fragment_html(self.config, start, end)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            return
        if parsed.path == "/jobs":
            self.redirect("/reports")
            return
        if parsed.path == "/settings":
            if not self.require_admin(session):
                return
            self.send_html(settings_page(self.config))
            return
        if parsed.path == "/settings/keywords":
            if not self.require_admin(session):
                return
            self.send_html(keywords_page(self.config))
            return
        if parsed.path == "/settings/policy":
            if not self.require_admin(session):
                return
            self.send_html(policy_page(self.config))
            return
        if parsed.path == "/settings/internal-targets":
            if not self.require_admin(session):
                return
            self.send_html(internal_targets_page(self.config))
            return
        if parsed.path == "/settings/archive-suffixes":
            if not self.require_admin(session):
                return
            self.send_html(archive_suffixes_page(self.config))
            return
        if parsed.path == "/settings/plm-login":
            if not self.require_admin(session):
                return
            self.send_html(plm_login_policy_page(self.config))
            return
        if parsed.path == "/settings/terminal-behavior-review":
            if not self.require_admin(session):
                return
            self.send_html(terminal_behavior_policy_page(self.config))
            return
        if parsed.path == "/settings/decrypt-records":
            if not self.require_admin(session):
                return
            self.send_html(decrypt_records_page(self.config))
            return
        if parsed.path == "/settings/encryption-terminals":
            if not self.require_admin(session):
                return
            self.send_html(encryption_terminals_page(self.config, params=parse_qs(parsed.query)))
            return
        if parsed.path == "/settings/organization-aliases":
            if not self.require_admin(session):
                return
            self.send_html(organization_aliases_page(self.config))
            return
        if parsed.path == "/settings/organization-tree":
            if not self.require_admin(session):
                return
            self.send_html(organization_tree_page(self.config))
            return
        if parsed.path == "/settings/auth":
            if not self.require_admin(session):
                return
            self.send_html(auth_settings_page(self.config))
            return
        if parsed.path == "/settings/exclusions":
            if not self.require_admin(session):
                return
            self.send_html(exclusions_page(self.config))
            return
        if parsed.path.startswith("/jobs/"):
            job_id = parsed.path.rsplit("/", 1)[-1]
            if not session_can_view_job_log(self.config, session, job_id):
                self.send_forbidden("无权限查看该生成任务。")
                return
            self.send_html(job_page(self.config, job_id))
            return
        if parsed.path in {"/api/decrypt-risk-summary-fragment", "/api/decrypt-risk-fragment", "/api/decrypt-risk-detail", "/api/decrypt-risk-warmup"}:
            params = parse_qs(parsed.query)
            try:
                start = parse_local_datetime((params.get("start") or [""])[-1], self.config.timezone)
                end = parse_local_datetime((params.get("end") or [""])[-1], self.config.timezone)
                if end <= start:
                    raise ValueError("结束时间必须晚于开始时间。")
                if end - start > timedelta(days=MAX_RANGE_DAYS):
                    raise ValueError(f"时间跨度不能超过 {MAX_RANGE_DAYS} 天。")
            except ValueError as exc:
                self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
                return
            try:
                if parsed.path == "/api/decrypt-risk-detail":
                    self.send_html(live_decrypt_detail_page(self.config, start, end, params))
                    return
                if parsed.path == "/api/decrypt-risk-warmup":
                    data = live_decrypt_warmup_json(self.config, start, end)
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(data)
                    return
                if parsed.path == "/api/decrypt-risk-summary-fragment":
                    data = live_decrypt_summary_fragment(self.config, start, end)
                else:
                    data = live_decrypt_fragment(self.config, start, end)
            except Exception as exc:
                if parsed.path == "/api/decrypt-risk-warmup":
                    data = json.dumps(
                        {"status": "error", "error": f"{type(exc).__name__}: {str(exc)[:240]}"},
                        ensure_ascii=False,
                    ).encode("utf-8")
                    self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(data)
                    return
                data = (
                    '<section id="decrypt-risk-tracking" class="section-block decrypt-risk-shell">'
                    f'<p class="note">解密实时计算失败：{esc(type(exc).__name__)}: {esc(str(exc)[:240])}</p>'
                    "</section>"
                ).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            return
        if parsed.path == "/api/jobs":
            data = b"[]"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            return
        self.serve_static(parsed.path, session)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if self.redirect_canonical_host(parsed, HTTPStatus.TEMPORARY_REDIRECT):
            return
        session = self.require_session(self.request_next_path(parsed))
        if not session:
            return
        parsed_form = self.parse_request_form(parsed.path)
        if parsed_form is None:
            return
        form, files = parsed_form
        if parsed.path == "/api/temporary-report/cleanup":
            deleted = cleanup_temporary_report(self.config, session, form.get("path", ""))
            data = json.dumps({"deleted": deleted}, ensure_ascii=False).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            return
        if not self.csrf_ok(form, session) and not self.csrf_upload_fallback_ok(parsed.path, session):
            self.send_error(HTTPStatus.FORBIDDEN, "bad csrf token")
            return
        if parsed.path.startswith("/settings/keywords/"):
            if not self.require_admin(session):
                return
            self.handle_keyword_post(parsed.path, form)
            return
        if parsed.path.startswith("/settings/policy/"):
            if not self.require_admin(session):
                return
            self.handle_policy_post(parsed.path, form)
            return
        if parsed.path.startswith("/settings/internal-targets/"):
            if not self.require_admin(session):
                return
            self.handle_internal_targets_post(parsed.path, form)
            return
        if parsed.path.startswith("/settings/archive-suffixes/"):
            if not self.require_admin(session):
                return
            self.handle_archive_suffixes_post(parsed.path, form)
            return
        if parsed.path.startswith("/settings/plm-login/"):
            if not self.require_admin(session):
                return
            self.handle_plm_login_policy_post(parsed.path, form)
            return
        if parsed.path.startswith("/settings/terminal-behavior-review/"):
            if not self.require_admin(session):
                return
            self.handle_terminal_behavior_policy_post(parsed.path, form)
            return
        if parsed.path.startswith("/settings/decrypt-records/"):
            if not self.require_admin(session):
                return
            self.handle_decrypt_records_post(parsed.path, form, files)
            return
        if parsed.path.startswith("/settings/encryption-terminals/"):
            if not self.require_admin(session):
                return
            self.handle_encryption_terminals_post(parsed.path, form, files)
            return
        if parsed.path.startswith("/settings/organization-aliases/"):
            if not self.require_admin(session):
                return
            self.handle_organization_alias_post(parsed.path, form)
            return
        if parsed.path.startswith("/settings/auth/"):
            if not self.require_admin(session):
                return
            self.handle_auth_policy_post(parsed.path, form)
            return
        if parsed.path.startswith("/settings/exclusions/"):
            if not self.require_admin(session):
                return
            self.handle_exclusion_post(parsed.path, form)
            return
        if parsed.path == "/terminal-check/review":
            if session.role not in {"admin", "global"}:
                self.send_forbidden("仅授权查看全集团报告的用户可以保存风险终端复核记录。")
                return
            self.handle_terminal_check_review_post(form, session)
            return
        if parsed.path != "/api/generate":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            job = self.build_job(form, session)
        except ValueError as exc:
            self.send_html(manual_page(self.config, session, str(exc)), HTTPStatus.BAD_REQUEST)
            return
        if not RUN_LOCK.acquire(blocking=False):
            self.send_html(manual_page(self.config, session, "已有报告生成任务在运行，请稍后再试。"), HTTPStatus.CONFLICT)
            return
        with JOBS_LOCK:
            JOBS[job.job_id] = job
        thread = threading.Thread(target=run_job, args=(self.config, job), daemon=True)
        thread.start()
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", f"/jobs/{job.job_id}")
        self.end_headers()

    def handle_auth_callback(self, parsed: Any) -> None:
        params = parse_qs(parsed.query)
        code = (params.get("code") or [""])[-1]
        state = (params.get("state") or [""])[-1]
        saved = self.cookie_value(AUTH_STATE_COOKIE_NAME)
        saved_state, _, saved_next = saved.partition("|")
        next_path = unquote(saved_next or "%2F")
        if not code or not state or not saved_state or not hmac.compare_digest(state, saved_state):
            data, state_cookie = login_page(self.config, "/", "企业微信认证状态校验失败，请重新扫码。")
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", auth_cookie_header(self.config, AUTH_STATE_COOKIE_NAME, state_cookie, 600))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        try:
            identity = auth_proxy_request(self.config, "/auth/wecom/code", {"code": code})
        except Exception as exc:
            data, state_cookie = login_page(self.config, "/", f"企业微信认证失败：{type(exc).__name__}")
            self.send_response(HTTPStatus.BAD_GATEWAY)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", auth_cookie_header(self.config, AUTH_STATE_COOKIE_NAME, state_cookie, 600))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        userid = str(identity.get("userid") or "").strip()
        if not userid:
            self.send_html(forbidden_page("企业微信未返回有效 userid。"), HTTPStatus.FORBIDDEN)
            return
        session_company, session_department = wecom_item_org_fields(identity)
        session_hours = int(auth_policy(self.config)["session_hours"])
        session = AuthSession(
            session_id=secrets.token_urlsafe(32),
            userid=userid,
            name=str(identity.get("name") or ""),
            company=session_company,
            department=session_department,
            status=str(identity.get("status") or ""),
            csrf_token=secrets.token_urlsafe(32),
            expires_at=time.time() + session_hours * 3600,
        )
        if not session_is_allowed(self.config, session):
            self.send_html(forbidden_page("该企业微信账号未授权访问审计报告，或通讯录公司/状态无效。"), HTTPStatus.FORBIDDEN)
            return
        with SESSIONS_LOCK:
            SESSIONS[session.session_id] = session
            write_sessions_locked(self.config)
        if not next_path.startswith("/"):
            next_path = "/"
        next_path = normalize_login_next(next_path)
        if not self.login_next_available(next_path, session):
            next_path = "/"
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", public_redirect_url(self.config, next_path))
        self.send_header("Set-Cookie", auth_cookie_header(self.config, AUTH_COOKIE_NAME, session.session_id, session_hours * 3600))
        self.send_header("Set-Cookie", auth_cookie_header(self.config, AUTH_STATE_COOKIE_NAME, "", 0))
        self.end_headers()

    def redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()

    def login_next_available(self, next_path: str, session: AuthSession) -> bool:
        path = urlparse(next_path).path or "/"
        dynamic_paths = {
            "/",
            "/manual",
            "/reports",
            "/settings",
            "/settings/keywords",
            "/settings/policy",
            "/settings/internal-targets",
            "/settings/archive-suffixes",
            "/settings/plm-login",
            "/settings/terminal-behavior-review",
            "/settings/decrypt-records",
            "/settings/encryption-terminals",
            "/settings/organization-aliases",
            "/settings/organization-tree",
            "/settings/auth",
            "/settings/exclusions",
            "/terminal-check",
            "/terminal-check/events",
        }
        if path in dynamic_paths or path.startswith("/jobs/"):
            return True
        target = self.static_target(path)
        if not target or not target.exists() or not target.is_file():
            return False
        if not session_can_access_report_path(self.config, session, target):
            return False
        return True

    def handle_keyword_post(self, path: str, form: dict[str, str]) -> None:
        with RULES_LOCK:
            doc = load_keyword_doc(self.config)
            if not path.endswith("/save"):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            doc["rules"] = parse_keyword_editor_text(form.get("keywords") or "")
            write_rule_doc(keywords_path(self.config), doc, self.config)
        self.redirect("/settings/keywords")

    def handle_policy_post(self, path: str, form: dict[str, str]) -> None:
        with RULES_LOCK:
            if not path.endswith("/save"):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            doc = load_policy_doc(self.config)
            doc["design_suffixes"] = {
                "three_d": normalize_suffixes(form.get("three_d") or ""),
                "two_d": normalize_suffixes(form.get("two_d") or ""),
                "pcb_ecad": [],
            }
            write_rule_doc(policy_path(self.config), doc, self.config)
        self.redirect("/settings/policy")

    def handle_internal_targets_post(self, path: str, form: dict[str, str]) -> None:
        with RULES_LOCK:
            if not path.endswith("/save"):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            doc = load_policy_doc(self.config)
            doc["internal_targets"] = {
                "domains": normalize_domains(form.get("internal_domains") or ""),
                "networks": normalize_networks(form.get("internal_networks") or ""),
            }
            write_rule_doc(policy_path(self.config), doc, self.config)
        self.redirect("/settings/internal-targets")

    def handle_archive_suffixes_post(self, path: str, form: dict[str, str]) -> None:
        with RULES_LOCK:
            if not path.endswith("/save"):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            doc = load_policy_doc(self.config)
            doc["archive_suffixes"] = normalize_suffixes(form.get("archive_suffixes") or "")
            write_rule_doc(policy_path(self.config), doc, self.config)
        self.redirect("/settings/archive-suffixes")

    def handle_plm_login_policy_post(self, path: str, form: dict[str, str]) -> None:
        with RULES_LOCK:
            if not path.endswith("/save"):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            departments = normalize_unique_text_list(form.get("constrained_departments") or "")
            if not departments:
                self.send_html(plm_login_policy_page(self.config, error="至少保留一个强约束部门。"), HTTPStatus.BAD_REQUEST)
                return
            doc = load_policy_doc(self.config)
            plm_login_audit = doc.get("plm_login_audit")
            if not isinstance(plm_login_audit, dict):
                plm_login_audit = {}
            plm_login_audit["constrained_departments"] = departments
            plm_login_audit["terminal_match_fields"] = DEFAULT_PLM_TERMINAL_MATCH_FIELDS
            doc["plm_login_audit"] = plm_login_audit
            write_rule_doc(policy_path(self.config), doc, self.config)
        self.redirect("/settings/plm-login")

    def handle_terminal_behavior_policy_post(self, path: str, form: dict[str, str]) -> None:
        with RULES_LOCK:
            if not path.endswith("/save"):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            doc = load_policy_doc(self.config)
            policy = terminal_review.normalized_review_policy(doc)
            policy["enabled"] = form.get("enabled") == "1"
            for key, default in terminal_review.DEFAULT_REVIEW_POLICY.items():
                if key == "enabled":
                    continue
                policy[key] = clamp_int(str(form.get(key, default)), int(default), 0, 100000)
            doc["terminal_behavior_review"] = policy
            write_rule_doc(policy_path(self.config), doc, self.config)
            terminal_check_clear_cache()
        self.redirect("/settings/terminal-behavior-review")

    def handle_terminal_check_review_post(self, form: dict[str, str], session: AuthSession) -> None:
        try:
            start = parse_local_datetime(form.get("start", ""), self.config.timezone)
            end = parse_local_datetime(form.get("end", ""), self.config.timezone)
        except ValueError as exc:
            self.send_html(terminal_check_page(self.config, session, error=str(exc)), HTTPStatus.BAD_REQUEST)
            return
        selected = {key.removeprefix("candidate__") for key, value in form.items() if key.startswith("candidate__") and value == "1"}
        if not selected:
            self.send_html(
                terminal_check_page(self.config, session, {"preset": ["custom"], "start": [datetime_input_value(start)], "end": [datetime_input_value(end)]}, error="请至少勾选一条候选记录。"),
                HTTPStatus.BAD_REQUEST,
            )
            return
        try:
            policy_doc = load_policy_doc(self.config)
            cached_data = terminal_check_cached_data(self.config, policy_doc, start, end, wait_seconds=90)
            if not cached_data:
                raise RuntimeError("候选仍在后台生成，请稍后再保存。")
            candidates = cached_data["candidates"]
            existing_reviews = {review.candidate_id: review for review in cached_data["reviews"]}
        except Exception as exc:
            self.send_html(terminal_check_page(self.config, session, error=f"候选重新计算失败：{exc}"), HTTPStatus.BAD_REQUEST)
            return
        now = datetime.now(local_tz(self.config.timezone)) if local_tz(self.config.timezone) else datetime.now()
        rows: list[dict[str, Any]] = []
        for candidate in candidates:
            if candidate.candidate_id not in selected:
                continue
            status = form.get(f"status__{candidate.candidate_id}") or "待核查"
            if status not in terminal_review.REVIEW_STATUSES:
                status = "待核查"
            include = 0 if status in terminal_review.REPORT_EXCLUDED_STATUSES else 1
            existing_review = existing_reviews.get(candidate.candidate_id)
            notes = (form.get(f"notes__{candidate.candidate_id}") or (existing_review.notes if existing_review else "") or "").strip()
            conclusion = (form.get(f"conclusion__{candidate.candidate_id}") or (existing_review.conclusion if existing_review else "") or "").strip()
            owner_department = (form.get(f"owner__{candidate.candidate_id}") or (existing_review.owner_department if existing_review else "") or "").strip()
            due_raw = (form.get(f"due__{candidate.candidate_id}") or (existing_review.due_date[:10] if existing_review else "") or "").strip()
            due_date = due_raw if re.fullmatch(r"\d{4}-\d{2}-\d{2}", due_raw) else None
            rows.append(
                {
                    "event_date": candidate.event_date.isoformat(),
                    "event_start": candidate.event_start.strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
                    "event_end": candidate.event_end.strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
                    "review_id": candidate.candidate_id,
                    "candidate_id": candidate.candidate_id,
                    "anomaly_type": candidate.anomaly_type,
                    "status": status,
                    "include_in_report": include,
                    "reviewer_userid": session.userid,
                    "reviewer_name": session.name,
                    "review_time": now.strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
                    "updated_at": now.strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
                    "company": candidate.company,
                    "department": candidate.department,
                    "person": candidate.person,
                    "client_name": candidate.client_name,
                    "client_ip": candidate.client_ip,
                    "client_mac": candidate.client_mac,
                    "event_count": candidate.event_count,
                    "structure_count": candidate.structure_count,
                    "electrical_count": candidate.electrical_count,
                    "three_d_count": candidate.three_d_count,
                    "dwg_count": candidate.dwg_count,
                    "archive_count": candidate.archive_count,
                    "channels": candidate.channels,
                    "targets": candidate.targets,
                    "sample_files": candidate.sample_files,
                    "event_ids": candidate.event_ids,
                    "conclusion": conclusion,
                    "notes": notes,
                    "owner_department": owner_department,
                    "due_date": due_date,
                    "evidence_json": json.dumps(
                        {
                            "basis": candidate.basis,
                            "event_ids": candidate.event_ids[:500],
                            "sample_files": candidate.sample_files,
                            "channels": candidate.channels,
                            "targets": candidate.targets,
                        },
                        ensure_ascii=False,
                    ),
                }
            )
        if not rows:
            self.send_html(
                terminal_check_page(self.config, session, {"preset": ["custom"], "start": [datetime_input_value(start)], "end": [datetime_input_value(end)]}, error="所选候选已不在当前周期结果中，请刷新后重试。"),
                HTTPStatus.BAD_REQUEST,
            )
            return
        try:
            terminal_review.insert_reviews(self.config, rows)
            refreshed_reviews = terminal_review.fetch_reviews(self.config, start, end, include_all_status=True)
            terminal_check_put_cache(policy_doc, start, end, candidates, refreshed_reviews)
        except Exception as exc:
            self.send_html(terminal_check_page(self.config, session, error=f"核查记录保存失败：{exc}"), HTTPStatus.BAD_REQUEST)
            return
        params = urlencode({"preset": "custom", "start": datetime_input_value(start), "end": datetime_input_value(end)})
        self.redirect(f"/terminal-check?{params}")

    def handle_decrypt_records_post(
        self,
        path: str,
        form: dict[str, str],
        files: dict[str, list[dict[str, Any]]],
    ) -> None:
        if not path.endswith("/upload"):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        uploads = [item for item in files.get("decrypt_file", []) if isinstance(item, dict)]
        if not uploads:
            self.send_html(decrypt_records_page(self.config, error="请选择至少一个 .xlsx 文件。"), HTTPStatus.BAD_REQUEST)
            return
        day_dir = decrypt_upload_dir() / datetime.now().strftime("%Y%m%d")
        summaries: list[decrypt_records.ImportSummary] = []
        failures: list[str] = []
        try:
            day_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            self.send_html(
                decrypt_records_page(self.config, error=f"上传目录不可用：{type(exc).__name__}: {str(exc)[:240]}"),
                HTTPStatus.BAD_REQUEST,
            )
            return
        with RULES_LOCK:
            policy_doc = load_policy_doc(self.config)
        for idx, uploaded in enumerate(uploads, 1):
            original_filename = safe_upload_filename(str(uploaded.get("filename") or ""))
            content = uploaded.get("content")
            if not original_filename.lower().endswith(".xlsx"):
                failures.append(f"{original_filename or '未命名文件'}：仅支持 .xlsx")
                continue
            if not isinstance(content, (bytes, bytearray)) or not content:
                failures.append(f"{original_filename}：文件为空")
                continue
            batch_id = datetime.now().strftime("%Y%m%d%H%M%S") + f"-{idx:02d}-" + secrets.token_hex(4)
            dest = day_dir / f"{batch_id}_{original_filename}"
            try:
                dest.write_bytes(bytes(content))
                dest.chmod(0o640)
                summary = decrypt_records.import_decrypt_workbook(
                    clickhouse_args(self.config),
                    dest,
                    original_filename,
                    batch_id,
                    policy_doc,
                )
                summaries.append(summary)
            except Exception as exc:
                failures.append(f"{original_filename}：{type(exc).__name__}: {str(exc)[:160]}")

        if not summaries:
            self.send_html(
                decrypt_records_page(self.config, error="导入失败：" + "；".join(failures[:8])),
                HTTPStatus.BAD_REQUEST,
            )
            return

        total_rows = sum(summary.total_rows for summary in summaries)
        inserted_rows = sum(summary.inserted_rows for summary in summaries)
        duplicate_rows = sum(summary.duplicate_rows for summary in summaries)
        critical_rows = sum(summary.critical_design_rows for summary in summaries)
        unmatched_rows = sum(summary.unmatched_org_rows for summary in summaries)
        detail = "；".join(
            f"{summary.source_file}: 新增 {summary.inserted_rows}, 重复 {summary.duplicate_rows}"
            for summary in summaries[:6]
        )
        if len(summaries) > 6:
            detail += f"；另 {len(summaries) - 6} 个文件"
        failure_text = f"；失败 {len(failures)} 个：{'；'.join(failures[:4])}" if failures else ""
        message = (
            f"批量导入完成：成功 {len(summaries)} 个文件{failure_text}；"
            f"总行数 {total_rows}，新增 {inserted_rows}，重复 {duplicate_rows}；"
            f"标准图纸命中 {critical_rows}，未归一组织 {unmatched_rows}。"
            f" 明细：{detail}"
        )
        live_decrypt_clear_cache()
        self.send_html(decrypt_records_page(self.config, message=message))

    def handle_encryption_terminals_post(
        self,
        path: str,
        form: dict[str, str],
        files: dict[str, list[dict[str, Any]]],
    ) -> None:
        if not path.endswith("/upload"):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        uploads = [item for item in files.get("terminal_file", []) if isinstance(item, dict)]
        if not uploads:
            self.send_html(encryption_terminals_page(self.config, error="请选择至少一个 .xlsx 文件。"), HTTPStatus.BAD_REQUEST)
            return
        day_dir = encryption_terminal_upload_dir() / datetime.now().strftime("%Y%m%d")
        summaries: list[encryption_terminals.TerminalImportSummary] = []
        failures: list[str] = []
        try:
            day_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            self.send_html(
                encryption_terminals_page(self.config, error=f"上传目录不可用：{type(exc).__name__}: {str(exc)[:240]}"),
                HTTPStatus.BAD_REQUEST,
            )
            return
        for idx, uploaded in enumerate(uploads, 1):
            original_filename = safe_upload_filename(str(uploaded.get("filename") or ""))
            content = uploaded.get("content")
            if not original_filename.lower().endswith(".xlsx"):
                failures.append(f"{original_filename or '未命名文件'}：仅支持 .xlsx")
                continue
            if not isinstance(content, (bytes, bytearray)) or not content:
                failures.append(f"{original_filename}：文件为空")
                continue
            batch_id = datetime.now().strftime("%Y%m%d%H%M%S") + f"-{idx:02d}-" + secrets.token_hex(4)
            dest = day_dir / f"{batch_id}_{original_filename}"
            try:
                dest.write_bytes(bytes(content))
                dest.chmod(0o640)
                summary = encryption_terminals.import_terminal_workbook(
                    clickhouse_args(self.config),
                    dest,
                    original_filename,
                    batch_id,
                )
                summaries.append(summary)
            except Exception as exc:
                failures.append(f"{original_filename}：{type(exc).__name__}: {str(exc)[:180]}")

        if not summaries:
            self.send_html(
                encryption_terminals_page(self.config, error="导入失败：" + "；".join(failures[:8])),
                HTTPStatus.BAD_REQUEST,
            )
            return

        total_rows = sum(summary.total_rows for summary in summaries)
        inserted_rows = sum(summary.inserted_rows for summary in summaries)
        duplicate_rows = sum(summary.duplicate_rows for summary in summaries)
        valid_ip_rows = sum(summary.valid_ip_rows for summary in summaries)
        unique_ips = sum(summary.unique_ips for summary in summaries)
        unique_terminal_keys = sum(summary.unique_terminal_keys for summary in summaries)
        missing_ip_rows = sum(summary.missing_ip_rows for summary in summaries)
        detail = "；".join(
            f"{summary.source_file}: 新增 {summary.inserted_rows}, 终端键 {summary.unique_terminal_keys}, IP {summary.unique_ips}, 重复 {summary.duplicate_rows}"
            for summary in summaries[:6]
        )
        if len(summaries) > 6:
            detail += f"；另 {len(summaries) - 6} 个文件"
        failure_text = f"；失败 {len(failures)} 个：{'；'.join(failures[:4])}" if failures else ""
        message = (
            f"终端列表导入完成：成功 {len(summaries)} 个文件{failure_text}；"
            f"总行数 {total_rows}，新增 {inserted_rows}，重复 {duplicate_rows}；"
            f"有效IP行 {valid_ip_rows}，合规终端键合计 {unique_terminal_keys}，唯一IP合计 {unique_ips}，缺IP行 {missing_ip_rows}。"
            f" 明细：{detail}"
        )
        self.send_html(encryption_terminals_page(self.config, message=message))

    def handle_organization_alias_post(self, path: str, form: dict[str, str]) -> None:
        with RULES_LOCK:
            doc = load_policy_doc(self.config)
            aliases = normalize_organization_aliases(doc.get("organization_aliases"))
            if path.endswith("/add"):
                item = organization_alias_from_form(form, default_enabled=True)
                if not item["canonical_company"]:
                    self.send_html(organization_aliases_page(self.config, error="标准公司不能为空。"), HTTPStatus.BAD_REQUEST)
                    return
                if not (item["raw_org_path"] or item["raw_company"] or item["raw_department"]):
                    self.send_html(organization_aliases_page(self.config, error="至少填写一个原始组织条件。"), HTTPStatus.BAD_REQUEST)
                    return
                aliases.append(item)
            elif path.endswith("/update"):
                idx = clamp_int(form.get("idx", ""), -1, -1, max(len(aliases) - 1, -1))
                if idx < 0 or idx >= len(aliases):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                item = organization_alias_from_form(form, default_enabled=False)
                if not item["canonical_company"]:
                    self.send_html(organization_aliases_page(self.config, error="标准公司不能为空。"), HTTPStatus.BAD_REQUEST)
                    return
                aliases[idx] = item
            elif path.endswith("/delete"):
                idx = clamp_int(form.get("idx", ""), -1, -1, max(len(aliases) - 1, -1))
                if idx < 0 or idx >= len(aliases):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                del aliases[idx]
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            doc["organization_aliases"] = aliases
            write_rule_doc(policy_path(self.config), doc, self.config)
        self.redirect("/settings/organization-aliases")

    def handle_auth_policy_post(self, path: str, form: dict[str, str]) -> None:
        with RULES_LOCK:
            if not path.endswith("/save"):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            doc = load_policy_doc(self.config)
            doc["auth"] = {
                "policy_admin_userids": [FIXED_POLICY_ADMIN_USERID],
                "global_viewer_userids": normalize_userids(form.get("global_viewer_userids") or ""),
                "session_hours": max(1, min(24, clamp_int(form.get("session_hours", "8"), 8, 1, 24))),
            }
            write_rule_doc(policy_path(self.config), doc, self.config)
        self.redirect("/settings/auth")

    def handle_exclusion_post(self, path: str, form: dict[str, str]) -> None:
        with RULES_LOCK:
            doc = load_exclusion_doc(self.config)
            rules = [rule for rule in doc.get("rules", []) if isinstance(rule, dict)]
            if path.endswith("/add"):
                rule_name = " ".join((form.get("rule_name") or "").strip().split())
                if rule_name:
                    rules.append(
                        {
                            "enabled": True,
                            "rule_name": rule_name,
                            "topic": (form.get("topic") or "*").strip(),
                            "target_contains": form_list(form.get("target_contains") or ""),
                            "target_regex": form_list(form.get("target_regex") or ""),
                            "file_contains": form_list(form.get("file_contains") or ""),
                            "file_regex": form_list(form.get("file_regex") or ""),
                            "process_contains": form_list(form.get("process_contains") or ""),
                            "subject_contains": form_list(form.get("subject_contains") or ""),
                            "action": "exclude",
                            "note": (form.get("note") or "").strip(),
                        }
                    )
            elif path.endswith("/toggle"):
                idx = clamp_int(form.get("idx", ""), -1, -1, max(len(rules) - 1, -1))
                if 0 <= idx < len(rules):
                    rules[idx]["enabled"] = not rule_enabled(rules[idx])
            elif path.endswith("/delete"):
                idx = clamp_int(form.get("idx", ""), -1, -1, max(len(rules) - 1, -1))
                if 0 <= idx < len(rules):
                    del rules[idx]
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            doc["rules"] = unique_rules(rules, "rule_name")
            write_rule_doc(exclusions_path(self.config), doc, self.config)
        self.redirect("/settings/exclusions")

    def build_job(self, form: dict[str, str], session: AuthSession) -> Job:
        start_dt = parse_local_datetime(form.get("start", ""), self.config.timezone)
        end_dt = parse_local_datetime(form.get("end", ""), self.config.timezone)
        if end_dt <= start_dt:
            raise ValueError("结束时间必须晚于开始时间。")
        if end_dt - start_dt > timedelta(days=MAX_RANGE_DAYS):
            raise ValueError(f"时间跨度不能超过 {MAX_RANGE_DAYS} 天。")
        job_id = make_job_id()
        start_token = start_dt.strftime("%Y%m%d%H%M")
        end_token = end_dt.strftime("%Y%m%d%H%M")
        base_name = f"tianqing_custom_{start_token}_{end_token}_{job_id}.html"
        log_name = f"{job_id}.log"
        return Job(
            job_id=job_id,
            label=safe_label(form.get("label", "")),
            start_text=start_dt.strftime("%Y-%m-%d %H:%M:%S"),
            end_text=end_dt.strftime("%Y-%m-%d %H:%M:%S"),
            max_events=0,
            output_name=base_name,
            log_name=log_name,
            refresh_clickhouse=True,
        )

    def send_jobs_json(self, session: AuthSession) -> None:
        with JOBS_LOCK:
            jobs = list(JOBS.values())
        payload = [job.__dict__ for job in jobs]
        data = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def static_target(self, request_path: str) -> Path | None:
        path = unquote(request_path.split("?", 1)[0].split("#", 1)[0])
        if path in {"", "/", "/index.html"}:
            archive_home = default_home_report_path(self.config)
            if archive_home and archive_home.exists() and archive_home.is_file():
                return archive_home
            official_home = (self.config.report_dir / "tianqing_leadership_previous-day.html").resolve()
            if official_home.exists() and official_home.is_file():
                return official_home
            latest_home = (self.config.report_dir / "index.html").resolve()
            if latest_home.exists() and latest_home.is_file():
                return latest_home
            path = "/index.html"
        normalized = posixpath.normpath(path)
        parts = [part for part in normalized.split("/") if part and part not in {".", ".."}]
        if not parts:
            parts = ["index.html"]
        if parts[0] == "jobs":
            return None
        target = (self.config.report_dir.joinpath(*parts)).resolve()
        try:
            target.relative_to(self.config.report_dir.resolve())
        except ValueError:
            return None
        return target

    def serve_static(self, request_path: str, session: AuthSession) -> None:
        target = self.static_target(request_path)
        if not target or not target.exists() or not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if not session_can_access_report_path(self.config, session, target):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        mime = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        try:
            data = target.read_bytes()
        except OSError:
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if mime.startswith("text/html") or target.suffix.lower() in {".html", ".htm"}:
            if not ai_policy_enabled(self.config):
                data = suppress_static_ai_section(data)
            data = inject_identity_bar(data, session)
            data = inject_report_navigation_patch(data, self.config, target)
            data = inject_top_risk_definition(data)
            data = inject_global_management_summary(data, self.config, target)
            data = inject_home_history_dropdown(data, self.config, session)
            data = inject_temporary_report_cleanup(data, self.config, target)
            path = unquote(request_path.split("?", 1)[0].split("#", 1)[0])
            normalized = posixpath.normpath(path)
            parts = [part for part in normalized.split("/") if part and part not in {".", ".."}]
            if not parts or parts == ["index.html"]:
                data = inject_job_status_bar(data, self.config, session)
            data = inject_trend_visual_patch(data)
            data = inject_live_decrypt_loader(data, self.config)
            data = inject_event_table_sorting(data)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        cache_value = "no-store" if mime.startswith("text/html") or target.suffix.lower() in {".html", ".htm"} else "public, max-age=60"
        self.send_header("Cache-Control", cache_value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)


class ReportServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], handler_class: type[BaseHTTPRequestHandler], config: AppConfig):
        super().__init__(server_address, handler_class)
        self.config = config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve data-security audit reports and custom report generation form.")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--report-dir", default=DEFAULT_REPORT_DIR)
    parser.add_argument("--app-dir", default=DEFAULT_APP_DIR)
    parser.add_argument("--audit-policy-file", default=os.getenv("TIANQING_AUDIT_POLICY_FILE", ""))
    parser.add_argument("--sensitive-keywords-file", default=os.getenv("TIANQING_SENSITIVE_KEYWORDS_FILE", ""))
    parser.add_argument("--exclusion-file", default=os.getenv("TIANQING_AUDIT_EXCLUSION_FILE", ""))
    parser.add_argument("--log-file", default=DEFAULT_LOG_FILE)
    parser.add_argument("--timezone", default=DEFAULT_TIMEZONE)
    parser.add_argument("--python", default="/usr/bin/python3")
    parser.add_argument("--disable-clickhouse", action="store_true", help="Generate custom reports by scanning the raw log instead of querying ClickHouse.")
    parser.add_argument("--clickhouse-url", default=os.getenv("CLICKHOUSE_URL", DEFAULT_CLICKHOUSE_URL))
    parser.add_argument("--clickhouse-database", default=os.getenv("CLICKHOUSE_DB", DEFAULT_CLICKHOUSE_DATABASE))
    parser.add_argument("--clickhouse-user", default=os.getenv("CLICKHOUSE_USER", ""))
    parser.add_argument("--clickhouse-password", default=os.getenv("CLICKHOUSE_PASSWORD", ""))
    parser.add_argument("--clickhouse-timeout", type=int, default=int(os.getenv("CLICKHOUSE_TIMEOUT", "120")))
    parser.add_argument("--public-base-url", default=os.getenv("TIANQING_REPORT_PUBLIC_URL", DEFAULT_PUBLIC_BASE_URL))
    parser.add_argument("--auth-callback-url", default=os.getenv("TIANQING_AUTH_CALLBACK_URL", DEFAULT_AUTH_CALLBACK_URL))
    parser.add_argument("--auth-cookie-domain", default=os.getenv("TIANQING_AUTH_COOKIE_DOMAIN", DEFAULT_AUTH_COOKIE_DOMAIN))
    parser.add_argument("--auth-proxy-base-url", default=os.getenv("TIANQING_AUTH_PROXY_BASE_URL", DEFAULT_AUTH_PROXY_BASE_URL))
    parser.add_argument("--auth-proxy-token", default=os.getenv("TIANQING_AUTH_PROXY_TOKEN", ""))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    app_dir = Path(args.app_dir)
    config = AppConfig(
        host=args.host,
        port=args.port,
        report_dir=Path(args.report_dir),
        app_dir=app_dir,
        policy_file=Path(args.audit_policy_file) if args.audit_policy_file else app_dir / "audit_policy.json",
        keywords_file=Path(args.sensitive_keywords_file) if args.sensitive_keywords_file else app_dir / "sensitive_keywords.json",
        exclusions_file=Path(args.exclusion_file) if args.exclusion_file else app_dir / "audit_exclusions.json",
        log_file=Path(args.log_file),
        timezone=args.timezone,
        python=args.python,
        use_clickhouse=not args.disable_clickhouse,
        clickhouse_url=args.clickhouse_url,
        clickhouse_database=args.clickhouse_database,
        clickhouse_user=args.clickhouse_user,
        clickhouse_password=args.clickhouse_password,
        clickhouse_timeout=args.clickhouse_timeout,
        public_base_url=args.public_base_url.rstrip("/"),
        auth_callback_url=args.auth_callback_url.strip(),
        auth_cookie_domain=args.auth_cookie_domain.strip(),
        auth_proxy_base_url=args.auth_proxy_base_url.rstrip("/"),
        auth_proxy_token=args.auth_proxy_token,
    )
    config.report_dir.mkdir(parents=True, exist_ok=True)
    (config.report_dir / "jobs").mkdir(parents=True, exist_ok=True)
    cleanup_temporary_reports(config)
    with SESSIONS_LOCK:
        SESSIONS.update(read_persisted_sessions(config))
        write_sessions_locked(config)
    server = ReportServer((config.host, config.port), ReportHandler, config)
    print(f"Serving data-security audit reports on {config.host}:{config.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
