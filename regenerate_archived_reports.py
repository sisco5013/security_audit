#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import fcntl
from pathlib import Path


APP_DIR = Path(os.environ.get("TIANQING_REPORT_APP_DIR", "/opt/tianqing-report-app"))
REPORT_DIR = Path(os.environ.get("TIANQING_REPORT_DIR", "/opt/tianqing-reports"))
PUBLIC_BASE_URL = os.environ.get("TIANQING_REPORT_PUBLIC_URL", "https://audit.daqo.com")
POLICY_FILE = Path(os.environ.get("TIANQING_AUDIT_POLICY_FILE", "/data/tianqing-audit/config/audit_policy.json"))
KEYWORDS_FILE = Path(os.environ.get("TIANQING_SENSITIVE_KEYWORDS_FILE", "/data/tianqing-audit/config/sensitive_keywords.json"))
EXCLUSION_FILE = Path(os.environ.get("TIANQING_AUDIT_EXCLUSION_FILE", "/data/tianqing-audit/config/audit_exclusions.json"))
ARCHIVE_INDEX = REPORT_DIR / "report_archives.jsonl"
LOG_DIR = REPORT_DIR / "jobs"
CLICKHOUSE_ENV = Path("/data/tianqing-audit/clickhouse/.env")
REPORT_LOCK_FILE = Path(os.environ.get("TIANQING_REPORT_LOCK_FILE", "/run/lock/tianqing-report-generate.lock"))


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        text = line.strip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        key, value = text.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def read_archives() -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for line in ARCHIVE_INDEX.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if (
            isinstance(item, dict)
            and str(item.get("scope") or "global") == "global"
            and item.get("path")
            and item.get("period_start")
            and item.get("period_end")
        ):
            entries.append(item)
    return entries


def archive_sort_key(item: dict[str, str]) -> tuple[str, str, str, str]:
    return (
        str(item.get("period_start") or ""),
        str(item.get("scope") or "global"),
        str(item.get("company") or ""),
        str(item.get("path") or ""),
    )


def generator_command(item: dict[str, str], output_path: Path, env_values: dict[str, str]) -> list[str]:
    cmd = [
        "/usr/bin/python3",
        str(APP_DIR / "tianqing_external_audit_report.py"),
        "--start",
        str(item["period_start"]),
        "--end",
        str(item["period_end"]),
        "--use-clickhouse",
        "--clickhouse-url",
        env_values.get("CLICKHOUSE_URL", "http://127.0.0.1:8123"),
        "--clickhouse-database",
        env_values.get("CLICKHOUSE_DB", "tianqing"),
        "--format",
        "html",
        "--wecom-directory-authoritative",
        "--public-base-url",
        PUBLIC_BASE_URL,
        "--people-map",
        str(APP_DIR / "people_mapping.csv"),
        "--recipient-map",
        str(APP_DIR / "recipient_mapping.csv"),
        "--disposition-file",
        str(APP_DIR / "audit_dispositions.csv"),
        "--sensitive-keywords-file",
        str(KEYWORDS_FILE),
        "--audit-policy-file",
        str(POLICY_FILE),
        "--exclusion-file",
        str(EXCLUSION_FILE),
        "--wecom-directory-cache",
        str(APP_DIR / "wecom_directory_cache.json"),
        "--wecom-directory-cache-hours",
        "8760",
        "--output",
        str(output_path),
    ]
    return cmd


def low_priority_prefix() -> list[str]:
    if shutil.which("ionice"):
        return ["nice", "-n", "15", "ionice", "-c2", "-n7"]
    return ["nice", "-n", "15"]


def replace_report_files(tmp_dir: Path, target: Path) -> int:
    target.parent.mkdir(parents=True, exist_ok=True)
    stem = target.stem
    old_files = list(target.parent.glob(stem + "*.html"))
    new_files = list(tmp_dir.glob(stem + "*.html"))
    if not (tmp_dir / target.name).exists():
        raise RuntimeError(f"main output missing: {target.name}")
    for old in old_files:
        old.unlink()
    moved = 0
    for new in new_files:
        final = target.parent / new.name
        new.replace(final)
        final.chmod(0o644)
        moved += 1
    return moved


def main() -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%d%H%M%S")
    log_path = LOG_DIR / f"regenerate_archives_{run_id}.log"
    env_values = load_dotenv(CLICKHOUSE_ENV)
    env = os.environ.copy()
    env.update(env_values)
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONPYCACHEPREFIX"] = "/tmp"
    tmp_root = REPORT_DIR / f".regen-archives-{run_id}"
    tmp_root.mkdir(parents=True, exist_ok=True)
    backup_path = REPORT_DIR / f"report_archives.before-regenerate-{run_id}.jsonl"
    shutil.copy2(ARCHIVE_INDEX, backup_path)
    entries = sorted(read_archives(), key=archive_sort_key)
    ok = 0
    failed = 0
    with REPORT_LOCK_FILE.open("w", encoding="utf-8") as lock_handle, log_path.open("w", encoding="utf-8") as log:
        def write(message: str) -> None:
            print(message, flush=True)
            log.write(message + "\n")
            log.flush()

        write(f"waiting_for_lock={REPORT_LOCK_FILE}")
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        write(f"lock_acquired={REPORT_LOCK_FILE}")
        write(f"started={time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
        write(f"entries={len(entries)}")
        write(f"archive_backup={backup_path}")
        for index, item in enumerate(entries, 1):
            rel = Path(str(item["path"]))
            target = REPORT_DIR / rel
            tmp_dir = tmp_root / f"{index:03d}"
            tmp_dir.mkdir(parents=True, exist_ok=True)
            tmp_output = tmp_dir / target.name
            label = f"[{index}/{len(entries)}] {item.get('period')} {item.get('scope')} {item.get('company') or '-'} {item.get('period_start')} -> {item.get('period_end')} {rel.as_posix()}"
            write(f"RUN {label}")
            cmd = low_priority_prefix() + generator_command(item, tmp_output, env_values)
            started = time.time()
            proc = subprocess.run(
                cmd,
                cwd=str(APP_DIR),
                env={**env, "TIANQING_REPORT_GENERATED_AT": str(item.get("generated_at") or item.get("period_end") or "")},
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            elapsed = int(time.time() - started)
            if proc.returncode != 0:
                failed += 1
                write(f"FAIL {label} rc={proc.returncode} elapsed={elapsed}s")
                continue
            try:
                moved = replace_report_files(tmp_dir, target)
            except Exception as exc:
                failed += 1
                write(f"FAIL_REPLACE {label} error={exc} elapsed={elapsed}s")
                continue
            ok += 1
            write(f"OK {label} files={moved} elapsed={elapsed}s")
        try:
            shutil.rmtree(tmp_root)
        except Exception as exc:
            write(f"WARN cleanup_tmp_failed={exc}")
        write(f"finished={time.strftime('%Y-%m-%dT%H:%M:%S%z')} ok={ok} failed={failed}")
    print(log_path)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
