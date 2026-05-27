#!/usr/bin/env bash
set -euo pipefail

PERIOD="${1:-current-week}"
UPDATE_INDEX="${2:-1}"
REMOTE_DIR="${TIANQING_REPORT_DIR:-/opt/tianqing-reports}"
APP_DIR="${TIANQING_REPORT_APP_DIR:-/opt/tianqing-report-app}"
PUBLIC_BASE_URL="${TIANQING_REPORT_PUBLIC_URL:-https://audit.daqo.com}"
LOG_FILE="${TIANQING_LOG_FILE:-/data/tianqing-audit/raw-log/tianqing.log}"
POLICY_FILE="${TIANQING_AUDIT_POLICY_FILE:-/data/tianqing-audit/config/audit_policy.json}"
KEYWORDS_FILE="${TIANQING_SENSITIVE_KEYWORDS_FILE:-/data/tianqing-audit/config/sensitive_keywords.json}"
EXCLUSION_FILE="${TIANQING_AUDIT_EXCLUSION_FILE:-/data/tianqing-audit/config/audit_exclusions.json}"

case "$PERIOD" in
  previous-day|current-week|previous-week|current-month|previous-month|today|all) ;;
  *)
    echo "Unsupported period: $PERIOD" >&2
    exit 2
    ;;
esac

mkdir -p "$REMOTE_DIR"
cd "$APP_DIR"
mkdir -p "$(dirname "$POLICY_FILE")" "$(dirname "$KEYWORDS_FILE")" "$(dirname "$EXCLUSION_FILE")"
if [[ ! -f "$POLICY_FILE" && -f "$APP_DIR/audit_policy.json" ]]; then
  cp -n "$APP_DIR/audit_policy.json" "$POLICY_FILE"
  chmod 0640 "$POLICY_FILE" 2>/dev/null || true
fi
if [[ ! -f "$KEYWORDS_FILE" && -f "$APP_DIR/sensitive_keywords.json" ]]; then
  cp -n "$APP_DIR/sensitive_keywords.json" "$KEYWORDS_FILE"
  chmod 0644 "$KEYWORDS_FILE" 2>/dev/null || true
fi
if [[ ! -f "$EXCLUSION_FILE" && -f "$APP_DIR/audit_exclusions.json" ]]; then
  cp -n "$APP_DIR/audit_exclusions.json" "$EXCLUSION_FILE"
  chmod 0644 "$EXCLUSION_FILE" 2>/dev/null || true
fi

if [[ -f /data/tianqing-audit/clickhouse/.env ]]; then
  set -a
  # shellcheck disable=SC1091
  . /data/tianqing-audit/clickhouse/.env
  set +a
fi

REPORT_LOCK_FILE="${TIANQING_REPORT_LOCK_FILE:-/run/lock/tianqing-report-generate.lock}"
mkdir -p "$(dirname "$REPORT_LOCK_FILE")"
exec 9>"$REPORT_LOCK_FILE"
flock 9

ARCHIVE_OFFICIAL="${TIANQING_REPORT_ARCHIVE:-0}"
SEAMLESS_WEEKLY="${TIANQING_SEAMLESS_WEEKLY:-1}"
WEEKLY_STATE_FILE="$REMOTE_DIR/.weekly_${PERIOD}_success_end"

archive_enabled() {
  [[ "$ARCHIVE_OFFICIAL" == "1" && ( "$PERIOD" == *week || "$PERIOD" == "previous-day" || "$PERIOD" == "today" ) ]]
}

register_archive() {
  local output_path="$1"
  local scope="$2"
  local company="${3:-}"
  if ! archive_enabled; then
    return 0
  fi
  python3 - "$REMOTE_DIR" "$output_path" "$PERIOD" "$STAMP" "$scope" "$company" <<'PY'
import json
import os
import sys
from datetime import datetime
from pathlib import Path

root = Path(sys.argv[1]).resolve()
target = Path(sys.argv[2]).resolve()
period, stamp, scope, company = sys.argv[3:7]
try:
    rel = target.relative_to(root).as_posix()
except ValueError:
    raise SystemExit(0)
index = root / "report_archives.jsonl"
entry = {
    "period": period,
    "stamp": stamp,
    "scope": scope or "global",
    "company": company,
    "path": rel,
    "period_start": os.environ.get("REPORT_START", ""),
    "period_end": os.environ.get("REPORT_END", ""),
    "generated_at": os.environ.get("TIANQING_REPORT_GENERATED_AT") or datetime.now().astimezone().isoformat(timespec="seconds"),
    "source": "systemd-timer",
}

def archive_label(item):
    period_value = str(item.get("period") or "")
    start = str(item.get("period_start") or "")[:10]
    end = str(item.get("period_end") or "")[:10]
    if period_value in {"previous-day", "today"}:
        return start
    if period_value in {"current-week", "previous-week"}:
        return end
    return f"{start}->{end}"

def archive_key(item):
    return (
        str(item.get("scope") or "global"),
        str(item.get("company") or ""),
        str(item.get("period") or ""),
        archive_label(item),
    )

new_key = archive_key(entry)
lines = []
if index.exists():
    for line in index.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            item = json.loads(line)
        except Exception:
            continue
        if not isinstance(item, dict):
            continue
        if str(item.get("path") or "") == rel or archive_key(item) == new_key:
            continue
        lines.append(json.dumps(item, ensure_ascii=False, separators=(",", ":")))
lines.append(json.dumps(entry, ensure_ascii=False, separators=(",", ":")))
tmp = index.with_suffix(index.suffix + ".tmp")
tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
tmp.replace(index)
try:
    os.chmod(index, 0o640)
except OSError:
    pass
PY
}

resolve_period_args() {
  if [[ -n "${TIANQING_REPORT_START:-}" || -n "${TIANQING_REPORT_END:-}" ]]; then
    if [[ -z "${TIANQING_REPORT_START:-}" || -z "${TIANQING_REPORT_END:-}" ]]; then
      echo "TIANQING_REPORT_START and TIANQING_REPORT_END must be set together." >&2
      exit 2
    fi
    printf '%s\n%s\n' "$TIANQING_REPORT_START" "$TIANQING_REPORT_END"
  elif [[ "$ARCHIVE_OFFICIAL" == "1" && "$PERIOD" == "previous-day" ]]; then
    python3 - <<'PY'
from datetime import datetime, time, timedelta
try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

tz = ZoneInfo("Asia/Shanghai") if ZoneInfo else None
today = datetime.now(tz).date()
start = datetime.combine(today - timedelta(days=1), time.min, tz)
end = datetime.combine(today, time.min, tz)
print(start.strftime("%Y-%m-%d %H:%M:%S"))
print(end.strftime("%Y-%m-%d %H:%M:%S"))
PY
  elif [[ "$ARCHIVE_OFFICIAL" == "1" && "$SEAMLESS_WEEKLY" == "1" && "$PERIOD" == "current-week" ]]; then
    python3 - "$WEEKLY_STATE_FILE" <<'PY'
import sys
from datetime import datetime, timedelta
try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

tz = ZoneInfo("Asia/Shanghai") if ZoneInfo else None
now = datetime.now(tz).replace(second=0, microsecond=0)
state_path = sys.argv[1]
start = None
try:
    raw = open(state_path, encoding="utf-8").read().strip()
    if raw:
        start = datetime.fromisoformat(raw)
        if start.tzinfo is None and tz:
            start = start.replace(tzinfo=tz)
        elif start.tzinfo is not None and tz:
            start = start.astimezone(tz)
except Exception:
    start = None
if start is None or start >= now:
    start = now - timedelta(days=7)
print(start.strftime("%Y-%m-%d %H:%M:%S"))
print(now.strftime("%Y-%m-%d %H:%M:%S"))
PY
  else
    printf '\n\n'
  fi
}

write_weekly_state() {
  local end_text="$1"
  if [[ "$ARCHIVE_OFFICIAL" != "1" || "$SEAMLESS_WEEKLY" != "1" || "$PERIOD" != "current-week" ]]; then
    return 0
  fi
  python3 - "$WEEKLY_STATE_FILE" "$end_text" <<'PY'
import os
import sys
from datetime import datetime
from pathlib import Path

path = Path(sys.argv[1])
end_text = sys.argv[2]
parsed = datetime.fromisoformat(end_text)
path.write_text(parsed.isoformat(sep=" ", timespec="seconds") + "\n", encoding="utf-8")
try:
    os.chmod(path, 0o640)
except OSError:
    pass
PY
}

if [[ "${TIANQING_SKIP_INGEST:-0}" == "1" ]]; then
  echo "Skip ClickHouse ingest refresh."
else
  python3 tianqing_clickhouse_ingest.py \
    --log-file "$LOG_FILE" \
    --audit-policy-file "$POLICY_FILE" \
    --batch-size "${TIANQING_INGEST_BATCH_SIZE:-20000}"
fi

STAMP="${TIANQING_REPORT_STAMP:-$(date +%Y%m%d-%H%M%S)}"
STAMPED="tianqing_leadership_${PERIOD}_${STAMP}.html"
STABLE="tianqing_leadership_${PERIOD}.html"
ALIAS="tianqing_leadership_${PERIOD//-/_}.html"
OUTPUT_STEM="${STAMPED%.html}"

mapfile -t RESOLVED_PERIOD < <(resolve_period_args)
REPORT_START="${RESOLVED_PERIOD[0]:-}"
REPORT_END="${RESOLVED_PERIOD[1]:-}"
PERIOD_ARGS=(--period "$PERIOD")
if [[ -n "$REPORT_START" && -n "$REPORT_END" ]]; then
  PERIOD_ARGS=(--start "$REPORT_START" --end "$REPORT_END")
  echo "Resolved report range: $REPORT_START -> $REPORT_END"
fi
export REPORT_START REPORT_END

python3 tianqing_external_audit_report.py \
  "${PERIOD_ARGS[@]}" \
  --use-clickhouse \
  --clickhouse-url "${CLICKHOUSE_URL:-http://127.0.0.1:8123}" \
  --clickhouse-database "${CLICKHOUSE_DB:-tianqing}" \
  --format html \
  --wecom-directory-authoritative \
  --public-base-url "$PUBLIC_BASE_URL" \
  --people-map people_mapping.csv \
  --recipient-map recipient_mapping.csv \
  --disposition-file audit_dispositions.csv \
  --sensitive-keywords-file "$KEYWORDS_FILE" \
  --audit-policy-file "$POLICY_FILE" \
  --exclusion-file "$EXCLUSION_FILE" \
  --wecom-directory-cache wecom_directory_cache.json \
  --wecom-directory-refresh \
  --output "$REMOTE_DIR/$STAMPED"

cp "$REMOTE_DIR/$STAMPED" "$REMOTE_DIR/$STABLE"
cp "$REMOTE_DIR/$STAMPED" "$REMOTE_DIR/$ALIAS"
if [[ "$UPDATE_INDEX" != "0" ]]; then
  cp "$REMOTE_DIR/$STAMPED" "$REMOTE_DIR/index.html"
fi
find "$REMOTE_DIR" -maxdepth 1 -type f \( \
  -name "$STAMPED" -o \
  -name "$STABLE" -o \
  -name "$ALIAS" -o \
  -name "${OUTPUT_STEM}_*.html" \
\) -exec chmod 0644 {} +
register_archive "$REMOTE_DIR/$STAMPED" "global" ""

if [[ -n "$REPORT_END" ]]; then
  write_weekly_state "$REPORT_END"
fi

echo "Published: $PUBLIC_BASE_URL/$STABLE"
echo "Compatibility alias: $PUBLIC_BASE_URL/$ALIAS"
if [[ "$UPDATE_INDEX" != "0" ]]; then
  echo "Stable latest: $PUBLIC_BASE_URL/"
fi
