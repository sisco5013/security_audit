#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${TIANQING_REPORT_APP_DIR:-/opt/tianqing-report-app}"
REMOTE_DIR="${TIANQING_REPORT_DIR:-/opt/tianqing-reports}"
LOG_DIR="$REMOTE_DIR/jobs"
START_DATE="${1:-2026-05-05}"
END_DATE_EXCLUSIVE="${2:-2026-05-14}"
SLEEP_SECONDS="${BACKFILL_SLEEP_SECONDS:-600}"
INCLUDE_WEEKLY="${BACKFILL_INCLUDE_WEEKLY:-1}"
WEEKLY_START="${BACKFILL_WEEKLY_START:-2026-05-01 18:10:00}"
WEEKLY_END="${BACKFILL_WEEKLY_END:-2026-05-08 18:10:00}"
WEEKLY_STAMP="${BACKFILL_WEEKLY_STAMP:-20260508-181000}"

mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/backfill_archives_$(date +%Y%m%d%H%M%S).log"

exec > >(tee -a "$LOG_FILE") 2>&1
exec 8>/run/lock/tianqing-report-backfill.lock
if ! flock -n 8; then
  echo "Another Tianqing archive backfill is already running."
  exit 1
fi

cd "$APP_DIR"

low_priority() {
  if command -v ionice >/dev/null 2>&1; then
    nice -n 15 ionice -c2 -n7 "$@"
  else
    nice -n 15 "$@"
  fi
}

archive_has_path() {
  local rel_path="$1"
  python3 - "$REMOTE_DIR/report_archives.jsonl" "$rel_path" <<'PY'
import json
import sys
from pathlib import Path

index = Path(sys.argv[1])
needle = sys.argv[2]
if not index.exists():
    raise SystemExit(1)
for line in index.read_text(encoding="utf-8", errors="ignore").splitlines():
    try:
        item = json.loads(line)
    except Exception:
        continue
    if item.get("path") == needle:
        raise SystemExit(0)
raise SystemExit(1)
PY
}

echo "backfill_started=$(date --iso-8601=seconds)"
echo "daily_range=${START_DATE}..${END_DATE_EXCLUSIVE} exclusive"
echo "sleep_seconds=${SLEEP_SECONDS}"
echo "log_file=${LOG_FILE}"

if [[ -f /data/tianqing-audit/clickhouse/.env ]]; then
  set -a
  # shellcheck disable=SC1091
  . /data/tianqing-audit/clickhouse/.env
  set +a
fi

echo "Refresh ClickHouse ingest once before backfill."
if ! low_priority python3 tianqing_clickhouse_ingest.py \
  --log-file "${TIANQING_LOG_FILE:-/data/tianqing-audit/raw-log/tianqing.log}" \
  --batch-size "${TIANQING_INGEST_BATCH_SIZE:-20000}"; then
  echo "WARN: ingest refresh failed, continue with existing ClickHouse data."
fi

mapfile -t DAYS < <(python3 - "$START_DATE" "$END_DATE_EXCLUSIVE" <<'PY'
import sys
from datetime import date, timedelta

start = date.fromisoformat(sys.argv[1])
end = date.fromisoformat(sys.argv[2])
current = start
while current < end:
    print(current.isoformat())
    current += timedelta(days=1)
PY
)

for day in "${DAYS[@]}"; do
  IFS=$'\t' read -r start_text end_text stamp < <(python3 - "$day" <<'PY'
import sys
from datetime import date, datetime, time, timedelta

day = date.fromisoformat(sys.argv[1])
end = day + timedelta(days=1)
print("\t".join([
    datetime.combine(day, time.min).strftime("%Y-%m-%d %H:%M:%S"),
    datetime.combine(end, time.min).strftime("%Y-%m-%d %H:%M:%S"),
    end.strftime("%Y%m%d-000000"),
]))
PY
)
  output="$REMOTE_DIR/tianqing_leadership_previous-day_${stamp}.html"
  rel_output="tianqing_leadership_previous-day_${stamp}.html"
  if archive_has_path "$rel_output"; then
    echo "SKIP daily ${day}: archive registered ${rel_output}"
  else
    echo "RUN daily ${day}: ${start_text} -> ${end_text}"
    if ! TIANQING_REPORT_ARCHIVE=1 \
      TIANQING_SKIP_INGEST=1 \
      TIANQING_REPORT_START="$start_text" \
      TIANQING_REPORT_END="$end_text" \
      TIANQING_REPORT_STAMP="$stamp" \
      TIANQING_REPORT_GENERATED_AT="$end_text" \
      low_priority ./generate_tianqing_period_report.sh previous-day 0; then
      echo "ERROR daily ${day} failed; continue."
    fi
  fi
  if [[ "$SLEEP_SECONDS" != "0" ]]; then
    echo "sleep ${SLEEP_SECONDS}s"
    sleep "$SLEEP_SECONDS"
  fi
done

if [[ "$INCLUDE_WEEKLY" == "1" ]]; then
  weekly_output="$REMOTE_DIR/tianqing_leadership_previous-week_${WEEKLY_STAMP}.html"
  weekly_rel="tianqing_leadership_previous-week_${WEEKLY_STAMP}.html"
  if archive_has_path "$weekly_rel"; then
    echo "SKIP previous-week: archive registered ${weekly_rel}"
  else
    echo "RUN previous-week: ${WEEKLY_START} -> ${WEEKLY_END}"
    if ! TIANQING_REPORT_ARCHIVE=1 \
      TIANQING_SKIP_INGEST=1 \
      TIANQING_REPORT_START="$WEEKLY_START" \
      TIANQING_REPORT_END="$WEEKLY_END" \
      TIANQING_REPORT_STAMP="$WEEKLY_STAMP" \
      TIANQING_REPORT_GENERATED_AT="$WEEKLY_END" \
      low_priority ./generate_tianqing_period_report.sh previous-week 0; then
      echo "ERROR previous-week failed."
    fi
  fi
fi

echo "backfill_finished=$(date --iso-8601=seconds)"
