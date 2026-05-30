#!/usr/bin/env bash
set -euo pipefail

PERIOD="${1:-current-week}"
REMOTE_HOST="${TIANQING_REPORT_HOST:-root@172.88.49.239}"
REMOTE_DIR="${TIANQING_REPORT_DIR:-/opt/tianqing-reports}"
REMOTE_APP_DIR="${TIANQING_REPORT_APP_DIR:-/opt/tianqing-report-app}"
PUBLIC_BASE_URL="${TIANQING_REPORT_PUBLIC_URL:-https://audit.daqo.com}"
POLICY_FILE="${TIANQING_AUDIT_POLICY_FILE:-/data/tianqing-audit/config/audit_policy.json}"
KEYWORDS_FILE="${TIANQING_SENSITIVE_KEYWORDS_FILE:-/data/tianqing-audit/config/sensitive_keywords.json}"
EXCLUSION_FILE="${TIANQING_AUDIT_EXCLUSION_FILE:-/data/tianqing-audit/config/audit_exclusions.json}"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$*" >&2
}

case "$PERIOD" in
  current-week|previous-week|current-month|previous-month|today|all) ;;
  *)
    echo "Unsupported period: $PERIOD" >&2
    exit 2
    ;;
esac

mkdir -p reports
log "Ensuring remote report directories on $REMOTE_HOST"
ssh -o BatchMode=yes "$REMOTE_HOST" "mkdir -p '$REMOTE_DIR' '$REMOTE_APP_DIR'"
APP_FILES=(
  tianqing_channel_matrix_module.py
  tianqing_external_audit_report.py
  tianqing_clickhouse_ingest.py
  tianqing_decrypt_audit_module.py
  tianqing_decrypt_data_module.py
  tianqing_decrypt_records.py
  tianqing_encryption_terminals.py
  tianqing_evidence_detail_module.py
  tianqing_organization_risk_module.py
  tianqing_rename_data_module.py
  tianqing_rename_tracking_module.py
  tianqing_report_modules.py
  tianqing_risk_overview_module.py
  tianqing_terminal_behavior_review.py
  tianqing_trend_module.py
  generate_tianqing_period_report.sh
  backfill_tianqing_archives.sh
  recipient_mapping.csv
  audit_dispositions.csv
  wecom_directory_cache.json
)
PROTECTED_CONFIG_FILES=(audit_policy.json sensitive_keywords.json audit_exclusions.json)
for protected in "${PROTECTED_CONFIG_FILES[@]}"; do
  for app_file in "${APP_FILES[@]}"; do
    if [[ "$app_file" == "$protected" ]]; then
      echo "Refusing to deploy mutable runtime config file: $protected" >&2
      exit 3
    fi
  done
done
if [[ -f tianqing_report_web.py ]]; then
  APP_FILES+=(tianqing_report_web.py)
fi
log "Uploading report application files"
scp -q "${APP_FILES[@]}" "$REMOTE_HOST:$REMOTE_APP_DIR/"
ssh -o BatchMode=yes "$REMOTE_HOST" "find '$REMOTE_APP_DIR' -maxdepth 1 -type f -exec chmod 0644 {} +; chmod 0755 '$REMOTE_APP_DIR/generate_tianqing_period_report.sh' '$REMOTE_APP_DIR/backfill_tianqing_archives.sh' 2>/dev/null || true"

STAMP="$(date +%Y%m%d-%H%M%S)"
LOCAL_FILE="reports/tianqing_leadership_${PERIOD}_${STAMP}.html"
LOCAL_ALIAS="reports/tianqing_leadership_${PERIOD//-/_}.html"
REMOTE_STAMPED="tianqing_leadership_${PERIOD}_${STAMP}.html"
REMOTE_FILE="tianqing_leadership_${PERIOD}.html"
REMOTE_ALIAS="tianqing_leadership_${PERIOD//-/_}.html"
SKIP_INGEST="${TIANQING_SKIP_INGEST:-0}"

ssh -o BatchMode=yes "$REMOTE_HOST" bash -s -- \
  "$PERIOD" \
  "$PUBLIC_BASE_URL" \
  "$REMOTE_DIR" \
  "$REMOTE_APP_DIR" \
  "$REMOTE_STAMPED" \
  "$REMOTE_FILE" \
  "$REMOTE_ALIAS" \
  "$SKIP_INGEST" \
  "$POLICY_FILE" \
  "$KEYWORDS_FILE" \
  "$EXCLUSION_FILE" <<'REMOTE_SCRIPT'
set -euo pipefail
PERIOD="$1"
PUBLIC_BASE_URL="$2"
REMOTE_DIR="$3"
REMOTE_APP_DIR="$4"
REMOTE_STAMPED="$5"
REMOTE_FILE="$6"
REMOTE_ALIAS="$7"
SKIP_INGEST="$8"
POLICY_FILE="$9"
KEYWORDS_FILE="${10}"
EXCLUSION_FILE="${11}"
LOCK_FILE="$REMOTE_DIR/.publish-${PERIOD}.lock"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$*" >&2
}

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "ERROR: another Tianqing report publish is already running for $PERIOD" >&2
  exit 75
fi

cd "$REMOTE_APP_DIR"
mkdir -p "$(dirname "$POLICY_FILE")" "$(dirname "$KEYWORDS_FILE")" "$(dirname "$EXCLUSION_FILE")"
if [[ ! -f "$POLICY_FILE" && -f "$REMOTE_APP_DIR/audit_policy.json" ]]; then
  cp -n "$REMOTE_APP_DIR/audit_policy.json" "$POLICY_FILE"
  chmod 0640 "$POLICY_FILE" 2>/dev/null || true
fi
if [[ ! -f "$KEYWORDS_FILE" && -f "$REMOTE_APP_DIR/sensitive_keywords.json" ]]; then
  cp -n "$REMOTE_APP_DIR/sensitive_keywords.json" "$KEYWORDS_FILE"
  chmod 0644 "$KEYWORDS_FILE" 2>/dev/null || true
fi
if [[ ! -f "$EXCLUSION_FILE" && -f "$REMOTE_APP_DIR/audit_exclusions.json" ]]; then
  cp -n "$REMOTE_APP_DIR/audit_exclusions.json" "$EXCLUSION_FILE"
  chmod 0644 "$EXCLUSION_FILE" 2>/dev/null || true
fi
if [[ -f /data/tianqing-audit/clickhouse/.env ]]; then
  set -a
  # shellcheck disable=SC1091
  . /data/tianqing-audit/clickhouse/.env
  set +a
fi

if [[ "$SKIP_INGEST" == "1" ]]; then
  log "Skipping ClickHouse ingest because TIANQING_SKIP_INGEST=1"
else
  log "Ingesting latest Tianqing syslog into ClickHouse"
  python3 tianqing_clickhouse_ingest.py \
    --log-file /data/tianqing-audit/raw-log/tianqing.log \
    --audit-policy-file "$POLICY_FILE" \
    --batch-size 20000
  log "ClickHouse ingest completed"
fi

log "Generating leadership HTML report for $PERIOD"
python3 tianqing_external_audit_report.py \
  --period "$PERIOD" \
  --use-clickhouse \
  --clickhouse-url "${CLICKHOUSE_URL:-http://127.0.0.1:8123}" \
  --clickhouse-database "${CLICKHOUSE_DB:-tianqing}" \
  --format html \
  --wecom-directory-authoritative \
  --public-base-url "$PUBLIC_BASE_URL" \
  --recipient-map recipient_mapping.csv \
  --disposition-file audit_dispositions.csv \
  --sensitive-keywords-file "$KEYWORDS_FILE" \
  --audit-policy-file "$POLICY_FILE" \
  --exclusion-file "$EXCLUSION_FILE" \
  --wecom-directory-cache wecom_directory_cache.json \
  --output "$REMOTE_DIR/$REMOTE_STAMPED"

log "Verifying generated report links"
python3 - "$REMOTE_DIR/$REMOTE_STAMPED" <<'PY'
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

report_path = Path(sys.argv[1])
root = report_path.parent.resolve()
html = report_path.read_text(encoding="utf-8", errors="replace")
missing: list[str] = []
for href in sorted(set(re.findall(r'href=["\']([^"\']+\.html(?:#[^"\']*)?)["\']', html))):
    parsed = urlparse(href)
    if parsed.scheme or parsed.netloc or href.startswith("/"):
        continue
    target_name = unquote(parsed.path)
    target = (root / target_name).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        missing.append(href)
        continue
    if not target.is_file():
        missing.append(href)
if missing:
    print("ERROR: generated report has missing local html links:", file=sys.stderr)
    for href in missing[:50]:
        print(f"  {href}", file=sys.stderr)
    if len(missing) > 50:
        print(f"  ... and {len(missing) - 50} more", file=sys.stderr)
    raise SystemExit(1)
print(f"Verified report links: {report_path.name}")
PY

log "Publishing stable aliases"
cp "$REMOTE_DIR/$REMOTE_STAMPED" "$REMOTE_DIR/$REMOTE_FILE"
cp "$REMOTE_DIR/$REMOTE_STAMPED" "$REMOTE_DIR/$REMOTE_ALIAS"
cp "$REMOTE_DIR/$REMOTE_STAMPED" "$REMOTE_DIR/index.html"
find "$REMOTE_DIR" -maxdepth 1 -name '*.html' -type f -exec chmod 0644 {} +
log "Stable publish does not register historical archives; official archives are written by generate_tianqing_period_report.sh"
REMOTE_SCRIPT

log "Downloading stamped report artifact"
scp -q "$REMOTE_HOST:$REMOTE_DIR/$REMOTE_STAMPED" "$LOCAL_FILE"
scp -q "$REMOTE_HOST:$REMOTE_DIR/${REMOTE_STAMPED%.html}_*.html" reports/ 2>/dev/null || true
cp "$LOCAL_FILE" "$LOCAL_ALIAS"

echo "Published: $PUBLIC_BASE_URL/$REMOTE_FILE"
echo "Compatibility alias: $PUBLIC_BASE_URL/$REMOTE_ALIAS"
echo "Stable latest: $PUBLIC_BASE_URL/"
