#!/usr/bin/env bash
set -euo pipefail

SOURCE_IPS="${SOURCE_IPS:-${SOURCE_IP:-172.88.49.50 172.88.49.52 172.88.49.53}}"
LISTEN_PORT="${LISTEN_PORT:-514}"
LOG_DIR="${LOG_DIR:-/data/tianqing-audit/raw-log}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/tianqing.log}"
CAPTURE_FILE="${CAPTURE_FILE:-$LOG_DIR/tianqing-syslog-test.pcap}"
SHOW_RAW="${SHOW_RAW:-0}"

if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

echo "== Listener =="
ss -lntp 2>/dev/null | grep -E ":$LISTEN_PORT\\b" || true

echo
echo "== Expected Tianqing sources =="
echo "$SOURCE_IPS"

echo
echo "== Rsyslog service =="
systemctl --no-pager --full status rsyslog 2>/dev/null | sed -n '1,18p' || true

echo
echo "== Tianqing log path =="
$SUDO ls -ld "$LOG_DIR" 2>/dev/null || true
$SUDO ls -l "$LOG_FILE" 2>/dev/null || true

echo
echo "== Recent Tianqing raw syslog =="
if $SUDO test -s "$LOG_FILE"; then
  if [[ "$SHOW_RAW" == "1" ]]; then
    $SUDO tail -n 20 "$LOG_FILE"
  else
    echo "Raw log output suppressed because Tianqing events can contain message bodies and personal data."
    echo "Use SHOW_RAW=1 $0 only when raw evidence review is explicitly needed."
    $SUDO wc -l "$LOG_FILE"
    $SUDO wc -c "$LOG_FILE"
  fi
else
  echo "No Tianqing syslog messages have been written yet."
fi

echo
echo "== JSON field summary =="
if $SUDO test -s "$LOG_FILE"; then
  $SUDO python3 - "$LOG_FILE" <<'PY' || true
import json
import os
import re
import sys
from collections import Counter

path = sys.argv[1]
keys = Counter()
topics = Counter()
nonempty = Counter()
rows = 0
with open(path, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        match = re.search(r"(\{.*\})\s*$", line)
        if not match:
            continue
        try:
            obj = json.loads(match.group(1))
        except Exception:
            continue
        rows += 1
        topics[str(obj.get("syslog_topic"))] += 1
        for key, value in obj.items():
            keys[key] += 1
            if value not in (None, "", [], {}, "[]"):
                nonempty[key] += 1

interesting = [
    "syslog_topic", "search_id", "event_detail", "enclosure_name",
    "enclosure_detail", "file_size", "download_url", "download_fileid",
    "download_file_key", "sender_urls", "addressee_urls", "mail_title",
    "process_name", "client_name", "client_ip", "sha256", "sha1", "md5",
    "hash", "archive_id", "storage_id", "path", "url",
]
print(f"rows={rows}")
print("topics=" + ",".join(f"{key}:{value}" for key, value in sorted(topics.items())))
for key in interesting:
    print(f"{key} present={keys.get(key, 0)} nonempty={nonempty.get(key, 0)}")
print(f"log_bytes={os.path.getsize(path)}")
PY
else
  echo "No log content available for JSON field summary."
fi

echo
echo "== Candidate attachment/index fields in recent raw log =="
if $SUDO test -s "$LOG_FILE"; then
  $SUDO tail -n 200 "$LOG_FILE" | grep -Eio '([[:alnum:]_.-]+\\.(docx?|xlsx?|pptx?|pdf|zip|rar|7z|tar|gz|csv|txt|sql|db)|sha256|sha1|md5|hash|event[_ -]?id|archive|归档|附件|下载|url|path|file|filename|filesize|size|policy|策略|终端|用户|目标)' | sort | uniq -c | sort -nr
else
  echo "No log content available for field scan."
fi

echo
echo "== Optional packet capture file =="
if $SUDO test -f "$CAPTURE_FILE"; then
  $SUDO ls -lh "$CAPTURE_FILE"
  if command -v capinfos >/dev/null 2>&1; then
    $SUDO capinfos "$CAPTURE_FILE" 2>/dev/null | sed -n '1,20p' || true
  fi
else
  echo "No packet capture found at $CAPTURE_FILE."
  echo "Capture command for controlled tests:"
  echo "  sudo tcpdump -i any -s 0 -w '$CAPTURE_FILE' 'tcp port $LISTEN_PORT and (host 172.88.49.50 or host 172.88.49.52 or host 172.88.49.53)'"
fi

echo
echo "== Interpretation checklist =="
echo "1. Attachment body transferable: a real attachment file appears on this server and its size/hash matches the test file."
echo "2. Attachment index usable: raw syslog contains event ID plus archive ID, download URL/path, attachment hash, or another stable lookup key."
echo "3. Event-only logging: raw syslog contains only alert summary/file metadata/policy fields, so attachments must still be downloaded from Tianqing Web or another archive channel."
