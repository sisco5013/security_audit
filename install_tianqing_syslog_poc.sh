#!/usr/bin/env bash
set -euo pipefail

SOURCE_IPS="${SOURCE_IPS:-${SOURCE_IP:-172.88.49.50 172.88.49.52 172.88.49.53}}"
LISTEN_PORT="${LISTEN_PORT:-514}"
LOG_DIR="${LOG_DIR:-/data/tianqing-audit/raw-log}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/tianqing.log}"
RSYSLOG_CONF="${RSYSLOG_CONF:-/etc/rsyslog.d/30-tianqing.conf}"
LOGROTATE_CONF="${LOGROTATE_CONF:-/etc/logrotate.d/tianqing-syslog}"
CAPTURE_FILE="${CAPTURE_FILE:-$LOG_DIR/tianqing-syslog-test.pcap}"

read -r -a ALLOWED_SOURCES <<< "$SOURCE_IPS"
if [[ "${#ALLOWED_SOURCES[@]}" -eq 0 ]]; then
  echo "ERROR: SOURCE_IPS is empty." >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run as root, or use: sudo $0" >&2
  exit 1
fi

echo "[1/8] Checking system..."
if ! command -v systemctl >/dev/null 2>&1; then
  echo "ERROR: systemctl is required for this deployment." >&2
  exit 1
fi

if ! command -v rsyslogd >/dev/null 2>&1; then
  echo "[2/8] Installing rsyslog..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y rsyslog
  elif command -v yum >/dev/null 2>&1; then
    yum install -y rsyslog
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install rsyslog
  else
    echo "ERROR: rsyslog is not installed and no supported package manager was found." >&2
    exit 1
  fi
else
  echo "[2/8] rsyslog already installed."
fi

if ss -lntH "( sport = :$LISTEN_PORT )" 2>/dev/null | grep -q .; then
  if ! ss -lntpH "( sport = :$LISTEN_PORT )" 2>/dev/null | grep -qi rsyslog; then
    echo "ERROR: TCP/$LISTEN_PORT is already in use by a non-rsyslog process." >&2
    ss -lntp "( sport = :$LISTEN_PORT )" >&2 || true
    exit 1
  fi
  echo "[info] TCP/$LISTEN_PORT is already used by rsyslog; updating Tianqing dedicated ruleset."
fi

LOG_OWNER="root"
if id -u syslog >/dev/null 2>&1; then
  LOG_OWNER="syslog"
fi

LOG_GROUP="root"
if getent group adm >/dev/null 2>&1; then
  LOG_GROUP="adm"
elif getent group syslog >/dev/null 2>&1; then
  LOG_GROUP="syslog"
fi

echo "[3/8] Creating Tianqing log directory..."
install -d -o "$LOG_OWNER" -g "$LOG_GROUP" -m 0750 "$LOG_DIR"
touch "$LOG_FILE"
chown "$LOG_OWNER":"$LOG_GROUP" "$LOG_FILE"
chmod 0640 "$LOG_FILE"

RSYSLOG_CONDITION=""
for source_ip in "${ALLOWED_SOURCES[@]}"; do
  if [[ -z "$RSYSLOG_CONDITION" ]]; then
    RSYSLOG_CONDITION="\$fromhost-ip == \"$source_ip\""
  else
    RSYSLOG_CONDITION="$RSYSLOG_CONDITION or \$fromhost-ip == \"$source_ip\""
  fi
done

echo "[4/8] Writing rsyslog config: $RSYSLOG_CONF"
if [[ -e "$RSYSLOG_CONF" ]]; then
  cp -a "$RSYSLOG_CONF" "$RSYSLOG_CONF.bak.$(date +%Y%m%d%H%M%S)"
fi
cat > "$RSYSLOG_CONF" <<EOF_CONF
# Tianqing external audit syslog PoC.
# Receives only TCP syslog from $SOURCE_IPS and writes it to $LOG_FILE.
# This file intentionally does not modify system log files such as
# /var/log/messages or /var/log/syslog.

module(load="imtcp")

ruleset(name="tianqing_remote") {
    if ($RSYSLOG_CONDITION) then {
        action(
            type="omfile"
            file="$LOG_FILE"
            createDirs="on"
            dirOwner="$LOG_OWNER"
            dirGroup="$LOG_GROUP"
            dirCreateMode="0750"
            fileOwner="$LOG_OWNER"
            fileGroup="$LOG_GROUP"
            fileCreateMode="0640"
        )
        stop
    }

    # Drop non-Tianqing traffic that reaches this dedicated input.
    stop
}

input(type="imtcp" port="$LISTEN_PORT" ruleset="tianqing_remote")
EOF_CONF
chmod 0644 "$RSYSLOG_CONF"

echo "[5/8] Writing logrotate config: $LOGROTATE_CONF"
if [[ -e "$LOGROTATE_CONF" ]]; then
  cp -a "$LOGROTATE_CONF" "$LOGROTATE_CONF.bak.$(date +%Y%m%d%H%M%S)"
fi
cat > "$LOGROTATE_CONF" <<EOF_ROTATE
$LOG_DIR/*.log {
    daily
    rotate 30
    maxage 30
    missingok
    notifempty
    compress
    delaycompress
    dateext
    create 0640 $LOG_OWNER $LOG_GROUP
    sharedscripts
    postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
EOF_ROTATE
chmod 0644 "$LOGROTATE_CONF"

echo "[6/8] Validating rsyslog config..."
rsyslogd -N1

echo "[7/8] Enabling and restarting rsyslog..."
systemctl enable rsyslog >/dev/null 2>&1 || true
systemctl restart rsyslog

echo "[8/8] Applying narrow firewall rule when a known manager is active..."
FIREWALL_STATUS="no active supported firewall manager detected"
if systemctl is-active --quiet firewalld 2>/dev/null && command -v firewall-cmd >/dev/null 2>&1; then
  for source_ip in "${ALLOWED_SOURCES[@]}"; do
    firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$source_ip\" port protocol=\"tcp\" port=\"$LISTEN_PORT\" accept"
  done
  firewall-cmd --reload
  FIREWALL_STATUS="firewalld rich rules added for $SOURCE_IPS tcp/$LISTEN_PORT"
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  for source_ip in "${ALLOWED_SOURCES[@]}"; do
    ufw allow from "$source_ip" to any port "$LISTEN_PORT" proto tcp comment "tianqing syslog poc"
  done
  FIREWALL_STATUS="ufw rules added for $SOURCE_IPS tcp/$LISTEN_PORT"
elif command -v iptables >/dev/null 2>&1; then
  while iptables -D INPUT -p tcp --dport "$LISTEN_PORT" -m comment --comment "tianqing-syslog-poc-jump" -j TIANQING_SYSLOG 2>/dev/null; do :; done
  iptables -F TIANQING_SYSLOG 2>/dev/null || true
  iptables -X TIANQING_SYSLOG 2>/dev/null || true
  iptables -N TIANQING_SYSLOG
  for source_ip in "${ALLOWED_SOURCES[@]}"; do
    iptables -A TIANQING_SYSLOG -s "$source_ip/32" -m comment --comment "tianqing-syslog-allow-$source_ip" -j ACCEPT
  done
  iptables -A TIANQING_SYSLOG -m comment --comment "tianqing-syslog-drop-other" -j DROP
  iptables -I INPUT 1 -p tcp --dport "$LISTEN_PORT" -m comment --comment "tianqing-syslog-poc-jump" -j TIANQING_SYSLOG
  if command -v ip6tables >/dev/null 2>&1; then
    while ip6tables -D INPUT -p tcp --dport "$LISTEN_PORT" -m comment --comment "tianqing-syslog-poc-drop-ipv6" -j DROP 2>/dev/null; do :; done
    ip6tables -I INPUT 1 -p tcp --dport "$LISTEN_PORT" -m comment --comment "tianqing-syslog-poc-drop-ipv6" -j DROP
  fi
  FIREWALL_STATUS="iptables chain TIANQING_SYSLOG allows $SOURCE_IPS tcp/$LISTEN_PORT and drops other tcp/$LISTEN_PORT sources"
fi

echo
echo "Deployment complete."
echo "Log file: $LOG_FILE"
echo "Rsyslog config: $RSYSLOG_CONF"
echo "Logrotate config: $LOGROTATE_CONF"
echo "Firewall: $FIREWALL_STATUS"
echo
echo "Next validation commands:"
echo "  ss -lntp | grep ':$LISTEN_PORT'"
echo "  tail -f '$LOG_FILE'"
echo
echo "Optional packet capture during controlled Tianqing tests:"
echo "  tcpdump -i any -s 0 -w '$CAPTURE_FILE' '(host ${ALLOWED_SOURCES[0]}) and tcp port $LISTEN_PORT'"
