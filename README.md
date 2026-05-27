# Security Audit Report

奇安信天擎外发审计、加密软件解密审计与审计报表 Web 服务。

## What Is In Git

- Python report generator and Web service code.
- Deployment, backfill, syslog verification, and systemd/logrotate templates.
- Sanitized example configuration under `config.example/`.

## What Is Not In Git

The repository intentionally excludes runtime and audit evidence data:

- Generated HTML reports under `reports/`.
- WeCom directory cache.
- Real audit policy, sensitive keywords, exclusions, people mapping, recipient mapping, and disposition files.
- Excel decrypt records and imported evidence.
- Local `.env`, sessions, logs, locks, and temporary files.

Production runtime configuration should live outside the app code directory, for example:

```bash
/data/tianqing-audit/config/audit_policy.json
/data/tianqing-audit/config/sensitive_keywords.json
/data/tianqing-audit/config/audit_exclusions.json
```

The Web service and report scripts support these environment variables:

```bash
TIANQING_AUDIT_POLICY_FILE=/data/tianqing-audit/config/audit_policy.json
TIANQING_SENSITIVE_KEYWORDS_FILE=/data/tianqing-audit/config/sensitive_keywords.json
TIANQING_AUDIT_EXCLUSION_FILE=/data/tianqing-audit/config/audit_exclusions.json
```

## Bootstrap Config

Use the example files as templates only:

```bash
mkdir -p /data/tianqing-audit/config
cp config.example/audit_policy.example.json /data/tianqing-audit/config/audit_policy.json
cp config.example/sensitive_keywords.example.json /data/tianqing-audit/config/sensitive_keywords.json
cp config.example/audit_exclusions.example.json /data/tianqing-audit/config/audit_exclusions.json
```

Do not commit the copied production files back to Git.

## Validation

Basic syntax checks:

```bash
PYTHONPYCACHEPREFIX=/tmp python3 -m py_compile \
  tianqing_external_audit_report.py \
  tianqing_report_web.py \
  tianqing_clickhouse_ingest.py \
  tianqing_decrypt_records.py

bash -n generate_tianqing_period_report.sh
bash -n publish_tianqing_report.sh
```
