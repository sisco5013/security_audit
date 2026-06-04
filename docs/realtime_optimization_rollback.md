# 实时计算优化回滚记录

## 目标

降低首页加密软件解密审计和风险终端复核的实时等待时间。优化原则是先返回轻量汇总，再后台预热完整下钻证据。

## 本轮优化点

- 新增运行时开关：`TIANQING_REALTIME_OPTIMIZATION`，默认启用。
- 解密审计首页汇总增加独立短缓存，不再每次刷新都重复计算同一周期的数字、趋势和公司矩阵。
- 解密审计首页汇总优先返回，完整下钻缓存预热改为汇总完成后再后台启动，避免和首屏数字抢资源。
- 解密审计公司矩阵与首页卡片共用同一份周期聚合结果，减少重复查询。
- 风险终端复核中的“加密软件解密审计”候选改为读取解密记录轻量数据，不再为候选列表强制构建完整流转链路。
- 风险终端复核中的“天擎一级风险候选”增加 ClickHouse 快照表 `terminal_behavior_candidate_cache`。同一周期、同一候选口径 hash 再次打开时直接读取候选快照，不重复扫大范围 `audit_events`。候选口径只包含图纸/压缩包/内部目标/复核阈值等会影响天擎候选的字段，认证名单、组织别名等无关配置不会打穿天擎候选快照。
- 策略文件保存时新增 `policy_change_log.jsonl` 记录变更 hash 和影响范围，但不触发天擎历史底稿或归档报告自动重算。
- `tianqing_clickhouse_ingest.py` 已改为默认不因策略 hash 变化重建 `audit_events`；只有显式传入 `--auto-rebuild-on-policy-change` 才会触发。

## 快速回滚

如上线后发现异常，先在服务环境中设置：

```bash
export TIANQING_REALTIME_OPTIMIZATION=0
systemctl restart tianqing-report-web.service
```

如果 systemd 未显式读取 shell 环境，需要在 `tianqing-report-web.service` 中加入：

```ini
Environment=TIANQING_REALTIME_OPTIMIZATION=0
```

然后执行：

```bash
systemctl daemon-reload
systemctl restart tianqing-report-web.service
```

## 代码回滚点

- `tianqing_report_web.py`
  - `realtime_optimization_enabled`
  - `DECRYPT_SUMMARY_CACHE`
  - `DECRYPT_DETAIL_WARMUP_CACHE`
  - `live_decrypt_summary_fragment`
  - `live_decrypt_warmup_json`
  - `inject_live_decrypt_loader`
  - `decrypt_review_candidates`
  - `terminal_check_tianqing_candidates`
- `tianqing_terminal_behavior_review.py`
  - `terminal_behavior_candidate_cache`
  - `fetch_cached_candidates`
  - `store_cached_candidates`
- `tianqing_clickhouse_ingest.py`
  - `--auto-rebuild-on-policy-change`

关闭开关后，解密完整预热会恢复为旧的同步请求方式；保留新代码但不启用新调度。

如需完全禁用天擎候选快照，可关闭 `TIANQING_REALTIME_OPTIMIZATION`，风险终端复核会退回旧的现场计算路径。`audit_events` 的策略变更自动重建默认仍保持关闭，除非手工执行 `--rebuild-events-from-raw` 或显式开启 `--auto-rebuild-on-policy-change`。
