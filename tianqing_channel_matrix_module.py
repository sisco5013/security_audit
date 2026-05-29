#!/usr/bin/env python3
"""Runtime-bound report submodule extracted from tianqing_external_audit_report.

The extracted functions keep the mature report logic intact. The main generator
binds its runtime namespace before calling these functions so shared policy,
HTML, ClickHouse, and classification helpers remain single-sourced during this
phase of modularization.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any


def bind_runtime_dependencies(namespace: dict[str, Any]) -> None:
    for key, value in namespace.items():
        if key.startswith("__"):
            continue
        globals()[key] = value


def channel_matrix_html(
    row_labels: list[str],
    matrix_counts: dict[tuple[str, str], int],
    row_totals: Counter,
    cell_links: dict[tuple[str, str], str],
    row_links: dict[str, str],
) -> str:
    rows = []
    cell_thresholds = heat_thresholds_from_counts(matrix_counts.values())
    total_thresholds = heat_thresholds_from_counts(row_totals.values())
    for row_label in row_labels:
        cells = [f'<th class="channel-name" scope="row">{esc(row_label)}</th>']
        for column in CHANNEL_MATRIX_COLUMNS:
            count = matrix_counts.get((row_label, column), 0)
            href = cell_links.get((row_label, column))
            title = f"查看{row_label} / {column}明细"
            cells.append(f"<td>{matrix_number_html(count, href, title, cell_thresholds)}</td>")
        total = row_totals.get(row_label, 0)
        href = row_links.get(row_label)
        cells.append(f"<td>{matrix_number_html(total, href, f'查看{row_label}全部明细', total_thresholds, total=True)}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    headers = "".join(f"<th>{esc(column)}</th>" for column in CHANNEL_MATRIX_COLUMNS)
    return f"""
      <div class="channel-matrix-wrap">
        <table class="channel-matrix">
          <thead><tr><th>通道</th>{headers}<th>合计</th></tr></thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
      </div>
"""


def build_tianqing_channel_matrix_result(
    args: argparse.Namespace,
    events: list[AuditEvent],
    internal_domains: set[str],
    tz: timezone,
    report_period: str,
    source_label: str,
) -> TianqingChannelMatrixResult:
    channel_event_map: dict[str, list[AuditEvent]] = defaultdict(list)
    channel_matrix_event_map: dict[tuple[str, str], list[AuditEvent]] = defaultdict(list)
    matrix_object_event_map: dict[str, list[AuditEvent]] = defaultdict(list)
    for event in events:
        if not is_leadership_focus_event(event, internal_domains):
            continue
        matrix_channel = audit_channel_group(event, internal_domains)
        if not matrix_channel:
            continue
        matrix_bucket = audit_matrix_bucket(event)
        if not matrix_bucket:
            continue
        channel_event_map[matrix_channel].append(event)
        channel_matrix_event_map[(matrix_channel, matrix_bucket)].append(event)
        matrix_object_event_map[matrix_bucket].append(event)

    matrix_counts = {key: len(value) for key, value in channel_matrix_event_map.items()}
    row_totals = Counter({channel: len(channel_events) for channel, channel_events in channel_event_map.items()})
    object_totals = Counter({bucket: len(bucket_events) for bucket, bucket_events in matrix_object_event_map.items()})
    dynamic_matrix_rows = [
        row_label
        for row_label, count in row_totals.most_common()
        if count > 0 and row_label not in CHANNEL_MATRIX_BASE_ROWS
    ]
    channel_matrix_rows = CHANNEL_MATRIX_BASE_ROWS + dynamic_matrix_rows
    row_links: dict[str, str] = {}
    cell_links: dict[tuple[str, str], str] = {}
    object_links: dict[str, str] = {}
    sidecar_pages: dict[str, str] = {}

    for row_label in channel_matrix_rows:
        row_events = channel_event_map.get(row_label, [])
        if not row_events:
            continue
        page = sidecar_page_filename(args, "matrix-channel", row_label)
        row_links[row_label] = page
        sidecar_pages[page] = build_event_detail_page(
            f"通道矩阵明细：{row_label}",
            row_events,
            args,
            tz,
            report_period,
            source_label,
            f"{row_label} 通道下进入审计报告的全部真实外发/拷贝重点事件。",
        )

    for (row_label, bucket), cell_events in sorted(channel_matrix_event_map.items(), key=lambda item: (item[0][0], item[0][1])):
        if not cell_events:
            continue
        page = sidecar_page_filename(args, "matrix-cell", f"{row_label}|{bucket}")
        cell_links[(row_label, bucket)] = page
        sidecar_pages[page] = build_event_detail_page(
            f"通道矩阵明细：{row_label} / {bucket}",
            cell_events,
            args,
            tz,
            report_period,
            source_label,
            f"{row_label} 通道中属于 {bucket} 的重点事件。",
        )

    for bucket in CHANNEL_MATRIX_COLUMNS:
        bucket_events = matrix_object_event_map.get(bucket, [])
        if not bucket_events:
            continue
        page = sidecar_page_filename(args, "matrix-object", bucket)
        object_links[bucket] = page
        sidecar_pages[page] = build_event_detail_page(
            f"对象矩阵明细：{bucket}",
            bucket_events,
            args,
            tz,
            report_period,
            source_label,
            f"进入首页通道矩阵且对象归类为 {bucket} 的全部真实外发、上传和外设拷贝重点事件。",
        )

    return TianqingChannelMatrixResult(
        block_html=channel_matrix_html(channel_matrix_rows, matrix_counts, row_totals, cell_links, row_links),
        focus_metrics_html=channel_focus_metric_chips(len(events), channel_matrix_rows, row_totals, row_links),
        row_links=row_links,
        cell_links=cell_links,
        object_links=object_links,
        row_totals=row_totals,
        object_totals=object_totals,
        rows=channel_matrix_rows,
        sidecar_pages=sidecar_pages,
    )
