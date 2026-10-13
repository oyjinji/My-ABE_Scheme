"""Headless, data-backed Phase 5B figure generation."""
from __future__ import annotations

from collections import defaultdict
import csv
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from .core import write_csv, write_json


PLOT_VERSION = 'MYABE08-PLOT-V1'
COLORS = {
    'SGX_DEBUG_GRAMINE_V1': '#1261a0',
    'EMULATED_TEE_PROFILE': '#d55e00',
    'UNIQUE': '#0072b2', 'LOW_REPEAT': '#e69f00',
    'MEDIUM_REPEAT': '#009e73', 'HIGH_REPEAT': '#cc79a7',
    'AND': '#0072b2', 'threshold': '#e69f00', 'repeated': '#009e73',
}
PALETTE = ('#1261a0', '#d55e00', '#009e73', '#cc79a7', '#e69f00', '#56b4e9')


def _setup():
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 9,
        'axes.titlesize': 10, 'axes.labelsize': 9, 'legend.fontsize': 8,
        'figure.figsize': (6.6, 4.2), 'savefig.dpi': 180,
        'axes.grid': True, 'grid.alpha': .23})


def _save(fig, directory: Path, figure_id: str, rows: list[dict],
          metadata: dict) -> None:
    if not rows:
        raise ValueError('empty figure data')
    fields = sorted({key for row in rows for key in row})
    write_csv(directory / f'figure_{figure_id}_data.csv', rows, fields)
    write_json(directory / f'figure_{figure_id}_metadata.json',
               dict(plot_version=PLOT_VERSION, figure_id=figure_id, **metadata))
    fig.tight_layout()
    fig.savefig(directory / f'{figure_id}.png', dpi=180)
    fig.savefig(directory / f'{figure_id}.pdf', metadata={'Title': figure_id,
        'Creator': 'MYABE08 Phase 5B analysis'})
    plt.close(fig)


def numeric_figure(directory: Path, figure_id: str, rows: list[dict], *,
                   x: str, y: str, title: str, xlabel: str, ylabel: str,
                   series: str = 'series', mode: str = 'line',
                   p95: str | None = None, metadata: dict) -> None:
    """Plot already aggregated figure-data rows without silently filtering."""
    _setup(); fig, ax = plt.subplots()
    groups = defaultdict(list)
    for row in rows:
        if row.get(x) is None or row.get(y) is None:
            raise ValueError('missing plotted axis')
        groups[str(row.get(series, 'observed'))].append(row)
    for index, (name, points) in enumerate(sorted(groups.items())):
        points = sorted(points, key=lambda item: (item[x], str(item.get('configuration_id', ''))))
        color = COLORS.get(name, PALETTE[index % len(PALETTE)])
        xx = [point[x] for point in points]; yy = [point[y] for point in points]
        if mode == 'line':
            ax.plot(xx, yy, '-o', color=color, label=name, linewidth=1.5,
                    markersize=4)
        elif mode == 'scatter':
            ax.scatter(xx, yy, color=color, label=name, s=34)
        else:
            raise ValueError('unsupported numeric plot mode')
        if p95:
            ax.scatter(xx, [point[p95] for point in points], color=color,
                       marker='^', s=18, alpha=.65)
    ax.set(title=title, xlabel=xlabel, ylabel=ylabel)
    if len(groups) > 1:
        ax.legend(frameon=False, loc='best')
    meta = dict(metadata, x_field=x, y_field=y, series_field=series,
                statistic='median; triangles show p95' if p95 else metadata.get('statistic','observed'))
    _save(fig, directory, figure_id, rows, meta)


def bar_figure(directory: Path, figure_id: str, rows: list[dict], *,
               label: str, value: str, title: str, ylabel: str,
               metadata: dict, stack: bool = False, log_scale: bool = False) -> None:
    _setup(); fig, ax = plt.subplots()
    if stack:
        labels = list(dict.fromkeys(str(row[label]) for row in rows))
        components = list(dict.fromkeys(str(row['component']) for row in rows))
        bottoms = [0.] * len(labels)
        for i, component in enumerate(components):
            amounts = [next(float(row[value]) for row in rows
                        if str(row[label]) == category and row['component'] == component)
                       for category in labels]
            ax.bar(labels, amounts, bottom=bottoms,
                   color=PALETTE[i % len(PALETTE)], label=component)
            bottoms = [a + b for a, b in zip(bottoms, amounts)]
        ax.legend(frameon=False, fontsize=7, ncol=2)
    else:
        labels = [str(row[label]) for row in rows]
        ax.bar(labels, [row[value] for row in rows],
               color=[PALETTE[i % len(PALETTE)] for i in range(len(rows))])
    ax.set(title=title, xlabel=label.replace('_',' '), ylabel=ylabel)
    if log_scale:
        ax.set_yscale('log')
    ax.tick_params(axis='x', labelrotation=35)
    _save(fig, directory, figure_id, rows,
          dict(metadata, x_field=label, y_field=value,
               y_scale='log' if log_scale else 'linear',
               statistic=metadata.get('statistic','observed')))


def distribution_figure(directory: Path, figure_id: str, rows: list[dict], *,
                        group: str, value: str, title: str, ylabel: str,
                        metadata: dict) -> None:
    _setup(); fig, ax = plt.subplots()
    grouped = defaultdict(list)
    for row in rows:
        grouped[str(row[group])].append(float(row[value]))
    names = sorted(grouped)
    ax.boxplot([grouped[name] for name in names], labels=names,
               showfliers=True, patch_artist=False)
    # Every raw point remains visible, including points beyond the whiskers.
    for index, name in enumerate(names, 1):
        values = grouped[name]
        offsets = [((i % 7) - 3) * .015 for i in range(len(values))]
        ax.scatter([index + offset for offset in offsets], values,
                   alpha=.4, s=10, color=COLORS.get(name, PALETTE[(index-1)%len(PALETTE)]))
    ax.set(title=title, xlabel=group.replace('_',' '), ylabel=ylabel)
    ax.tick_params(axis='x', labelrotation=25)
    _save(fig, directory, figure_id, rows,
          dict(metadata, x_field=group, y_field=value,
               statistic='raw distribution; no outlier removal'))
