"""
EXPORT RESULTS
==============
Collects every Stage 1 (detection) and Stage 2 (PALL attribution) output
already produced in the working directory, consolidates the JSON/CSV into
one results/data/ folder, and renders the report figures as PNGs into
results/figures/.

Looks for (all optional -- skips with a message if a file is missing):
  events.csv, bots.csv, bursts.csv, window_scores.csv   (Stage 1 / detection.py)
  sweep_results.csv                                      (Stage 1 / sweep.py)
  candidates_ip.csv, candidates_channel.csv,
  table_topk_mrr.csv, ablation.csv, top_candidates_report.csv,
  false_alarm_vs_true.csv, attribution_summary.json      (Stage 2 / attribution.py)

Usage:
    python export_results.py
    python export_results.py --outdir results

Produces:
  results/
    data/        every input CSV/JSON copied in, plus results_combined.json
    figures/
      fig1_detection_timeline.png
      fig2_topk_mrr_ip.png
      fig3_topk_mrr_channel.png
      fig4_ablation.png
      fig5_top_candidates.png
      fig6_false_alarm_vs_true.png
      fig7_detection_summary.png
      fig8_sweep_sensitivity.png   (only if sweep_results.csv is present)
"""
import argparse
import json
import shutil
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import pandas as pd

# ---------------- validated categorical palette (dataviz skill default) -----
BLUE, ORANGE, AQUA, YELLOW, MAGENTA, GREEN, VIOLET, RED = (
    "#2a78d6", "#eb6834", "#1baf7a", "#eda100",
    "#e87ba4", "#008300", "#4a3aa7", "#e34948",
)
TEXT_PRIMARY, TEXT_SECONDARY, GRID = "#0b0b0b", "#52514e", "#dddddb"
SURFACE = "#fcfcfb"

METHOD_COLOR = {
    "PALL": BLUE, "Contact-count": ORANGE, "Degree": AQUA,
    "Full": BLUE, "No Rarity": ORANGE, "No Lag": AQUA, "No Coverage": YELLOW,
}

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
    "axes.edgecolor": GRID, "axes.labelcolor": TEXT_PRIMARY,
    "text.color": TEXT_PRIMARY, "xtick.color": TEXT_SECONDARY,
    "ytick.color": TEXT_SECONDARY, "grid.color": GRID,
    "axes.grid": True, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "font.size": 10, "axes.titlesize": 12, "axes.titleweight": "bold",
    "savefig.facecolor": SURFACE, "savefig.dpi": 160,
})


def _save(fig, path):
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  saved {path}")


def _bar_metric_group(ax, df, label_col, metrics, colors_by_label):
    """Grouped bars: one group per metric, one bar per row (method/component)."""
    labels = df[label_col].tolist()
    n = len(labels)
    x = range(len(metrics))
    width = 0.8 / max(n, 1)
    for i, (_, row) in enumerate(df.iterrows()):
        offs = [xi - 0.4 + width / 2 + i * width for xi in x]
        vals = [row[m] for m in metrics]
        color = colors_by_label.get(row[label_col], BLUE)
        bars = ax.bar(offs, vals, width=width, label=row[label_col], color=color)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.015, f"{v:.2f}",
                     ha="center", va="bottom", fontsize=7, color=TEXT_SECONDARY)
    ax.set_xticks(list(x))
    ax.set_xticklabels(metrics)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("score")
    # Legend above the plot, horizontal, out of the way of every bar.
    ax.legend(frameon=False, fontsize=8, loc="lower center",
              bbox_to_anchor=(0.5, 1.01), ncol=max(n, 1))


# ------------------------------------------------------------- figures ------
def fig_detection_timeline(outdir, events, bursts, scores):
    if events is None or bursts is None or scores is None:
        print("  [skip] fig1_detection_timeline.png -- needs events.csv, bursts.csv, window_scores.csv")
        return
    victim = bursts["victim"].mode().iat[0]
    s = scores[scores.DstAddr == victim].sort_values("win")
    if s.empty:
        print("  [skip] fig1_detection_timeline.png -- no window scores for the main victim")
        return
    t0_win = s["win"].min()
    x = (s["win"] - t0_win) * 10 / 60.0  # minutes, 10s windows

    fig, ax = plt.subplots(figsize=(11, 4.2))
    ax.plot(x, s["pkts"], color=BLUE, linewidth=1.4, label="packet rate (per 10s window)")

    for _, b in bursts[bursts.victim == victim].iterrows():
        pass  # bursts.csv has no win index directly comparable here; handled via events below

    ev = events[events.victim == victim]
    first_band = True
    for _, e in ev.iterrows():
        w0, w1 = e["win_start"] - t0_win, e["win_end"] - t0_win
        ax.axvspan(w0 * 10 / 60.0, (w1 + 1) * 10 / 60.0, color=RED, alpha=0.18,
                   label="detected event" if first_band else None)
        first_band = False

    ax.set_xlabel("time (minutes from first window)")
    ax.set_ylabel("packets / 10s window")
    ax.set_title(f"Figure 4.1 - Detected events on the victim ({victim})")
    ax.legend(frameon=False, fontsize=8, loc="upper right")
    _save(fig, outdir / "fig1_detection_timeline.png")


def fig_topk_mrr(outdir, table, level, filename, title):
    if table is None:
        print(f"  [skip] {filename} -- needs table_topk_mrr.csv")
        return
    is_channel = table["method"].str.contains("channel", case=False)
    sub = table[is_channel if level == "channel" else ~is_channel].copy()
    if sub.empty:
        print(f"  [skip] {filename} -- no '{level}'-level rows in table_topk_mrr.csv")
        return
    short_map = {
        "PALL (IP level)": "PALL", "PALL (channel level)": "PALL",
        "Contact-count baseline": "Contact-count", "Contact-count (channel)": "Contact-count",
        "Degree baseline (C only)": "Degree", "Degree (channel)": "Degree",
    }
    sub["method_short"] = sub["method"].map(short_map).fillna(
        sub["method"].str.replace(r"\s*\(.*\)", "", regex=True))
    colors = {row["method_short"]: METHOD_COLOR.get(row["method_short"], BLUE) for _, row in sub.iterrows()}
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    _bar_metric_group(ax, sub.assign(method=sub["method_short"]),
                       "method", ["top1", "top3", "top5", "MRR"], colors)
    ax.set_title(title, pad=38)
    _save(fig, outdir / filename)


def fig_ablation(outdir, ablation):
    if ablation is None:
        print("  [skip] fig4_ablation.png -- needs ablation.csv")
        return
    a = ablation.copy()
    a["short"] = a["component"].str.replace(r"\s*\(.*\)", "", regex=True)
    colors = {row["short"]: METHOD_COLOR.get(row["short"], BLUE) for _, row in a.iterrows()}
    fig, ax = plt.subplots(figsize=(8, 4.5))
    _bar_metric_group(ax, a.assign(method=a["short"]), "method",
                       ["top1", "top3", "top5", "MRR"], colors)
    ax.set_title("Table 4.6 - Ablation: dropping one PALL component", pad=38)
    _save(fig, outdir / "fig4_ablation.png")


def fig_top_candidates(outdir, top5):
    if top5 is None or top5.empty:
        print("  [skip] fig5_top_candidates.png -- needs top_candidates_report.csv")
        return
    fig, ax = plt.subplots(figsize=(8, 4.2))
    y = range(len(top5))
    ax.barh(list(y), top5["PALL"], color=BLUE)
    ax.set_yticks(list(y))
    ax.set_yticklabels(top5["key"])
    ax.invert_yaxis()
    for i, v in enumerate(top5["PALL"]):
        ax.text(v + 0.003, i, f"{v:.3f}", va="center", fontsize=8, color=TEXT_SECONDARY)
    ax.set_xlabel("PALL score")
    ax.set_title(f"Table 4.5 - Top candidates, event {top5['event_id'].iat[0]} "
                 f"(victim {top5['victim'].iat[0]})")
    _save(fig, outdir / "fig5_top_candidates.png")


def fig_false_alarm_vs_true(outdir, fa):
    if fa is None:
        print("  [skip] fig6_false_alarm_vs_true.png -- needs false_alarm_vs_true.csv")
        return
    fa = fa.dropna(subset=["max_PALL"])
    if fa.empty:
        print("  [skip] fig6_false_alarm_vs_true.png -- no events with a computed PALL score")
        return
    groups = [fa[fa.is_true_attack]["max_PALL"].values, fa[~fa.is_true_attack]["max_PALL"].values]
    labels = ["True attack events", "False-alarm events"]
    colors = [GREEN, RED]
    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    bp = ax.boxplot(groups, tick_labels=labels, patch_artist=True, widths=0.5)
    for patch, c in zip(bp["boxes"], colors):
        patch.set_facecolor(c); patch.set_alpha(0.35); patch.set_edgecolor(c)
    for med in bp["medians"]:
        med.set_color(TEXT_PRIMARY)
    for i, g in enumerate(groups, start=1):
        ax.scatter([i] * len(g), g, color=colors[i - 1], zorder=3, s=22)
    ax.set_ylabel("best candidate's PALL score")
    ax.set_title("Item (e) - max PALL: true attacks vs false alarms")
    _save(fig, outdir / "fig6_false_alarm_vs_true.png")


def fig_detection_summary(outdir, events, bursts, bots):
    if events is None and bursts is None and bots is None:
        print("  [skip] fig7_detection_summary.png -- needs events.csv / bursts.csv / bots.csv")
        return
    fig, axes = plt.subplots(2, 2, figsize=(9, 7))

    ax = axes[0, 0]
    if bursts is not None and not bursts.empty:
        detected = int(bursts["detected"].sum())
        missed = len(bursts) - detected
        ax.bar(["Detected", "Missed"], [detected, missed], color=[GREEN, RED])
        for i, v in enumerate([detected, missed]):
            ax.text(i, v + 0.1, str(v), ha="center", color=TEXT_SECONDARY)
    ax.set_title("True attack bursts"); ax.set_ylabel("count")

    ax = axes[0, 1]
    if bursts is not None and bursts["delay_s"].notna().any():
        d = bursts["delay_s"].dropna()
        ax.bar(range(len(d)), d, color=BLUE)
        ax.axhline(d.mean(), color=ORANGE, linestyle="--", linewidth=1.2,
                   label=f"mean = {d.mean():.0f}s")
        ax.set_xlabel("burst #"); ax.legend(frameon=False, fontsize=8)
    ax.set_title("Detection delay per burst"); ax.set_ylabel("seconds")

    ax = axes[1, 0]
    if events is not None and not events.empty:
        true_victim = bursts["victim"].mode().iat[0] if bursts is not None and not bursts.empty else None
        on_true = int((events["victim"] == true_victim).sum()) if true_victim else 0
        false_alarm = len(events) - on_true
        ax.bar(["On true victim", "False alarm"], [on_true, false_alarm], color=[GREEN, RED])
        for i, v in enumerate([on_true, false_alarm]):
            ax.text(i, v + 0.2, str(v), ha="center", color=TEXT_SECONDARY)
    ax.set_title("Detected events"); ax.set_ylabel("count")

    ax = axes[1, 1]
    if bots is not None and not bots.empty:
        per_event = bots.groupby("event_id")["bot"].nunique()
        ax.hist(per_event, bins=range(1, per_event.max() + 2), color=BLUE,
                edgecolor=SURFACE, align="left")
    ax.set_title("Bots found per event"); ax.set_xlabel("bots"); ax.set_ylabel("events")

    fig.suptitle("Stage 1 - Detection summary", fontsize=13, fontweight="bold")
    _save(fig, outdir / "fig7_detection_summary.png")


def fig_sweep(outdir, sweep):
    if sweep is None:
        print("  [skip] fig8_sweep_sensitivity.png -- needs sweep_results.csv (run sweep.py first)")
        return
    fig, ax = plt.subplots(figsize=(8, 5))
    for i, k in enumerate(sorted(sweep["K"].unique())):
        sub = sweep[sweep.K == k].sort_values("min_bots")
        ax.plot(sub["min_bots"], sub["window_F1"], marker="o",
                color=[BLUE, ORANGE, AQUA, YELLOW][i % 4], label=f"K = {k}")
    ax.set_xlabel("minimum bots"); ax.set_ylabel("window F1")
    ax.set_title("Sensitivity: detection F1 vs K / min-bots")
    ax.legend(frameon=False, fontsize=8, title="packet-rate threshold")
    _save(fig, outdir / "fig8_sweep_sensitivity.png")


# ---------------------------------------------------------------- main ------
def _read_csv(path, **kw):
    p = Path(path)
    return pd.read_csv(p, **kw) if p.exists() else None


def _read_json(path):
    p = Path(path)
    return json.loads(p.read_text()) if p.exists() else None


def main(outdir="results"):
    outdir = Path(outdir)
    data_dir, fig_dir = outdir / "data", outdir / "figures"
    data_dir.mkdir(parents=True, exist_ok=True)
    fig_dir.mkdir(parents=True, exist_ok=True)

    sources = [
        "events.csv", "bots.csv", "bursts.csv", "window_scores.csv", "sweep_results.csv",
        "candidates_ip.csv", "candidates_channel.csv", "table_topk_mrr.csv", "ablation.csv",
        "top_candidates_report.csv", "false_alarm_vs_true.csv", "attribution_summary.json",
    ]
    print("Collecting result files into results/data/ ...")
    for name in sources:
        src = Path(name)
        if src.exists():
            shutil.copy(src, data_dir / name)
            print(f"  copied {name}")
        else:
            print(f"  [missing] {name}")

    events = _read_csv("events.csv", parse_dates=["start", "end"])
    bots = _read_csv("bots.csv", parse_dates=["t_i"])
    bursts = _read_csv("bursts.csv", parse_dates=["start"])
    scores = _read_csv("window_scores.csv")
    sweep = _read_csv("sweep_results.csv")
    candidates_ip = _read_csv("candidates_ip.csv")
    table_topk = _read_csv("table_topk_mrr.csv")
    ablation = _read_csv("ablation.csv")
    top5 = _read_csv("top_candidates_report.csv")
    fa = _read_csv("false_alarm_vs_true.csv")
    attribution_summary = _read_json("attribution_summary.json")

    print("\nRendering figures into results/figures/ ...")
    fig_detection_timeline(fig_dir, events, bursts, scores)
    fig_topk_mrr(fig_dir, table_topk, "IP", "fig2_topk_mrr_ip.png",
                 "Table 4.4 - Top-k accuracy / MRR (IP level)")
    fig_topk_mrr(fig_dir, table_topk, "channel", "fig3_topk_mrr_channel.png",
                 "Table 4.4 - Top-k accuracy / MRR (channel level)")
    fig_ablation(fig_dir, ablation)
    fig_top_candidates(fig_dir, top5)
    fig_false_alarm_vs_true(fig_dir, fa)
    fig_detection_summary(fig_dir, events, bursts, bots)
    fig_sweep(fig_dir, sweep)

    # ---- consolidated results_combined.json -------------------------------
    combined = {"attribution": attribution_summary}
    if bursts is not None and not bursts.empty:
        combined["detection"] = {
            "attack_bursts": len(bursts),
            "bursts_detected": int(bursts["detected"].sum()),
            "mean_delay_s": round(bursts["delay_s"].dropna().mean(), 1) if bursts["delay_s"].notna().any() else None,
        }
    if events is not None:
        combined.setdefault("detection", {})["events_total"] = len(events)
    if bots is not None:
        combined.setdefault("detection", {})["bots_found_total"] = bots["bot"].nunique()
    (data_dir / "results_combined.json").write_text(json.dumps(combined, indent=2, default=str))
    print(f"  saved {data_dir / 'results_combined.json'}")

    print(f"\nDone. Everything is under {outdir.resolve()}/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--outdir", default="results")
    args = parser.parse_args()
    main(args.outdir)
