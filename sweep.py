"""Sensitivity analysis for Stage 1: how detection changes with the main settings.
Usage: python sweep.py capture20110818.binetflow     -> prints table, saves sweep_results.csv"""
import sys, itertools, pandas as pd
import detection as D

df = D.load_flows(sys.argv[1])
w = D.spread_flows(df)
rows = []
for K, MINP in itertools.product([3.0, 4.0, 5.0], [1000, 3000]):
    D.K, D.MIN_ALERT_PKTS = K, MINP
    feat = D.window_features(w)
    scores = D.score_windows(feat)
    for MB in [1, 3, 5]:
        D.MIN_BOTS = MB
        ev = D.group_events(scores)
        t0 = df.attrs["t0"]
        ev["start"] = t0 + pd.to_timedelta(ev.win_start * D.WINDOW_S, unit="s")
        ev["end"] = t0 + pd.to_timedelta((ev.win_end + 1) * D.WINDOW_S, unit="s")
        bots = D.find_bots(df, w, ev)
        drop = D.response_filter(ev, bots)
        nb = bots.groupby("event_id").size().reindex(ev.index).fillna(0)
        kept = ev[~ev.index.isin(drop) & (nb >= MB)]
        kb = bots[bots.event_id.isin(kept.index)]
        s, _ = D.evaluate(df, w, kept, kb)
        rows.append({"K": K, "min_pkts": MINP, "min_bots": MB, **{k: s[k] for k in
                     ["bursts_detected", "attack_bursts", "mean_delay_s", "false_alarm_events",
                      "window_precision", "window_recall", "window_F1", "bot_precision", "bot_recall"]}})
        print(rows[-1], flush=True)
out = pd.DataFrame(rows); out.to_csv("sweep_results.csv", index=False)
print("\n", out.to_string()); print("\nSaved: sweep_results.csv")
