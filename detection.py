"""
STAGE 1 - DDoS DETECTION  (version 2, tuned after the first CTU-13 run)
=====================================================================
Detects DDoS attacks in NetFlow data (CTU-13 .binetflow format) using three
indicators per destination host in 10-second windows:

  (a) packet rate        - packets the destination receives per window
  (b) source-IP entropy  - how spread out the senders are (Shannon entropy, bits)
  (c) mean packet size   - bytes / packets; flagged if it moves far from
                           normal in EITHER direction

Adaptive thresholds: each indicator has an EWMA baseline (mean and spread),
learned per destination; an indicator fires if |value - mean| > K * spread.
The baseline is frozen while an alert is active.

Alert rule (volumetric 2-of-3): packet rate MUST fire at the full threshold
(K * spread); at least one of entropy / packet size must CONFIRM it at half
the threshold (K/2 * spread); the window must carry >= MIN_ALERT_PKTS packets.
An attack event must last >= MIN_EVENT consecutive alert windows.

Design decisions added after the first real run (explain in the report):
  0. Baseline frozen whenever any indicator is abnormal (stops a flood being
     slowly absorbed into "normal").
  1. Long flows are SPREAD over the windows they last (a 1000 s flow is not
     counted as one giant spike in its first window).
  2. Packet rate is mandatory + minimum volume: removes alarms on busy
     servers whose entropy / packet size drift but whose volume is normal.
  4. "Distributed" rule: an event needs >= MIN_BOTS surging sources.
  5. The baseline re-learns if an alert lasts longer than MAX_FREEZE windows.
  3. Response-traffic filter: if an alarm's "victim" is a bot of a
     simultaneous attack, it is the victim's replies, not a new attack.
"""
import numpy as np
import pandas as pd

# ---------------- parameters (report these in the Experimental Setup) ----------
WINDOW_S      = 10     # window length in seconds
K             = 3.0    # packet rate fires if |value - mean| > K * spread
K_CONFIRM     = 1.5    # entropy / size confirm if |value - mean| > K_CONFIRM * spread
ALPHA         = 0.05   # EWMA smoothing factor
WARMUP        = 30     # windows (5 min) to learn a baseline before alerts allowed
MIN_ALERT_PKTS = 1000  # an alert window must carry >= 1000 packets (100 pkt/s)
STD_FLOOR     = {"pkts": 10.0, "entropy": 0.5, "size": 100.0}
REL_FLOOR     = 0.5    # spread is at least 50% of the baseline mean (pkts, size)
MIN_EVENT     = 3      # attack must last >= 3 consecutive alert windows (30 s)
MERGE_GAP     = 3      # alert windows <= 3 apart belong to the same event
MAX_SPREAD    = 360    # spread a long flow over at most 360 windows (1 hour)
ONSET_WIN     = 6      # bots identified in the first 6 windows (60 s) of an event
BEFORE_WIN    = 30     # ...compared with the 30 windows (5 min) before it
SURGE         = 10.0   # bot = packets to victim surge >= 10x
BOT_MIN_PKTS  = 100    # ...and >= 100 packets in the onset minute
GT_MIN_PKTS   = 50     # ground truth: window has >= 50 labelled attack packets
MIN_BOTS      = 3      # "distributed": an attack needs >= 3 surging sources
MAX_FREEZE    = 180    # re-learn baseline if an alert lasts > 180 windows (30 min)


# ------------------------------------------------------------------ loading ----
def load_flows(path):
    df = pd.read_csv(path, low_memory=False)
    df["StartTime"] = pd.to_datetime(df["StartTime"], format="mixed")
    df["Dur"] = pd.to_numeric(df["Dur"], errors="coerce").fillna(0).clip(lower=0)
    df["End"] = df["StartTime"] + pd.to_timedelta(df["Dur"], unit="s")
    df["Label"] = df["Label"].astype(str)
    for c in ["TotPkts", "TotBytes"]:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    t0 = df["StartTime"].min()
    df["win"] = ((df["StartTime"] - t0).dt.total_seconds() // WINDOW_S).astype(int)
    lab = df["Label"]
    df["is_attack"] = lab.str.contains("From-Botnet") & ~lab.str.contains("CC|DNS|HTTP")
    df.attrs["t0"] = t0
    return df


def spread_flows(df):
    """One row per (flow, window it is active in); packets/bytes split evenly."""
    n = np.minimum(np.ceil(df["Dur"].values / WINDOW_S).astype(int), MAX_SPREAD)
    n = np.maximum(n, 1)
    idx = np.repeat(np.arange(len(df)), n)
    offset = np.arange(len(idx)) - np.repeat(np.cumsum(n) - n, n)
    w = pd.DataFrame({
        "win": df["win"].values[idx] + offset,
        "SrcAddr": df["SrcAddr"].values[idx],
        "DstAddr": df["DstAddr"].values[idx],
        "pkts": df["TotPkts"].values[idx] / n[idx],
        "bytes": df["TotBytes"].values[idx] / n[idx],
        "is_attack": df["is_attack"].values[idx],
    })
    return w


# ------------------------------------------------------------- indicators -----
def window_features(w):
    per = w.groupby(["DstAddr", "win"])["pkts"].sum()
    busy = per[per >= MIN_ALERT_PKTS].index.get_level_values("DstAddr").unique()
    d = w[w["DstAddr"].isin(busy)]

    s = d.groupby(["DstAddr", "win", "SrcAddr"])["pkts"].sum()
    s = s[s > 0]
    T = s.groupby(level=[0, 1]).transform("sum")
    # entropy = log2(T) - sum(s*log2 s)/T   (vectorised Shannon entropy)
    slog = (s * np.log2(s)).groupby(level=[0, 1]).sum()
    tot = s.groupby(level=[0, 1]).sum()
    ent = (np.log2(tot) - slog / tot).rename("entropy")

    agg = d.groupby(["DstAddr", "win"]).agg(pkts=("pkts", "sum"), bytes=("bytes", "sum"))
    feat = agg.join(ent)
    n_win = int(w["win"].max()) + 1
    full = pd.MultiIndex.from_product([busy, range(n_win)], names=["DstAddr", "win"])
    feat = feat.reindex(full)
    feat[["pkts", "bytes", "entropy"]] = feat[["pkts", "bytes", "entropy"]].fillna(0)
    feat["size"] = feat["bytes"] / feat["pkts"].replace(0, np.nan)
    return feat.reset_index()


def _score_one_destination(dst, P, E, S):
    names = ("pkts", "entropy", "size")
    mean = {n: None for n in names}; var = {n: 0.0 for n in names}
    out = []; frozen = 0
    for i in range(len(P)):
        vals = {"pkts": P[i], "entropy": E[i], "size": S[i]}
        f = {}
        for n in names:
            v = vals[n]
            if mean[n] is None or np.isnan(v) or i < WARMUP:
                f[n] = False; continue
            rel = REL_FLOOR * abs(mean[n]) if n != "entropy" else 0.0
            std = max(np.sqrt(var[n]), STD_FLOOR[n], rel)
            f[n] = abs(v - mean[n]) > (K if n == "pkts" else K_CONFIRM) * std
        alert = (f["pkts"] and (f["entropy"] or f["size"]) and P[i] >= MIN_ALERT_PKTS)
        frozen = frozen + 1 if any(f.values()) else 0
        if frozen == 0 or frozen > MAX_FREEZE:  # freeze while abnormal (max 30 min)
            for n in names:
                v = vals[n]
                if np.isnan(v): continue
                if mean[n] is None: mean[n] = v
                else:
                    dlt = v - mean[n]; mean[n] += ALPHA * dlt
                    var[n] = (1 - ALPHA) * (var[n] + ALPHA * dlt * dlt)
        out.append((i, P[i], E[i], S[i], f["pkts"], f["entropy"], f["size"], alert))
    return out


def score_windows(feat):
    parts = []
    for dst, g in feat.sort_values(["DstAddr", "win"]).groupby("DstAddr", sort=False):
        r = pd.DataFrame(_score_one_destination(dst, g.pkts.values, g.entropy.values,
                                                g["size"].values),
                         columns=["win", "pkts", "entropy", "size",
                                  "f_pkts", "f_entropy", "f_size", "alert"])
        r.insert(0, "DstAddr", dst); parts.append(r)
    if not parts:                       # nothing on the network was ever busy enough
        return pd.DataFrame(columns=["DstAddr", "win", "pkts", "entropy", "size",
                                     "f_pkts", "f_entropy", "f_size", "alert"])
    return pd.concat(parts, ignore_index=True)


# ------------------------------------------------------------ events & bots ---
def _runs(wins, gap):
    wins = sorted(wins); runs = []; s = p = wins[0]
    for x in wins[1:]:
        if x - p > gap: runs.append((s, p)); s = x
        p = x
    runs.append((s, p)); return runs


def group_events(scores):
    ev = []
    for dst, g in scores[scores.alert].groupby("DstAddr"):
        for s, e in _runs(g.win, MERGE_GAP):
            ev.append((dst, s, e))
    events = pd.DataFrame(ev, columns=["victim", "win_start", "win_end"])
    events["n_windows"] = events.win_end - events.win_start + 1
    events = events[events.n_windows >= MIN_EVENT]
    return events.sort_values("win_start").reset_index(drop=True)


def find_bots(df, w, events):
    out = []
    t0 = df.attrs["t0"]
    for eid, e in events.iterrows():
        to_v = w[w.DstAddr == e.victim]
        s0 = e.win_start - 1
        during = to_v[(to_v.win >= s0) & (to_v.win < s0 + 1 + ONSET_WIN)]
        # "before" = the last BEFORE_WIN NORMAL windows (skip earlier attack windows
        # on this victim, so back-to-back bursts are compared with real normal traffic)
        busy = set()
        for o in events[events.victim == e.victim].itertuples():
            busy.update(range(o.win_start - 1, o.win_end + 1))
        normal = [x for x in range(s0 - 1, -1, -1) if x not in busy][:BEFORE_WIN]
        before = to_v[to_v.win.isin(normal)]
        p_dur = during.groupby("SrcAddr")["pkts"].sum()
        p_bef = before.groupby("SrcAddr")["pkts"].sum().reindex(p_dur.index).fillna(0)
        bots = p_dur[(p_dur >= BOT_MIN_PKTS) & (p_dur >= SURGE * (p_bef + 1))].index
        on_s = t0 + pd.Timedelta(seconds=s0 * WINDOW_S)
        on_e = t0 + pd.Timedelta(seconds=(s0 + 1 + ONSET_WIN) * WINDOW_S)
        fl = df[(df.DstAddr == e.victim) & df.SrcAddr.isin(bots)
                & (df.StartTime <= on_e) & (df.End >= on_s)]
        for ip in bots:
            t_i = fl[fl.SrcAddr == ip]["StartTime"].min()
            out.append((eid, e.victim, ip, t_i, int(p_dur[ip])))
    return pd.DataFrame(out, columns=["event_id", "victim", "bot", "t_i", "pkts_to_victim"])


def response_filter(events, bots):
    """Drop reply-traffic events. Event e is reply traffic if its 'victim' is a bot
    of an overlapping event o AND o has at least as many bots as e. When an attack
    and its reverse (victim replying to the bots) point at each other, the real
    attack - the side with more attacking sources - is kept."""
    nb = bots.groupby("event_id").size().to_dict()
    bset = {k: set(g.bot) for k, g in bots.groupby("event_id")}
    drop = set()
    for eid, e in events.iterrows():
        for oid, o in events.iterrows():
            if oid == eid: continue
            overlap = e.win_start <= o.win_end + MERGE_GAP and o.win_start <= e.win_end + MERGE_GAP
            if overlap and e.victim in bset.get(oid, set()) and nb.get(oid, 0) >= nb.get(eid, 0):
                drop.add(eid)
    return drop


def detect(df):
    w = spread_flows(df)
    scores = score_windows(window_features(w))
    events = group_events(scores)
    t0 = df.attrs["t0"]
    events["start"] = t0 + pd.to_timedelta(events.win_start * WINDOW_S, unit="s")
    events["end"] = t0 + pd.to_timedelta((events.win_end + 1) * WINDOW_S, unit="s")
    bots = find_bots(df, w, events)
    drop = response_filter(events, bots)
    events["response_traffic"] = events.index.isin(drop)
    n_bots = bots.groupby("event_id").size().reindex(events.index).fillna(0)
    events["n_bots"] = n_bots.astype(int)
    kept = events[~events.response_traffic & (events.n_bots >= MIN_BOTS)]
    bots = bots[bots.event_id.isin(kept.index)].reset_index(drop=True)
    return kept, bots, scores, w, events


# -------------------------------------------------------------- evaluation ----
def evaluate(df, w, events, bots):
    t0 = df.attrs["t0"]
    a = w[w.is_attack].groupby(["DstAddr", "win"])["pkts"].sum()
    gt = a[a >= GT_MIN_PKTS].reset_index()[["DstAddr", "win"]]
    T = set(map(tuple, gt.values))
    P = {(r.victim, x) for r in events.itertuples() for x in range(r.win_start, r.win_end + 1)}
    tp, fp, fn = len(P & T), len(P - T), len(T - P)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0

    # attack bursts = runs of ground-truth windows on the same victim
    bursts = []
    for dst, g in gt.groupby("DstAddr"):
        for s, e in _runs(g.win, MERGE_GAP):
            hit = events[(events.victim == dst) & (events.win_start <= e) & (events.win_end >= s)]
            delay = (hit.win_start.min() + 1 - s) * WINDOW_S if len(hit) else None
            bursts.append({"victim": dst,
                           "start": t0 + pd.Timedelta(seconds=s * WINDOW_S),
                           "length_s": (e - s + 1) * WINDOW_S,
                           "detected": len(hit) > 0, "delay_s": delay})
    bursts = pd.DataFrame(bursts)

    true_victims = set(gt.DstAddr)
    tev = events[events.victim.isin(true_victims)]
    true_bots = set(df[df.Label.str.contains("From-Botnet")].SrcAddr)
    found = set(bots[bots.event_id.isin(tev.index)].bot)
    summary = {
        "window_precision": round(prec, 3), "window_recall": round(rec, 3),
        "window_F1": round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0.0,
        "attack_bursts": len(bursts), "bursts_detected": int(bursts.detected.sum()) if len(bursts) else 0,
        "mean_delay_s": round(bursts.delay_s.dropna().mean(), 1) if len(bursts) else None,
        "events_total": len(events), "events_on_true_victim": len(tev),
        "false_alarm_events": len(events) - len(tev),
        "bots_found": len(found), "bots_true": len(true_bots),
        "bot_precision": round(len(found & true_bots) / len(found), 3) if found else 0.0,
        "bot_recall": round(len(found & true_bots) / len(true_bots), 3) if true_bots else 0.0,
    }
    return summary, bursts


if __name__ == "__main__":
    import sys, json
    # optional: python detection.py <file> --min-bots 2
    if "--min-bots" in sys.argv:
        MIN_BOTS = int(sys.argv[sys.argv.index("--min-bots") + 1])
    print(f"Settings: K={K}, min alert packets={MIN_ALERT_PKTS}, min bots={MIN_BOTS}\n")
    df = load_flows(sys.argv[1])
    events, bots, scores, w, all_events = detect(df)
    summary, bursts = evaluate(df, w, events, bots)
    pd.set_option("display.width", 200)
    print("=== TRUE ATTACK BURSTS (from labels) and whether we caught them ===")
    print(bursts.to_string())
    print(f"\n=== DETECTED EVENTS ({len(events)}; removed: {int(all_events.response_traffic.sum())} "
          f"reply-traffic, {int((all_events.n_bots < MIN_BOTS).sum())} with < {MIN_BOTS} bots) ===")
    print(events.drop(columns="response_traffic").to_string())
    print("\n=== BOTS PER EVENT (first 40 rows) ===")
    print(bots.head(40).to_string())
    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2, default=str))
    events.to_csv("events.csv", index=False); bots.to_csv("bots.csv", index=False)
    scores.to_csv("window_scores.csv", index=False); bursts.to_csv("bursts.csv", index=False)
    print("\nSaved: events.csv, bots.csv, window_scores.csv, bursts.csv")
