"""
STAGE 2 - C2 BOTMASTER ATTRIBUTION (PALL)
==========================================
Implements the PALL scoring method described in Chapter 3.4 of the report:

    PALL(h) = Coverage(h) x Lag-consistency(h) x Rarity(h)

For a detected attack event with bots b_1..b_n and attack-start times
t_1..t_n (from Stage 1 / detection.py), every host a bot was in contact
with in the 300 s before it attacked is a candidate controller. A real
C&C node should be contacted by (almost) every bot (high Coverage),
shortly before each bot's attack with a similar delay across bots (high
Lag-consistency), and should not be a host that ordinary, non-bot traffic
also uses (high Rarity). PALL is the product of the three, so a host that
fails any one of them (e.g. a popular DNS server reached by everyone,
bots included) scores low.

Usage:
    python attribution.py capture20110818.binetflow
        -> reads events.csv / bots.csv (Stage 1 output) in the working
           directory, computes PALL candidates for every event, evaluates
           against ground-truth C&C IPs / the TCP:6667 channel, compares
           with two baselines and an ablation, and saves:
             candidates_ip.csv        - every IP-level candidate, ranked
             candidates_channel.csv   - every channel-level candidate, ranked
             table_topk_mrr.csv       - Table 4.4 (PALL vs baselines)
             ablation.csv             - Table 4.6 (drop one measure at a time)
             top_candidates_report.csv- Table 4.5 (top-5 for a chosen event)
             false_alarm_vs_true.csv  - item (e): best PALL in FA vs true events
             attribution_summary.json
"""
import numpy as np
import pandas as pd

import detection as D  # reuse Stage 1's load_flows / spread_flows / GT_MIN_PKTS

# ---------------- parameters (report these in 3.4 / Table 3.2-equivalent) ----
LOOKBACK_S   = 300      # candidate = host contacted in the 300s before t_i
TAU          = 10.0     # lag-consistency time constant tau (s)
RARITY_HOURS = 1        # "ordinary traffic" population window before the event
CC_PROTO     = "tcp"
CC_PORT      = 6667
MATCH_TOL_S  = 30       # tolerance (s) when matching bots.csv rows back to an event


# ----------------------------------------------------------------- loading ---
def load_stage1(events_path="events.csv", bots_path="bots.csv"):
    events = pd.read_csv(events_path, parse_dates=["start", "end"])
    bots = pd.read_csv(bots_path, parse_dates=["t_i"])
    return events.reset_index(drop=True), bots


def match_bots_to_events(events, bots, tol_s=MATCH_TOL_S):
    """events.csv is saved without its original Stage-1 index, so bots.csv's
    event_id can't be joined positionally. Re-match instead by victim + the
    bot's attack time t_i falling inside [event.start, event.end] (+/- tol_s).
    Returns bots with a fresh 'event_id' column = events' row position."""
    tol = pd.Timedelta(seconds=tol_s)
    out = []
    for eid, e in events.iterrows():
        cand = bots[(bots.victim == e.victim) &
                    (bots.t_i >= e.start - tol) & (bots.t_i <= e.end + tol)]
        if cand.empty:
            continue
        c = cand.copy()
        c["event_id"] = eid
        out.append(c)
    if not out:
        return bots.iloc[0:0].assign(event_id=[])
    matched = pd.concat(out, ignore_index=True)
    unmatched = len(bots) - len(matched)
    if unmatched:
        print(f"[match_bots_to_events] WARNING: {unmatched} bot rows could not "
              f"be matched to an event (tolerance={tol_s}s)")
    return matched


# --------------------------------------------------------- candidate search --
def _contacts_for_bot(df, bot, t_i, victim, lookback_s=LOOKBACK_S):
    """Flows from `bot` active at any point in (t_i - lookback, t_i], i.e.
    started on/before t_i and still active within the lookback window --
    this is what picks up long-lived sessions (e.g. an hour-long IRC
    connection) opened well before the lookback started. Excludes the victim."""
    lo = t_i - pd.Timedelta(seconds=lookback_s)
    f = df[(df.SrcAddr == bot) & (df.DstAddr != victim) &
           (df.StartTime <= t_i) & (df.End >= lo)]
    if f.empty:
        return f
    last_end = f.groupby("DstAddr")["End"].transform("max")
    # c_i(h) = min(latest end time of bot i's flows to h, t_i)
    f = f.assign(contact_time=last_end.clip(upper=t_i))
    return f


def _rarity_population(df, anchor, bot_ips, hours=RARITY_HOURS):
    """Non-bot hosts active in the `hours` before `anchor`, and which
    destinations they contacted -- used to penalise popular/shared hosts."""
    lo = anchor - pd.Timedelta(hours=hours)
    w = df[(df.StartTime <= anchor) & (df.End >= lo) & (~df.SrcAddr.isin(bot_ips))]
    N = w.SrcAddr.nunique()
    return w, N


def event_candidates(df, event_id, victim, event_bots):
    """IP-level and channel-level PALL candidates for one event.
    event_bots: rows of bots.csv (event_id, victim, bot, t_i, pkts_to_victim)
    already matched to this event."""
    n = len(event_bots)
    if n == 0:
        empty = pd.DataFrame(columns=["event_id", "victim", "key", "C", "L", "R",
                                       "PALL", "contact_count", "n_bots_contacted"])
        return empty, empty.copy()

    contacts = []
    for row in event_bots.itertuples():
        f = _contacts_for_bot(df, row.bot, row.t_i, victim)
        if f.empty:
            continue
        per_host = (f.groupby(["DstAddr", "Proto", "Dport"])["contact_time"]
                    .max().reset_index())
        per_host["bot"] = row.bot
        per_host["t_i"] = row.t_i
        contacts.append(per_host)

    if not contacts:
        empty = pd.DataFrame(columns=["event_id", "victim", "key", "C", "L", "R",
                                       "PALL", "contact_count", "n_bots_contacted"])
        return empty, empty.copy()

    c = pd.concat(contacts, ignore_index=True)
    c["lag_s"] = (c["t_i"] - c["contact_time"]).dt.total_seconds().clip(lower=0)

    anchor = event_bots.t_i.min()
    bot_ips = set(event_bots.bot)
    pop, N = _rarity_population(df, anchor, bot_ips)

    def _score(frame, key_col, pop_key_fn):
        g = frame.groupby(key_col)
        cov = g["bot"].nunique() / n
        touch = g["bot"].nunique()
        lag_std = g["lag_s"].std()                       # NaN when only 1 bot
        lag_std = lag_std.where(touch > 1)                # force NaN -> neutral
        L = np.exp(-lag_std / TAU)
        L = L.fillna(0.5)
        n_h = pop_key_fn().reindex(cov.index).fillna(0)
        R = (np.log((N + 1) / (n_h + 1)) / np.log(N + 1)) if N > 0 else pd.Series(1.0, index=cov.index)
        out = pd.DataFrame({
            "key": cov.index, "C": cov.values, "L": L.values, "R": R.values,
            "contact_count": g.size().reindex(cov.index).values,
            "n_bots_contacted": touch.values,
        })
        out["PALL"] = out.C * out.L * out.R
        out = out.sort_values("PALL", ascending=False, kind="mergesort").reset_index(drop=True)
        out.insert(0, "event_id", event_id)
        out.insert(1, "victim", victim)
        return out

    ip_out = _score(c, "DstAddr",
                     lambda: pop.groupby("DstAddr")["SrcAddr"].nunique())

    ch = c.assign(channel=c["Proto"].astype(str) + "/" + c["Dport"].astype(str))
    pop_ch = pop.assign(channel=pop["Proto"].astype(str) + "/" + pop["Dport"].astype(str))
    ch_out = _score(ch, "channel",
                     lambda: pop_ch.groupby("channel")["SrcAddr"].nunique())

    return ip_out, ch_out


# ----------------------------------------------------------- ground truth ---
def ground_truth_cc(df):
    """Bot->C&C flows (From-Botnet AND labelled CC), for looking up which
    C&C IPs a given set of bots actually used."""
    is_bot = df.Label.str.contains("From-Botnet", case=False)
    is_cc = df.Label.str.contains("CC", case=True)
    return df[is_bot & is_cc]


def true_victims(df):
    """Same definition detection.evaluate() uses: destinations that receive
    a true (>= GT_MIN_PKTS) attack burst, per 10s window."""
    w = D.spread_flows(df)
    a = w[w.is_attack].groupby(["DstAddr", "win"])["pkts"].sum()
    gt = a[a >= D.GT_MIN_PKTS].reset_index()[["DstAddr", "win"]]
    return set(gt.DstAddr), w


# --------------------------------------------------------------- ranking ----
def rank_of(sorted_keys, target_set):
    for i, k in enumerate(sorted_keys, start=1):
        if k in target_set:
            return i
    return None


def summarize_ranks(ranks, ks=(1, 3, 5)):
    n = len(ranks)
    out = {f"top{k}": round(sum(1 for r in ranks if r is not None and r <= k) / n, 3) if n else 0.0
           for k in ks}
    out["MRR"] = round(sum((1 / r if r else 0.0) for r in ranks) / n, 3) if n else 0.0
    out["n_events"] = n
    out["n_found"] = sum(1 for r in ranks if r is not None)
    return out


# ------------------------------------------------------------------ main ----
def run(flow_path, events_path="events.csv", bots_path="bots.csv"):
    print("Loading flows ...")
    df = D.load_flows(flow_path)
    events, bots_raw = load_stage1(events_path, bots_path)
    bots = match_bots_to_events(events, bots_raw)

    print("Computing ground truth (true victims, C&C flows) ...")
    tv, _w = true_victims(df)
    cc_flows = ground_truth_cc(df)
    cc_channel = f"{CC_PROTO}/{CC_PORT}"

    ip_rows, ch_rows = [], []
    event_meta = []
    for eid, e in events.iterrows():
        eb = bots[bots.event_id == eid]
        ip_df, ch_df = event_candidates(df, eid, e.victim, eb)
        ip_rows.append(ip_df)
        ch_rows.append(ch_df)
        is_true = e.victim in tv
        gt_ips = set(cc_flows[cc_flows.SrcAddr.isin(set(eb.bot))].DstAddr) if is_true else set()
        event_meta.append({"event_id": eid, "victim": e.victim, "n_bots": len(eb),
                            "is_true_attack": is_true, "gt_ips": gt_ips})

    candidates_ip = pd.concat(ip_rows, ignore_index=True) if ip_rows else pd.DataFrame()
    candidates_ch = pd.concat(ch_rows, ignore_index=True) if ch_rows else pd.DataFrame()
    meta = pd.DataFrame(event_meta)

    # ---------------- Table 4.4: PALL vs baselines, IP + channel level -----
    def eval_method(frame, key_col, score_col, true_events_only=True, channel=False):
        ranks = []
        for m in event_meta:
            if true_events_only and not m["is_true_attack"]:
                continue
            g = frame[frame.event_id == m["event_id"]].sort_values(
                score_col, ascending=False, kind="mergesort")
            target = {cc_channel} if channel else m["gt_ips"]
            if not target:
                continue
            ranks.append(rank_of(g[key_col].tolist(), target))
        return summarize_ranks(ranks)

    table_rows = []
    for label, col, frame, is_ch in [
        ("PALL (IP level)",        "PALL",          candidates_ip, False),
        ("Contact-count baseline", "contact_count", candidates_ip, False),
        ("Degree baseline (C only)", "C",            candidates_ip, False),
        ("PALL (channel level)",   "PALL",          candidates_ch, True),
        ("Contact-count (channel)","contact_count", candidates_ch, True),
        ("Degree (channel)",       "C",              candidates_ch, True),
    ]:
        key_col = "key"
        res = eval_method(frame, key_col, col, channel=is_ch)
        res["method"] = label
        table_rows.append(res)
    table_topk = pd.DataFrame(table_rows)[["method", "top1", "top3", "top5", "MRR", "n_events", "n_found"]]

    # ---------------- Table 4.6: ablation (drop one measure at a time) -----
    cip = candidates_ip.copy()
    cip["CL"] = cip.C * cip.L
    cip["CR"] = cip.C * cip.R
    cip["LR"] = cip.L * cip.R
    abl_rows = []
    for label, col in [("Full PALL (C x L x R)", "PALL"),
                        ("No Rarity (C x L)", "CL"),
                        ("No Lag (C x R)", "CR"),
                        ("No Coverage (L x R)", "LR")]:
        res = eval_method(cip, "key", col, channel=False)
        res["component"] = label
        abl_rows.append(res)
    ablation = pd.DataFrame(abl_rows)[["component", "top1", "top3", "top5", "MRR", "n_events", "n_found"]]

    # ---------------- item (e): false-alarm vs true-event PALL max ----------
    best_pall = (candidates_ip.groupby("event_id")["PALL"].max()
                 .reindex(meta.event_id).reset_index())
    best_pall = best_pall.merge(meta[["event_id", "victim", "is_true_attack", "n_bots"]],
                                 on="event_id")
    best_pall = best_pall.rename(columns={"PALL": "max_PALL"})

    # ---------------- Table 4.5: top-5 candidates for the first true event --
    true_eids = meta[meta.is_true_attack].event_id.tolist()
    top5_report = pd.DataFrame()
    if true_eids:
        first_true = true_eids[0]
        top5_report = (candidates_ip[candidates_ip.event_id == first_true]
                        .head(5)[["event_id", "victim", "key", "C", "L", "R", "PALL",
                                   "contact_count", "n_bots_contacted"]])

    # ---------------- save everything ---------------------------------------
    candidates_ip.to_csv("candidates_ip.csv", index=False)
    candidates_ch.to_csv("candidates_channel.csv", index=False)
    table_topk.to_csv("table_topk_mrr.csv", index=False)
    ablation.to_csv("ablation.csv", index=False)
    top5_report.to_csv("top_candidates_report.csv", index=False)
    best_pall.to_csv("false_alarm_vs_true.csv", index=False)

    import json
    summary = {
        "n_events_total": len(events),
        "n_true_attack_events": int(meta.is_true_attack.sum()),
        "n_false_alarm_events": int((~meta.is_true_attack).sum()),
        "table_topk_mrr": table_topk.to_dict(orient="records"),
        "ablation": ablation.to_dict(orient="records"),
        "false_alarm_vs_true": {
            "mean_max_PALL_true": round(best_pall[best_pall.is_true_attack].max_PALL.mean(), 4)
                if best_pall.is_true_attack.any() else None,
            "mean_max_PALL_false_alarm": round(best_pall[~best_pall.is_true_attack].max_PALL.mean(), 4)
                if (~best_pall.is_true_attack).any() else None,
        },
    }
    with open("attribution_summary.json", "w") as fh:
        json.dump(summary, fh, indent=2, default=str)

    return candidates_ip, candidates_ch, table_topk, ablation, top5_report, best_pall, summary


if __name__ == "__main__":
    import sys, json
    flow_path = sys.argv[1] if len(sys.argv) > 1 else "capture20110818.binetflow"
    (candidates_ip, candidates_ch, table_topk, ablation,
     top5_report, best_pall, summary) = run(flow_path)

    pd.set_option("display.width", 200)
    print("\n=== TABLE 4.4: Top-k accuracy / MRR, PALL vs baselines (true attack events only) ===")
    print(table_topk.to_string(index=False))
    print("\n=== TABLE 4.6: Ablation (drop one PALL component at a time) ===")
    print(ablation.to_string(index=False))
    print("\n=== TABLE 4.5: Top-5 candidates for the first true attack event ===")
    print(top5_report.to_string(index=False))
    print("\n=== Item (e): max PALL score, true events vs false-alarm events ===")
    print(best_pall.groupby("is_true_attack")["max_PALL"].describe().to_string())
    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2, default=str))
    print("\nSaved: candidates_ip.csv, candidates_channel.csv, table_topk_mrr.csv, "
          "ablation.csv, top_candidates_report.csv, false_alarm_vs_true.csv, "
          "attribution_summary.json")
