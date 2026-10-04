"""
SYNTHETIC SENSITIVITY ANALYSIS FOR PALL
========================================
Stage 1/2 (detection.py / attribution.py) need real flow data; this
script instead tests the PALL formula directly against constructed
scenarios with a KNOWN true controller, to answer the methodology's
open question (3.5): when does PALL stop ranking the controller first?

Every scenario has three kinds of candidate:
  - TRUE CONTROLLER: contacted by all n_bots, with a lag (time between
    last contact and attack start) of mean_delay +/- jitter_std per bot.
    Rarely contacted by ordinary (non-bot) hosts.
  - POPULAR DISTRACTOR: also contacted by all n_bots (same coverage as
    the controller) but at UNCORRELATED times (e.g. a shared DNS/NTP-like
    service everyone happens to use) -- and also reached by many ordinary
    background hosts, so it should normally be suppressed by rarity.
  - INCIDENTAL DISTRACTORS: contacted by only 1-2 bots at random times
    (an unrelated service a couple of bots happened to use).

PALL = C x L x R, using the exact formulas from attribution.py (tau=10s).
Each scenario reports whether the true controller still comes out on top.
"""
import numpy as np
import pandas as pd

TAU = 10.0
N_REPS = 60


def pall_score(n_bots_contacted, n_total_bots, lag_values, n_shared_normal, N_background):
    C = n_bots_contacted / n_total_bots
    if len(lag_values) > 1:
        L = np.exp(-np.std(lag_values, ddof=1) / TAU)
    else:
        L = 0.5  # neutral, matches attribution.py's single-bot case
    R = np.log((N_background + 1) / (n_shared_normal + 1)) / np.log(N_background + 1)
    return C, L, R, C * L * R


def run_scenario(n_bots, jitter_std, n_shared_normal, mean_delay=60.0,
                  N_background=200, n_incidental=5, seed=None):
    rng = np.random.default_rng(seed)

    true_lags = np.clip(rng.normal(mean_delay, jitter_std, size=n_bots), 1, None)
    C_t, L_t, R_t, PALL_t = pall_score(n_bots, n_bots, true_lags, n_shared_normal=1,
                                        N_background=N_background)

    distractor_lags = rng.uniform(1, 300, size=n_bots)
    C_d, L_d, R_d, PALL_d = pall_score(n_bots, n_bots, distractor_lags,
                                        n_shared_normal=n_shared_normal, N_background=N_background)

    best_incidental, best_incidental_detail = 0.0, None
    for _ in range(n_incidental):
        k = int(rng.integers(1, 3))
        lags = rng.uniform(1, 300, size=k)
        n_shared_i = int(rng.integers(0, 5))
        _, _, _, pall_i = pall_score(k, n_bots, lags, n_shared_normal=n_shared_i, N_background=N_background)
        if pall_i > best_incidental:
            best_incidental, best_incidental_detail = pall_i, k

    candidates = {"true_controller": PALL_t, "popular_distractor": PALL_d, "best_incidental": best_incidental}
    ranked = sorted(candidates, key=candidates.get, reverse=True)
    return {
        "PALL_true": PALL_t, "PALL_distractor": PALL_d, "PALL_best_incidental": best_incidental,
        "C_true": C_t, "L_true": L_t, "R_true": R_t,
        "C_distractor": C_d, "L_distractor": L_d, "R_distractor": R_d,
        "top1_correct": ranked[0] == "true_controller",
        "rank_of_true": ranked.index("true_controller") + 1,
        "beaten_by": ranked[0] if ranked[0] != "true_controller" else None,
    }


def sweep_jitter(n_bots=10, n_shared_normal=60, N_background=200, n_reps=N_REPS):
    rows = []
    for jitter in [0, 5, 10, 20, 40, 80, 120, 180]:
        for rep in range(n_reps):
            r = run_scenario(n_bots, jitter, n_shared_normal, N_background=N_background,
                              seed=rep * 10_000 + jitter)
            r.update({"sweep": "jitter", "jitter_std_s": jitter, "n_bots": n_bots,
                       "n_shared_normal": n_shared_normal})
            rows.append(r)
    return rows


def sweep_bots(jitter_std=5, n_shared_normal=60, N_background=200, n_reps=N_REPS):
    rows = []
    for n_bots in [2, 3, 5, 10, 20]:
        for rep in range(n_reps):
            r = run_scenario(n_bots, jitter_std, n_shared_normal, N_background=N_background,
                              seed=rep * 10_000 + n_bots)
            r.update({"sweep": "bots", "jitter_std_s": jitter_std, "n_bots": n_bots,
                       "n_shared_normal": n_shared_normal})
            rows.append(r)
    return rows


def sweep_popularity(n_bots=10, jitter_std=5, N_background=200, n_reps=N_REPS):
    rows = []
    for n_shared in [0, 5, 20, 60, 120, 199]:
        for rep in range(n_reps):
            r = run_scenario(n_bots, jitter_std, n_shared, N_background=N_background,
                              seed=rep * 10_000 + n_shared)
            r.update({"sweep": "popularity", "jitter_std_s": jitter_std, "n_bots": n_bots,
                       "n_shared_normal": n_shared})
            rows.append(r)
    return rows


if __name__ == "__main__":
    all_rows = sweep_jitter() + sweep_bots() + sweep_popularity()
    df = pd.DataFrame(all_rows)
    df.to_csv("synthetic_results.csv", index=False)

    summary = (df.groupby(["sweep", "jitter_std_s", "n_bots", "n_shared_normal"])
               .agg(top1_accuracy=("top1_correct", "mean"),
                    mean_rank_of_true=("rank_of_true", "mean"))
               .reset_index())
    summary.to_csv("synthetic_summary.csv", index=False)
    pd.set_option("display.width", 200)
    print(summary.to_string(index=False))
