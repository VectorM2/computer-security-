"""
Data check for CTU-13 (.binetflow files)
Usage:  python data_check.py capture20110818.binetflow
Prints everything we need to confirm the PALL idea works on this scenario,
and saves the same output to data_check_report.txt
"""
import sys
import pandas as pd

path = sys.argv[1]
out_lines = []
def say(x=""):
    print(x); out_lines.append(str(x))

df = pd.read_csv(path, low_memory=False)
df["StartTime"] = pd.to_datetime(df["StartTime"], format="mixed")
df["Label"] = df["Label"].astype(str)

say(f"FILE: {path}")
say(f"Total flows: {len(df):,}")
say(f"Time span: {df.StartTime.min()}  ->  {df.StartTime.max()}")

# ---- 1. Overall label groups
grp = df["Label"].str.extract(r"flow=(Background|Normal|From-Botnet|To-Botnet|From-Normal|To-Normal)")[0].fillna("Other")
say("\n1) LABEL GROUPS")
say(grp.value_counts().to_string())

bot = df[df["Label"].str.contains("Botnet", case=False)]
say("\n2) ALL BOTNET LABELS (count)")
say(bot["Label"].value_counts().head(40).to_string())

# ---- 2. Bots
bots = sorted(df[df["Label"].str.contains("From-Botnet", case=False)]["SrcAddr"].unique())
say(f"\n3) BOT IPs ({len(bots)}): {bots}")

# ---- 3. C&C flows
cc = bot[bot["Label"].str.contains("CC", case=True)]
say(f"\n4) C&C FLOWS: {len(cc):,}")
if len(cc):
    say("C&C server candidates (DstAddr : Dport : flows):")
    say(cc.groupby(["DstAddr", "Dport"]).size().sort_values(ascending=False).head(10).to_string())
cc_ips = set(cc["DstAddr"].unique())

# ---- 4. Victim of the DDoS = destination receiving most non-C&C bot flows
attack = bot[(bot["SrcAddr"].isin(bots)) & (~bot["DstAddr"].isin(cc_ips))]
say("\n5) TOP DESTINATIONS OF BOT TRAFFIC (excluding C&C) -> victim should be #1")
top = attack.groupby(["DstAddr", "Proto"]).agg(flows=("TotPkts", "size"),
                                               packets=("TotPkts", "sum"),
                                               bots=("SrcAddr", "nunique"))
say(top.sort_values("flows", ascending=False).head(5).to_string())

if len(attack):
    victim = attack["DstAddr"].value_counts().idxmax()
    vflows = attack[attack["DstAddr"] == victim]
    say(f"\nVICTIM: {victim}")
    say(f"Attack period: {vflows.StartTime.min()} -> {vflows.StartTime.max()}")
    say(f"Mean packet size of attack flows: {(vflows.TotBytes.sum()/vflows.TotPkts.sum()):.1f} bytes")

    # ---- 5. The key test: did bots contact C&C shortly before attacking?
    say("\n6) PER-BOT TIMING (the key test for lag consistency)")
    say(f"{'bot':<18}{'attack start':<28}{'last C&C contact before':<28}{'gap (s)':>10}")
    gaps = []
    for b in bots:
        a = vflows[vflows.SrcAddr == b]
        if a.empty: continue
        t_i = a.StartTime.min()
        c = cc[(cc.SrcAddr == b) & (cc.StartTime < t_i)]
        if c.empty:
            say(f"{b:<18}{str(t_i):<28}{'none':<28}{'-':>10}"); continue
        last = c.StartTime.max(); gap = (t_i - last).total_seconds(); gaps.append(gap)
        say(f"{b:<18}{str(t_i):<28}{str(last):<28}{gap:>10.1f}")
    if gaps:
        s = pd.Series(gaps)
        say(f"\nGap summary: min={s.min():.1f}s  median={s.median():.1f}s  max={s.max():.1f}s  std={s.std():.1f}s")
        say("VERDICT: " + ("lag test looks GOOD for a 5-minute window" if s.median() <= 300
                           else "gaps are long -> use a longer window or rely on synthetic data for lag"))

open("data_check_report.txt", "w").write("\n".join(out_lines))
print("\nSaved: data_check_report.txt")
