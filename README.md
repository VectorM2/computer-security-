# DDoS Detection and PALL Botmaster Attribution

A two-stage pipeline that (1) detects DDoS attacks in network-flow data and (2)
ranks the devices most likely to be controlling the attacking bots, using a
Pre-Attack Lead-Lag (PALL) score. Built and evaluated on the public **CTU-13**
botnet dataset.

This README is written so anyone on the team can copy and paste their way from
a blank computer to a working run, even with zero prior setup.

---

## What's in this repo

| File | What it does |
|---|---|
| `data_check.py` | Sanity-checks a CTU-13 `.binetflow` file before anything else runs |
| `detection.py` | Stage 1 — detects DDoS attack events and the bots behind them |
| `sweep.py` | Sensitivity analysis for Stage 1 (varies detection thresholds) |
| `attribution.py` | Stage 2 — PALL attribution: ranks candidate botmasters per event |
| `synthetic_sensitivity.py` | Synthetic experiments: when does PALL stop working? |
| `export_results.py` | Collects every result into `results/data/` and `results/figures/` |
| `requirements.txt` | The Python packages everything above needs |

---

## 1. Install Python

You need **Python 3.10 or newer**. If you're not sure whether you already have
it, open a terminal and run:

```bash
python3 --version
```

If that prints `Python 3.10.x` or higher, skip to [Step 2](#2-get-the-code).
If it says "command not found" or shows an older version, install it below.

### Windows

1. Go to **https://www.python.org/downloads/** and click the yellow **Download
   Python** button.
2. Run the installer. **Important:** on the first screen, tick the checkbox
   at the bottom that says **"Add python.exe to PATH"** before clicking
   Install.
3. Open a new **PowerShell** or **Command Prompt** window and check it worked:
   ```powershell
   python --version
   ```

### macOS

Easiest way is with [Homebrew](https://brew.sh):

```bash
# Install Homebrew first, if you don't have it:
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Then install Python:
brew install python
python3 --version
```

(Alternatively, download the installer directly from
https://www.python.org/downloads/macos/.)

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git
python3 --version
```

### Linux (Fedora)

```bash
sudo dnf install -y python3 python3-pip git
python3 --version
```

---

## 2. Get the code

You'll also need **Git**. Windows users: install it from
https://git-scm.com/downloads (the default options are fine). macOS and Linux
already have it, or it was installed in Step 1 above.

Clone the repo and move into it:

```bash
git clone https://github.com/<your-org-or-username>/<your-repo-name>.git
cd <your-repo-name>
```

> Replace `<your-org-or-username>/<your-repo-name>` with the actual GitHub
> path once the repo is public.

---

## 3. Install the dependencies

From inside the project folder (the one you just `cd`-ed into), it's best
practice to use a virtual environment so this project's packages don't clash
with anything else on your machine — but it isn't required.

**With a virtual environment (recommended):**

macOS / Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Without a virtual environment (quickest):**

```bash
pip install -r requirements.txt
```

If `pip` isn't found, try `pip3` instead. On some Linux distributions you may
need:
```bash
pip install -r requirements.txt --break-system-packages
```

---

## 4. Get the dataset

The scripts run on the **CTU-13** botnet dataset (García et al., 2014),
specifically **Scenario 10** (and optionally Scenario 11). It is not included
in this repo — the file is too large for GitHub (~170 MB).

1. Go to the Stratosphere Lab's CTU-13 page:
   **https://www.stratosphereips.org/datasets-ctu13**
2. Download **Scenario 10** (folder name `CTU-13-Dataset/10/`) and look for
   the file ending in `.binetflow` (bidirectional NetFlow, e.g.
   `capture20110818.binetflow`).
3. Optionally also download **Scenario 11** the same way, for the secondary
   evaluation.
4. Place the `.binetflow` file(s) in the root of this project folder (the
   same folder as `detection.py`).

---

## 5. Run the pipeline

Run these **in order** from inside the project folder. Each step writes its
output as `.csv` / `.json` files into the same folder, which the next step
reads.

```bash
# 1. Sanity-check the dataset (prints a report, also saves data_check_report.txt)
python3 data_check.py capture20110818.binetflow

# 2. Stage 1 — detect attacks and bots
#    (saves events.csv, bots.csv, window_scores.csv, bursts.csv)
python3 detection.py capture20110818.binetflow

# 3. (optional) Sensitivity sweep over detection thresholds
#    (saves sweep_results.csv)
python3 sweep.py capture20110818.binetflow

# 4. Stage 2 — PALL attribution
#    (saves candidates_ip.csv, candidates_channel.csv, table_topk_mrr.csv,
#     ablation.csv, top_candidates_report.csv, false_alarm_vs_true.csv,
#     attribution_summary.json)
python3 attribution.py capture20110818.binetflow

# 5. (optional) Synthetic sensitivity analysis — "when does PALL fail?"
#    (saves synthetic_results.csv, synthetic_summary.csv; no dataset needed)
python3 synthetic_sensitivity.py

# 6. Collect everything into one results/ folder, with PNG charts
python3 export_results.py --outdir results
```

On Windows, replace `python3` with `python` in every command above.

> **Heads up on runtime:** `detection.py` and `attribution.py` load the full
> flow file into memory and can take a few minutes on Scenario 10 (~1.3
> million rows). This is normal — let it finish.

### Quick copy-paste (everything, one block)

```bash
git clone https://github.com/<your-org-or-username>/<your-repo-name>.git
cd <your-repo-name>
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# -> download CTU-13 Scenario 10 from https://www.stratosphereips.org/datasets-ctu13
#    and place the .binetflow file in this folder before continuing
python3 data_check.py capture20110818.binetflow
python3 detection.py capture20110818.binetflow
python3 sweep.py capture20110818.binetflow
python3 attribution.py capture20110818.binetflow
python3 synthetic_sensitivity.py
python3 export_results.py --outdir results
```

---

## 6. What you get

After Step 6, everything is collected under `results/`:

```
results/
  data/       every CSV/JSON the pipeline produced, plus results_combined.json
  figures/    PNG charts — detection timeline, Top-k/MRR, ablation,
              top candidates, false-alarm comparison, synthetic sensitivity
```

Open any `.png` in `results/figures/` directly, or load the `.csv`/`.json`
files in `results/data/` into Excel, pandas, or your report.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `python3: command not found` | Use `python` instead (common on Windows), or re-check Step 1 |
| `pip: command not found` | Use `pip3`, or `python3 -m pip install -r requirements.txt` |
| `ModuleNotFoundError: No module named 'pandas'` | You're not in the virtual environment — run the `activate` command from Step 3 again, or just re-run `pip install -r requirements.txt` |
| `error: externally-managed-environment` (Linux) | Add `--break-system-packages` to the `pip install` command, or use a virtual environment |
| Script can't find the `.binetflow` file | Make sure it's in the same folder you're running the command from, and the filename matches exactly (check with `ls` / `dir`) |
| `attribution.py` prints a "WARNING: ... bot rows could not be matched" | Expected — a small number of bots fall just outside the matching time window; this doesn't stop the script |
| `export_results.py` skips a figure | That just means its input file wasn't found (e.g. you skipped the optional `sweep.py` step) — run the missing step first, then re-run `export_results.py` |
