# Spectre v1 Supplementary Experiments

## Scope

This supplement extends the frozen LocalBP baseline without overwriting any
existing formal result directory. All new runs are under `supplement-results/`.
The gem5 binary includes the previously documented v24.1 TimingSimpleCPU
CLFLUSH backport `cf949085`.

The current reproducibility inputs are included in the supplementary archive:

- `se-run.py`
- `spectre_v1_fr.c`
- `patches/gem5-v24.1-timing-clflush-mode.patch`

## Full Table

| run | group | BP | workload | mispredict rate | squash/Minst | squashed issued/Minst | L1D miss | L2 miss | CleanInvalidReq | accuracy |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| attack-o3-bp-tournament | A | TournamentBP | `spectre_v1_fr 8 10` | 1.0501% | 1,664.49 | 7,798.00 | 6.8841% | 97.0375% | 22,900 | 4/8 |
| attack-o3-bp-ltage | A | LTAGE | `spectre_v1_fr 8 10` | 0.4065% | 480.37 | 8,430.87 | 6.9015% | 97.0686% | 22,900 | 2/8 |
| attack-o3-bp-bimode | A | BiModeBP | `spectre_v1_fr 8 10` | 1.3741% | 2,265.33 | 7,685.76 | 6.8408% | 96.8105% | 22,900 | 8/8 |
| benign-compute-tournament | B | TournamentBP | benign compute | 0.4388% | 241.14 | 230.90 | 2.0282% | 70.8969% | 0 | n/a |
| benign-cache-tournament | B | TournamentBP | benign cache | 0.0632% | 12.91 | 12.60 | 19.9835% | 71.1986% | 0 | n/a |
| benign-syscall-tournament | B | TournamentBP | benign syscall | 0.0908% | 729.60 | 733.89 | 0.2978% | 72.0633% | 0 | n/a |
| attack-o3-jitter-seed1 | C | LocalBP | seed 1 | 1.1070% | 1,918.51 | 8,458.87 | 5.4792% | 96.4487% | 24,160 | 8/8 |
| attack-o3-jitter-seed2 | C | LocalBP | seed 2 | 1.1018% | 1,913.55 | 8,492.01 | 5.4293% | 96.4574% | 24,225 | 8/8 |
| attack-o3-jitter-seed3 | C | LocalBP | seed 3 | 1.1078% | 1,919.44 | 8,452.87 | 5.4865% | 96.4475% | 24,151 | 8/8 |
| attack-o3-jitter-seed4 | C | LocalBP | seed 4 | 1.0973% | 1,909.48 | 8,520.81 | 5.3858% | 96.4651% | 24,283 | 8/8 |
| attack-o3-jitter-seed5 | C | LocalBP | seed 5 | 1.1002% | 1,912.84 | 8,506.97 | 5.4066% | 96.4614% | 24,255 | 8/8 |
| benign-flush-local | D | LocalBP | benign flush | 0.3265% | 278.87 | 175.75 | 0.9065% | 60.6432% | 12,800 | n/a |
| benign-flush-tournament | D | TournamentBP | benign flush | 0.3219% | 274.84 | 165.91 | 0.8969% | 59.1547% | 12,800 | n/a |

`summary.csv` and `summary.json` contain ticks, simulated and wall time,
instruction counts, raw counters, rates, hit/miss/access counts, calibration
values, and accuracy.

## A. Branch Predictor Sensitivity

Including the prior LocalBP baseline, attack accuracy is:

| BP | accuracy | mispredict rate | squash/Minst | squashed issued/Minst |
|---|---:|---:|---:|---:|
| LocalBP | 8/8 | 1.1962% | 1,960.44 | 7,661.52 |
| TournamentBP | 4/8 | 1.0501% | 1,664.49 | 7,798.00 |
| LTAGE | 2/8 | 0.4065% | 480.37 | 8,430.87 |
| BiModeBP | 8/8 | 1.3741% | 2,265.33 | 7,685.76 |

Accuracy spans 2/8 to 8/8, confirming meaningful BP sensitivity. Leakage is
not unique to LocalBP: BiMode reaches 8/8 and Tournament reaches 4/8, while
LTAGE is weakest at 2/8. Across all four BPs, however, squashed-issued intensity
remains tightly grouped at 7,661.52 to 8,430.87/Minst, and cache/flush signals
are also stable. BP selection strongly changes exploit success but does not
remove the attack's high wrong-path activity.

## B. TournamentBP Attack Versus Benign

Tournament attack divided by the largest Tournament benign value:

| signal | attack | benign maximum | ratio |
|---|---:|---:|---:|
| mispredict rate | 1.0501% | 0.4388% | 2.39x |
| squash events/Minst | 1,664.49 | 729.60 | 2.28x |
| squashed issued/Minst | 7,798.00 | 733.89 | 10.63x |
| L2 miss rate | 97.0375% | 72.0633% | 1.35x |

The previous separation therefore remains under the default TournamentBP.
As before, L1D miss rate is not a safe standalone signal: benign-cache reaches
19.9835%, above the attack's 6.8841%.

## C. Randomized Statistical Stability

The optional invocation `spectre_v1_fr 8 10 0 <seed>` enables a jitter range
of 32 while preserving the original no-jitter behavior when the additional
arguments are absent. For each attack round, 0-31 additional training calls
are inserted before the original 30-call 5:1 sequence.

All five seeds achieved 8/8. Calibration was identical in all runs:
hit=24, miss=77, threshold=50.

| metric | mean | minimum | maximum | range |
|---|---:|---:|---:|---:|
| accuracy (of 8) | 8.00 | 8 | 8 | 0 |
| mispredict rate | 1.1028% | 1.0973% | 1.1078% | 0.0105 percentage points |
| squash events/Minst | 1,914.76 | 1,909.48 | 1,919.44 | 9.96 |
| squashed issued/Minst | 8,486.31 | 8,452.87 | 8,520.81 | 67.94 |
| L1D miss rate | 5.4375% | 5.3858% | 5.4865% | 0.1008 percentage points |
| L2 miss rate | 96.4560% | 96.4475% | 96.4651% | 0.0176 percentage points |
| CleanInvalidReq | 24,214.8 | 24,151 | 24,283 | 132 |

The nonzero metric ranges demonstrate that these are genuinely different
execution streams rather than deterministic reruns, while leakage and the main
detection signals remain stable for these five seeds.

## D. Benign CLFLUSH Pressure Test

Both benign-flush runs execute 12,800 `CleanInvalidReq` operations. A detector
based only on `flush_count > 0` therefore produces a false positive.

Against benign-flush under the matching BP, the attack separation is:

| BP | flush density | mispredict rate | squash events/Minst | squashed issued/Minst |
|---|---:|---:|---:|---:|
| LocalBP attack / benign | 3.05x | 3.66x | 7.03x | 43.59x |
| Tournament attack / benign | 3.04x | 3.26x | 6.06x | 47.00x |

An illustrative rule evaluated over the combined original and supplementary
test set is:

```text
CleanInvalidReq/Minst > 5000 AND squashedInstsIssued/Minst > 1000
```

It flags every attack run, including weak-accuracy Tournament and LTAGE runs,
and flags none of the eight benign runs, including both benign-flush variants.
This is a zero-FP/zero-FN result only for the current finite test set, not a
production threshold or a general FPR claim. It nevertheless demonstrates the
value of the requested joint rule: benign flush usage has substantial flush
traffic but two orders of magnitude less wrong-path intensity.

## Reproducibility Notes

- All prior formal result directories under `results/` were left unchanged.
- All new outputs are under `supplement-results/`.
- `se-run.py` now accepts `--bp local|tournament|ltage|bimode`.
- `spectre_v1_fr.c` keeps its original behavior unless jitter arguments are
  supplied.
- Every run directory contains `command.txt`, `stdout.txt`, `stderr.txt`,
  `stats.txt`, and `config.ini`.
- `jitter-stability.json` contains machine-readable mean/min/max/range values.
