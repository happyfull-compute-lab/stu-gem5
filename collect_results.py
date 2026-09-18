import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RUNS = [
    ("attack-o3-r10a", "O3", "spectre_v1_fr 8 10"),
    ("attack-o3-r10b", "O3", "spectre_v1_fr 8 10"),
    ("attack-o3-r10c", "O3", "spectre_v1_fr 8 10"),
    ("attack-o3-r30", "O3", "spectre_v1_fr 8 30"),
    ("attack-timing", "TimingSimpleCPU", "spectre_v1_fr 8 10"),
    ("attack-atomic", "AtomicSimpleCPU", "spectre_v1_fr 8 10"),
    ("benign-compute", "O3", "benign_compute"),
    ("benign-cache", "O3", "benign_cache"),
    ("benign-syscall", "O3", "benign_syscall"),
]


def parse_stats(path):
    values = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 2:
            try:
                values[fields[0]] = float(fields[1])
            except ValueError:
                pass
    return values


def value(stats, suffix):
    matches = [v for k, v in stats.items() if k.endswith(suffix)]
    if len(matches) != 1:
        raise KeyError(f"Expected one field ending in {suffix}, got {len(matches)}")
    return matches[0]


def optional_value(stats, suffix):
    matches = [v for k, v in stats.items() if k.endswith(suffix)]
    return matches[0] if len(matches) == 1 else 0


def wall_seconds(path):
    match = re.search(r"^real\s+(\d+)m([0-9.]+)s$", path.read_text(), re.M)
    return int(match.group(1)) * 60 + float(match.group(2)) if match else None


rows = []
for run, cpu, workload in RUNS:
    directory = RESULTS / run
    stats = parse_stats(directory / "stats.txt")
    stdout = (directory / "stdout.txt").read_text()
    accuracy = re.search(r"accuracy=(\d+/\d+)", stdout)
    insts = value(stats, "simInsts")
    cond_incorrect = value(stats, "branchPred.condIncorrect") if cpu == "O3" else 0
    cond_predicted = value(stats, "branchPred.condPredicted") if cpu == "O3" else 0
    branch_squashes = value(stats, "commit.branchMispredicts") if cpu == "O3" else 0
    squashed_issued = value(stats, "squashedInstsIssued") if cpu == "O3" else 0
    l1_hits = value(stats, "l1dcaches.demandHits::total")
    l1_misses = value(stats, "l1dcaches.demandMisses::total")
    l2_hits = value(stats, "l2cache.demandHits::total")
    l2_misses = value(stats, "l2cache.demandMisses::total")
    flushes = optional_value(stats, "l2bus.transDist::CleanInvalidReq")
    row = {
        "run": run,
        "cpu": cpu,
        "workload": workload,
        "ticks": int(value(stats, "simTicks")),
        "sim_seconds": value(stats, "simSeconds"),
        "wall_seconds": wall_seconds(directory / "stderr.txt"),
        "insts": int(insts),
        "cond_incorrect": int(cond_incorrect),
        "cond_predicted": int(cond_predicted),
        "mispred_rate": cond_incorrect / cond_predicted if cond_predicted else 0,
        "branch_squashes": int(branch_squashes),
        "squash_events_per_minst": branch_squashes / insts * 1e6,
        "squashed_issued": int(squashed_issued),
        "squashed_issued_per_minst": squashed_issued / insts * 1e6,
        "l1d_hits": int(l1_hits),
        "l1d_misses": int(l1_misses),
        "l1d_accesses": int(l1_hits + l1_misses),
        "l1d_miss_rate": l1_misses / (l1_hits + l1_misses),
        "l2_hits": int(l2_hits),
        "l2_misses": int(l2_misses),
        "l2_accesses": int(l2_hits + l2_misses),
        "l2_miss_rate": l2_misses / (l2_hits + l2_misses),
        "clean_invalid_reqs": int(flushes),
        "clean_invalid_per_minst": flushes / insts * 1e6,
        "accuracy": accuracy.group(1) if accuracy else "n/a",
    }
    rows.append(row)

with (RESULTS / "summary.csv").open("w", newline="") as output:
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
(RESULTS / "summary.json").write_text(json.dumps(rows, indent=2) + "\n")

headers = [
    "run", "CPU", "workload", "ticks", "insts", "mispred rate",
    "squash/1M inst", "L1D miss rate", "L2 miss rate", "accuracy",
]
lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
for row in rows:
    lines.append(
        "| {run} | {cpu} | {workload} | {ticks} | {insts} | {mispred_rate:.4%} | "
        "{squash_events_per_minst:.2f} | {l1d_miss_rate:.4%} | "
        "{l2_miss_rate:.4%} | {accuracy} |".format(**row)
    )
(RESULTS / "summary.md").write_text("\n".join(lines) + "\n")
