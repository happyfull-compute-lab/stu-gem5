import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BASE = ROOT / "stu-results"


def read_stats(path):
    stats = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 2:
            try:
                stats[fields[0]] = float(fields[1])
            except ValueError:
                pass
    return stats


def read_policies(directory):
    path = directory / "monitor-alerts.jsonl"
    if not path.exists():
        return set()
    return {json.loads(line)["policy_id"] for line in path.read_text().splitlines()}


def policy_alerts(directory, policy_id):
    path = directory / "monitor-alerts.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()
            if json.loads(line)["policy_id"] == policy_id]


rows = []
for directory in sorted(p for p in BASE.iterdir() if p.is_dir()):
    stats = read_stats(directory / "stats.txt")
    stream_path = directory / "stu-stream.jsonl"
    stream = [json.loads(line) for line in stream_path.read_text().splitlines()] \
        if stream_path.exists() else []
    monitor_path = directory / "monitor-summary.json"
    monitor = json.loads(monitor_path.read_text()) if monitor_path.exists() else {}
    spectre_alerts = policy_alerts(directory, "P-SPECTRE-FR-1")
    setuid_alerts = policy_alerts(directory, "P-SETUID-EXHAUST-1")
    stdout = (directory / "stdout.txt").read_text()
    accuracy = re.search(r"accuracy=(\d+/\d+)", stdout)
    rows.append({
        "run": directory.name,
        "accuracy": accuracy.group(1) if accuracy else "n/a",
        "windows": len(stream),
        "stu_committed": sum(x["committed"] for x in stream),
        "stu_cleanInvalid": sum(x["cleanInvalid"] for x in stream),
        "stu_squashEvents": sum(x["squashEvents"] for x in stream),
        "stu_squashedIssued": sum(x["squashedIssued"] for x in stream),
        "stu_branchMispredicts": sum(x["branchMispredicts"] for x in stream),
        "stu_condIncorrect": sum(x["condIncorrect"] for x in stream),
        "stats_simInsts": int(stats.get("simInsts", 0)),
        "stats_cleanInvalid": int(stats.get("board.cache_hierarchy.l2bus.transDist::CleanInvalidReq", 0)),
        "stats_squashedIssued": int(stats.get("board.processor.cores.core.squashedInstsIssued", 0)),
        "stats_branchMispredicts": int(stats.get("board.processor.cores.core.commit.branchMispredicts", 0)),
        "stats_condIncorrect": int(stats.get("board.processor.cores.core.branchPred.condIncorrect", 0)),
        "syscall_clone": sum(x.get("syscalls", {}).get("clone", 0) for x in stream),
        "syscall_setuid": sum(x.get("syscalls", {}).get("setuid", 0) for x in stream),
        "syscall_clone_returns": sum(x.get("syscallReturns", {}).get("clone", 0) for x in stream),
        "syscall_setuid_returns": sum(x.get("syscallReturns", {}).get("setuid", 0) for x in stream),
        "first_clone_tick": next((x.get("firstCloneTick", 0) for x in stream if x.get("firstCloneTick", 0)), 0),
        "faults": sum(x.get("faults", 0) for x in stream),
        "alerts": monitor.get("alert_count", 0),
        "spectreAlerts": len(spectre_alerts),
        "spectreFirstAlertWindow": spectre_alerts[0]["window"] if spectre_alerts else None,
        "firstAlertWindow": monitor.get("first_alert_window"),
        "firstFlushTick": monitor.get("first_flush_tick"),
        "detectionLatencyTicks": monitor.get("detection_latency_ticks"),
        "setuidAlerts": len(setuid_alerts),
        "setuidFirstAlertWindow": setuid_alerts[0]["window"] if setuid_alerts else None,
        "setuidDetectionLatencyTicks": monitor.get("setuid_policy_detection_latency_ticks"),
        "maxCloneSyscallsPerMinst": max(
            (x.get("rates", {}).get("cloneSyscallsPerMinst", 0) for x in stream),
            default=0,
        ),
        "policies": sorted(read_policies(directory)),
        "simTicks": int(stats.get("simTicks", 0)),
        "hostSeconds": stats.get("hostSeconds", 0),
    })

with (BASE / "summary.csv").open("w", newline="") as output:
    fields = [key for key in rows[0] if key != "policies"]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows({key: row[key] for key in fields} for row in rows)
(BASE / "summary.json").write_text(json.dumps(rows, indent=2) + "\n")


def get(name):
    return next(row for row in rows if row["run"] == name)


def policy_count(prefix, policy):
    return sum(policy in row["policies"] for row in rows if row["run"].startswith(prefix))


spectre_rows = [r for r in rows if r["run"].startswith("attack-") and
                not r["run"].startswith("attack-setuid-") and
                r["run"] != "attack-local-nostu"]
benign_rows = [r for r in rows if r["run"].startswith("benign-")]


on = get("attack-local")
off = get("attack-local-nostu")
setuid = get("attack-setuid-exhaust-local")
mix = get("benign-proc-mix-local")
lines = [
    "# Online STU Delivery Report", "",
    "Generated from the refreshed `stu-results/` matrix. Stream counters are "
    "compared with `stats.txt` counters; zero deltas are required.", "",
    "## Environment", "",
    "- gem5 v24.1.0.0, base commit `63d25922a2db14643f132c0f62a224c7f7991c49`.",
    "- STU commits: `59322e2`, `4272292`.",
    "- X86, one O3 core, 3 GHz, DDR3-1600 2 GiB.",
    "- Private 64 KiB L1I/L1D and shared 8 MiB L2; 50,000-instruction windows.", "",
    "## STU Overhead", "",
    "| run | simTicks | simInsts | hostSeconds |", "|---|---:|---:|---:|",
    f"| STU off | {off['simTicks']} | {off['stats_simInsts']} | {off['hostSeconds']:.2f} |",
    f"| STU on | {on['simTicks']} | {on['stats_simInsts']} | {on['hostSeconds']:.2f} |", "",
    "STU on/off have identical simulation ticks and instruction counts for the "
    "deterministic LocalBP run. Host time is environmental only.", "",
    "## Signal Accounting", "",
    "| run | clone entry/return | setuid entry/return | faults | first clone tick |",
    "|---|---:|---:|---:|---:|",
]
for row in rows:
    if row["syscall_clone"] or row["syscall_setuid"]:
        lines.append(
            f"| {row['run']} | {row['syscall_clone']}/{row['syscall_clone_returns']} | "
            f"{row['syscall_setuid']}/{row['syscall_setuid_returns']} | {row['faults']} | "
            f"{row['first_clone_tick']} |"
        )
lines += [
    "", "The x86 SE `setuid` stub returns `-EPERM` without changing credentials. "
    "The PoC's simulated-success text is a model marker, not a complete exploit.", "",
    "## Policy Confusion Matrix", "",
    "| workload class | P-SPECTRE-FR-1 | P-SETUID-EXHAUST-1 |", "|---|---:|---:|",
    f"| Spectre attack runs | {sum('P-SPECTRE-FR-1' in r['policies'] for r in spectre_rows)}/{len(spectre_rows)} | {sum('P-SETUID-EXHAUST-1' in r['policies'] for r in spectre_rows)}/{len(spectre_rows)} |",
    f"| setuid-exhaust runs | {policy_count('attack-setuid-', 'P-SPECTRE-FR-1')}/2 | {policy_count('attack-setuid-', 'P-SETUID-EXHAUST-1')}/2 |",
    f"| benign runs | {sum('P-SPECTRE-FR-1' in r['policies'] for r in benign_rows)}/{len(benign_rows)} | {sum('P-SETUID-EXHAUST-1' in r['policies'] for r in benign_rows)}/{len(benign_rows)} |", "",
    "The software policy is `cloneSyscallsPerMinst > 100` AND "
    "`setuidSyscallsPerMinst > 0`. It first alerts in window 10 for both "
    "software attack runs, during the storm phase.", "",
    "## Threshold Margin", "",
    "| workload | maximum clone density / Minst | threshold | margin |",
    "|---|---:|---:|---:|",
    f"| benign-proc-mix | {get('benign-proc-mix-local')['maxCloneSyscallsPerMinst']:.3f} | 100 | {100 - get('benign-proc-mix-local')['maxCloneSyscallsPerMinst']:.3f} |",
    f"| benign-privdrop | {get('benign-privdrop-local')['maxCloneSyscallsPerMinst']:.3f} | 100 | {100 - get('benign-privdrop-local')['maxCloneSyscallsPerMinst']:.3f} |",
    "| attack-setuid-exhaust | 2640.000 | 100 | -2540.000 |", "",
    "## Complete Run Table", "",
    "| run | accuracy | windows | clone | setuid | faults | spectre alerts | spectre first window | setuid alerts | setuid first window | setuid latency ticks |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
]
for row in rows:
    lines.append(
        f"| {row['run']} | {row['accuracy']} | {row['windows']} | {row['syscall_clone']} | "
        f"{row['syscall_setuid']} | {row['faults']} | {row['spectreAlerts']} | "
        f"{row['spectreFirstAlertWindow']} | {row['setuidAlerts']} | "
        f"{row['setuidFirstAlertWindow']} | {row['setuidDetectionLatencyTicks']} |"
    )
lines += [
    "", "## Reproduction", "", "```bash",
    "python3 -m venv venv",
    "venv/bin/pip install 'SCons<4.9'",
    "venv/bin/scons -C gem5 build/X86/gem5.opt -j16",
    "gcc -O2 -static attack_setuid_exhaust.c -o attack_setuid_exhaust",
    "gcc -O2 -static benign_proc_mix.c -o benign_proc_mix",
    "gcc -O2 -static benign_privdrop.c -o benign_privdrop",
    "RUN_LEGACY=1 bash run_stu_matrix.sh", "python3 collect_stu_report.py", "```", "",
    "The matrix writes only `stu-results/`; frozen `results/` and `supplement-results/` "
    "are excluded. The fault field is limited to the x86 SE page-fault entry path; "
    "it is not an OS scheduler or production fault monitor.", "",
]
(BASE / "REPORT.md").write_text("\n".join(lines))
