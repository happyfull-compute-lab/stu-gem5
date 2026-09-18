# STU-gem5: Security Telemetry Unit Prototype on gem5

This repository contains a Security Telemetry Unit (STU) prototype built on
the gem5 simulator. The STU is a bypass-probe-based on-chip-style component:
it counts security-relevant runtime events on the CPU, cache, and syscall
paths, aggregates them into fixed-size sliding windows of committed
instructions, and streams one JSON summary record per window to a file. An
independent host-side monitor process reads the stream and evaluates every
record against all detection policies described in an external policy file.
Attaching the STU does not alter simulated timing: cycle counts and
instruction counts are bit-identical with the STU attached or detached.

Two attacks and seven benign workloads are included, together with the full
experiment matrix runner and result summaries.

## The Two Attacks

### Spectre v1 Flush+Reload (`spectre_v1_fr.c`)

A transient-execution cache side-channel attack. The program contains a
`noinline` victim function guarded by a bounds check on a volatile size
variable. A training loop calls the victim 5 times with in-bounds indices,
then once with an out-of-bounds index; while the branch predictor still
expects the trained direction, the processor transiently executes a
dependent load whose address depends on a secret byte, touching one of 256
cache-line-aligned probe-array lines. Before each attempt every probe line
is evicted with `clflush`; after the transient window the program times a
pseudo-random-ordered reload sweep over all 256 lines, and the line whose
reload became fast reveals the secret byte. The program first runs a
calibration pass to set the hit/miss latency threshold, then recovers an
8-byte secret and reports per-byte results and overall accuracy.

Optional jitter arguments (`8 10 0 <seed>`) insert between 0 and 31 extra
training calls before each attack round, producing distinct execution
streams under a fixed configuration.

### setuid exhaustion (`attack_setuid_exhaust.c`)

A RageAgainstTheCage-style privilege-escalation behavior pattern. The
program issues 40,000 `clone()` calls in a storm, performs one `setuid()`
probe during the storm, then performs the remaining `setuid()` calls after
it. Under gem5 syscall-emulation mode the x86 SE `setuid` handler is a stub
that returns `-EPERM` without touching any credentials; the program counts
the failing calls and reports a model-level marker. The clone calls are
likewise rejected by the simulator; the syscall-entry events are what the
telemetry observes.

Both attacks operate on fixed simulated data. No real credentials or host
resources are involved.

## Benign Workloads

| Workload | Behavior |
|---|---|
| `benign_compute` | FNV-style hash loop, register-resident |
| `benign_cache` | 16 MiB array, two strided passes |
| `benign_syscall` | High-frequency `getpid()` loop |
| `benign_flush` | Legitimate `clflush` pressure (12,800 flushes) |
| `benign_proc_mix` | Sparse process creation plus syscalls |
| `benign_privdrop` | Moderate-rate process creation plus `setuid()` drops |

## Repository Layout

```
se-run.py                  gem5 SE configuration: --cpu, --bp, --stu, --window
spectre_v1_fr.c            Spectre v1 Flush+Reload PoC (jitter-capable)
attack_setuid_exhaust.c    setuid-exhaustion pattern
benign_*.c                 benign workload sources
stu/                       STU SimObject sources (readable copy)
patches/
  gem5-v24.1-timing-...    X86 timing-mode CLFLUSH backport (upstream cf949085)
  stu-probe-points.patch   STU component + probe points (applies to gem5 v24.1.0.0)
monitor/
  stu_monitor.py           independent policy-evaluating monitor process
  policy.json              dual policies: P-SPECTRE-FR-1 / P-SETUID-EXHAUST-1
run_matrix.sh              baseline attack/benign matrix (no STU)
run_stu_matrix.sh          online-detection matrix (STU + monitor)
collect_results.py         baseline result collector
collect_stu_report.py      online-detection result collector
results/                   frozen result summaries (REPORT.md + summary.csv)
```

## Frozen Configuration

| Item | Value |
|---|---|
| gem5 release | `v24.1.0.0` (base commit `63d25922`) |
| ISA / CPU | X86, one O3 core, 3 GHz |
| Branch predictors | LocalBP / TournamentBP / LTAGE / BiModeBP via `--bp` |
| Caches | classic private 64 KiB L1I/L1D + shared 8 MiB L2 |
| Memory | DDR3-1600, 2 GiB |
| Workload build | GCC `-O2 -static` |
| Default window | 50,000 committed instructions |

## Build

```bash
git clone https://github.com/gem5/gem5 && git -C gem5 checkout v24.1.0.0
git -C gem5 apply ../patches/gem5-v24.1-timing-clflush-mode.patch
git -C gem5 apply ../patches/stu-probe-points.patch
python3 -m venv venv && venv/bin/pip install 'SCons<4.9'
venv/bin/scons -C gem5 build/X86/gem5.opt -j"$(nproc)"
make
```

Run commands from the repository root; the scripts use local
`BinaryResource` paths and expect the gem5 tree checked out next to this
repository.

## Quick Checks

```bash
make flush-check     # clflush hit/miss latency separation (expect ratio >= 3x)
make spectre-check   # expect accuracy=8/8 under O3
```

## Online Detection

```bash
bash run_stu_matrix.sh            # software-attack + benign-privdrop runs
RUN_LEGACY=1 bash run_stu_matrix.sh   # full matrix incl. Spectre runs
python3 collect_stu_report.py
```

Each run directory under `stu-results/` contains the command line, console
output, gem5 stats, the per-window `stu-stream.jsonl` telemetry, and the
`monitor-alerts.jsonl` alert records. The monitor runs concurrently with the
simulation and terminates when the stream is complete.

The two policies in `monitor/policy.json`:

```
P-SPECTRE-FR-1:      cleanInvalidPerMinst > 5000 AND squashedIssuedPerMinst > 1000
P-SETUID-EXHAUST-1:  cloneSyscallsPerMinst > 100 AND setuidSyscallsPerMinst > 0
```

## Results Summary

Detection results over the full matrix (details in `results/stu-REPORT.md`):

| Workload class | P-SPECTRE-FR-1 | P-SETUID-EXHAUST-1 |
|---|---:|---:|
| Spectre attack runs (11) | 11 detected | 0 false positives |
| setuid-exhaustion runs (2) | 0 false positives | 2 detected |
| Benign runs (12) | 0 false positives | 0 false positives |

- Detection latency: 14.3–16.6 us (Spectre) and 60.1–64.5 us (setuid) with
  50k-instruction windows; 261.5 us with 200k-instruction windows.
- Zero timing disturbance: simTicks 2,142,358,164 bit-identical with the
  STU on and off for the deterministic LocalBP attack run.
- STU window counters match gem5's own statistics field-for-field.

`results/baseline-REPORT.md` and `results/supplement-REPORT.md` contain the
offline signal-separation analysis (branch-predictor sensitivity, jitter
seeds, benign clflush pressure) that motivated the two policies.

## Measurement Conventions

```
misprediction rate     = branchPred.condIncorrect / branchPred.condPredicted
squash events /Minst   = commit.branchMispredicts / simInsts * 1e6
squashed instrs /Minst = squashedInstsIssued / simInsts * 1e6
flush traffic          = l2bus.transDist::CleanInvalidReq  (x86 CLFLUSH)
```

Do not compare telemetry collected with different branch predictors.

## License

MIT. Copyright (c) 2026 [HappyFull Compute Lab](https://github.com/happyfull-compute-lab)
(https://happyfull.tech). The patches modify gem5 (BSD-3-Clause licensed) and
remain compatible with upstream relicensing terms.
