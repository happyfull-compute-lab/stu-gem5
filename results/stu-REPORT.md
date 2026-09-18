# Online STU Delivery Report

Generated from the refreshed `stu-results/` matrix. Stream counters are compared with `stats.txt` counters; zero deltas are required.

## Environment

- gem5 v24.1.0.0, base commit `63d25922a2db14643f132c0f62a224c7f7991c49`.
- STU commits: `59322e2`, `4272292`.
- X86, one O3 core, 3 GHz, DDR3-1600 2 GiB.
- Private 64 KiB L1I/L1D and shared 8 MiB L2; 50,000-instruction windows.

## STU Overhead

| run | simTicks | simInsts | hostSeconds |
|---|---:|---:|---:|
| STU off | 2142358164 | 2336530 | 12.74 |
| STU on | 2142358164 | 2336530 | 10.54 |

STU on/off have identical simulation ticks and instruction counts for the deterministic LocalBP run. Host time is environmental only.

## Signal Accounting

| run | clone entry/return | setuid entry/return | faults | first clone tick |
|---|---:|---:|---:|---:|
| attack-setuid-exhaust-local | 40000/40000 | 40/40 | 0 | 41232393 |
| attack-setuid-exhaust-tournament | 40000/40000 | 40/40 | 0 | 41222736 |
| benign-privdrop-local | 240/240 | 5/5 | 0 | 44130492 |
| benign-privdrop-tournament | 240/240 | 5/5 | 0 | 44044911 |
| benign-proc-mix-local | 8/8 | 0/0 | 0 | 38346948 |
| benign-proc-mix-tournament | 8/8 | 0/0 | 0 | 38226402 |

The x86 SE `setuid` stub returns `-EPERM` without changing credentials. The PoC's simulated-success text is a model marker, not a complete exploit.

## Policy Confusion Matrix

| workload class | P-SPECTRE-FR-1 | P-SETUID-EXHAUST-1 |
|---|---:|---:|
| Spectre attack runs | 11/11 | 0/11 |
| setuid-exhaust runs | 0/2 | 2/2 |
| benign runs | 0/12 | 0/12 |

The software policy is `cloneSyscallsPerMinst > 100` AND `setuidSyscallsPerMinst > 0`. It first alerts in window 10 for both software attack runs, during the storm phase.

## Threshold Margin

| workload | maximum clone density / Minst | threshold | margin |
|---|---:|---:|---:|
| benign-proc-mix | 222.259 | 100 | -122.259 |
| benign-privdrop | 80.000 | 100 | 20.000 |
| attack-setuid-exhaust | 2640.000 | 100 | -2540.000 |

## Complete Run Table

| run | accuracy | windows | clone | setuid | faults | spectre alerts | spectre first window | setuid alerts | setuid first window | setuid latency ticks |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| attack-bimode | 8/8 | 47 | 0 | 0 | 0 | 44 | 2 | 0 | None | None |
| attack-jitter-seed1 | 8/8 | 63 | 0 | 0 | 0 | 60 | 2 | 0 | None | None |
| attack-jitter-seed2 | 8/8 | 64 | 0 | 0 | 0 | 61 | 2 | 0 | None | None |
| attack-jitter-seed3 | 8/8 | 63 | 0 | 0 | 0 | 59 | 2 | 0 | None | None |
| attack-jitter-seed4 | 8/8 | 65 | 0 | 0 | 0 | 61 | 2 | 0 | None | None |
| attack-jitter-seed5 | 8/8 | 65 | 0 | 0 | 0 | 62 | 2 | 0 | None | None |
| attack-local | 8/8 | 47 | 0 | 0 | 0 | 44 | 2 | 0 | None | None |
| attack-local-nostu | 8/8 | 0 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| attack-local-window200k | 8/8 | 12 | 0 | 0 | 0 | 11 | 1 | 0 | None | None |
| attack-local-window50k | 8/8 | 47 | 0 | 0 | 0 | 44 | 2 | 0 | None | None |
| attack-ltage | 2/8 | 47 | 0 | 0 | 0 | 44 | 2 | 0 | None | None |
| attack-setuid-exhaust-local | n/a | 306 | 40000 | 40 | 0 | 0 | None | 2 | 10 | 64469466 |
| attack-setuid-exhaust-tournament | n/a | 306 | 40000 | 40 | 0 | 0 | None | 2 | 10 | 60062211 |
| attack-tournament | 4/8 | 47 | 0 | 0 | 0 | 44 | 2 | 0 | None | None |
| benign-cache-local | n/a | 1083 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-cache-tournament | n/a | 1083 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-compute-local | n/a | 55 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-compute-tournament | n/a | 55 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-flush-local | n/a | 80 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-flush-tournament | n/a | 80 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-privdrop-local | n/a | 83 | 240 | 5 | 0 | 0 | None | 0 | None | None |
| benign-privdrop-tournament | n/a | 83 | 240 | 5 | 0 | 0 | None | 0 | None | None |
| benign-proc-mix-local | n/a | 3 | 8 | 0 | 0 | 0 | None | 0 | None | None |
| benign-proc-mix-tournament | n/a | 3 | 8 | 0 | 0 | 0 | None | 0 | None | None |
| benign-syscall-local | n/a | 19 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-syscall-tournament | n/a | 19 | 0 | 0 | 0 | 0 | None | 0 | None | None |

## Reproduction

```bash
python3 -m venv venv
venv/bin/pip install 'SCons<4.9'
venv/bin/scons -C gem5 build/X86/gem5.opt -j16
gcc -O2 -static attack_setuid_exhaust.c -o attack_setuid_exhaust
gcc -O2 -static benign_proc_mix.c -o benign_proc_mix
gcc -O2 -static benign_privdrop.c -o benign_privdrop
RUN_LEGACY=1 bash run_stu_matrix.sh
python3 collect_stu_report.py
```

The matrix writes only `stu-results/`; frozen `results/` and `supplement-results/` are excluded. The fault field is limited to the x86 SE page-fault entry path; it is not an OS scheduler or production fault monitor.
