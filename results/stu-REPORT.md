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
| benign runs | 0/18 | 0/18 |

The software policy is `cloneSyscallsPerMinst > 100` AND `setuidSyscallsPerMinst > 0`. It first alerts in window 10 for both software attack runs, during the storm phase.

## E1 Realistic Application Control

The added workload is a statically linked file-indexing application. It recursively scans `/usr/include` to depth two and performs `lstat`, `opendir/readdir`, `open`, `read`, and `close` operations. It processed 2,714 files and 6,569,397 bytes per run. The host tools suggested for this experiment were not used because `/bin/ls`, `find`, `grep`, `sort`, and `tar` are dynamically linked host binaries and are not portable SE workloads.

| BP | repetitions | squashedIssued peak mean / Minst | peak | CleanInvalidReq peak / Minst | policy alerts |
|---|---:|---:|---:|---:|---:|
| local | 3 | 5940.00 | 5940.00 | 0.00 | 0 |
| tournament | 3 | 6400.00 | 6400.00 | 0.00 | 0 |

The file-index workload exceeds the standalone wrong-path threshold (`squashedIssued > 1,000/Minst`) but generates no cache-clean traffic. The joint Spectre policy therefore produces zero alerts in all six runs. This is a realistic application-style control, not a SPEC CPU benchmark.

## E2 Numeric Audit

For `attack-local`, `simFreq=1,000,000,000,000 ticks/s`, `simTicks=2,142,358,164`, and `simInsts=2,336,530`. Simulated time is `0.002142358164 s`; equivalent 3 GHz CPU cycles are `6,427,074.492`; instructions per equivalent CPU cycle are `0.363545`. The refreshed E2 baseline first alerts in window 2 at tick `58,309,965`. The PoC first-success marker is `byte=0`, with guest TSC reported separately; guest TSC is not comparable to gem5 ticks.

## E3 Adaptive Variants

| run | change | accuracy | first success byte | first alert window | max flush / Minst | max squash / Minst |
|---|---|---:|---:|---:|---:|---:|
| e2-baseline | original | 8/8 | 0 | 2 | 11500.00 | 10420.00 |
| e3-sparse-flush | flush stride 4 | 0/8 | none | none | 3860.00 | 13462.90 |
| e3-long-gap | attack gap 2000 | 8/8 | 0 | 2 | 8720.00 | 10340.00 |

The sparse-flush variant produced `0/8` and no alert, documenting a known false-negative adaptive case. The longer-gap variant retained `8/8` and was detected.

## E4 Holdout and Limits

The policies were locked before the E2/E3 runs. Existing LTAGE/BiModeBP, jitter, file-index, and adaptive runs are treated as held-out families. The fixed policy remains zero-FP on benign groups; sparse flush is the known false-negative case. BusyBox `sort` aborted on unimplemented `setgid(#106)`, and the pthread workload created zero threads because SE had no spare thread context. Real `make -j` and scheduler experiments require FS and a separate baseline.

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
| benign-file-index-local | n/a | 838 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-file-index-local-r2 | n/a | 838 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-file-index-local-r3 | n/a | 838 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-file-index-tournament | n/a | 838 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-file-index-tournament-r2 | n/a | 838 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-file-index-tournament-r3 | n/a | 838 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-flush-local | n/a | 80 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-flush-tournament | n/a | 80 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-privdrop-local | n/a | 83 | 240 | 5 | 0 | 0 | None | 0 | None | None |
| benign-privdrop-tournament | n/a | 83 | 240 | 5 | 0 | 0 | None | 0 | None | None |
| benign-proc-mix-local | n/a | 3 | 8 | 0 | 0 | 0 | None | 0 | None | None |
| benign-proc-mix-tournament | n/a | 3 | 8 | 0 | 0 | 0 | None | 0 | None | None |
| benign-syscall-local | n/a | 19 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| benign-syscall-tournament | n/a | 19 | 0 | 0 | 0 | 0 | None | 0 | None | None |
| e2-baseline | 8/8 | 64 | 0 | 0 | 0 | 61 | 2 | 0 | None | None |
| e3-long-gap | 8/8 | 96 | 0 | 0 | 0 | 78 | 2 | 0 | None | None |
| e3-sparse-flush | 0/8 | 52 | 0 | 0 | 0 | 0 | None | 0 | None | None |

## Reproduction

```bash
python3 -m venv /tmp/opencode/gem5-venv
/tmp/opencode/gem5-venv/bin/pip install 'SCons<4.9'
/tmp/opencode/gem5-venv/bin/scons -C gem5 build/X86/gem5.opt -j16
gcc -O2 -static attack_setuid_exhaust.c -o attack_setuid_exhaust
gcc -O2 -static benign_proc_mix.c -o benign_proc_mix
gcc -O2 -static benign_privdrop.c -o benign_privdrop
RUN_LEGACY=1 bash run_stu_matrix.sh
python3 collect_stu_report.py
```

The matrix writes only `stu-results/`; frozen `results/` and `supplement-results/` are excluded. The fault field is limited to the x86 SE page-fault entry path; it is not an OS scheduler or production fault monitor.
