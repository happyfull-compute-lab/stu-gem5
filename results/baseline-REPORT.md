# gem5 Spectre v1 STU Baseline Results

## Environment

- gem5 release: `v24.1.0.0`
- gem5 base commit: `63d25922a2db14643f132c0f62a224c7f7991c49`
- Required backport: upstream `cf949085`, saved as
  `patches/gem5-v24.1-timing-clflush-mode.patch`
- ISA/CPU: X86, one O3 core with `LocalBP`
- Caches: classic private 64 KiB L1I/L1D and shared 8 MiB L2
- Memory/clock: DDR3-1600 2 GiB, 3 GHz
- PoC: static GCC `-O2`; `victim_function` locally compiled at O0

The backport only fixes the X86 CLFLUSH translation callback mode used by
TimingSimpleCPU. It does not modify O3 speculation or cache behavior. All
formal runs in the table were collected with the same rebuilt gem5 binary.

## Run Matrix

| run | CPU | workload | ticks | insts | mispred rate | squash/1M inst | L1D miss rate | L2 miss rate | accuracy |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| attack-o3-r10a | O3 | `spectre_v1_fr 8 10` | 2,136,635,559 | 2,330,087 | 1.1962% | 1,960.44 | 6.8915% | 96.8548% | 8/8 |
| attack-o3-r10b | O3 | `spectre_v1_fr 8 10` | 2,136,635,559 | 2,330,087 | 1.1962% | 1,960.44 | 6.8915% | 96.8548% | 8/8 |
| attack-o3-r10c | O3 | `spectre_v1_fr 8 10` | 2,136,635,559 | 2,330,087 | 1.1962% | 1,960.44 | 6.8915% | 96.8548% | 8/8 |
| attack-o3-r30 | O3 | `spectre_v1_fr 8 30` | 6,280,547,499 | 6,594,407 | 1.0057% | 1,711.00 | 7.3404% | 98.4963% | 8/8 |
| attack-timing | TimingSimpleCPU | `spectre_v1_fr 8 10` | 2,678,872,446 | 2,329,116 | n/a | n/a | 2.7167% | 96.7922% | 0/8 |
| attack-atomic | AtomicSimpleCPU | `spectre_v1_fr 8 10` | 1,543,608,513 | 2,328,876 | n/a | n/a | 2.8106% | 99.3935% | 0/8 |
| benign-compute | O3 | ALU loop, 200k iterations | 712,959,327 | 2,732,824 | 0.4401% | 241.14 | 2.0766% | 70.9854% | n/a |
| benign-cache | O3 | 16 MiB array, two 64-byte-stride passes | 14,567,357,394 | 54,133,596 | 0.0649% | 13.30 | 19.9702% | 71.2824% | n/a |
| benign-syscall | O3 | 100k `getpid()` calls | 1,345,437,549 | 932,020 | 0.0896% | 716.72 | 0.3001% | 72.5121% | n/a |

Complete metrics, including wall time, hit/miss/access counts and both squash
metrics, are in `summary.csv` and `summary.json`.

## Signal Separation

The A1 mean is identical across the three deterministic repetitions.
Compared with the largest value among the three benign workloads:

| signal | A1 mean | benign maximum | A1 / benign max |
|---|---:|---:|---:|
| conditional misprediction rate | 1.1962% | 0.4401% | 2.72x |
| branch squash events / 1M instructions | 1,960.44 | 716.72 | 2.74x |
| squashed instructions issued / 1M instructions | 7,661.52 | 763.93 | 10.03x |
| L2 demand miss rate | 96.8548% | 72.5121% | 1.34x |

Flush traffic is the strongest discriminator. The actual field is
`board.cache_hierarchy.l2bus.transDist::CleanInvalidReq`: A1 has 22,900
requests and A2 has 68,660, while all C workloads have zero. This gives exact
separation for this test set but should be combined with mispredict/squash
signals because benign software may legitimately execute cache flushes.

L1D miss rate is not a safe standalone detector. `benign-cache` reaches
19.9702%, which is higher than A1's 6.8915%. The useful detection rule is a
combination of high flush density, elevated branch mispredictions, and elevated
wrong-path instruction activity.

## Negative Controls

- TimingSimpleCPU: `accuracy=0/8`
- AtomicSimpleCPU: `accuracy=0/8`

Both execute the same binary and arguments as A1. The lack of leakage on both
in-order/non-speculative models supports attribution to O3 speculative
execution rather than an architectural read or scoring shortcut.

AtomicSimpleCPU reports nearly identical calibrated hit/miss values because
atomic accesses do not model timing cache latency in the same way. It remains
a valid no-speculation output control, but its timing numbers should not be
compared with timing-mode CPUs.

## Transient Window

The representative victim PCs are:

```text
0x401ac8  bounds branch
0x401ad8  source load array1[x]
0x401aea  dependent probe load probe[value * 512]
```

For dynamic branch sequence 748984, the wrong-path victim body spans sequence
numbers 748985 through 749000: 16 x86 micro-ops. The branch entered the ROB at
tick 242,710,380 and was identified as mispredicted at tick 242,759,664, a
49,284-tick interval, approximately 148 cycles at 3 GHz. The source and probe
loads were marked ready before the squash. They are later removed rather than
architecturally committed. See `evidence/transient-window.txt`.

## Transient Cache Fill

The correlated trace directly links dynamic probe load sequence 296003 to
secret byte `T`:

```text
probe physical address = 0xad000 + 84 * 512 = 0xb7800
load PC 0x401aea issues ReadReq [b7800:b7800]
the instruction is squashed
L2 receives ReadResp and fills block 0xb7800
L1D receives ReadResp and fills block 0xb7800
```

This is direct evidence that the wrong-path instruction's architectural effect
is discarded while its cache fill survives. See `evidence/transient-fill.txt`
and the complete `trace-correlated/trace-correlated.log.gz`.

## CLFLUSH Packet Type

The exact classic-cache request command is `CleanInvalidReq`, marked `PoC`.
The response is `CleanInvalidResp`. When flushing a dirty line, L1D first
creates and sends `WriteClean`, then completes the invalidation. The complete
minimal path is in `evidence/clflush-packet.txt`.

For STU instrumentation, `CleanInvalidReq` on the L1D/L2 path is the direct
flush-event signal. Cache block updates provide the fill signal, and O3's
branch-mispredict/squash probes provide the speculation signal.

## Actual Stats Fields

```text
simTicks
simSeconds
simInsts
board.processor.cores.core.branchPred.condPredicted
board.processor.cores.core.branchPred.condIncorrect
board.processor.cores.core.commit.branchMispredicts
board.processor.cores.core.squashedInstsIssued
board.cache_hierarchy.l1dcaches.demandHits::total
board.cache_hierarchy.l1dcaches.demandMisses::total
board.cache_hierarchy.l1dcaches.demandAccesses::total
board.cache_hierarchy.l2cache.demandHits::total
board.cache_hierarchy.l2cache.demandMisses::total
board.cache_hierarchy.l2cache.demandAccesses::total
board.cache_hierarchy.l2bus.transDist::CleanInvalidReq
```

Definitions used:

```text
mispredict rate = condIncorrect / condPredicted
squash events / Minst = commit.branchMispredicts / simInsts * 1,000,000
squashed issued / Minst = squashedInstsIssued / simInsts * 1,000,000
cache miss rate = demandMisses / (demandHits + demandMisses)
```

## Problems Encountered

1. gem5 v24.1 has no `SEBoard` class; `SimpleBoard` provides the required SE
   workload API in this release.
2. Placing `sink` and `probe[0]` in one cache line caused a false reload hit.
   The probe is now page aligned.
3. The default TournamentBP generated unrelated wrong-path pressure; LTAGE
   could learn the fixed attack rhythm. LocalBP produced stable 8/8 leakage.
4. GCC code generation affected whether the dependent load issued. The program
   remains globally `-O2`; only `victim_function` uses GCC's local O0 attribute.
5. gem5 v24.1 TimingSimpleCPU asserted on X86 CLFLUSH because its translation
   callback changed Write mode to Read. The exact upstream fix, commit
   `cf949085`, was backported and stored in
   `patches/gem5-v24.1-timing-clflush-mode.patch`. The original failed run is
   retained under `attack-timing-failed-prepatch`.

## Artifact Layout

- Formal runs: one directory per row in the table
- Full traces: `trace-o3`, `trace-cache`, `trace-correlated`, `trace-flush`
- Extracted evidence: `evidence/`
- Machine-readable tables: `summary.csv`, `summary.json`
- Human-readable table: `summary.md`
- Pre-patch A runs and failed Timing run: `prepatch/` and
  `attack-timing-failed-prepatch/`; these are not included in formal metrics
