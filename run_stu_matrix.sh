#!/usr/bin/env bash
set -euo pipefail

gem5=gem5/build/X86/gem5.opt
root=stu-results
mkdir -p "$root"
run_legacy=${RUN_LEGACY:-0}

run_one() {
    local name=$1
    local window=$2
    shift 2
    local out="$root/$name"
    rm -rf "$out"
    mkdir -p "$out"
    printf '%q ' "$gem5" --outdir="$out" se-run.py "$@" > "$out/command.txt"
    printf '\n' >> "$out/command.txt"
    python3 monitor/stu_monitor.py --stream "$out/stu-stream.jsonl" \
        --policy monitor/policy.json --alerts "$out/monitor-alerts.jsonl" \
        --summary "$out/monitor-summary.json" --done "$out/.done" \
        > "$out/monitor.stdout" 2> "$out/monitor.stderr" &
    local monitor_pid=$!
    { time "$gem5" --outdir="$out" se-run.py "$@"; } \
        > "$out/stdout.txt" 2> "$out/stderr.txt"
    touch "$out/.done"
    wait "$monitor_pid"
    rm -f "$out/.done"
}

if [[ "$run_legacy" == 1 ]]; then
    run_one attack-local 50000 --cpu o3 --bp local --stu --window 50000 \
        --binary spectre_v1_fr 8 10
    run_one attack-tournament 50000 --cpu o3 --bp tournament --stu --window 50000 \
        --binary spectre_v1_fr 8 10
    run_one attack-ltage 50000 --cpu o3 --bp ltage --stu --window 50000 \
        --binary spectre_v1_fr 8 10
    run_one attack-bimode 50000 --cpu o3 --bp bimode --stu --window 50000 \
        --binary spectre_v1_fr 8 10
    for seed in 1 2 3 4 5; do
        run_one "attack-jitter-seed${seed}" 50000 --cpu o3 --bp local --stu \
            --window 50000 --binary spectre_v1_fr 8 10 0 "$seed"
    done
    run_one attack-local-window50k 50000 --cpu o3 --bp local --stu \
        --window 50000 --binary spectre_v1_fr 8 10
    run_one attack-local-window200k 200000 --cpu o3 --bp local --stu \
        --window 200000 --binary spectre_v1_fr 8 10
    for bp in local tournament; do
        run_one "benign-compute-${bp}" 50000 --cpu o3 --bp "$bp" --stu \
            --window 50000 --binary benign_compute
        run_one "benign-cache-${bp}" 50000 --cpu o3 --bp "$bp" --stu \
            --window 50000 --binary benign_cache
        run_one "benign-syscall-${bp}" 50000 --cpu o3 --bp "$bp" --stu \
            --window 50000 --binary benign_syscall
    done
    run_one benign-flush-local 50000 --cpu o3 --bp local --stu --window 50000 \
        --binary benign_flush
    run_one benign-flush-tournament 50000 --cpu o3 --bp tournament --stu \
        --window 50000 --binary benign_flush
fi

for bp in local tournament; do
    run_one "attack-setuid-exhaust-${bp}" 50000 --cpu o3 --bp "$bp" --stu \
        --window 50000 --binary attack_setuid_exhaust
    run_one "benign-proc-mix-${bp}" 50000 --cpu o3 --bp "$bp" --stu \
        --window 50000 --binary benign_proc_mix
    run_one "benign-privdrop-${bp}" 50000 --cpu o3 --bp "$bp" --stu \
        --window 50000 --binary benign_privdrop
done

# E1 realistic application control (static file indexer, 3 reps x 2 BPs)
for bp in local tournament; do
    run_one "benign-file-index-${bp}" 50000 --cpu o3 --bp "$bp" --stu \
        --window 50000 --binary benign_file_index /usr/include
    run_one "benign-file-index-${bp}-r2" 50000 --cpu o3 --bp "$bp" --stu \
        --window 50000 --binary benign_file_index /usr/include
    run_one "benign-file-index-${bp}-r3" 50000 --cpu o3 --bp "$bp" --stu \
        --window 50000 --binary benign_file_index /usr/include
done

# E2/E3 numeric-audit baseline and adaptive variants (jitter seed 0)
run_one e2-baseline 50000 --cpu o3 --bp local --stu --window 50000 \
    --binary spectre_v1_fr 8 10 0 0 1 0
run_one e3-sparse-flush 50000 --cpu o3 --bp local --stu --window 50000 \
    --binary spectre_v1_fr 8 10 8 0 4 0
run_one e3-long-gap 50000 --cpu o3 --bp local --stu --window 50000 \
    --binary spectre_v1_fr 8 10 0 0 1 2000
