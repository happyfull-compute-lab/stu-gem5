#!/usr/bin/env bash
set -euo pipefail

gem5=gem5/build/X86/gem5.opt

run_one() {
    local name=$1
    shift
    local out=results/$name
    mkdir -p "$out"
    printf '%q ' "$gem5" --outdir="$out" se-run.py "$@" > "$out/command.txt"
    printf '\n' >> "$out/command.txt"
    { time "$gem5" --outdir="$out" se-run.py "$@"; } \
        > "$out/stdout.txt" 2> "$out/stderr.txt"
}

run_one attack-o3-r30 --cpu o3 --binary spectre_v1_fr 8 30
run_one attack-timing --cpu timing --binary spectre_v1_fr 8 10
run_one attack-atomic --cpu atomic --binary spectre_v1_fr 8 10
run_one benign-compute --cpu o3 --binary benign_compute
run_one benign-cache --cpu o3 --binary benign_cache
run_one benign-syscall --cpu o3 --binary benign_syscall
