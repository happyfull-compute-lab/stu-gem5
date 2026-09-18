#!/usr/bin/env python3
import argparse
import json
import time
from pathlib import Path

OPS = {
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
}

parser = argparse.ArgumentParser()
parser.add_argument("--stream", type=Path, required=True)
parser.add_argument("--policy", type=Path, required=True)
parser.add_argument("--alerts", type=Path, required=True)
parser.add_argument("--summary", type=Path, required=True)
parser.add_argument("--done", type=Path, required=True)
args = parser.parse_args()

policies = json.loads(args.policy.read_text())["policies"]
seen = 0
windows = []
alerts = []

while True:
    if args.stream.exists():
        lines = args.stream.read_text().splitlines()
        for line in lines[seen:]:
            window = json.loads(line)
            windows.append(window)
            for policy in policies:
                matched = all(
                    OPS[condition["op"]](
                        window["rates"][condition["metric"]],
                        condition["value"],
                    )
                    for condition in policy["all"]
                )
                if matched:
                    alerts.append({
                        "policy_id": policy["policy_id"],
                        "window": window["window"],
                        "tick": window["end_tick"],
                        "signal": window["rates"],
                    })
        seen = len(lines)
    if args.done.exists():
        if not args.stream.exists() or seen >= len(args.stream.read_text().splitlines()):
            break
    time.sleep(0.02)

args.alerts.write_text("".join(json.dumps(alert) + "\n" for alert in alerts))
first = alerts[0] if alerts else None
first_by_policy = {}
for alert in alerts:
    first_by_policy.setdefault(alert["policy_id"], alert)
first_flush = next((w["firstFlushTick"] for w in windows if w["firstFlushTick"]), None)
first_clone = next((w["firstCloneTick"] for w in windows if w["firstCloneTick"]), None)
setuid_alert = first_by_policy.get("P-SETUID-EXHAUST-1")
summary = {
    "total_windows": len(windows),
    "alert_count": len(alerts),
    "first_alert_window": first["window"] if first else None,
    "first_alert_tick": first["tick"] if first else None,
    "first_flush_tick": first_flush,
    "detection_latency_ticks": first["tick"] - first_flush if first and first_flush else None,
    "first_alert_by_policy": {
        policy_id: alert["tick"] for policy_id, alert in first_by_policy.items()
    },
    "first_clone_tick": first_clone,
    "setuid_policy_alert_count": sum(
        alert["policy_id"] == "P-SETUID-EXHAUST-1" for alert in alerts
    ),
    "setuid_policy_first_alert_window": (
        setuid_alert["window"] if setuid_alert else None
    ),
    "setuid_policy_detection_latency_ticks": (
        setuid_alert["tick"] - first_clone
        if setuid_alert and first_clone else None
    ),
}
args.summary.write_text(json.dumps(summary, indent=2) + "\n")
