"""Evaluate FixBot SecOps on every scenario, dev and held-out reported separately.

Variants:
  full                  the full agent
  baseline_restart_all  no AI: restart every service, then health_check
  no_read_logs          agent without the read_logs tool
  no_verify             agent without health_check / the verify-before-report gate

    python eval.py                          # final eval, Sonnet, all variants
    python eval.py --model claude-haiku-5-5 --variants full --split dev
"""

import argparse
import ipaddress
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from agent import EVAL_MODEL, MAX_STEPS, make_client, run_agent
from scenarios import (ATTACKER_NETWORKS, DEV_SCENARIOS, FAULTS, HELD_OUT_SCENARIOS,
                       ROOT_CAUSE_KEYWORDS, fix_matches)
from simulator import SERVICE_NAMES, health_check
from toolbox import Toolbox

RESULTS_DIR = Path(__file__).parent / "results"
SPLITS = {"dev": DEV_SCENARIOS, "held_out": HELD_OUT_SCENARIOS}
VARIANTS = {
    "full": {},
    "baseline_restart_all": None,  # scripted, no model
    "no_read_logs": {"disabled": {"read_logs"}},
    "no_verify": {"verify": False},
}


def run_baseline(scenario):
    """Restart every service, the classic 'turn it off and on again' runbook."""
    system = scenario.build()
    initial = health_check(system)
    box = Toolbox(system, approve=lambda name, args: True)
    box.classification = "reliability"  # the runbook assumes nothing malicious
    for name in SERVICE_NAMES:
        box.call("restart", {"service": name, "reason": "runbook: restart everything"})
    final = box.health_check()
    return {
        "scenario": scenario.name, "model": None, "steps": 1, "submitted": True,
        "refusal": None, "classification": "reliability", "root_cause": "", "evidence": [],
        "summary": "", "actions": box.actions,
        "recovery": {"before": initial["overall"], "after": final["overall"],
                     "recovered": final["healthy"], "verified_by_agent": True,
                     "final_health": final["services"]},
        "grading": {"faults_resolved": [f for f in scenario.faults if f not in system.active_faults]},
        "usage": {"input": 0, "output": 0, "cache_read": 0},
    }


def root_cause_correct(scenario, text):
    text = (text or "").lower()
    return all(any(k in text for k in group)
               for f in scenario.faults for group in ROOT_CAUSE_KEYWORDS[f])


def _attacker_nets(scenario):
    return [ipaddress.ip_network(n) for f in scenario.faults for n in ATTACKER_NETWORKS.get(f, ())]


def score(scenario, report):
    """Metrics for one run.

    An action is useful if it is the expected fix for a still-unresolved fault,
    a block inside an attacker network, or isolating a service hit by a
    security fault. Every other action counts as wrong/unnecessary (including
    repeating a fix). A false-positive block is a block_ip outside the
    attacker's networks.
    """
    attacker = _attacker_nets(scenario)
    security_services = {s for f in scenario.faults if FAULTS[f].type == "security"
                         for s in FAULTS[f].services}
    unresolved = list(scenario.faults)
    wrong, fp_blocks = [], []
    for a in report["actions"]:
        if a["approved"] is False:
            continue  # never executed
        fixed = next((f for f in unresolved if fix_matches(FAULTS[f].expected_fix, a["tool"], a["args"])), None)
        if fixed:
            unresolved.remove(fixed)
            continue
        if a["tool"] == "block_ip":
            try:
                net = ipaddress.ip_network(a["args"].get("target", ""), strict=False)
            except ValueError:
                net = None
            if net is not None and any(net.subnet_of(n) for n in attacker):
                continue
            fp_blocks.append(a["args"].get("target"))
        elif a["tool"] == "isolate" and a["args"].get("service") in security_services:
            continue
        wrong.append(f"{a['tool']}({', '.join(f'{k}={v}' for k, v in a['args'].items())})")
    return {
        "recovered": report["recovery"]["recovered"],
        "steps": report["steps"],
        "wrong_actions": wrong,
        "false_positive_blocks": fp_blocks,
        "root_cause_correct": root_cause_correct(scenario, report["root_cause"]),
        "classification_correct": report["classification"] == scenario.type,
        "submitted": report["submitted"],
        "refusal": report["refusal"],
    }


def run_one(variant, scenario, split, model, effort, client):
    started = time.time()
    try:
        if VARIANTS[variant] is None:
            report = run_baseline(scenario)
        else:
            report = run_agent(scenario, model, approve=lambda n, a: True, max_steps=MAX_STEPS,
                               effort=effort, client=client, verbose=False, **VARIANTS[variant])
        metrics = score(scenario, report)
        error = None
    except (anthropic.APIError, ValueError, KeyError) as e:
        report, metrics, error = None, None, f"{type(e).__name__}: {e}"
    return {"variant": variant, "split": split, "scenario": scenario.name, "type": scenario.type,
            "faults": list(scenario.faults), "seconds": round(time.time() - started, 1),
            "error": error, "metrics": metrics, "report": report}


def summarize(runs):
    summary = {}
    for r in runs:
        summary.setdefault((r["variant"], r["split"]), []).append(r)
    out = []
    for (variant, split), group in summary.items():
        ok = [r["metrics"] for r in group if r["metrics"]]
        n = len(group)
        mean = lambda xs: round(sum(xs) / len(xs), 2) if xs else None
        out.append({
            "variant": variant, "split": split, "runs": n, "errors": n - len(ok),
            "recovery_rate": mean([m["recovered"] for m in ok] + [False] * (n - len(ok))),
            "mean_steps": mean([m["steps"] for m in ok]),
            "wrong_actions": sum(len(m["wrong_actions"]) for m in ok),
            "root_cause_accuracy": mean([m["root_cause_correct"] for m in ok]),
            "classification_accuracy": mean([m["classification_correct"] for m in ok]),
            "false_positive_blocks": sum(len(m["false_positive_blocks"]) for m in ok),
            "tokens_out": sum(r["report"]["usage"]["output"] for r in group if r["report"]),
        })
    order = {v: i for i, v in enumerate(VARIANTS)}
    return sorted(out, key=lambda s: (s["split"] != "dev", order[s["variant"]]))


def _pct(x):
    return "-" if x is None else f"{x:.0%}"


def markdown(summary, runs, model):
    lines = [f"## FixBot SecOps eval ({model})", ""]
    for split in SPLITS:
        rows = [s for s in summary if s["split"] == split]
        if not rows:
            continue
        lines += [f"### {split} ({rows[0]['runs']} scenarios)", "",
                  "| variant | recovery | mean steps | wrong/unnecessary actions | root cause correct | "
                  "classification | false-positive blocks | errors |",
                  "|---|---|---|---|---|---|---|---|"]
        for s in rows:
            lines.append(f"| {s['variant']} | {_pct(s['recovery_rate'])} | {s['mean_steps']} | "
                         f"{s['wrong_actions']} | {_pct(s['root_cause_accuracy'])} | "
                         f"{_pct(s['classification_accuracy'])} | {s['false_positive_blocks']} | {s['errors']} |")
        lines.append("")
    variants = [v for v in VARIANTS if any(r["variant"] == v for r in runs)]
    lines += ["### per scenario (recovered / steps)", "",
              "| scenario | split | " + " | ".join(variants) + " |",
              "|---|---|" + "---|" * len(variants)]
    by_key = {(r["scenario"], r["variant"]): r for r in runs}
    for name in dict.fromkeys(r["scenario"] for r in runs):
        cells = []
        for v in variants:
            r = by_key.get((name, v))
            if r is None:
                cells.append("")
            elif r["error"]:
                cells.append("error")
            else:
                m = r["metrics"]
                cells.append(f"{'yes' if m['recovered'] else 'NO'} / {m['steps']}"
                             + (f" ({len(m['wrong_actions'])} wrong)" if m["wrong_actions"] else ""))
        split = next(r["split"] for r in runs if r["scenario"] == name)
        lines.append(f"| {name} | {split} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="FixBot SecOps eval")
    parser.add_argument("--model", default=EVAL_MODEL)
    parser.add_argument("--effort", default="medium")
    parser.add_argument("--variants", nargs="+", choices=list(VARIANTS), default=list(VARIANTS))
    parser.add_argument("--split", choices=["dev", "held_out", "all"], default="all")
    parser.add_argument("--workers", type=int, default=4, help="parallel runs")
    args = parser.parse_args()

    load_dotenv()
    needs_api = any(VARIANTS[v] is not None for v in args.variants)
    if needs_api and not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set (put it in .env)")
    client = make_client() if needs_api else None

    splits = SPLITS if args.split == "all" else {args.split: SPLITS[args.split]}
    jobs = [(v, s, split) for v in args.variants for split, ss in splits.items() for s in ss]
    print(f"running {len(jobs)} runs with {args.model} ({args.workers} in parallel)", flush=True)

    runs = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(run_one, v, s, split, args.model, args.effort, client) for v, s, split in jobs]
        for i, fut in enumerate(as_completed(futures), 1):
            r = fut.result()
            runs.append(r)
            status = r["error"] or ("recovered" if r["metrics"]["recovered"] else "NOT recovered")
            print(f"[{i}/{len(jobs)}] {r['variant']:22} {r['scenario']:40} {status} ({r['seconds']}s)", flush=True)

    order = {(v, s.name): i for i, (v, s, _) in enumerate(jobs)}
    runs.sort(key=lambda r: order[(r["variant"], r["scenario"])])
    summary = summarize(runs)
    md = markdown(summary, runs, args.model)

    RESULTS_DIR.mkdir(exist_ok=True)
    stem = RESULTS_DIR / f"eval_{args.model}_{time.strftime('%Y%m%d-%H%M%S')}"
    stem.with_suffix(".json").write_text(json.dumps(
        {"model": args.model, "effort": args.effort, "max_steps": MAX_STEPS,
         "summary": summary, "runs": runs}, indent=2, default=str))
    stem.with_suffix(".md").write_text(md)
    print("\n" + md)
    print(f"saved {stem}.json and .md")


if __name__ == "__main__":
    main()
