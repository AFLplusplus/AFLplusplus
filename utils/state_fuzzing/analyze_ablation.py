#!/usr/bin/env python3
"""Summarise a state fuzzing ablation run produced by run_ablation.sh.

The headline is source coverage, measured by replaying each arm's final corpus
through one coverage build (run_ablation.sh -c/-s). That is the only unit the
arms share. edges_found is what the fuzzer counted in its own coverage map, and
that map is not the same object in two binaries: arms C and E run a different
target, and folding a state hash into the edge index changes what one edge is.
It is reported for context and flagged, never used for a contrast when coverage
data is present.

Reports three normalised numbers, not one:

  per wall-clock second   what you get for an hour of machine time
  per execution           whether the executor or the search improved
  per operation           the only axis that stays comparable once one input
                          byte can drive a thousand target operations

The per-operation axis needs the harness to write its total operation count to
the file named by AFL_OPS_COUNTER_FILE; run_ablation.sh sets that variable. It
is reported as n/a when the harness does not cooperate.

"States found" is deliberately not reported as a result. A broken observer that
hashes the clock finds millions of them.
"""

import json
import os
import statistics
import sys

ARMS = ["A", "B", "C", "D", "E"]

ARM_DESC = {
    "A": "baseline: normal coverage, normal executor",
    "B": "improved executor",
    "C": "improved executor + record mutator",
    "D": "improved executor + state signal",
    "E": "improved executor + records + state",
}

# Differences that the experiment exists to produce.
CONTRASTS = [
    ("B", "A", "engineering wins"),
    ("D", "B", "state wins"),
    ("C", "B", "record mutator wins"),
    ("E", "D", "records on top of state"),
]

# Reported for context, never as the headline.
CONTEXT_KEYS = [
    "target_time_pct",
    "slow_path_pct",
    "cov_edges_found",
    "hw_only_saves",
    "plugin_ops_avg",
    "shelf_members",
]


def read_stats(path):
    stats = {}
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                stats[key.strip()] = val.strip()
    except OSError:
        return None
    return stats


def as_float(stats, key, default=0.0):
    raw = stats.get(key)
    if raw is None:
        return default
    try:
        return float(raw.rstrip("%"))
    except ValueError:
        return default


def find_runs(root, arm):
    """Every fuzzer_stats under <root>/<arm>/, one per repetition."""
    runs = []
    arm_dir = os.path.join(root, arm)
    if not os.path.isdir(arm_dir):
        return runs
    for rep in sorted(os.listdir(arm_dir)):
        rep_dir = os.path.join(arm_dir, rep)
        if not os.path.isdir(rep_dir):
            continue
        # afl-fuzz puts fuzzer_stats in <out>/default/ unless -M/-S is used.
        for cand in (
            os.path.join(rep_dir, "default", "fuzzer_stats"),
            os.path.join(rep_dir, "fuzzer_stats"),
        ):
            stats = read_stats(cand)
            if stats:
                stats["_ops"] = read_ops(os.path.join(rep_dir, "ops_count"))
                stats["_cov"] = read_cov(rep_dir)
                runs.append(stats)
                break
    return runs


def read_cov(rep_dir):
    """Coverage summary written by replay_coverage.sh, or None."""
    path = os.path.join(rep_dir, "cov", "summary.json")
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def read_ops(path):
    try:
        with open(path, "r") as fh:
            return float(fh.read().strip())
    except (OSError, ValueError):
        return None


def summarise(runs):
    """Median of the three normalised rates, plus the raw result."""
    if not runs:
        return None

    edges, per_sec, per_exec, per_op = [], [], [], []
    regions, lines, denoms = [], [], set()

    for st in runs:
        found = as_float(st, "edges_found")
        secs = max(as_float(st, "run_time"), 1.0)
        execs = max(as_float(st, "execs_done"), 1.0)
        edges.append(found)
        ops = st.get("_ops")
        cov = st.get("_cov")

        # Normalise the fair metric when it exists, the fuzzer's own count when
        # it does not - and say which, rather than silently mixing them.
        primary = found
        if cov:
            primary = cov["regions_covered"]
            regions.append(cov["regions_covered"])
            lines.append(cov["lines_covered"])
            denoms.add((cov["regions_total"], cov["lines_total"]))

        per_sec.append(primary / secs)
        per_exec.append(primary / execs * 1e6)
        if ops:
            per_op.append(primary / max(ops, 1.0) * 1e6)

    return {
        "n": len(runs),
        "edges": statistics.median(edges),
        "edges_min": min(edges),
        "edges_max": max(edges),
        "regions": statistics.median(regions) if regions else None,
        "regions_min": min(regions) if regions else None,
        "regions_max": max(regions) if regions else None,
        "lines": statistics.median(lines) if lines else None,
        "denoms": denoms,
        "per_sec": statistics.median(per_sec),
        "per_exec": statistics.median(per_exec),
        "per_op": statistics.median(per_op) if per_op else None,
        "runs": runs,
    }


def fmt(val, width=10, prec=2):
    if val is None:
        return f"{'n/a':>{width}}"
    return f"{val:>{width}.{prec}f}"


def main(argv):
    if len(argv) != 2:
        print(f"usage: {argv[0]} <ablation output dir>", file=sys.stderr)
        return 1

    root = argv[1]
    results = {}
    for arm in ARMS:
        summary = summarise(find_runs(root, arm))
        if summary:
            results[arm] = summary

    if not results:
        print(f"no completed runs found under {root}", file=sys.stderr)
        return 1

    have_cov = all(r["regions"] is not None for r in results.values())
    metric = "regions" if have_cov else "edges"

    all_denoms = set()
    for r in results.values():
        all_denoms |= r["denoms"]
    if len(all_denoms) > 1:
        print()
        print("!! the coverage builds do not agree on how much code there is:")
        for d in sorted(all_denoms):
            print(f"     regions_total={d[0]} lines_total={d[1]}")
        print("   The arms are being scored against different denominators, so")
        print("   the comparison is invalid. Use one -s for all arms, and give")
        print("   -x to drop the harness sources that differ between them.")

    print()
    print("=== results ===")
    print()
    if not have_cov:
        print("!! no coverage replay data: falling back to edges_found, which is")
        print("   NOT comparable across arms that run different binaries.")
        print("   Re-run with -c and -s. Treat everything below as indicative.")
        print()

    label = "regions" if have_cov else "edges*"
    print(
        f"{'arm':<4}{'n':>3}  {label:>10}{'  (min-max)':>16}{'lines':>9}"
        f"{'per sec':>12}{'per Mexec':>12}{'per Mop':>12}  description"
    )
    for arm in ARMS:
        r = results.get(arm)
        if not r:
            continue
        if have_cov:
            mid, lo, hi = r["regions"], r["regions_min"], r["regions_max"]
        else:
            mid, lo, hi = r["edges"], r["edges_min"], r["edges_max"]
        rng = f"({lo:.0f}-{hi:.0f})"
        print(
            f"{arm:<4}{r['n']:>3}  {fmt(mid, 10, 0)}{rng:>16}"
            f"{fmt(r['lines'], 9, 0)}"
            f"{fmt(r['per_sec'], 12, 3)}{fmt(r['per_exec'], 12, 1)}"
            f"{fmt(r['per_op'], 12, 1)}  {ARM_DESC[arm]}"
        )
    if have_cov:
        print()
        print("edges_found, for context only - not comparable across arms:")
        for arm in ARMS:
            r = results.get(arm)
            if r:
                print(f"  {arm}: {r['edges']:.0f} "
                      f"({r['edges_min']:.0f}-{r['edges_max']:.0f})")

    print()
    print("=== contrasts ===")
    print()
    any_contrast = False
    for hi, lo, label in CONTRASTS:
        if hi not in results or lo not in results:
            continue
        any_contrast = True
        a, b = results[hi], results[lo]
        key = "regions" if have_cov else "edges"
        delta = a[key] - b[key]
        pct = (delta / b[key] * 100) if b[key] else 0.0
        spread = max(a[key + "_max"] - a[key + "_min"],
                     b[key + "_max"] - b[key + "_min"])
        note = ""
        if abs(delta) <= spread:
            note = "  <- within run-to-run spread, do not read anything into it"
        print(f"{hi} - {lo}  {label:<26}{delta:>+10.0f} {metric} "
              f"({pct:+.1f}%){note}")

    if not any_contrast:
        print("(need at least two arms to contrast)")

    print()
    print("=== context, not results ===")
    print()
    for arm in ARMS:
        r = results.get(arm)
        if not r:
            continue
        first = r["runs"][0]
        vals = [f"{k}={first[k]}" for k in CONTEXT_KEYS if k in first]
        if vals:
            print(f"{arm}: " + "  ".join(vals))

    if not any(r["per_op"] is not None for r in results.values()):
        print()
        print("note: no per-operation numbers. Once one input byte can drive a")
        print("      thousand target operations, executions per second stops")
        print("      being comparable across arms. Have the harness write its")
        print("      operation count to $AFL_OPS_COUNTER_FILE.")

    if any(r["n"] < 3 for r in results.values()):
        print()
        print("note: fewer than 3 repetitions in at least one arm. Fuzzing")
        print("      run-to-run variance routinely exceeds the effect sizes")
        print("      being measured here; treat single runs as anecdotes.")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
