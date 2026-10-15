# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# bench/stats.py
# ==============
#
# The statistics of a benchmark record (bench/run.py), kept apart from the
# runner so that bench/test_bench.py checks them on synthetic data.
#
# R by paired median. In each round r, both implementations ran once on
# the same set and operation; R_r is this library's round median divided
# by the baseline's. R is the median of the R_r. Pairing within a round
# cancels drift slower than a round (thermal state, background load).
#
# The verdict. The R_r of one comparison are treated as independent draws
# from one distribution whose median is the true ratio. A distribution-free
# confidence interval for that median comes from the sign test: with the
# R_r sorted as x(1) <= ... <= x(n), the interval [x(k), x(n+1-k)] covers
# the median with probability 1 - 2 P[Bin(n, 1/2) <= k-1], whatever the
# distribution. k is the largest value for which that probability is at
# least LEVEL (95%). The comparison is resolved ("R < 1" or "R > 1") only
# when this interval excludes 1, and inconclusive otherwise. Below
# MIN_ROUNDS rounds no k exists at 95% (for n = 5, even [x(1), x(5)]
# covers with only 1 - 2/32 = 93.75%), so fewer rounds are always
# inconclusive. With equal implementations the rule resolves a comparison
# in at most 5% of runs (the 1 - coverage of the interval; 3.1% at 6
# rounds, 3.9% at 9, 3.5% at 15), which test_bench.py checks by
# simulation. The quartiles of the R_r are kept as a spread figure; they
# describe the scatter of the ratios, not the uncertainty of R.
#
# The same rule judges throughput (per round: the baseline's rate over
# this library's, so that lower is better there too) and the cost of this
# library's fault check (signing with it over signing without it, both from
# one process of the testing build).

import math
import statistics

LEVEL = 0.95
MIN_ROUNDS = 6


def quartiles(values):
    """(q1, median, q3) by the inclusive method; one value gives itself."""
    if len(values) == 1:
        return values[0], values[0], values[0]
    q = statistics.quantiles(values, n=4, method="inclusive")
    return q[0], q[1], q[2]


def sign_test_k(n, level=LEVEL):
    """The largest k with coverage of [x(k), x(n+1-k)] >= level, or 0."""
    alpha, k, tail = 1.0 - level, 0, 0
    for j in range(1, n // 2 + 1):
        tail += math.comb(n, j - 1)          # sum of C(n, i) for i < j
        if 2 * tail / 2 ** n <= alpha:
            k = j
        else:
            break
    return k


def median_interval(values, level=LEVEL):
    """(low, high, coverage) of the sign-test interval, or None."""
    n = len(values)
    k = sign_test_k(n, level)
    if k == 0:
        return None
    x = sorted(values)
    coverage = 1.0 - 2 * sum(math.comb(n, i) for i in range(k)) / 2 ** n
    return x[k - 1], x[n - k], coverage


def judge(values):
    """Row fields for paired ratios: R, interval, spread and verdict."""
    q1, med, q3 = quartiles(values)
    row = dict(R=med, R_q1=q1, R_q3=q3, R_min=min(values), R_max=max(values),
               rounds=len(values), interval_level=LEVEL)
    ci = median_interval(values) if len(values) >= MIN_ROUNDS else None
    if ci is None:
        row.update(R_low=None, R_high=None, interval_coverage=None, verdict="inconclusive")
    else:
        low, high, coverage = ci
        row.update(R_low=low, R_high=high, interval_coverage=coverage,
                   verdict="inconclusive" if low <= 1.0 <= high
                   else ("R < 1" if med < 1.0 else "R > 1"))
    return row


def summarise(observations):
    """Per (name, set, op): sample and round statistics, in nanoseconds."""
    groups = {}
    for o in observations:
        if o.get("status") == "ok" and "ns" in o:
            groups.setdefault((o["name"], o["set"], o["op"]), []).append(o)
    rows = []
    for (name, s, op), obs in sorted(groups.items()):
        samples = [v for o in obs for v in o["ns"]]
        rounds = [statistics.median(o["ns"]) for o in sorted(obs, key=lambda o: o["round"])]
        q1, med, q3 = quartiles(samples)
        spread = [(quartiles(o["ns"])[2] - quartiles(o["ns"])[0]) / statistics.median(o["ns"])
                  for o in obs]
        row = dict(name=name, set=s, op=op, variant=obs[0]["variant"], samples=len(samples),
                   rounds=len(obs), median_ns=med, q1_ns=q1, q3_ns=q3, min_ns=min(samples),
                   max_ns=max(samples), round_median_ns=rounds,
                   within_round_iqr_rel=statistics.median(spread))
        if all("tsc" in o for o in obs):
            row["median_tsc"] = statistics.median([v for o in obs for v in o["tsc"]])
        rows.append(row)
    return rows


def is_subject_build(name, subject):
    """This library's own programs (the public one and the testing build)."""
    return name == subject or name.startswith(subject + "-")


def paired(cost, subject):
    """Rows of judged ratios from cost[(name, key, round)] -> value.

    For each key and each other implementation, the ratio of the subject's
    cost to that implementation's, per round both have."""
    names = sorted({n for n, _, _ in cost if not is_subject_build(n, subject)})
    rows = []
    for key in sorted({k for _, k, _ in cost}):
        for b in names:
            values = [cost[(subject, key, r)] / cost[(b, key, r)]
                      for (n, k, r) in sorted(cost)
                      if n == b and k == key and (subject, key, r) in cost]
            if values:
                rows.append((key, b, judge(values)))
    return rows


def ratios(observations, subject):
    """R by paired median for every (set, op, baseline) with common rounds."""
    cost = {(o["name"], (o["set"], o["op"]), o["round"]): statistics.median(o["ns"])
            for o in observations if o.get("status") == "ok" and "ns" in o}
    return [dict(set=s, op=op, baseline=b, **row) for (s, op), b, row in paired(cost, subject)]


def throughput_rows(observations):
    """Per (name, set, op, threads): rate in calls per second over rounds."""
    groups = {}
    for o in observations:
        if o.get("status") == "ok" and "calls" in o:
            groups.setdefault((o["name"], o["set"], o["op"], o["threads"]), []).append(
                1e9 * o["calls"] / o["wall_ns"])
    return [dict(name=n, set=s, op=op, threads=t, rounds=len(v), median_ops_per_s=
                 statistics.median(v), min_ops_per_s=min(v), max_ops_per_s=max(v))
            for (n, s, op, t), v in sorted(groups.items())]


def throughput_ratios(observations, subject):
    """R for throughput: per round, the baseline's rate over the subject's."""
    cost = {(o["name"], (o["set"], o["op"], o["threads"]), o["round"]): o["wall_ns"] / o["calls"]
            for o in observations if o.get("status") == "ok" and o.get("calls")}
    return [dict(set=s, op=op, threads=t, baseline=b, **row)
            for (s, op, t), b, row in paired(cost, subject)]


FAULT_CHECK = {"sign": "sign-unchecked", "sign-det": "sign-det-unchecked"}


def fault_check_cost(observations, testing):
    """Per (set, op): signing with the check over signing without it.

    Both come from the same process of the testing build in each round."""
    med = {(o["set"], o["op"], o["round"]): statistics.median(o["ns"])
           for o in observations if o.get("name") == testing and o.get("status") == "ok"
           and "ns" in o}
    rows = []
    for s in sorted({k[0] for k in med}):
        for op, unchecked in FAULT_CHECK.items():
            values = [med[(s, op, r)] / med[(s, unchecked, r)]
                      for (s2, op2, r) in sorted(med)
                      if s2 == s and op2 == op and (s, unchecked, r) in med]
            if values:
                rows.append(dict(set=s, op=op, **judge(values)))
    return rows
