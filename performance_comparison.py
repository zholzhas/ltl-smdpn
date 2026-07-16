import glob
import multiprocessing
import os
import pickle
import random
import signal
import sys
import time
import traceback
import tracemalloc

import numpy

from naive import ltl_model_check_smdpn as ltl_naive
from optimized import ltl_model_check_smdpn as ltl_optimized
from util import *

file_lock = multiprocessing.Lock()


def exampleDpn():
    rules = {
        "r1": ("p0", "g0", "p1", "g1 g0", "pp", "ww", frozenset(["r_con_1"])),
        "r2": ("p5", "g1", "p2", "g2 g0"),
        "r3": ("p2", "g2", "p3", ""),
        "r4": ("p4", "g0", "p0", ""),
        "r5": ("p1", "g1", "p4", "g0"),
    }
    smrules = {
        "smr1": ("p3", ("r1", "r5"), "p4"),
        "smr2": ("p2", ("r2", "r3"), "p5"),
        "smr3": ("p5", ("r3", "r2"), "p2"),
    }

    phase0 = frozenset(["r5", "r2", "r3", "r4", "smr1"])
    phase1 = frozenset(["r1", "r2", "r3", "r4", "smr1"])
    phase_loop = frozenset(["r1", "r2", "r3", "r4", "r5", "smr1", "smr2", "smr3"])

    rules_con = {"r_con_1": ("pp", "ww", "pp", "ww")}
    smrules_con = {}

    smdpds_example = (
        set(["p0", "p1", "p2", "p3", "p4", "p5"]),
        set(["g0", "g1", "g2"]),
        rules,
        smrules,
    )
    smdpds_example_concur = (set(["pp"]), set(["ww"]), rules_con, smrules_con)

    smdpn = [smdpds_example, smdpds_example_concur]
    init = [("p0", ["g0"], frozenset(phase_loop))]
    ltl = ["<> p1", "!pp -> <> a"]

    return (smdpn, init, ltl)


TIMEOUT = 60 * 60
time_optimized = multiprocessing.Value("f")
memory_optimized = multiprocessing.Value("f")
time_naive = multiprocessing.Value("f")
memory_naive = multiprocessing.Value("f")


def runOptimized(smdpn, init, ltl):
    print("start optimized")
    try:
        global time_optimized, memory_optimized
        tracemalloc.start()
        start_time = time.time()
        # res_optimized = ltl_optimized(smdpn, init, ltl)
        ltl_optimized(smdpn, init, ltl)
        time_optimized.value = time.time() - start_time
        memory_optimized.value = tracemalloc.get_traced_memory()[1]
        print("Optimized finished after {}".format(time_optimized.value), flush=True)
        tracemalloc.stop()
    except Timeout:
        raise
    except Exception as e:
        print("Error in optimized\n{}".format(e), flush=True)
        traceback.print_exception(e)


def runNaive(smdpn, init, ltl):
    print("start naive")
    try:
        global time_naive, memory_naive
        tracemalloc.start()
        start_time = time.time()
        # res_optimized = ltl_optimized(smdpn, init, ltl)
        ltl_naive(smdpn, init, ltl)
        time_naive.value = time.time() - start_time
        memory_naive.value = tracemalloc.get_traced_memory()[1]
        print("Naive finished after {}".format(time_naive.value), flush=True)
        tracemalloc.stop()
    except Timeout:
        raise
    except Exception as e:
        print("Error in naive\n{}".format(e), flush=True)
        traceback.print_exception(e)


class Timeout(Exception):
    pass


def handle(_a, _b):
    raise Timeout()


def compareTimes(smdpn, init, ltl, timeout_naive=TIMEOUT):
    global TIMEOUT

    print(
        f"Size: {len(smdpn)} proc {max(len(construct_ba(f)[1]) for f in ltl)} ltl, {len(smdpn[0][2])} rules, {len(smdpn[0][3])} smrules"
    )

    signal.signal(signal.SIGALRM, handle)
    signal.alarm(TIMEOUT)
    opt_timeout = False
    try:
        runOptimized(smdpn, init, ltl)
    except Timeout:
        opt_timeout = True
    signal.alarm(0)

    signal.alarm(timeout_naive)
    naive_timeout = False
    try:
        runNaive(smdpn, init, ltl)
    except Timeout:
        naive_timeout = True
    signal.alarm(0)

    global time_optimized, time_naive, memory_optimized, memory_naive

    res_opt = (
        (time_optimized.value, memory_optimized.value)
        if not opt_timeout
        else ("TIMEOUT", "TIMEOUT")
    )
    res_naive = (
        (time_naive.value, memory_naive.value)
        if not naive_timeout
        else ("TIMEOUT", "TIMEOUT")
    )

    return (res_opt, res_naive)


random.seed(time.time())
dump_file = "experiments/{}.pkl".format(random.randint(0, 9999))


def compareRandoms():
    random.seed(time.time())
    state_size = random.randint(3, 8)
    alphabet_size = random.randint(2, 5)
    num_dyn_rules = random.randint(1, 3)
    num_smrules = random.randint(1, 5)
    num_dpds = random.randint(1, 5)
    num_rules = random.randint(
        state_size * alphabet_size, state_size * alphabet_size * 2
    )

    ltl_size = random.randint(0, 2)

    smdpn = generateRandomSMDPN(
        num_dpds, state_size, alphabet_size, num_rules, num_dyn_rules, num_smrules
    )
    ltl = getRandomLtl(smdpn, ltl_size)
    ba_size = len(construct_ba(ltl[0])[1])
    init = getRandomInit(smdpn, 1)

    experiments = []
    if os.path.isfile(dump_file):
        with open(dump_file, "rb") as file:
            experiments = pickle.load(file)

    print("Dump at {}".format(dump_file))

    print([state_size, alphabet_size, num_rules, num_dyn_rules, num_smrules, ba_size])

    (optimized, naive) = compareTimes(smdpn, init, ltl)
    experiments.append(
        {
            "model": smdpn,
            "init": init,
            "ltl": ltl,
            "results": {"optimized": optimized, "naive": naive},
        }
    )

    with open(dump_file, "wb") as file:
        pickle.dump(experiments, file)

    print(optimized, naive)


# There are two options:
#   1. `python performance_comparison.py` will generate random SM-DPNs and
#       record the results into the experiments folder
#   2. `python performance_comparison.py rerun` will go through successful experiments
#       and rerun them 5 times to get average values and deviation.
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "rerun":
        data = []

        for filename in glob.glob("experiments/*.pkl"):
            with open(filename, "rb") as f:
                data += pickle.load(f)

        data = [r for r in data if isinstance(r["results"]["optimized"][0], float)]
        # sort by number of proceses:
        data = sorted(data, key=lambda r: len(r["model"]))
        # sort by smrules
        data = sorted(data, key=lambda r: len(r["model"][0][3]))
        # sort by rules:
        data = sorted(data, key=lambda r: len(r["model"][0][2]))

        stats = []
        for di, d in enumerate(data):
            print(f"model {di}/{len(data)}")
            num = len(stats)
            results = []
            num_runs = 5
            for i in range(num_runs):
                print(f"run {i + 1}/{num_runs}")
                naive_timeout = TIMEOUT
                # if (
                #     d["results"]["naive"][0] == "TIMEOUT"
                #     or d["results"]["naive"][0] > 3000
                # ):
                #     print(f"naive should timeout: {d['results']['naive'][0]}")
                #     naive_timeout = 2

                (optimized, naive) = compareTimes(
                    d["model"], d["init"], d["ltl"], naive_timeout
                )
                results.append({"optimized": optimized, "naive": naive})
            opt_times = [r["optimized"][0] for r in results]
            nai_times = [r["naive"][0] for r in results]
            opt_mem = [r["optimized"][1] for r in results]
            nai_mem = [r["naive"][1] for r in results]

            if d["results"]["naive"][0] == "TIMEOUT":
                res_naive = {
                    "time": "TIMEOUT",
                    "mem": "TIMEOUT",
                }
            else:
                res_naive = {
                    "time": nai_times,
                    "mem": nai_mem,
                }

            res = {
                "optimized": {
                    "time": opt_times,
                    "mem": opt_mem,
                },
                "naive": res_naive,
            }
            stats.append(
                {
                    "num_proc": len(d["model"]),
                    "num_states": len(d["model"][0][0]),
                    "num_alphabet": len(d["model"][0][1]),
                    "num_rules": len(d["model"][0][2]),
                    "num_sm": len(d["model"][0][3]),
                    "ltl": d["ltl"],
                    "res": res,
                }
            )
            with open(f"results_{di}.pkl", "wb") as file:
                pickle.dump(stats, file)
        print(stats)

    else:
        while True:
            compareRandoms()
