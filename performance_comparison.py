from naive import ltl_model_check_smdpn as ltl_naive
from optimized import ltl_model_check_smdpn as ltl_optimized
from util import *
import multiprocessing


import time
import random
import tracemalloc
import pickle
import traceback
import os
import signal

file_lock = multiprocessing.Lock()

def exampleDpn():
    rules = {
        'r1' : ('p0', 'g0', 'p1', 'g1 g0', 'pp', 'ww', frozenset(['r_con_1'])),
        'r2' : ('p5', 'g1', 'p2', 'g2 g0'),
        'r3' : ('p2', 'g2', 'p3', ''),
        'r4' : ('p4', 'g0', 'p0', ''),
        'r5' : ('p1', 'g1', 'p4', 'g0'),
    }
    smrules = {
        'smr1' : ('p3', ('r1', 'r5'), 'p4'),
        'smr2' : ('p2', ('r2', 'r3'), 'p5'),
        'smr3' : ('p5', ('r3', 'r2'), 'p2')
    }

    phase0 = frozenset([ 'r5', 'r2', 'r3', 'r4', 'smr1' ])
    phase1 = frozenset([ 'r1', 'r2', 'r3', 'r4', 'smr1' ])
    phase_loop = frozenset([ 'r1', 'r2', 'r3', 'r4', 'r5', 'smr1', 'smr2', 'smr3' ])

    rules_con = {
        'r_con_1' : ('pp', 'ww', 'pp', 'ww')
    }
    smrules_con = {}

    smdpds_example = (set([ 'p0', 'p1', 'p2', 'p3', 'p4', 'p5']), set(['g0', 'g1', 'g2']), rules, smrules)
    smdpds_example_concur = (set([ 'pp' ]), set(['ww']), rules_con, smrules_con)

    smdpn = [smdpds_example, smdpds_example_concur]
    init = [('p0', [ 'g0' ], frozenset(phase_loop))]
    ltl = ['<> p1', '!pp -> <> a']

    return (smdpn, init, ltl)

TIMEOUT = 60*60
time_optimized = multiprocessing.Value('f')
memory_optimized = multiprocessing.Value('f')
time_naive = multiprocessing.Value('f')
memory_naive = multiprocessing.Value('f')

def runOptimized(smdpn, init, ltl):
    print('start optimized')
    try:
        global time_optimized, memory_optimized
        tracemalloc.start()
        start_time = time.time()
        # res_optimized = ltl_optimized(smdpn, init, ltl)
        ltl_optimized(smdpn, init, ltl)
        time_optimized.value = time.time() - start_time
        memory_optimized.value = tracemalloc.get_traced_memory()[1]
        print('Optimized finished after {}'.format(time_optimized.value), flush=True)
        tracemalloc.stop()
    except Timeout:
        raise
    except Exception as e:
        print('Error in optimized\n{}'.format(e), flush=True)
        traceback.print_exception(e)

def runNaive(smdpn, init, ltl):
    print('start naive')
    try:
        global time_naive, memory_naive
        tracemalloc.start()
        start_time = time.time()
        # res_optimized = ltl_optimized(smdpn, init, ltl)
        ltl_naive(smdpn, init, ltl)
        time_naive.value = time.time() - start_time
        memory_naive.value = tracemalloc.get_traced_memory()[1]
        print('Naive finished after {}'.format(time_naive.value), flush=True)
        tracemalloc.stop()
    except Timeout:
        raise
    except Exception as e:
        print('Error in naive\n{}'.format( e), flush=True)
        traceback.print_exception(e)

class Timeout(Exception):
    pass

def handle(_a, _b):
    raise Timeout()

def compareTimes(smdpn, init, ltl):
    global TIMEOUT

    signal.signal(signal.SIGALRM, handle)
    signal.alarm(TIMEOUT)
    opt_timeout = False
    try:
        runOptimized(smdpn, init, ltl)
    except Timeout:
        opt_timeout = True
    signal.alarm(0)

    signal.alarm(TIMEOUT)
    naive_timeout = False
    try:
        runNaive(smdpn, init, ltl)
    except Timeout:
        naive_timeout = True
    signal.alarm(0)
    
    global time_optimized, time_naive, memory_optimized, memory_naive

    res_opt = (time_optimized.value, memory_optimized.value) if not opt_timeout else ('TIMEOUT', 'TIMEOUT')
    res_naive = (time_naive.value, memory_naive.value) if not naive_timeout else ('TIMEOUT', 'TIMEOUT')

    return (res_opt, res_naive)

random.seed(time.time())
dump_file = 'experiments/{}.pkl'.format(random.randint(0, 9999))

def compareRandoms():
    random.seed(time.time())
    state_size = random.randint(3, 8)
    alphabet_size = random.randint(2, 5)
    num_dyn_rules = random.randint(1, 3)
    num_smrules = random.randint(1, 5)
    num_dpds = random.randint(1, 5)
    num_rules = random.randint(state_size * alphabet_size, state_size * alphabet_size * 2)

    ltl_size = random.randint(0, 2)

    smdpn = generateRandomSMDPN(num_dpds, state_size, alphabet_size, num_rules, num_dyn_rules, num_smrules)
    ltl = getRandomLtl(smdpn, ltl_size)
    ba_size = len(construct_ba(ltl[0])[1])
    init = getRandomInit(smdpn, 1)

    experiments = []
    if os.path.isfile(dump_file):
        with open(dump_file, "rb") as file:
            experiments = pickle.load(file)

    print('Dump at {}'.format(dump_file))

    print([ state_size, alphabet_size, num_rules, num_dyn_rules, num_smrules, ba_size ])

    (optimized, naive) = compareTimes(smdpn, init, ltl)
    experiments.append({ 'model': smdpn, 'init': init, 'ltl': ltl, 'results': { 'optimized': optimized, 'naive': naive } })

    with open(dump_file, "wb") as file:
        pickle.dump(experiments, file)

    print(optimized, naive)


if __name__ == '__main__':
    while True:
        compareRandoms()
