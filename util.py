from itertools import chain, combinations
import subprocess
from promela_parser import Ltl2baParser, parse_transitions
import argparse
import random
import csv
import time
import random
# import tracemalloc

random.seed(1)

DEBUG_LEVEL = 999

def set_debug_level(l = 0):
    global DEBUG_LEVEL
    DEBUG_LEVEL = l

def powerset(iterable):
    "powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s)+1))

def prune_dead_transitions(pre, acc):
    acc_map = {}
    visible = set()
    visited = set()
    for (p, g, q) in pre:
        if q not in acc_map:
            acc_map[q] = []
        acc_map[q].append((p, g, q))

    acc_queue = list(acc)
    while len(acc_queue) > 0:
        s = acc_queue.pop()
        if s in visited:
            continue
        visited.add(s)
        if s not in acc_map:
            continue
        for (p, g, q) in acc_map[s]:
            acc_queue.append(p)
            visible.add((p, g, q))
    return visible


def construct_ba(ltl):
    result = subprocess.run(["ltl2ba", "-f", "{}".format(ltl)], capture_output=True, text=True)
    code = result.returncode
    output = result.stdout
    err = result.stderr
    if code != 0:
        print(output)
        print(err, flush=True)
        exit()
    ba = Ltl2baParser.parse(output.strip())
    return (ba[0], parse_transitions(ba[1]), ba[2], ba[3])

def debug(*args, level = 0):
    if DEBUG_LEVEL <= level:
        print(*args)

def debug_memory_start(level = 0):
    if DEBUG_LEVEL <= level:
        tracemalloc.start()

def debug_memory_stop(level = 0):
    if DEBUG_LEVEL <= level:
        tracemalloc.stop()

def debug_memory_peek(level = 0):
    if DEBUG_LEVEL <= level:
        print(tracemalloc.get_traced_memory())

def view_ma(ma, name):
    dot = graphviz.Digraph(comment=name)
    phases = {}
    phase_offset = 0
    nodes = {}
    edges = []
    for t in ma:
        (q, g, q1) = t
        if isinstance(q, tuple):
            if not q[1] in phases:
                phases[q[1]] = 'Phase_{}'.format(phase_offset)
                phase_offset += 1
            q = (q[0], phases[q[1]])
        if isinstance(q1, tuple):
            if not q1[1] in phases:
                phases[q1[1]] = 'Phase_{}'.format(phase_offset)
                phase_offset += 1
            q1 = (q1[0], phases[q1[1]])
        dot.edge('{}'.format(q), '{}'.format(q1), '{} / {}'.format(g[0], g[1]))
    for (phase, pname) in phases.items():
        dot.node('{} -> {}'.format(pname, phase))
    dot.view(name)


OFFSET = 0

def generateRandomSMDPN(number_of_dpds, number_of_states, alphabet_size, number_of_rules, number_of_dynamic_rules, number_of_smrules):
    global OFFSET

    assert number_of_rules < number_of_states * alphabet_size * number_of_states * alphabet_size * alphabet_size

    smdpn = []
    pd_index = {}
    for i in range(number_of_dpds):
        states = []
        for j in range(number_of_states):
            name = 'p{}'. format(OFFSET)
            states.append(name)
            pd_index[name] = i
            OFFSET += 1
        alphabet = []
        for j in range(alphabet_size):
            alphabet.append('y{}'.format(OFFSET))
            OFFSET += 1

        smdpn.append((states, alphabet, {}, {}))

    for (i, smdpds) in enumerate(smdpn):
        (states, alphabet, _, _) = smdpds
        rules = {}
        smrules = {}
        for j in range(number_of_rules):
            from_state = states[random.randint(0, len(states) - 1)]
            to_state = states[random.randint(0, len(states) - 1)]
            gamma_1 = alphabet[random.randint(0, len(alphabet) - 1)]
            w_length = random.randint(0, 2)
            w = ''
            if w_length == 1:
                w = alphabet[random.randint(0, len(alphabet) - 1)]
            elif w_length == 2:
                w = '{} {}'.format(alphabet[random.randint(0, len(alphabet) - 1)], alphabet[random.randint(0, len(alphabet) - 1)])
            rule_name = 'r{}'.format(OFFSET)
            OFFSET += 1
            rules[rule_name] = (from_state, gamma_1, to_state, w)

        for j in range(number_of_dynamic_rules):
            from_state = states[random.randint(0, len(states) - 1)]
            to_state = states[random.randint(0, len(states) - 1)]
            gamma_1 = alphabet[random.randint(0, len(alphabet) - 1)]
            w_length = random.randint(0, 2)
            w = ''
            if w_length == 1:
                w = alphabet[random.randint(0, len(alphabet) - 1)]
            elif w_length == 2:
                w = '{} {}'.format(alphabet[random.randint(0, len(alphabet) - 1)], alphabet[random.randint(0, len(alphabet) - 1)])

            other_dpds = smdpn[random.randint(0, len(smdpn) - 1)]
            other_state = other_dpds[0][random.randint(0, len(other_dpds[0]) - 1)]
            other_stack = other_dpds[1][random.randint(0, len(other_dpds[1]) - 1)]
            other_phase = []
            rule_name = 'r{}'.format(OFFSET)
            OFFSET += 1
            rules[rule_name] = (from_state, gamma_1, to_state, w, other_state, other_stack, other_phase)

        for j in range(number_of_smrules):
            from_state = states[random.randint(0, len(states) - 1)]
            to_state = states[random.randint(0, len(states) - 1)]

            rule_name = 'r{}'.format(OFFSET)
            OFFSET += 1
            smrules[rule_name] = (from_state, ('', ''), to_state)

        rule_names = set((rules | smrules).keys())
        for (name, smrule) in smrules.items():
            av_rules = list(rule_names.difference([name]))
            smrules[name] = (
                smrules[name][0],
                (av_rules[random.randint(0, len(av_rules) - 1)], av_rules[random.randint(0, len(av_rules) - 1)]),
                smrules[name][2]
            )
        smdpn[i] = (states, alphabet, rules, smrules)

    for dpds in smdpn:
        (states, alphabet, rules, smrules) = dpds
        for (name, rule) in rules.items():
            if len(rule) == 7:
                ind = pd_index[rule[4]]
                rule_set = set((smdpn[ind][2] | smdpn[ind][3]).keys())
                for smrule in smdpn[ind][3].values():
                    if random.randint(0, 2) > 0:
                        rule_set = rule_set.difference([ smrule[1][1] ])
                rules[name] = (rule[0], rule[1], rule[2], rule[3], rule[4], rule[5], frozenset(rule_set))
    return smdpn

def getRandomInit(smdpn, number_of_processes):
    proc = []
    for i in range(number_of_processes):
        smdpds = smdpn[random.randint(0, len(smdpn) - 1)]
        (states, alphabet, rules, smrules) = smdpds
        state = states[random.randint(0, len(states) - 1)]
        word = tuple([ alphabet[random.randint(0, len(alphabet) - 1)] ])
        phase = set()
        rule_set = set((rules | smrules).keys())
        for i in range(random.randint(len(rules), len(rules) + len(smrules))):
            phase.add(rule_set.pop())
        proc.append((state, word, frozenset(phase)))
    return proc

def getRandomLtl(smdpn, length):
    res = []
    for smdpds in smdpn:
        (states, alphabet, rules, smrules) = smdpds
        ltl = '{}'.format(states[random.randint(0, len(states) - 1)])
        binary = [ '&&', '||' ]
        unary = [ 'X <>', 'X', '<>', '[]' ]
        for i in range(length):
            state = states[random.randint(0, len(states) - 1)]
            ltl = '{} && (<> {})'.format(ltl, state)
        res.append(ltl)
    return res

def computeClusters(smdpn):
    max_cluster_num = 0
    cluster_nums = [0 for i in smdpn]
    for i, smdpds in enumerate(smdpn):
        cluster_num = 0
        visited = set()
        for state in smdpds[0]:
                if state in visited:
                    continue
                cluster_num += 1
                stack = [state]
                while len(stack) > 0:
                    cur = stack.pop()
                    if cur in visited:
                        continue
                    visited.add(cur)
                    for r in smdpds[2].values():
                        if r[0] == cur:
                            stack.append(r[2])
                    for r in smdpds[3].values():
                        if r[0] == cur:
                            stack.append(r[2])
        cluster_nums[i] = cluster_num
    return cluster_nums
