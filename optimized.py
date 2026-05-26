from util import *
import util
import time
import sys
from typing import Any
from enum import Enum
from alive_progress import alive_it

PROGRESS = False

def add_rel(rel, trans):
    if (trans[0], trans[1][0]) not in rel:
        rel[(trans[0], trans[1][0])] = []
    rel[(trans[0], trans[1][0])].append(trans)

def rel_contains(rel, trans):
    if (trans[0], trans[1][0]) not in rel:
        rel[(trans[0], trans[1][0])] = []
    return trans in rel[(trans[0], trans[1][0])]

def rel_get(rel, trans):
    if (trans[0], trans[1]) not in rel:
        rel[(trans[0], trans[1])] = []
    return rel[(trans[0], trans[1])]

def rule_map_add(rule_map, rule, name):
    if rule.type != RuleType.SELF_MODIFYING:
        key = (rule.end, rule.new)
    else:
        key = rule.end
    if key not in rule_map:
        rule_map[key] = []
    rule_map[key].append(name)

def rule_map_get(rule_map, key):
    if key not in rule_map:
        rule_map[key] = []
    return rule_map[key]

def tmp_phase_rules_add(tmp_phase_rules, key, rule):
    if key not in tmp_phase_rules:
        tmp_phase_rules[key] = {}
    rule_map_add(tmp_phase_rules[key], rule[0], rule)

def tmp_phase_rules_get(tmp_phase_rules, rule_key):
    if rule_key not in tmp_phase_rules:
        return []
    return rule_map_get(tmp_phase_rules[rule_key], rule_key)

def rule_set_find(rule_set, key):
    res = []
    for r in rule_set:
        if isinstance(key, tuple) and len(key) == 2 and (len(r) > 3) and r[2] == key[0] and r[3] == key[1]:
            res.append(r)
        elif isinstance(key, str) and len(r) == 3 and r[2] == key:
            res.append(r)
    return res

def remove_dead_tmp_states(transitions):
    dest_map = {}
    for t in transitions:
        (q, g, q1) = t
        dest_map[q1] = t
    newt = set()
    for t in transitions:
        (q, g, q1) = t
        if isinstance(q, str) and not q in dest_map:
            pass
        else:
            newt.add(t)
    return newt


GLOBAL_OFFSET = 0
# Replace transitions into initial state with transitions into a temporary state
def remove_transitions_into_initial_states(transitions):
    newtrans = set()
    tmp_names = {}
    global GLOBAL_OFFSET

    for t in transitions:
        (q, (g, d), q1) = t
        if isinstance(q1, tuple):
            if q1 not in tmp_names:
                tmp_names[q1] = '$tmp-{}'.format(GLOBAL_OFFSET)
                GLOBAL_OFFSET += 1
                newtrans.add((q1, ('', d), tmp_names[q1]))
            q1_ = tmp_names[q1]
        else:
            q1_ = q1
        if isinstance(q, tuple):
            if q not in tmp_names:
                tmp_names[q] = '$tmp-{}'.format(GLOBAL_OFFSET)
                GLOBAL_OFFSET += 1
                newtrans.add((q, ('', d), tmp_names[q]))
            q_ = tmp_names[q]
        else:
            q_ = q
        newtrans.add((q_, (g, d), q1_))
    return remove_epsilon(newtrans)

def remove_epsilon(automaton):
    trans = list()
    trans_map = {}
    for t in automaton:
        (q, (g, d), q1) = t
        if not q in trans_map:
            trans_map[q] = []
        if g != '':
            trans_map[q].append(t)

    for t in automaton:
        (q, (g, d), q1) = t
        if g == '' and q1 in trans_map:
            trans_map[q] += trans_map[q1]
    for (q, transitions) in trans_map.items():
        for t in transitions:
            (_, g, q1) = t
            trans.append((q, g, q1))
    return trans

class RuleType(Enum):
    NORMAL = 0
    DYNAMIC = 1
    SELF_MODIFYING = 2

class Rule:
    def __init__(self, *args):
        if len(args) == 4:
            self.type = RuleType.NORMAL
            (start, top, end, new,) = args
            self.start = start
            self.top = top
            self.end = end
            new = new.split(' ')
            self.new = new[0]
            if len(new) > 1:
                self.new_extra = new[1]
                self.has_extra = True
            else:
                self.has_extra = False

        if len(args) == 5:
            (start, top, end, new, dclic) = args
            self.type = RuleType.DYNAMIC
            self.start = start
            self.top = top
            self.end = end
            new = new.split(' ')
            self.new = new[0]
            if len(new) > 1:
                self.new_extra = new[1]
                self.has_extra = True
            else:
                self.has_extra = False
            self.dclic = dclic
        if len(args) == 3:
            (start, modification, end) = args
            self.type = RuleType.SELF_MODIFYING
            self.start = start
            self.end = end
            self.modification = modification

    def __str__(self):
        if self.type == RuleType.NORMAL:
            return str((self.start, self.top, self.end, self.new, self.new_extra if self.has_extra else None))
        if self.type == RuleType.DYNAMIC:
            return str((self.start, self.top, self.end, self.new, self.new_extra, self.dclic))
        if self.type == RuleType.SELF_MODIFYING:
            return str((self.start, self.modification, self.end))
    def __repr__(self):
        return str(self)



class SMDPDS:
    def __init__(self, states, alphabet, rules, smrules):
        self.states = set(states)
        self.alphabet = set(alphabet)
        self.smrules = dict(smrules)
        self.rules = {}

        self.pre_star = set()
        self.pre = set()
        self.pre_plus = set()

        self.phases = {}
        self.phase_names = {}
        self.phase_offset = 0

        self.dclics = {}
        self.dclic_offset = 0
        self.dclic_names = {}
        for (name, rule) in (rules | smrules).items():
            if len(rule) == 7:
                (_, _, _, _, state, stack, phase) = rule
                key = (state, stack, phase)
                if not key in self.dclic_names:
                    self.dclics[self.dclic_offset] = (state, stack, phase)
                    self.dclic_names[key] = self.dclic_offset
                    self.dclic_offset += 1
                self.rules[name] = Rule(*rule[:4], self.dclic_names[key])
            else:
                self.rules[name] = Rule(*rule)

        self.pre_rule_map = {}
        for (name, rule) in self.rules.items():
            self.rule_map_add(rule, name)

    def rule_map_add(self, rule, name):
        if rule.type != RuleType.SELF_MODIFYING:
            key = (rule.end, rule.new)
        else:
            key = rule.end
        if key not in self.pre_rule_map:
            self.pre_rule_map[key] = []
        self.pre_rule_map[key].append(name)

    def rule_map_get(self, key):
        if key not in self.pre_rule_map:
            self.pre_rule_map[key] = []
        return self.pre_rule_map[key]

    def get_or_add_phase(self, phase):
        if not phase in self.phase_names:
            self.phases[self.phase_offset] = phase
            self.phase_names[phase] = self.phase_offset
            self.phase_offset += 1
        return self.phase_names[phase]


    def compute_possible_phases(self, phases):
        queue = list(phases)
        visited = set()
        while len(queue) > 0:
            phase = queue.pop()
            if phase in visited:
                continue
            # print(phase)
            visited.add(phase)
            phase = self.phases[phase]
            # print(phase)

            for (name, rule) in self.rules.items():
                if rule.type == RuleType.SELF_MODIFYING:
                    # print(name, rule)
                    r1, r2 = rule.modification
                    # print(r1.issubset(phase), r2.issubset(phase))
                    # exit()

                    if not isinstance(r1, frozenset):
                        r1 = frozenset([r1])
                    if not isinstance(r2, frozenset):
                        r2 = frozenset([r2])
                    if r1.issubset(phase):
                        queue.append(self.get_or_add_phase(phase.difference(r1).union(r2)))
                    if r2.issubset(phase):
                        queue.append(self.get_or_add_phase(phase.difference(r2).union(r1)))

        return visited

    def compute_pre_star(self, transitions, new_trans=None):
        rel = {}

        # Map of buckets for temporary (fake) rules used for
        # pushdown rules with 2 new elements on stack.
        # Uses the same data structure as rule_map.
        # See tmp_phase_rules_* functions.
        tmp_phase_rules = {}

        # set of transtions (p/theta, gamma/D, p'/theta')
        
        trans = remove_epsilon(transitions)

        # Set of states that we checked epsilon transitions into themselves (q -- e --> q)
        visited_epsilon_states = set()
        visited = set()
        # iterate through transitions to process
        while len(trans) > 0:
            # pop t = (q/theta, gamma/D, q') from trans
            t = trans.pop()
            (_q, (gamma, dc), q1) = t
            # skip all internal transitions (they do not affect pre*)
            if not isinstance(_q, tuple) or dc == None:
                add_rel(rel, t)

                # find fake rules generated that wait for this transition to be added
                for (r2, dc_old, phase_name) in tmp_phase_rules_get(tmp_phase_rules, (_q, gamma)):
                    p2, gamma2 = r2.start, r2.top
                    if r2.type == RuleType.NORMAL:
                        newdc = dc.union(dc_old)
                        trans.append(((p2, phase_name), (gamma2, newdc), q1))
                    elif r2.type == RuleType.DYNAMIC:
                        newdc = dc.union(dc_old, [ r2.dclic ])
                        trans.append(((p2, phase_name), (gamma2, newdc), q1))
                continue
            (q, phase_name) = _q
            phase = self.phases[phase_name]

            # Adding transitions into initial states by applying epsilon rules
            if not (q, phase) in visited_epsilon_states:
                visited_epsilon_states.add((q, phase))
                # add direct transitions for rules of form (p g \-> p1) and (p g \-> p1 |> p2 w2 t2)
                # new transitions are of type (p -- g --> p1)
                for r_name in self.rule_map_get((q, '')):
                    if not r_name in phase:
                        continue
                    rule = self.rules[r_name]
                    if rule.type == RuleType.DYNAMIC:
                        d = frozenset([rule.dclic])
                    else:
                        d = frozenset()
                    newt = ((rule.start, phase_name), (rule.top, d), (rule.end, phase_name))
                    trans.append(newt)

            # if we did not process the transition yet
            if not t in visited:
                visited.add(t)
                add_rel(rel, t)

                # self-modifying rules
                for r in self.rule_map_get(q):
                    if not r in phase:
                        continue
                    rule = self.rules[r]
                    (r1, r2) = rule.modification
                    # normalize self-modifying rule to have sets instead single rules
                    # this is handy for working on buchi sm-pds because they replace
                    # sets of rules instead of singles
                    if not isinstance(r2, frozenset):
                        r2 = frozenset([r2])
                    if not isinstance(r1, frozenset):
                        r1 = frozenset([r1])
                    # if this sm-rule was not applied we skip it
                    if not r2.issubset(phase):
                        continue
                    # add new transition from source state of the sm-rule and extend
                    # the phase with rules that this sm-rule have deleted
                    # while deleting rules that this sm-rule added
                    newphase = self.get_or_add_phase(frozenset(phase.copy()).difference(r2).union(r1))
                    trans.append(((rule.start, newphase), (gamma, dc), q1))

                debug('EVAL {}'.format(t), level=2)
                # process pushdown rules (not self-modifying)
                for r_name in self.rule_map_get((q, gamma)):
                    if not r_name in phase:
                        continue
                    rule = self.rules[r_name]

                    (p1, gamma1, _, w) = (rule.start, rule.top, rule.end, rule.new)
                    if rule.type == RuleType.NORMAL:
                        newdc = dc
                    elif rule.type == RuleType.DYNAMIC:
                        newdc = frozenset(dc.union([ rule.dclic ]))
                    else:
                        raise 'something is wrong, if you get this, that means rule_map has invalid rules under (q, gamma)'

                    # if the rule replaces top of the stack without adding new symbols, add the transtion from source state of the rule
                    if not rule.has_extra:
                        trans.append(((p1, phase_name), (gamma1, newdc), q1))

                    # if the rule adds symbols to the stack
                    if rule.has_extra:
                        gamma2 = rule.new_extra
                        if rule.type == RuleType.NORMAL:
                            tmp_rule = Rule(p1, gamma1, q1, gamma2)
                        else:
                            tmp_rule = Rule(p1, gamma1, q1, gamma2, rule.dclic)

                        # Save a fake rule for future new transitions from (q1, gamma2) to be aware of.
                        # We also need to save the dclic set to combine the dclics of a future transition
                        tmp_phase_rules_add(tmp_phase_rules, (q1, gamma2), (tmp_rule, dc, phase_name))
                        # if there already is such transtion, add the new transition to immediately
                        for (_, (_, d2), q2) in rel_get(rel, (q1, gamma2)):
                            newdc = newdc.union(d2)
                            trans.append(((p1, phase_name), (gamma1, newdc), q2))

                # find fake rules generated that wait for this transition to be added
                for (r2, dc_old, _) in tmp_phase_rules_get(tmp_phase_rules, ((q, phase_name), gamma)):
                    p2, gamma2 = r2.start, r2.top
                    if r2.type == RuleType.NORMAL:
                        newdc = dc.union(dc_old)
                        trans.append(((p2, phase_name), (gamma2, newdc), q1))
                    elif r2.type == RuleType.DYNAMIC:
                        newdc = dc.union(dc_old, [ r2.dclic ])
                        trans.append(((p2, phase_name), (gamma2, newdc), q1))

        res = set([ t for l in rel.values() for t in l ])

        return res

    def compute_pre(self, transitions):
        rel = {}

        # set of transtions (p/theta, gamma/D, p'/theta')

        trans = []
        rel = {}
        for t in remove_epsilon(transitions):
            if not isinstance(t[0], tuple):
                trans.append(t)
                add_rel(rel, t)

        # trans = remove_epsilon(remove_transitions_into_initial_states(trans))

        for t in transitions:
            (_q, (gamma, dc), q1) = t
            if not isinstance(_q, tuple) or dc == None:
                continue
            (q, phase_name) = _q
            phase = self.phases[phase_name]
            for r in self.rule_map_get((q, '')):
                rule = self.rules[r]
                global GLOBAL_OFFSET
                tmp_name = '$tmp{}'.format(GLOBAL_OFFSET)
                GLOBAL_OFFSET += 1
                if rule.type == RuleType.DYNAMIC:
                    d = frozenset([ rule.dclic ])
                else:
                    d = frozenset()
                trans.append(((rule.start, phase_name), (rule.top, dc.union(d)), tmp_name))
                trans.append((tmp_name, (gamma, dc), q1))
            for r in self.rule_map_get((q, gamma)):
                rule = self.rules[r]
                if not r in phase:
                    continue
                # self-modifying rules
                if rule.type == RuleType.SELF_MODIFYING:
                    p1, (r1, r2) = rule.start, rule.modification
                    if not isinstance(r2, frozenset):
                        r2 = frozenset([r2])
                    if not isinstance(r1, frozenset):
                        r1 = frozenset([r1])
                    if not r2.issubset(phase):
                        continue

                    newphase = set(phase.copy()).difference(r2).union(r1)
                    trans.append(((p1, self.get_or_add_phase(newphase)), (gamma, dc), q1))
                else:
                    p1, gamma1, p2, w = rule.start, rule.top, rule.end, rule.new
                    if rule.type == RuleType.NORMAL:
                        newdc = dc
                    elif rule.type == RuleType.DYNAMIC:
                        newdc = dc.union([ rule.dclic ])
                    else:
                        raise 'something is wrong, if you get this, that means rule_map has invalid rules under (q, gamma)'

                    # if the rule replaces top of the stack without adding new symbols, add the transtion from source state of the rule
                    if not rule.has_extra and w != '':
                        trans.append(((p1, phase_name), (gamma1, newdc), q1))

                    # if the rule adds symbols to the stack
                    if rule.has_extra:
                        gamma2 = rule.new_extra
                        # if there already is such transtion, add the new transition to immediately
                        for tt in rel_get(rel, (q1, gamma2)):
                            newdc = newdc.union(tt[1][1])
                            trans.append(((p1, phase_name), (gamma1, newdc), tt[2]))


        res = set(trans)
        return res

    # Finding a list of repeating heads of form (state, phase, gamma, dclics)
    # Meaning that the configuration (<state, gamma>, phase) reaches (<state, /gamma .*/>, phase),
    # generating dclics, and visiting at least one accepting state on the way.
    def find_repeating_heads(self, acc, used_phases):

        repeating_heads = []

        rule_pow = self.compute_possible_phases(set(used_phases))

        # automaton that accepts any arbitrary tail.
        # we will extend this automaton to generate others
        ACC_STATE = 'acc'
        general_ma = set()
        for g in self.alphabet:
            general_ma.add((ACC_STATE, (g, frozenset()), ACC_STATE))
        debug('{} states, {} symbols, {} phases'.format(len(self.states), len(self.alphabet), len(rule_pow)), level=1)
        debug('{} Total heads'.format(len(self.states) * len(self.alphabet) * len(rule_pow)), level=1)

        heads = set()
        for rule in self.rules.values():
            if hasattr(rule, 'top'):
                heads.add((rule.start, rule.top))
            else:
                for gamma in self.alphabet:
                    heads.add((rule.start, gamma))
        debug('Reduced heads: {} -> {} (* {})'.format(len(self.states) * len(self.alphabet), len(heads), len(list(rule_pow))), level=1)
        i = 1

        debug_memory_start(1)
        total = len(heads) * len(rule_pow)

        if PROGRESS:
            heads = alive_it(heads)

        for (state, gamma) in heads:
            for phase in list(rule_pow):
                # print('Checking (<{}, {}>, {}) ({}/{})'.format(state, gamma, phase, i, total))
                # here, we check that < (state, phase) gamma > is a repeating head
                # to do that, we compute pre3 = pre+((acc x rule_pow x .*) intersect pre*(< (state, phase) /gamma .*/ >))
                # and then, we check if < (state, phase) gamma > is accepted by pre3

                # ma accepts L(< (state, phase) /gamma .*/ >, {})
                ma = general_ma.copy()
                ma.add(((state, phase), (gamma, frozenset()), ACC_STATE))
                debug('Computing pre1', level=1)
                # pre1 = pre*(ma) = pre*({(state, phase)} x /gamma .*/ x {})
                pre1 = self.compute_pre_star(ma)
                debug('{} Transitions'.format(len(pre1)), level=1)
                # del ma
                debug_memory_peek(1)
                debug('Computing pre2', level=1)
                # remove transitions into initial states (states of form (state, phase))
                # to easily modify the accepting conditions

                pre2 = remove_epsilon(remove_transitions_into_initial_states(pre1))
                pre2 = remove_dead_tmp_states(pre2)
                debug('{} Transitions'.format(len(pre2)), level=1)
                # del pre1
                debug_memory_peek(1)

                # remove all transition from states not in buchi acceptance
                # to have that only buchi accepting states are in pre2.
                # Because we removed transitions into initial states,
                # we can just isolate initial states that are not in acc
                # Therefore, pre2 = (acc x rule_pow x .*) intersect pre*(< (state, phase) /gamma .*/ >)
                for t in pre2.copy():
                    (q, g, q1) = t
                    if isinstance(q, tuple) and not q[0] in acc:
                        pre2.remove(t)

                debug('Computing pre3_1', level=1)
                # pre3_1 = pre(pre2) <-- compute pre by applying exactly ONE rule
                pre3_1 = self.compute_pre(pre2)
                pre3_1 = remove_epsilon(remove_transitions_into_initial_states(pre3_1))
                pre3_1 = remove_dead_tmp_states(pre3_1)

                debug('{} Transitions'.format(len(pre3_1)), level=1)
                # del pre2
                debug_memory_peek(1)
                debug('Computing pre3', level=1)
                # pre3 = pre*(pre3_1) = pre+(pre2)

                pre3 = self.compute_pre_star(pre3_1)
                debug('{} Transitions'.format(len(pre3)), level=1)
                # del pre3_1
                debug_memory_peek(1)

                debug('checking if head is repeating', level=1)
                # check that (< (state, phase) gamma >, d) is accepted for some d
                # if yes, then it is a repeating head
                for t in pre3:
                    (q, (g, d), q1) = t
                    if q == (state, phase) and g == gamma and q1 == ACC_STATE:
                        repeating_heads.append(((state, phase), gamma, d ))
                i += 1

                debug_memory_peek(1)
        return repeating_heads
   
# Compute the Self-Modifying Buchi Dynamic Pushdown System (SM-BDPDS)
def compute_bp_optimized(
        ba,
        dpds,
        labelled=lambda s, a: s == a
    ):
    (states, alphabet, rules, smrules) = dpds
    (states, transitions, init, acc) = ba
    newrules = {}
    newsmrules = {}
    newstates = set()
    newacc = set()
    newalphabet = set()
    prod = {}

    rules = rules | smrules

    name_map = {}

    rule_offset = 0
    for (name, rule) in (rules | smrules).items():
        name_map[name] = []
        for (g, label, g1) in transitions:
            valid = True
            for apexpr in label:
                if apexpr[0] == '!':
                    ap = apexpr[1:]
                    if labelled(rule[0], ap):
                        valid = False
                        break
                else:
                    ap = apexpr
                    if not labelled(rule[0], ap):
                        valid = False
                        break
            if valid:
                if len(rule) == 4:
                    (p, y, p1, w1) = rule

                    newname = 'bp{}'.format(rule_offset)
                    newrules[newname] = ((p, g), y, (p1, g1), w1)
                    name_map[name].append(newname)
                    rule_offset += 1
                if len(rule) == 7:
                    (p, y, p1, w1, p2, w2, t2) = rule

                    newname = 'bp{}'.format(rule_offset)
                    newrules[newname] = ((p, g), y, (p1, g1), w1, p2, w2, t2)
                    name_map[name].append(newname)
                    rule_offset += 1
                if len(rule) == 3:
                    (p, (r1, r2), p1) = rule

                    newname = 'bp{}'.format(rule_offset)
                    newsmrules[newname] = ((p, g), (r1, r2), (p1, g1))
                    name_map[name].append(newname)
                    rule_offset += 1
    for (name, rule) in newsmrules.items():
        (p, (r1, r2), p1) = rule
        if isinstance(r1, frozenset):
            new_r1 = set()
            for r in r1:
                new_r1 = new_r1.union(name_map[r])
            new_r1 = frozenset(new_r1)
        else:
            new_r1 = frozenset(name_map[r1])
        if isinstance(r2, frozenset):
            new_r2 = set()
            for r in r2:
                new_r2 = new_r2.union(name_map[r])
            new_r2 = frozenset(new_r2)
        else:
            new_r2 = frozenset(name_map[r2])
        newsmrules[name] = (p, (new_r1, new_r2), p1)

    for (name, rule) in (newrules | newsmrules).items():
        state1 = rule[0]
        state2 = rule[2]
        (p, g) = state1
        (p1, g1) = state2
        newstates.add(state1)
        newstates.add(state2)
        if g in acc:
            newacc.add(state1)
        if g1 in acc:
            newacc.add(state2)

        if len(rule) > 3:
            newalphabet.add(rule[1])

    return (newstates, newalphabet, newrules, newsmrules, newacc, name_map, init)


# Auxillary recursive function that checks nfa acceptance
def check_nfa_aux(trans_map, start, accept, word, dclics, visited):
    key = (start, tuple(word), frozenset(dclics))
    if key in visited:
        return visited[key]
    res = []
    if len(word) == 0 and start in accept:
        res.append(dclics)

    visited[key] = res

    if not start in trans_map:
        return res

    debug("AA -> ", word, start, dclics)
    debug("SWEEP -> ", trans_map[start])
    for t in trans_map[start]:
        (q, (g, d), q1) = t
        if g == '':
            res += check_nfa_aux(trans_map, q1, accept, word, dclics.union(d), visited)
        if len(word) > 0 and g == word[0]:
            res += check_nfa_aux(trans_map, q1, accept, word[1:], dclics.union(d), visited)

    visited[key] = res
    return res

# Check if NFA accpets word from start by checking accept states
def check_nfa_acceptance(transitions, start, accept, word):
    trans_map = {}
    for (q, g, q1) in transitions:
        if q not in trans_map:
            trans_map[q] = []
        trans_map[q].append((q, g, q1))

    v = {}
    dclic_sets = check_nfa_aux(trans_map, start, accept, word, frozenset(), v)

    return dclic_sets


# Generate an automaton that accepts configurations that reach repeating heads
def get_rh_automaton(alphabet, repeating_heads, smdpds):
    ACC_STATE = 'acc'
    ma = set()
    for g in alphabet:
        ma.add((ACC_STATE, (g, frozenset()), ACC_STATE))

    for rh in repeating_heads:
        (s, g, d) = rh
        ma.add((s, (g, d), ACC_STATE))

    pre5 = smdpds.compute_pre_star(ma)
    # print(ma)
    # view_ma(pre5, 'pre5_{}'.format(list(smdpds.rules.values())[0]))

    return (pre5, set([ACC_STATE]))

# Construct the array of SM-BDPDS and return a pd_index relation (dict) that
# maps a state from DPDS to its index in the DPN
def construct_sm_bdpn(smdpn, single_ind_ba, labelled=lambda s, a: s == a):
    assert len(smdpn) == len(single_ind_ba)
    pd_index = {}
    for (i, smdpds) in enumerate(smdpn):
        (states, _, _, _) = smdpds
        for s in states:
            pd_index[s] = i

    res = []
    for (smdpds, ba) in zip(smdpn, single_ind_ba):
        bp = compute_bp_optimized(ba, smdpds, labelled)
        res.append(bp)

    return (res, pd_index)

def construct_rh_automata(smbdpn, init):
    (bdpds_arr, pd_index) = smbdpn

    phases = [ set() for i in range(len(bdpds_arr)) ]

    for init_i in init:
        (init_state, init_stack, init_phase) = init_i
        phases[pd_index[init_state]].add(init_phase)
    for bdpds in bdpds_arr:
        (_, _, rules, _, _, _, _) = bdpds
        for rule in rules.values():
            if len(rule) == 7:
                (_, _, _, _, state, stack, phase) = rule
                phases[pd_index[state]].add(phase)

    res = []
    for (i, bdpds) in enumerate(bdpds_arr):
        (_, alphabet, rules, smrules, acc, prod_map, _) = bdpds
        smdpds = SMDPDS(*bdpds[:4])
        prod_phases = []
        # print('Total {} phases of SM-BDPDS {}'.format(len(phases[i]), i))
        j = 0
        for phase in phases[i]:
            # print(j)
            # print('Total {} rules in a phase'.format(len(phase)))
            prod1 = set().union(*(prod_map[r_name] for r_name in phase))
            prod_phases.append(smdpds.get_or_add_phase(frozenset(prod1)))
        rh = smdpds.find_repeating_heads(acc, prod_phases)
        # print('RH for {} ->'.format(i), rh)
        res.append((get_rh_automaton(alphabet, rh, smdpds), smdpds))
    return res


def find_fixpoint(smbdpn, rh_automata, init):
    (smbdpds_arr, pd_index) = smbdpn
    dclics = set()
    for smbdpds in smbdpds_arr:
        (_, _, rules, _, _, _, _) = smbdpds
        for rule in rules.values():
            if len(rule) == 7:
                (_, _, _, _, state, stack, phase) = rule
                dclics.add((state, stack, phase))

    d_i = dclics.copy()
    ltl_satisfied = False
    # print(d_i)
    while not ltl_satisfied and len(d_i) > 0:
        d_next = set()
        for conf in dclics:
            (state, stack, phase) = conf
            bp = smbdpds_arr[pd_index[state]]
            rh = rh_automata[pd_index[state]][0]
            smdpds = rh_automata[pd_index[state]][1]
            prod = set().union(*(bp[5][r] for r in phase))
            prod = frozenset(prod)
            phase_name = smdpds.get_or_add_phase(prod)
            # print(rh)
            # print(((state, bp[6]), phase_name))
            d_acc = check_nfa_acceptance(rh[0], ((state, bp[6]), phase_name), rh[1], tuple(stack.split(' ')))
            debug('MA -> ', rh[0])
            debug('WORD -> ', ((state, bp[6]), prod), rh[1], stack)
            debug('CHECK RH -> ', conf)
            debug('D_ACC -> ', d_acc)
            debug('D_i ->', d_i)
            for d_set in d_acc:
                if d_set.issubset(d_i):
                    d_next.add(conf)
                    break
        if d_i == d_next:
            ltl_satisfied = True
        d_i = d_next
    d_fp = d_i
    return d_fp

def ltl_model_check_smdpn(smpdn, init, ltl, labelled=lambda s, a: s.find(a) != -1):
    if len(ltl) != len(smpdn):
        return False
    smbpdn = construct_sm_bdpn(smpdn, [ construct_ba(f_i) for f_i in ltl ], labelled)
    (smbdpds_arr, pd_index) = smbpdn

    rhs = construct_rh_automata(smbpdn, init)
    fp = find_fixpoint(smbpdn, rhs, init)
    # print('FP -> ', fp)

    results = []
    for conf in init:
        (state, stack, phase) = conf
        bp = smbdpds_arr[pd_index[state]]
        rh = rhs[pd_index[state]][0]
        smdpds = rhs[pd_index[state]][1]
        prod = set().union(*(bp[5][r] for r in phase))
        prod = frozenset(prod)
        phase_name = smdpds.get_or_add_phase(prod)
        debug('LTL RH -> ', rh)
        # print('RH -> ', rh)
        debug('START -> ', ((state, bp[6]), phase_name))
        debug('STACK -> ', stack)
        # view_ma(rh[0], 'rh')
        d_acc = check_nfa_acceptance(rh[0], ((state, bp[6]), phase_name), rh[1], stack)
        debug('FOUND -> ', d_acc)
        valid = False
        for d_set in d_acc:
            d_set = { smdpds.dclics[d] for d in d_set }
            if d_set.issubset(fp):
                valid = True
                break
        if valid == False:
            return False
    return True


