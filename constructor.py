import angr, monkeyhex
import pickle
from angrutils import *
import unicorn
import resource
import sys
import glob
import os
import z3
import capstone
import archinfo
import psutil
import claripy
import mmap
import shutil
import optimized
import arch_helper
# import logger

def pickled_to_analyzable(pickled):
    pickled_rules, pickled_entries, init_phase = pickled
    rules = {}
    sm_rules = {}
    states = set()
    alphabet = set()
    for (name, r) in pickled_rules.items():
        states.add('{}'.format(r[0]))
        states.add('{}'.format(r[2]))
        if len(r) > 3:
            alphabet.add(r[1])
            alphabet.add(r[3])
            if len(r) > 4:
                if r[4] != '':
                    alphabet.add(r[4])
                    rules[name] = ('{}'.format(r[0]), '{}'.format(r[1]), '{}'.format(r[2]), '{} {}'.format(r[3], r[4]))
                if len(r) > 5:
                    rules[name] = ('{}'.format(r[0]), '{}'.format(r[1]), '{}'.format(r[2]), '{}'.format(r[3]), r[5], '$', frozenset(init_phase))
            else:
                rules[name] = ('{}'.format(r[0]), '{}'.format(r[1]), '{}'.format(r[2]), '{}'.format(r[3]))
        if len(r) == 3:
            sm_rules[name] = ('{}'.format(r[0]), r[1], '{}'.format(r[2]))

    entry = '$entry'
    for e in pickled_entries:
        rules['entry_rule_{}'.format(e)] = (entry, '$', '{}'.format(e), '$')
    states.add(entry)

    return [(states, alphabet, rules, sm_rules)], [(entry, ['$'], frozenset(init_phase))]

def memory_limit_half(half=0.9):
    """Limit max memory usage to half."""
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    # Convert KiB to bytes, and divide in two to half
    resource.setrlimit(resource.RLIMIT_AS, (int(get_memory() * 1024 * half), hard))

def get_memory():
    with open('/proc/meminfo', 'r') as mem:
        free_memory = 0
        for i in mem:
            sline = i.split()
            if str(sline[0]) in ('MemFree:', 'Buffers:', 'Cached:'):
                free_memory += int(sline[1])
    return free_memory  # KiB


class SM_DPDS_Constructor:
    rule_name_offset = 0
    def __init__(self, transitions, entries, init_trans, prefix=''):
        self.transitions = transitions
        self.init_trans = list(set(init_trans))

        self.entries = entries
        self.init_phase = None
        self.visited_transitions = set()

        self.source_map = {}
        self.fill_transition_source_map()
        self.sm_targets = set()
        self.fill_sm_targets()
        self.pushed_values = set()
        self.fill_pushed_values()

        self.all_rules = {}
        self.rule_names = {}
        self.prefix = prefix


        self.interesting_states = {}
        self.entry_location = 'entry'

        pass

    def add_rule(self, rule):
        if rule in self.rule_names:
            return self.rule_names[rule]

        from_state = rule[0]
        to_state = rule[2]
        name = 'rule_{}_to_{}/{}'.format(from_state, to_state, self.rule_name_offset)
        SM_DPDS_Constructor.rule_name_offset += 1
        self.all_rules[name] = rule
        self.rule_names[rule] = name
        return name

    def add_rules(self, rules):
        names = []
        for r in rules:
            names.append(self.add_rule(r))
        return names



    def is_valid_rule_state(self, state, source_map):
        if state in self.pushed_values:
            return True
        if state in self.entries:
            return True
        if not state in source_map or len(source_map[state]) != 1:
            return True
        trans = list(source_map[state])[0]
        trans = self.transitions[trans]
        instr = trans[1][1]
        typ = trans[0]
        return (typ == 'CALL' or typ == 'RET' or
                    (isinstance(state, str)) or
                    typ == 'SM+' or
                    typ == 'DYN' or
                    (instr != None and
                    instr.address in self.sm_targets))

    def get_next_state(self, to_state, source_map):
        if self.is_valid_rule_state(to_state, source_map):
            return to_state
        trans = list(source_map[to_state])[0]
        trans = self.transitions[trans]
        # print(trans)
        instr = trans[1][1]
        typ = trans[0]
        # print(trans[1][2])
        visited = set()
        # print(trans)
        while not self.is_valid_rule_state(trans[1][2], source_map):
            # print('Yes')
            # print(visited)
            if trans[1][2] in visited:
                # print('Nope')
                return trans[1][2]
            visited.add(trans[1][2])
            trans = list(source_map[trans[1][2]])[0]
            trans = self.transitions[trans]
            # print(trans)
        return trans[1][2]

    def hashable_trans(self, t):
        if t[1][1] == None:
            return t[1]
        return (t[1][0], bytes(t[1][1].bytes), t[1][2])

    def ltrans_diff(self, old, new):
        old_set = set()
        for t in old:
            old_set.add(t)
        new_set = set()
        for t in new:
            new_set.add(t)

        res_old = []
        for t in old:
            if t in new_set:
                continue
            res_old.append(t)
        res_new = []
        for t in new:
            if t in old_set:
                continue
            res_new.append(t)
        return tuple(res_old), tuple(res_new)

    def get_rules_from_transtion(self, ltransition, source_map):

        rules = []
        typ = ltransition[0]
        transition = ltransition[1]
        instr = transition[1]
        from_state = transition[0]
        to_state = transition[2]
        next_trans = transition

        # print('Transition: {}'.format(ltransition))
        if not self.is_valid_rule_state(from_state, source_map):
            # print('Skip.')
            return []

        to_state = self.get_next_state(to_state, source_map)

        rule_names = []
        if typ == 'CALL':
            pushes = transition[4]
            next_state = to_state
            for top in set(transition[3]).union(['$']):
                from_state = transition[0]
                if top != '$':
                    top = self.get_next_state(top, source_map)
                i = 0
                while i < len(pushes):
                    if i + 1 < len(pushes):
                        next_state = ('aux_{}_{}'.format(to_state[0], i), to_state[1])
                    else:
                        next_state = to_state
                    for v in pushes[i]:
                        rule_names.append(self.add_rule((from_state, top, next_state, self.get_next_state(v, source_map), top)))
                    from_state = next_state
                    i += 1
        elif typ == 'RET':
            rule_names.append(self.add_rule((from_state, '$', to_state, '$')))
            next_state = to_state
            from_state = transition[0]
            for top in transition[3]:
                if top != '$':
                    top = self.get_next_state(top, source_map)
                if top != '$':
                    rule_names.append(self.add_rule((from_state, top, top, '')))
        elif typ == 'SM+':
            sm = ltransition[2]
            old_t, new_t = self.ltrans_diff(sm[0], sm[1])

            new_source_map = source_map.copy()
            for name in old_t:
                t = self.transitions[name]
                new_edges = set()
                if t[1][0] in new_source_map:
                    for e in new_source_map[t[1][0]]:
                        if e == name:
                            continue
                        new_edges.add(e)
                new_source_map[t[1][0]] = new_edges

            for name in new_t:
                t = self.transitions[name]
                if not t[1][0] in new_source_map:
                    new_source_map[t[1][0]] = set()
                new_source_map[t[1][0]].add(name)

            print('Analyzing modified transitions...')

            old_rules = []
            new_rules = []
            try:
                for t in old_t:
                    old_rules += self.get_rules_from_transtion(self.transitions[t], new_source_map)

                for t in new_t:
                    new_rules += self.get_rules_from_transtion(self.transitions[t], new_source_map)
            except Exception:
                raise
            print('Analysis of modified transitions finished.')

            rule_names.append(self.add_rule((from_state, (frozenset(old_rules), frozenset(new_rules)), to_state)))
        elif typ == 'DYN':
            # print('Standard trasitions for pushed {}'.format(self.pushed_values))
            for top in set(transition[3]).union(['$']):
                if top != '$':
                    top = self.get_next_state(top, source_map)
                addrs = ltransition[2]
                for addr in addrs:
                    rule_names.append(self.add_rule((from_state, top, to_state, top, '', addr)))
        else:
            # print('Standard trasitions for pushed {}'.format(self.pushed_values))
            for top in set(transition[3]).union(['$']):
                if top != '$':
                    top = self.get_next_state(top, source_map)
                rule_names.append(self.add_rule((from_state, top, to_state, top)))
        return rule_names

    def fill_transition_source_map(self):
        for (i, t) in self.transitions.items():
            if not t[1][0] in self.source_map:
                self.source_map[t[1][0]] = set()
            self.source_map[t[1][0]].add(i)

    def fill_pushed_values(self):
        trans = self.transitions.copy()

        for (i, t) in trans.items():
            if t[0] == 'CALL':
                for opts in t[1][3]:
                    for v in opts:
                        self.pushed_values.add(self.get_next_state(v, self.source_map))

    def fill_sm_targets(self):
        for t in self.transitions.values():
            if t[0] == 'SM+':
                sm = t[2]
                old_t, new_t = self.ltrans_diff(sm[0], sm[1])
                for tt in old_t:
                    if self.transitions[tt][1][1] != None:
                        self.sm_targets.add(self.transitions[tt][1][1].address)

    def analyze_transitions(self):
        print('Converting CFG into SM-DPDS rules...')
        print('Total {} transitions to analyze...'.format(len(self.transitions)))
        source_map = {}
        for i in self.init_trans:
            t = self.transitions[i]
            if not t[1][0] in source_map:
                source_map[t[1][0]] = set()
            source_map[t[1][0]].add(i)

        init_names = []
        for name in self.init_trans:
            t = self.transitions[name]
            init_names += self.get_rules_from_transtion(t, source_map)
        self.init_phase = init_names
        print('Initial phase contains {} rules'.format(len(self.init_phase)))

        entry = self.entry_location
        for e in self.entries:
            r_name = 'entry_rule_{}'.format(e)
            self.all_rules[r_name] = (entry, '$', e, '$')
            self.init_phase = self.init_phase + [r_name]

        return self.all_rules

    def get_name(self, name):
        return '{}{}'.format(self.prefix, name)

    def get_gamma(self, symbol):
        return '{}'.format(symbol).replace(' ', '')

    def get_init_state(self):
        entry = self.get_name(self.entry_location)
        return (entry, '$', frozenset(self.init_phase))

    def to_analyzable(self, dclics):
        pickled_rules, pickled_entries = self.all_rules, self.entries
            # exit()
        rules = {}
        sm_rules = {}
        states = set()
        alphabet = set()
        for (old_name, r) in pickled_rules.items():
            # name = self.get_name(old_name)
            name = old_name
            states.add(self.get_name(r[0]))
            states.add(self.get_name(r[2]))
            if len(r) > 3:
                alphabet.add(self.get_gamma(r[1]))
                if r[3] != '':
                    alphabet.add(self.get_gamma(r[3]))
                if len(r) > 4:
                    if r[4] != '':
                        alphabet.add(self.get_gamma(r[4]))
                        rules[name] = (self.get_name(r[0]), self.get_gamma(r[1]), self.get_name(r[2]), '{} {}'.format(self.get_gamma(r[3]), self.get_gamma(r[4])))
                    if len(r) > 5:
                        init = dclics[(r[5][0], r[5][1])]
                        rules[name] = (self.get_name(r[0]), self.get_gamma(r[1]), self.get_name(r[2]), self.get_gamma(r[3]), init[0], init[1], init[2])
                else:
                    rules[name] = (self.get_name(r[0]), self.get_gamma(r[1]), self.get_name(r[2]), self.get_gamma(r[3]))
            if len(r) == 3:
                sm_rules[name] = (self.get_name(r[0]), r[1], self.get_name(r[2]))
        # 'syscall_send_from_73072'

        alphabet.add('$')

        return (states, alphabet, rules, sm_rules), self.get_init_state()



proc_counter = 0

class CFG_Constructor:
    REG_INST_OFFSET = 0
    trans_offset = 0
    supported_regs = [  ]
    max_reg_values = 2
    proc_left = None

    visited_dclics = {}

    parallel = []
    fast_cfgs = {}

    @staticmethod
    def new_mirai():
        c = CFG_Constructor('mal_mirai_x86_sm_cc.elf')
        return c

    @staticmethod
    def load_cfg():
        c = CFG_Constructor('mal_mirai_x86_sm_cc.elf')
        c.construct_cfg()
        return c

    @staticmethod
    def load_transitions(filename):
        c = CFG_Constructor(filename)
        c.construct_cfg()
        return c

    def __init__(self, filename: str, keep_state=True, max_steps=None, entry=None, angr_sm=False, max_proc=None,
                 syscalls=None, fast=False, context_sensitivity=0, base_state=None, avoid=None, base_fast=None, prints=False, naive=False):
        if max_proc != None:
            CFG_Constructor.proc_left = max_proc - 1
        self.context_sensitivity = context_sensitivity
        self.naive = naive
        self.fast = fast
        self.base_fast = base_fast
        self.total_syscalls = syscalls
        self.syscalls = None
        global proc_counter
        if syscalls != None and len(syscalls) > proc_counter:
            self.syscalls = syscalls[proc_counter]
            print(self.syscalls)
        self.avoid = avoid
        self.fast_cfg = None
        self.patch_filename = self.create_patch_file(filename)
        self.max_processes = max_proc
        self.max_steps = max_steps
        self.keep_state = keep_state
        self.entry = entry
        self.angr_sm = angr_sm
        self.prints = prints

        self.project = angr.Project(filename, load_options={'auto_load_libs': False})
        self.base_state = base_state
        # if base_state == None:
        #     self.base_stat = self.project.factory.entry_state()
        self.cfg = None
        self.entries = []

        self.address_to_node = {}

        self.register_instances = {}
        self.register_instance_values = {}
        self.pushed_values = set()

        self.transitions = {}
        self.transitions_names = {}
        self.node_transitions = {}

        self.basic_edges = {}
        self.arch_helper = arch_helper.ArchHelper.get(self.project)
        self.interesting_calls = {}

        self.returns = {}
        self.spawns = {}

    def get_or_add_transition(self, trans):
        key = (trans[0], trans[1][0], None if trans[1][1] == None else bytes(trans[1][1].bytes), trans[1][2])
        if not key in self.transitions_names:
            name = 't_{}'.format(CFG_Constructor.trans_offset)
            CFG_Constructor.trans_offset += 1
            self.transitions_names[key] = name
            self.transitions[name] = trans
        return self.transitions_names[key]

    def create_patch_file(self, filename):
        patch_filename = '{}_SMDPDS_patch'.format(filename)
        shutil.copyfile(filename, patch_filename)
        return patch_filename

    def modify_patch(self, addr, value, byte_size):
        with open(self.patch_filename, 'r+b') as f:
            mm = mmap.mmap(f.fileno(), 0)
            isLE = self.project.arch.memory_endness == self.project.arch.memory_endness.LE

            if isinstance(value, int):
                byte_value = value.to_bytes(byte_size, 'little' if isLE else 'big')
            else:
                byte_value = value
            mm[addr:addr+byte_size] = byte_value
            mm.flush()


    def fill_address_to_node(self):
        for node in self.cfg.nodes():
            if node.block != None:
                try:
                    instructions = node.block.disassembly.insns
                    for ins in instructions:
                        self.address_to_node[ins.address] = node
                except KeyError:
                    continue

    def get_or_add_reg_instance(self, instance):
        key = tuple( instance[r] for r in self.supported_regs )
        if not key in self.register_instances:
            self.register_instances[key] = self.REG_INST_OFFSET
            self.register_instance_values[self.REG_INST_OFFSET] = instance
            self.REG_INST_OFFSET += 1
        return self.register_instances[key]

    def listen_spawn(self, state):
        name = state.inspect.simprocedure_name
        # print(name, self.arch_helper.is_dynamic_procedure(name))
        if self.arch_helper.is_dynamic_procedure(name):
            dclic = (state.copy(), name)
            self.spawns[state.scratch.ins_addr] = self.spawns.get(state.scratch.ins_addr, []) + [dclic]
            # print(dclic)
            # print(state.scratch.ins_addr)
            # print(dclic[0].solver.eval_upto(dclic[0].regs.r8, 4))
            # exit()

    def construct_cfg(self):
        if self.entry == None:
            start_state = self.project.factory.entry_state()
        else:
            start_state = self.project.factory.blank_state(addr=self.entry)
        for r in CFG_Constructor.supported_regs:
            setattr(start_state.regs, r, 0x0)

        if self.fast:
            print('Constructing Full Coverage (-c)...')
            if self.project.filename in CFG_Constructor.fast_cfgs:
                cfg_fast = self.fast_cfgs[self.project.filename]
                print('Found constructed CFG')
            else:
                # cfg_filename = '{}_fast_cfg.pkl'.format(self.project.filename)
                # if os.path.isfile(cfg_filename):
                #     print('Found pickled CFG...')
                #     with open(cfg_filename, 'rb') as f:
                #         cfg_fast = pickle.load(f)
                # else:
                #     cfg_fast = self.project.analyses.CFGFast(skip_unmapped_addrs=False)
                #     print('Saving CFG...')
                #     with open(cfg_filename, 'wb') as f:
                #         pickle.dump(cfg_fast , f)

                cfg_fast = self.project.analyses.CFGFast(skip_unmapped_addrs=False)
                CFG_Constructor.fast_cfgs[self.project.filename] = cfg_fast
            self.fast_cfg = cfg_fast
            # print('Constructing Emulated CFG...')
            self.cfg = cfg_fast
            # self.cfg = self.project.analyses.CFGEmulated(keep_state=self.keep_state, context_sensitivity_level=self.context_sensitivity, initial_state=self.base_state,
            #                                              starts=[start_state.addr], max_steps=self.max_steps, base_graph=cfg_fast.model.graph, avoid_runs=self.avoid)
        else:
            if self.base_state == None:
                self.base_state = start_state.copy()
            else:
                self.base_state = self.base_state.copy()
            self.base_state.inspect.b('simprocedure', when=angr.BP_BEFORE, action=lambda s: self.listen_spawn(s))
            self.cfg = self.project.analyses.CFGEmulated(keep_state=self.keep_state, context_sensitivity_level=self.context_sensitivity, initial_state=self.base_state,
                                                         starts=[start_state.addr], max_steps=self.max_steps, avoid_runs=self.avoid)

        self.entries = self.get_sm_dpds_states(start_state)

        self.compute_basic_edges()
        self.fill_address_to_node()
        for e in self.entries:
            CFG_Constructor.visited_dclics[(self.project.filename, e)] = None

        return self.cfg

    def compute_basic_edges(self):
        print('Computing basic edges...')
        for node in self.cfg.model.nodes():
            self.basic_edges[node.addr] = [ s.addr for s in node.successors ]

    def is_interesting_syscall(self, state):
        if self.syscalls == None:
            return True
        for s in self.syscalls:
            if state.find(s) != -1:
                return True
        return False

    def is_call_interesting(self, transition_name, source_map):
        if transition_name in self.interesting_calls:
            return self.interesting_calls[transition_name]
        transition = self.transitions[transition_name]

        if transition[0] == 'RET':
            interesting = False
            self.interesting_calls[transition_name] = interesting
            return False
        elif transition[0] == 'SM+' or transition[0] == 'DYN' or (
            isinstance(transition[1][2], str) and self.is_interesting_syscall(transition[1][2])
        )  or (
            isinstance(transition[1][0], str) and self.is_interesting_syscall(transition[1][0])
        ):
            interesting = True
            self.interesting_calls[transition_name] = interesting
            return True

        # self.interesting_calls[transition_name] = False
        interesting = False
        queue = source_map.get(transition[1][2], []).copy()
        visited = set()
        while len(queue) > 0:
            t = queue.pop()
            if not t in visited:
                visited.add(t)
                if t in self.interesting_calls:
                    if self.interesting_calls[t]:
                        interesting = True
                        break
                    continue
                transition = self.transitions[t]
                if transition[0] == 'RET':
                    continue
                if transition[0] == 'SM+' or transition[0] == 'DYN' or (
                    isinstance(transition[1][2], str) and self.is_interesting_syscall(transition[1][2])
                )  or (
                    isinstance(transition[1][0], str) and self.is_interesting_syscall(transition[1][0])
                ):
                    interesting = True
                    break

                if transition[0] == 'CALL':
                    pushes = [ s for v in transition[1][4] for s in v ]
                    for p in pushes:
                        queue += source_map.get(p, [])
                for tt in source_map.get(transition[1][2], []):
                    if not tt in queue:
                        queue.append(tt)

        self.interesting_calls[transition_name] = interesting
        return interesting

    def prune_dead_transitions(self):
        print('Pruning transition that do not lead to syscalls...')
        source_map = {}
        for (name, t) in self.transitions.items():
            # print(t)
            source_map[t[1][0]] = source_map.get(t[1][0], []) + [name]

        new_trans = []
        for (name, t) in list(self.transitions.items()):
            if self.is_call_interesting(name, source_map):
                pass
            else:
                if name in self.init_trans:
                    queue = []
                    if t[0] == 'CALL':
                        pushes = [ s for v in t[1][4] for s in v ]
                        for p in pushes:
                            self.init_trans.append(self.get_or_add_transition(('STANDARD', (t[1][0], t[1][1], p, t[1][3]))))
                        self.init_trans.remove(name)

        return new_trans

    def loop_dead_transitions(self):
        source_map = {}
        for t in self.init_trans:
            t = self.transitions[t]
            source_map[t[1][0]] = source_map.get(t[1][0], []) + [t]
        for t in list(self.transitions.values()):
            if not t[1][2] in source_map:
                name = self.get_or_add_transition(('STANDARD', (t[1][2], None, t[1][2], ())))
                source_map[t[1][2]] = [name]
                self.init_trans.append(name)

    # def analyze_by_functions(self):


    def construct_result_cfg(self):
        self.construct_cfg()
        self.construct_standard_transitions()
        self.analyze_dynamic_transitions()
        self.prune_dead_transitions()
        self.loop_dead_transitions()
        self.propagate_returns()
        return self.get_transitions()

    def analyze_dynamic_transitions(self):
        print('Analyzing dynamic transitions...')
        for (name, t) in self.transitions.items():
            if t[0] == 'DYN':
                print(t)
                for spawn in t[2]:
                    if (CFG_Constructor.proc_left == None or CFG_Constructor.proc_left > 0) and (spawn[0], spawn[1]) not in CFG_Constructor.visited_dclics:
                        print('Analyzing Dynamic Transition for process {} at {} [{}]'.format(spawn[0], spawn[1], spawn))
                        CFG_Constructor.visited_dclics[(spawn[0], spawn[1])] = None
                        if CFG_Constructor.proc_left != None:
                            CFG_Constructor.proc_left -= 1
                        global proc_counter
                        prefix = 'dyn_{}_'.format(proc_counter)
                        proc_counter += 1
                        par = CFG_Constructor(spawn[0], entry=spawn[1], keep_state=self.keep_state, max_steps=self.max_steps, angr_sm=self.angr_sm,
                                              fast=self.fast, context_sensitivity=self.context_sensitivity,base_state=spawn[2], base_fast=self.fast_cfg, 
                                              naive=self.naive, syscalls=self.total_syscalls)
                        par.construct_result_cfg()
                        d = SM_DPDS_Constructor(par.get_transitions(), par.entries, par.init_trans, prefix=prefix)

                        d.analyze_transitions()
                        CFG_Constructor.parallel.append(d)
                        CFG_Constructor.visited_dclics[(spawn[0], spawn[1])] = d.get_init_state()

        return self.transitions


        print('Simplifying return locations done.')

    def propagate_returns(self):
        print('Propagating returns to reduce number of rules...')


        trans_map = {}
        for (name, t) in self.transitions.items():
            trans_map[t[1][0]] = set(list(trans_map.get(t[1][0], [])) + [name])

        new_trans = []
        for (name, t) in self.transitions.items():
            if t[0] == 'CALL':
                pushes = []
                for p in t[1][4]:
                    for v in p:
                        pushes.append(v)
                queue = [t[1][2]]
                visited = set()
                while len(queue) > 0:
                    state = queue.pop()
                    # if state in visited:
                    #     continue
                    transitions_i = trans_map.get(state, [])
                    for i in transitions_i:
                        if i in visited:
                            continue
                        visited.add(i)
                        rets = self.transitions[i][1][3]
                        new_rets = list(set(list(rets) + pushes))
                        if tuple(new_rets) == rets:
                            continue
                        new_trans = list(self.transitions[i])
                        new_t = list(new_trans[1])
                        new_t[3] = tuple(new_rets)
                        new_trans[1] = tuple(new_t)
                        self.transitions[i] = tuple(new_trans)
                        if self.transitions[i][0] == 'RET':
                            continue
                        if self.transitions[i][0] == 'CALL':
                            for p in self.transitions[i][1][4]:
                                for v in p:
                                    queue.append(v)
                            continue
                        if self.transitions[i][1][0] == self.transitions[i][1][2]:
                            continue
                        queue.append(new_trans[1][2])

    def construct_standard_transitions(self):
        if self.fast:
            cfg = self.fast_cfg
        else:
            cfg = self.cfg
        self.init_trans = []
        for node in cfg.nodes():
            if self.prints:
                print('Reading Node {}'.format(node))
            if node.block != None:
                trans = self.analyze_block_node(node)
                self.node_transitions[node.addr] = self.node_transitions.get(node.addr, []) + trans
                self.init_trans += trans
            if self.prints:
                print('Currently {} transitions'.format(len(self.transitions)))
        return self.get_transitions()


    def get_sm_dpds_states(self, state, addr=None):
        regs = {}
        if state != None:
            for reg_name in self.supported_regs:
                # if state.regs.get(reg_name).uninitialized:
                #     regs[reg_name] = '-'
                #     continue
                try:
                    # print('Trying {}'.format(state.regs.get(reg_name)))
                    state.solver.eval(state.regs.get(reg_name))
                    regs[reg_name] = state.solver.eval_atmost(state.regs.get(reg_name), CFG_Constructor.max_reg_values)
                except angr.errors.SimUnsatError:
                    regs[reg_name] = '-'
                except angr.errors.SimValueError:
                    regs[reg_name] = '-'
            address = state.addr
        else:
            address = addr
        queue = []
        queue.append({ n: (v[0] if v != '-' else '-') for (n, v) in regs.items()})
        for (n, v) in regs.items():
            if v == '-':
                continue
            for val in v[1:]:
                for ins in queue.copy():
                    new_ins = ins.copy()
                    new_ins[n] = val
                    queue.append(new_ins)
        return [ (address if addr == None else addr, self.get_or_add_reg_instance(ins)) for ins in queue ]

    def get_next_instr_address(self, instr: capstone.CsInsn):
        return instr.address + instr.size

    def is_dynamic_procedure(self, procedure):
        return self.arch_helper.is_dynamic_procedure(procedure.simprocedure_name)

    def get_dynamic_procedure_addresses(self, instr, sim_state, name):
        print(type(self.arch_helper), type(self.arch_helper.os_helper))
        addrs = self.arch_helper.get_created_process_addresses(instr, sim_state, name)
        print(addrs)

        states = []
        for addr in addrs:
            states.append((self.project.filename, addr, sim_state.copy()))

        return states

    def add_node_successor_transition(self, exit_inst, next_node, state, loop_check=None, orig_return=None):
        trans = []
        from_states = self.get_sm_dpds_states(state, exit_inst.address)
        ret_states = tuple()
        if orig_return == None:
            orig_return = exit_inst.address + exit_inst.size

        if next_node.simprocedure_name != None:
            name = 'syscall_{}_from_{}'.format(next_node.simprocedure_name, exit_inst.address)
            if self.is_dynamic_procedure(next_node):
                if exit_inst.address in self.spawns:
                    spawns = self.spawns[exit_inst.address]
                    dclics = [ self.get_dynamic_procedure_addresses(exit_inst, state, name) for (state, name) in spawns ]
                    to_states = self.get_sm_dpds_states(state, orig_return)
                    for dclic in dclics:
                        for from_state in from_states:
                            trans.append(self.get_or_add_transition(('DYN', (from_state, exit_inst, name, ret_states), tuple(dclic))))
                    # print(dclics)
                    # exit()
                else:
                    dclics = self.get_dynamic_procedure_addresses(exit_inst, state.copy(), next_node.simprocedure_name)
                    to_states = self.get_sm_dpds_states(state, orig_return)
                    for from_state in from_states:
                        trans.append(self.get_or_add_transition(('DYN', (from_state, exit_inst, name, ret_states), tuple(dclics))))
                for to_state in to_states:
                    trans.append(self.get_or_add_transition(('STANDARD', (name, exit_inst, to_state, ret_states))))
            else:
                for from_state in from_states:
                    trans.append(self.get_or_add_transition(('STANDARD', (from_state, exit_inst, name, ret_states))))

                to_states = self.get_sm_dpds_states(state, orig_return)

                for to_state in to_states:
                    trans.append(self.get_or_add_transition(('STANDARD', (name, None, to_state, ret_states))))

            if len(next_node.successors) == 0:
                trans.append(self.get_or_add_transition(('STANDARD', (name, None, name, ret_states))))
        elif next_node.block != None and next_node.addr in self.address_to_node and len(next_node.block.disassembly.insns) > 0 and next_node.block.disassembly.insns[0].insn.mnemonic == 'jmp':
            if loop_check == None:
                loop_check = set()

            if next_node.addr in loop_check:
                return []
            loop_check.add(next_node.addr)
            trans = []
            for succ in next_node.successors:
                trans += self.add_node_successor_transition(exit_inst, succ, state, loop_check, orig_return)
            return trans
        else:
            pushed_values = []
            to_states = self.get_sm_dpds_states(state, next_node.addr)
            if self.arch_helper.is_call(exit_inst) and next_node.addr != self.get_next_instr_address(exit_inst):
                typ = 'CALL'
                return_addr = (exit_inst.address + exit_inst.size)
                pushed_values = [ tuple(self.get_sm_dpds_states(state, return_addr)) ]
                self.returns[next_node.addr] = self.returns.get(next_node.addr, []) + list(self.get_sm_dpds_states(state, return_addr))
            elif self.arch_helper.is_return(exit_inst) and next_node.addr != self.get_next_instr_address(exit_inst):
                typ = 'RET'
            else:
                typ = 'STANDARD'
            for from_state in from_states:
                for to_state in to_states:
                    trans.append(self.get_or_add_transition((typ, (from_state, exit_inst, to_state, ret_states, tuple(pushed_values)))))
        return trans


    def add_terminate_transition(self, exit_inst, state):
        trans = []
        from_states = self.get_sm_dpds_states(state, exit_inst.address)
        ret_states = tuple()

        if self.arch_helper.is_return(exit_inst):
            for from_state in from_states:
                trans.append(self.get_or_add_transition(('RET', (from_state, None, from_state, ret_states))))
        else:
            for from_state in from_states:
                trans.append(self.get_or_add_transition(('STANDARD', (from_state, None, from_state, ret_states))))
        return trans

    def analyze_block_node(self, node):
        emulate = True
        input_state = node.input_state if hasattr(node, 'input_state') else None
        if input_state == None:
            input_state = self.project.factory.blank_state(addr=node.addr, options=angr.options.unicorn)
            emulate = False
        if not node.addr in self.address_to_node:
            return []
        if node.block.disassembly.insns[0].insn.mnemonic == 'jmp':
            return []
        instructions = { i.insn.address : i for i in node.block.disassembly.insns }
        new_transitions = []
        # print(instructions)
        states_before = dict()
        s = input_state.copy()

        sm_instructions = {}
        def check_sm_write(state):
            concrete_targets = []
            # print('Checkign sm for', state.inspect.mem_write_address)
            try:
                evaled = state.solver.eval_atmost(state.inspect.mem_write_address, 4)
                concrete_targets += evaled
                # print(concrete_targets)
            except angr.errors.SimUnsatError:
                pass
            except angr.errors.SimValueError:
                return
            for trg in concrete_targets:
                section = state.project.loader.main_object.find_section_containing(trg)
                if section == None:
                    continue
                if section.is_executable:
                    try:
                        values = state.solver.eval_atmost(state.inspect.mem_write_expr, 4)
                        sm_instructions[state.addr] = (trg, values, state.inspect.mem_write_length)
                    except angr.errors.SimUnsatError:
                        return
                    except angr.errors.SimValueError:
                        return

        s.inspect.b('mem_write', when=angr.BP_AFTER, action=check_sm_write)
        bp_before = s.inspect.b('instruction', when=angr.BP_BEFORE,
                                            # condition=lambda s: s.inspect.instruction + 4 in instructions,
                                            action=lambda s: states_before.update({ s.inspect.instruction : s.copy() }))
        try:
            if not self.naive:
                s.step()
            pass
        except angr.errors.SimOperationError:
            pass
        except angr.errors.SimSolverModeError:
            pass
        except angr.errors.SimIRSBNoDecodeError:
            pass

        for instr in node.block.disassembly.insns[:-1]:
            # instr_transitions = self.analyze_instruction_before(instructions[addr], self.get_next_instr_address(instructions[addr].insn) , s)
            instr_transitions = self.analyze_instruction_before2(instr.insn, input_state)
            if instr.insn.address in sm_instructions:
                for name in instr_transitions:
                    t = self.transitions[name]
                    new_transitions += self.analyze_sm_transition(( 'SM', t[1], sm_instructions[instr.insn.address] ))
            else:
                for t in instr_transitions:
                    new_transitions.append(t)

        if len(node.block.disassembly.insns) > 0:
            exit_inst = node.block.disassembly.insns[-1].insn
        else:
            exit_inst = None

        if exit_inst != None:
            # if hasattr(node, 'final_states') and len(node.final_states) > 0 and len(node.successors) > 0:
            #     for exit_state in node.final_states:
            #         for succ in node.successors:
            #             try:
            #                 if exit_state.addr == succ.addr:
            #                     new_transitions += self.add_node_successor_transition(exit_inst, succ, exit_state)
            #             except angr.errors.SimUnsatError:
            #                 pass
            #             except angr.errors.SimSolverModeError:
            #                 pass
            if len(node.successors) > 0:
                for succ in node.successors:
                    if exit_inst.address in states_before:
                        state = states_before[exit_inst.address]
                    elif hasattr(succ, 'input_state') and succ.input_state != None:
                        state = succ.input_state
                    else:
                        state = input_state
                    new_transitions += self.add_node_successor_transition(exit_inst, succ, state)

            if len(node.successors) == 0:
                new_transitions += self.add_terminate_transition(exit_inst, states_before.get(exit_inst.address, input_state))

        s.inspect.remove_breakpoint('instruction', filter_func=lambda x: True)
        s.inspect.remove_breakpoint('mem_write', filter_func=lambda x: True)
        return new_transitions

    def analyze_instruction_before2(self, instr, state):
        # instr: capstone.CsInsn = instr.insn
        # print('RAM memory % used:', psutil.virtual_memory()[2])
        # print('Translating 0x{:02x}'.format(instr.address))

        from_states = self.get_sm_dpds_states(state, instr.address)
        new_trans = []
        for from_state in from_states:
            to_states = self.get_sm_dpds_states(state, self.get_next_instr_address(instr))

            for to_state in to_states:
                new_trans.append(self.get_or_add_transition(('STANDARD', (from_state, instr, to_state, tuple()))))
        return new_trans

    def analyze_modified_node(self, node: angr.knowledge_plugins.cfg.CFGENode, addr, value, size):

        offset = self.project.loader.main_object.addr_to_offset(addr)

        self.modify_patch(offset, value, size)

        patch_project = angr.Project(self.patch_filename, load_options={'auto_load_libs': False})

        if node != None:
            node_addr = node.addr
            state = patch_project.factory.blank_state(addr=node_addr)
            if hasattr(node, 'input_state') and node.input_state != None:
                state.registers = node.input_state.registers
                state.memory = node.input_state.memory
        else:
            return []


        print('Found SM instruction writing {:02x} to {:02x}'.format(value, addr))
        print('Analyzing modified node at {:02x}...'.format(addr))


        new_cfg = patch_project.analyses.CFGEmulated(initial_state=state, starts=[node.addr], keep_state=self.keep_state)
        print(new_cfg.nodes())
        # print(patch_project.loader.main_object.memory.load(addr, 16))
        new_transitions = []
        for new_node in new_cfg.nodes():
            if new_node.addr == node_addr:
                # print(new_node.block.disassembly)
                # print(new_node.successors)
                # print(new_node.successors[0].successors)
                # exit()
                if new_node.block != None:
                    new_transitions += self.analyze_block_node(new_node)
        return new_transitions

    def analyze_sm_transition(self, transition):
        new_transitions = []

        sm_addr = transition[2][0]
        values = transition[2][1]
        size = transition[2][2]

        node = self.get_node_of_address(sm_addr)
        if node != None:
            old_trans = self.analyze_block_node(node)
        else:
            old_trans = []
        for value in values:
            new_trans = self.analyze_modified_node(node, sm_addr, value, size)
            new_transitions.append(self.get_or_add_transition(('SM+', transition[1], (frozenset(old_trans).difference(new_trans), frozenset(new_trans).difference(old_trans)))))

        return new_transitions

    def get_node_of_address(self, addr):
        max_offset = -16
        offset = 0
        while (not addr + offset in self.address_to_node and offset > max_offset):
            offset -= 1

        return self.address_to_node.get(addr + offset, None)

    def get_transitions(self):
        return self.transitions

    def construct_smdpn(self):
        self.construct_result_cfg()
        d = SM_DPDS_Constructor(self.transitions, self.entries, self.init_trans)
        d.analyze_transitions()

        main, entry = d.to_analyzable(CFG_Constructor.visited_dclics)
        smdpn = [main]
        for (i, d) in enumerate(self.parallel):
            dpds, init = d.to_analyzable(CFG_Constructor.visited_dclics)
            smdpn.append(dpds)



        return smdpn, [ entry ]
