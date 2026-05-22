import capstone, angr, monkeyhex

class ArchHelper:
    def __init__(self, project):
        self.os_helper = OsHelper.get(project)
        pass
    def is_dynamic_procedure(self, name):
        raise NotImplementedError
    def get_created_process_addresses(self, instr, state, name):
        raise NotImplementedError
    def is_call(self, instr):
        raise NotImplementedError
    def is_return(self, instr):
        raise NotImplementedError
    def dynamic_function_ret_addr(self, inst):
        raise NotImplementedError

    @staticmethod
    def get(project: angr.Project):
        if project.arch.name in ['X86', 'AMD64']:
            return x86Helper(project)
        if project.arch.name == 'ARMEL':
            return ARMHelper(project)
        print(project.arch.name)
        raise NotImplementedError

class OsHelper:
    def __init__(self, project):
        self.project = project
        pass
    def is_dynamic(self, name):
        raise NotImplementedError
    def get_spawn_location(self, state, name):
        raise NotImplementedError
    def get_syscall_ret_addr(self, instr):
        raise NotImplementedError

    @staticmethod
    def get(project):
        if project.loader.main_object.os == 'windows':
            return WinHelper(project)
        if project.loader.main_object.os.upper().find('UNIX') != -1:
            return LinuxHelper(project)

        print(project.loader.main_object.os)
        raise NotImplementedError(project.loader.main_object.os)

class WinHelper(OsHelper):
    def __init__(self, project):
        super().__init__(project)

    def is_dynamic(self, name):
        return name in ['CreateThread', 'CreateThreadA', 'CreateThreadEx',
                        # 'CreateProcess', 'CreateProcessW', 'CreateProcessA', 'CreateProcessAsUserA', 'CreateProcessAsUserW'
                        ]

    def get_spawn_location(self, state, name):
        if name in ['CreateThread', 'CreateThreadA', 'CreateThreadEx']:
            addr_arg_num = 2
        else:
            print(name)
            raise NotImplementedError

        print(state)
        print(addr_arg_num, self.project.arch.bits)

        if self.project.arch.bits == 32:
            offset = (state.project.arch.bits // 8) * addr_arg_num
            # print(state.memory.load(state.regs.sp, 4, endness=self.project.arch.memory_endness))
            # print(state.memory.load(state.regs.sp + 4, 4, endness=self.project.arch.memory_endness))
            # print(state.memory.load(state.regs.sp + 8, 4, endness=self.project.arch.memory_endness))
            # print(state.memory.load(state.regs.sp + 12, 4, endness=self.project.arch.memory_endness))
            # print(state.memory.load(state.regs.sp + offset, 3, endness=self.project.arch.memory_endness))
            # exit()
            return state.memory.load(state.regs.sp + offset, 3, endness=self.project.arch.memory_endness)
        elif self.project.arch.bits == 64:
            regs = [ 'rcx', 'rdx', 'r8', 'r9']
            # print(regs[addr_arg_num])
            # print(state.regs.get(regs[addr_arg_num]))
            # print(state.regs.get(regs[0]))
            # print(state.regs.get(regs[1]))
            # print(state.regs.get(regs[2]))
            # print(state.regs.get(regs[3]))
            # print(state.solver.eval(state.regs.get(regs[addr_arg_num ])))
            # exit()
            return state.regs.get(regs[addr_arg_num])
        else:
            raise NotImplementedError
    def get_syscall_ret_addr(self, instr):
        if self.project.arch.bits == 32:
            return None
        elif self.project.arch.bits == 64:
            return instr.address + instr.size
        raise NotImplementedError

class LinuxHelper(OsHelper):
    def __init__(self, project):
        super().__init__(project)

    def is_dynamic(self, name):
        return name in ['fork']

    def get_spawn_location(self, state, name):
        return state.addr
    def get_syscall_ret_addr(self, instr):
        return instr.address + instr.size

class x86Helper(ArchHelper):
    def __init__(self, project):
        super().__init__(project)

    def is_dynamic_procedure(self, name):
        return self.os_helper.is_dynamic(name)

    def get_created_process_addresses(self, instr: capstone.CsInsn, state: angr.SimState, name):
        addrs = []
        # print()
        # print('{:02x}'.format(state.solver.eval(state.memory.load(state.regs.sp + offset, 3))))
        # exit()
        try:
            vals = state.solver.eval_atmost(self.os_helper.get_spawn_location(state, name), 2)
            for val in vals:
                addrs.append(val)
            return addrs
        except angr.SimValueError:
            return []

    def is_call(self, instr):
        return instr.mnemonic == 'call'
    def is_return(self, instr):
        return instr.mnemonic == 'ret'
    def dynamic_function_ret_addr(self, inst):
        return self.os_helper.get_syscall_ret_addr(inst)


class ARMHelper(ArchHelper):
    dynamic_functions = [
        'fork'
    ]
    def __init__(self, project):
        super().__init__(project)

    def is_dynamic_procedure(self, name):
        return name in self.dynamic_functions

    def get_created_process_addresses(self, instr: capstone.CsInsn, state: angr.SimState, name):
        return [ instr.address + instr.size ]

    def is_call(self, instr):
        return instr.mnemonic in [ 'bl', 'blls', 'blgt', 'bllt', 'blal', 'blge', 'blle', 'bleq', 'blne', 'blcc', 'bllo', 'blhs', 'blcs', 'blmi', 'blpl', 'blvs', 'blhi', 'blvc' ]
    def is_return(self, instr):
        return instr.mnemonic.startswith('b') and instr.op_str == 'lr'

    def dynamic_function_ret_addr(self, inst):
        return inst.address + inst.size