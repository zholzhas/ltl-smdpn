from util import *
import glob
import smdpn_constructor
import os
import pickle
import optimized

if __name__ == '__main__':
    smdpn_constructor.memory_limit_half(0.95)
    parser = argparse.ArgumentParser(description='Analyze binary')
    parser.add_argument('-l', '--ltl', nargs='+', required=False)
    parser.add_argument('-r', '--reconstruct', action='store_true')
    parser.add_argument('-o', '--optimize', action='store_true')

    parser.add_argument('-m', '--max_steps', type=int, required=False, default=None)
    parser.add_argument('-p', '--max_processes', type=int, required=False, default=None)
    parser.add_argument('-s', '--context_sensitivity', type=int, required=False, default=0)
    parser.add_argument('-e', '--entry', type=str, required=False, default=None)
    parser.add_argument('-c', '--full_coverage', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-f', '--filepath', type=str,
                        help='File to analyze')
    parser.add_argument('-a', '--avoid', nargs='+', required=False)
    parser.add_argument('-sys', '--syscalls', nargs='+', required=False)
    parser.add_argument('-n', '--naive', action='store_true')
    args = parser.parse_args()

    pkl_name = '{}_smdpn.pkl'.format(args.filepath)

    if args.reconstruct or not os.path.isfile(pkl_name):
        syscalls = []
        for sys_str in args.syscalls:
            syscalls.append([ sys for sys in sys_str.split(' ') ])

        c = smdpn_constructor.CFG_Constructor(args.filepath, keep_state=not args.optimize, max_steps=args.max_steps, max_proc=args.max_processes,
                                              entry=None if args.entry == None else int(args.entry, 16), fast=args.full_coverage,
                                              context_sensitivity=args.context_sensitivity, avoid=args.avoid, syscalls=syscalls,
                                              prints=args.verbose, naive=args.naive)
        smdpn = c.construct_smdpn()
        with open(pkl_name, 'wb') as f:
            pickle.dump(smdpn, f)
    else:
        print('SMDPN pickle found.')

    with open(pkl_name, 'rb') as f:
        smdpn, init = pickle.load(f)
        print('Total {} processes and {} entries.'.format(len(smdpn), len(init)))
        for (i, p) in enumerate(smdpn):
            print('Available atomic propositions for process {}:'.format(i))
            # all_rules = (p[2] | p[3])
            print(set([ r[2][:r[2].find('_from_')] for r in (p[2] | p[3]).values() if r[2].find('syscall_') != -1 ]))

    if args.ltl != None and len(args.ltl) > 0:
        with open(pkl_name, 'rb') as f:
            smdpn, init = pickle.load(f)
            print('LTL formulas: {}'.format(args.ltl))
            result = optimized.ltl_model_check_smdpn(smdpn, init, args.ltl)
            print(result)