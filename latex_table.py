import glob
import pickle

import numpy

import util


def sizeof_fmt(num, suffix="B"):
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


max_file = 0
filename = ''
for f in glob.glob("experiments copy/results_*.pkl"):
    cur  = int(f[f.find('results_'):][len("results_") : -len(".pkl")])
    if cur > max_file:
        max_file = cur
        filename = f


with open(filename, "rb") as f:
    data = pickle.load(f)

res_latex = ""
timeout_str = "{\\bf \\color{red} TIMEOUT}"
rows = []
for d in data:
    print(d['ltl'])
    ba = max(len(util.construct_ba(l)[1]) for l in d["ltl"])

    opt_time_avg = round(numpy.average(d["res"]["optimized"]["time"]), 2)
    opt_time_var = round(numpy.std(d["res"]["optimized"]["time"]), 2)
    opt_mem_avg = sizeof_fmt(numpy.average(d["res"]["optimized"]["mem"]))
    opt_mem_var = sizeof_fmt(numpy.std(d["res"]["optimized"]["mem"]))

    if (
        d["res"]["naive"]["time"] == "TIMEOUT"
        or d["res"]["naive"]["time"][0] == "TIMEOUT"
        or "TIMEOUT" in d["res"]["naive"]["time"]
    ):
        row = [
            f"{d['num_proc']}",
            f"{ba}",
            f"{d['num_rules']} + {d['num_sm']}",
            f"{opt_time_avg}s $\\pm$ {opt_time_var}s",
            f"{opt_mem_avg} $\\pm$ {opt_mem_var}",
            timeout_str,
            timeout_str,
        ]
    else:
        naive_time_avg = round(numpy.average(d["res"]["naive"]["time"]), 2)
        naive_time_var = round(numpy.std(d["res"]["naive"]["time"]), 2)
        naive_mem_avg = sizeof_fmt(numpy.average(d["res"]["naive"]["mem"]))
        naive_mem_var = sizeof_fmt(numpy.std(d["res"]["naive"]["mem"]))

        row = [
            f"{d['num_proc']}",
            f"{ba}",
            f"{d['num_rules']} + {d['num_sm']}",
            f"{opt_time_avg}s $\\pm$ {opt_time_var}s",
            f"{opt_mem_avg} $\\pm$ {opt_mem_var}",
            f"{naive_time_avg}s $\\pm$ {naive_time_var}s",
            f"{naive_mem_avg} $\\pm$ {naive_mem_var}",
        ]

    rows.append(row)
rows_sorted = sorted(rows, key=lambda r: int(r[2][: r[2].find(" + ")]))
# rows_sorted = rows
for row in rows_sorted:
    line = " & ".join(row) + "\\\\ \\hline \n"
    res_latex += line

print(res_latex)
