# LTL model checking of Self-Modifying Concurrent code

_This is a public artifact for reproducing results presented in the paper Touili, T. and Zhangeldinov O. (2025). "LTL Model Checking of Concurrent Self Modifying Code"_

The repository provides the following:
 * `naive.py` - the naive LTL model checking algorithm
 * `optimized.py` - the direct LTL model checking algorithm
 * `util.py` - the generator for random SM-DPNs to compare both algorithms
 * `performance_comparison.py` - script to compare performance of the naive and direct algorithms
 * `detect_malware.py` - script to automatically check a binary file for malware using model checking
 * `constructor.py` - algorithm for translating binary files into SM-DPNs
 * `latex_table.py` - we used this script to build the table used
 in the paper

__Warning__: the algorithms for working with binary files rely on
ANGR (which must be installed). However, ANGR is not very reliable as it fails in many cases, and 
its reliability changes from version to version. For us, version
9.2.139 proved to work in most cases. However, from our observations,
the same version does not work the same on different machines.

## Requirements
Running the scripts in this repository requires the following:
1. Linux
2. Python 3
3. LTL2BA (can be found here [https://lsv.ens-paris-saclay.fr/~gastin/ltl2ba/]())

Make sure that LTL2BA is accessible globally (with the `ltl2ba` command)


## Results

### Reproducing the Performance Comparison Table

#### To reproduce the table
The repository contains images of SM-DPN models used for performance
comparison in the paper (`experiments/paper.pkl`). To reproduce the table
from these images, first, run:
```
python performance_comparison.py rerun
```
This script will create files `results_*.pkl`, each containing results
of both algorithms on the images from `experiments/paper.pkl`.

To construct the table from these results, run:
```
python latex_table.py
```
It will output the table used in the paper (the table also contains 
standard deviation that we omitted in the paper for readability).

#### To reproduce the whole experiment
You might want to compare performance on newly generated models (not those
in the paper). To generate new models, run:
```
python performance_comparison.py
```
The script will populate the `experiments` folder with new images of SM-DPN
models. The script **WILL NOT TERMINATE** until you interrupt it with Ctrl+C.
You might also want to delete the `experiments/paper.pkl` file
to exclude images used in the paper.

Then, continue like in the previous section: 
1. Run:
```
python performance_comparison.py rerun
```
2. And then:
```
python latex_table.py
```

### Malware Detection

We were able to detect the following versions of common malware:
 * Mirai - sha256sum: e86778bfb02461a8219a2d8ae1efda77ffd9d942dcff60c9eb95df537b2e14f2 (MalwareBazaar)
 * Gozi - sha256sum:
 b1ed0af6d7c34540bd571794b6a36fbe73f29f38ee8de4be70726d485500c6b1
 (MalwareBazaar)
 * Backdoor - sha256sum:
 6fa44454e29bc227b51fbfb54676db080e6a39cf2cb8e9f87559db02b316d5e1
 (Virusshare)

### False Positive evaluation

We tested the malware detection tool on benign programs and
did not register any false positives. 
We considered the following Windows programs:
 * Winrar - [https://filehippo.com/download_winrar-32/3.41/]()
 * 7Zip - [https://sourceforge.net/projects/sevenzip/]()
 * MS Paint - [https://filehippo.com/download_ms-paint/]()
 * VLC - [https://filehippo.com/download_vlc-media-player-64/3.0.1.0.0/]()
 * x32dbg - [https://sourceforge.net/projects/x64dbg.mirror/]()
 * Bluetooth Driver Installer - [https://filehippo.com/download_bluetooth-driver-installer/]()
 * Avast - [https://filehippo.com/download_avast-antivirus/19.6.2383/]()
 * CommandPromptProtable - [https://sourceforge.net/projects/portableapps/files/Command%20Prompt%20Portable/]()
 * Java Portable - [https://filehippo.com/download_java-portable/]()
 * Zoom - [https://filehippo.com/download_zoom-meetings/4.4.0.0/]()

And on the following Linux programs:
 * Zip - [https://linux.die.net/man/1/zip]()
 * Ping - [https://linux.die.net/man/8/ping]()
 * LD - [https://www.man7.org/linux/man-pages/man1/ld.1.html]()
 * Top - [https://www.man7.org/linux/man-pages/man1/top.1.html]()
 * Find - [https://www.man7.org/linux/man-pages/man1/find.1.html]()
 * Curl - [https://curl.se/]()
 * Wget - [https://www.gnu.org/software/wget/]()
 * Ssh - [https://man.openbsd.org/ssh]()
 * GDBServer - [https://www.man7.org/linux/man-pages/man1/gdbserver.1.html]()
 * Radare2 - [https://rada.re/n/radare2.html]()
