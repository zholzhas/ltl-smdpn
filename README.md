# LTL model checking of Self-Modifying Concurrent code

_This is a public artifact for reproducing results presented in the paper Touili, T. and Zhangeldinov O. (2025). "LTL Model Checking of Concurrent Self Modifying Code"_

The repository provides the following:
 * `naive.py` - the naive LTL model checking algorithm
 * `optimized.py` - the direct LTL model checking algorithm
 * `util.py` - the generator for random SM-DPNs to compare both algorithms
 * `performance_comparison.py` - script to compare performance of the naive and direct algorithms
 * `detect_malware.py` - script to automatically check a binary file for malware using model checking
 * `constructor.py` - algorithm for translating binary files into SM-DPNs

__Warning__: the algorithms for working with binary files rely on
ANGR (which must be installed). Moreover, ANGR is not very reliable as it fails in many cases, and 
its reliability changes from version to version.

We were able to detect the following versions of common malware:
 * Mirai - sha256sum: 6f1a931aa90469c53bbb911ca18dd32a029e90b7b65e7a90134aa533a6c26fe3
 * Gozi - sha256sum:
 b1ed0af6d7c34540bd571794b6a36fbe73f29f38ee8de4be70726d485500c6b1
 * Backdoor - sha256sum:
 6fa44454e29bc227b51fbfb54676db080e6a39cf2cb8e9f87559db02b316d5e1