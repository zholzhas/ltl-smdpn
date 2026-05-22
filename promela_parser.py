import re

# https://github.com/PatrickTrentin88/gltl2ba
class Ltl2baParser:
    prog_title = re.compile(r'^never\s+{\s+/\* (([^\*]|\*+[^/])*) \*+/$')
    prog_node = re.compile(r'^([^_]+?)_([^_]+?):$')
    prog_edge = re.compile(r'^\s+:: (.+?) -> goto (.+?)$')
    prog_skip = re.compile(r'^\s+(?:skip)$')
    prog_ignore = re.compile(r'(?:^\s+do)|(?:^\s+if)|(?:^\s+od)|'
                             r'(?:^\s+fi)|(?:})|(?:^\s+false);?$')

    @staticmethod
    def parse(ltl2ba_output):
        transitions = set()
        states = set()
        acc = set()
        init = None
        src_node = None
        for line in ltl2ba_output.split('\n'):
            if Ltl2baParser.is_title(line):
                title = Ltl2baParser.get_title(line)
            elif Ltl2baParser.is_node(line):
                name, label, accepting = Ltl2baParser.get_node(line)
                states.add(name)
                src_node = name
                if label == 'init':
                    init = name
                if accepting:
                    acc.add(name)
            elif Ltl2baParser.is_edge(line):
                dst_node, label = Ltl2baParser.get_edge(line)
                assert src_node is not None
                transitions.add((src_node, label, dst_node))
            elif Ltl2baParser.is_skip(line):
                assert src_node is not None
                transitions.add((src_node, "(1)", src_node))
            elif Ltl2baParser.is_ignore(line):
                pass
            else:
                print("--{}--".format(line))
                raise ValueError("{}: invalid input:\n{}"
                                 .format(Ltl2baParser.__name__, line))

        return (states, transitions, init, acc)

    @staticmethod
    def is_title(line):
        return Ltl2baParser.prog_title.match(line) is not None

    @staticmethod
    def get_title(line):
        assert Ltl2baParser.is_title(line)
        return Ltl2baParser.prog_title.search(line).group(1)

    @staticmethod
    def is_node(line):
        return Ltl2baParser.prog_node.match(line) is not None

    @staticmethod
    def get_node(line):
        assert Ltl2baParser.is_node(line)
        prefix, label = Ltl2baParser.prog_node.search(line).groups()
        return (prefix + "_" + label, label,
                True if prefix == "accept" else False)

    @staticmethod
    def is_edge(line):
        return Ltl2baParser.prog_edge.match(line) is not None

    @staticmethod
    def get_edge(line):
        assert Ltl2baParser.is_edge(line)
        label, dst_node = Ltl2baParser.prog_edge.search(line).groups()
        return (dst_node, label)

    @staticmethod
    def is_skip(line):
        return Ltl2baParser.prog_skip.match(line) is not None

    @staticmethod
    def is_ignore(line):
        return Ltl2baParser.prog_ignore.match(line) is not None

class ParseException(Exception):
    pass

def parse_conj(c: str):
    if not c.startswith('(') or not c.endswith(')'):
        raise ParseException('invalid conjunction {}'.format(c))
    queue = c.removeprefix('(').strip().removesuffix(')').strip()
    if queue == '1':
        return frozenset()
    res = [ a.strip() for a in queue.split('&&') ]

    return frozenset(res)

def parse_disj(l):
    queue = l
    try:
        res = [ parse_conj(c.strip()) for c in queue.split('||') ]
    except ParseException as e:
        raise ParseException('Invalid disjunction {}.\n{}'.format(l, e))
    return frozenset(res)


def parse_label(label):
    return parse_disj(label)

def parse_transitions(transitions):
    new = set()
    for t in transitions:
        newlabels = parse_label(t[1])
        for l in newlabels:
            new.add((t[0], l, t[2]))
    return frozenset(new)
