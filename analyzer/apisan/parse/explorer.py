#!/usr/bin/env python3
import copy
import multiprocessing as mp
import os
import xml.etree.ElementTree as ET
import time

from ..lib import dbg
from ..lib import utils
from .event import EventKind, EOPEvent, CallEvent, LocationEvent, AssumeEvent
from .symbol import SymbolKind

ROOT = os.path.dirname(__file__)
SIG = "@SYM_EXEC_EXTRACTOR"

def is_too_big(body):
    # > 1GB
    return len(body) / (2 ** 30) > 1

def sig_begin():
    return SIG + "_BEGIN"

def sig_end():
    return SIG + "_END"

def get_all_files(in_d):
    files = []
    for fn in utils.get_files(in_d):
        files.append(fn)
    return files

def feed_cmgr(cmgr, node):
    # return newly allocated ConstraintMgr if changed
    # otherwise return old one
    event = node.event
    if event.kind == EventKind.Assume:
        cond = event.cond
        if cond and cond.kind == SymbolKind.Constraint:
            # XXX : latest gives false positives
            if not cond.symbol in cmgr:
                new = dict(cmgr)
                new[cond.symbol] = cond.constraints
                #print(new, cond.symbol, cond.constraints)
                return new
    return cmgr


def is_eop(node):
    return (node.event is not None
            and isinstance(node.event, EOPEvent))

def is_call(node):
    return (node.event is not None
            and isinstance(node.event, CallEvent)
            and node.event.call is not None)

class ExecNode(object):
    __slots__ = ('children', 'event', 'cmgr')
    def __init__(self, node, children):
        assert node.tag == "NODE"
        self.children = children
        self.event = None

        for child in node:
            if child.tag == "EVENT":
                assert self.event is None
                self.event = self._parse_event(child)
            elif child.tag == "NODE":
                continue
            else:
                raise ValueError("Unknown tag")

    def _parse_event(self, node):
        kind = node[0]
        assert kind.tag == "KIND"

        if kind.text == "@LOG_CALL":
            return CallEvent(node)
        elif kind.text == "@LOG_LOCATION":
            return LocationEvent(node)
        elif kind.text == "@LOG_EOP":
            return EOPEvent(node)
        elif kind.text == "@LOG_ASSUME":
            return AssumeEvent(node)
        else:
            raise ValueError("Unknown kind")

    # debugging function
    def __str__(self, i=0):
        result = (" " * i + repr(self) + "\n")
        for child in self.children:
            result += child.__str__(i + 1)
        return result

class ExecTree(object):
    def parse(self, xml):
        self.root = self._parse(xml)
        self._set_cmgr()

    def _set_cmgr(self):
        stack = []
        stack.append((self.root, 0))
        self.root.cmgr = {}

        while stack:
            node, idx = stack.pop()
            if idx == len(node.children):
                # base case : all childrens are visited
                continue
            else:
                child = node.children[idx]
                child.cmgr = feed_cmgr(node.cmgr, node)

                stack.append((node, idx + 1))
                stack.append((child, 0))

    def _parse(self, xml):
        stack = []
        stack.append((xml, 0, []))

        while True:
            xml_node, idx, children = stack.pop()
            # + 1 because of event
            if len(xml_node) == idx + 1:
                node = ExecNode(xml_node, children)
                if not stack:
                    return node
                else:
                    # children
                    stack[-1][2].append(node)
            else:
                # increase stack & create new stack frame
                stack.append((xml_node, idx + 1, children))
                stack.append((xml_node[idx + 1], 0, []))

class Explorer(object):
    def __init__(self, checker):
        self.checker = checker

    def explore(self, in_d):
        result = []
        for fn in utils.get_files(in_d):
            result += self._explore_file(fn)
        return self.checker.merge(result)

    def _explore_file(self, fn):
        result = []
        start_time=time.time()
        res = self._parse_file(fn)
        dbg.info("Parsing %s took %.2fs" % (fn, time.time()-start_time))
        start_time = time.time()
        for tree in res:
            result.append(self.checker.process(tree))
        dbg.info("Processing %s took %.2fs" % (fn, time.time()-start_time))
        dbg.debug("Explored: %s" % fn)
        return result

    def explore_parallel(self, in_d):
        pool = mp.Pool(processes=mp.cpu_count(), maxtasksperchild=2)
        files = utils.get_all_files(in_d)
        results = pool.map(self._explore_file, files, 1)
        pool.close()
        pool.join()
        result = []
        for r in results:
            result += r
        return self.checker.merge(result)

    def _parse_file(self, fn):
        forest = []
        with open(fn, 'r') as f:
            start = False
            body = ""

            for line in f:
                if line.startswith(sig_begin()):
                    start = True
                    body = ""
                elif start:
                    if line.startswith(sig_end()):
                        start = False

                        # XXX: tooo large file cannot be handled
                        if is_too_big(body):
                            dbg.info("Ignore too large chunk in file : %s" % fn)
                            continue
                        try:
                            xml = ET.fromstring(body)
                        except Exception as e:
                            dbg.info("ERROR : %s when parsing %s" % (repr(e), fn))
                            return []

                        for root in xml:
                            tree = ExecTree()
                            tree.parse(root)
                            forest.append(tree)
                    else:
                        body += line
        return forest
