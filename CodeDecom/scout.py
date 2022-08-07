import inspect

class Scout(object):
    def __init__(self, tracer, ip, op, operands = None):
        self.tracer = tracer
        self.operands = operands or []
        self.op = op
        self.ip = ip

        tracer.found_insn(self)
        pass

    def __lt__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '<', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __le__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '<=', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __eq__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '==', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __ne__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '!=', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __gt__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '>', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __ge__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '>=', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __bool__(self):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        scout = Scout(self.tracer, ip, '?', [self])
        self.tracer.trace_arg_srcs(frame, self)
        return scout.bool_value

    def __add__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '+', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __sub__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '-', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __mul__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '*', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __rmul__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '*', [other, self])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __floordiv__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '//', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __truediv__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '/', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __rtruediv__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '/', [other, self])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __and__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '&', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __or__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '|', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __xor__(self, other):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        scout = Scout(self.tracer, ip, '^', [self, other])
        self.tracer.trace_arg_srcs(frame, self, other)
        return scout

    def __call__(self, *args, **kws):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        scout = Scout(self.tracer, ip, 'call', [self, args, kws])
        self.tracer.trace_arg_srcs(frame, self, *args, **kws)
        return scout

    def __iter__(self):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        scout = ScoutIter(self.tracer, ip, '__iter__', [self])
        self.tracer.trace_arg_srcs(frame, self)
        return scout
    pass

# Convert operands in the format of Scout to the format of Insn.
def conv_operands_scout_to_insn(scout):
    if scout.op == 'call':
        opnds = scout.operands
        v = (opnds[0].ip, tuple((a.ip for a in opnds[1])),
             tuple(((k, v.ip) for k, v in opnds[2].items())))
    else:
        v = tuple([op.ip for op in scout.operands])
        pass
    return v

class ScoutIter(Scout):
    def __init__(self, tracer, ip, op, operands = None):
        super(ScoutIter, self).__init__(tracer, ip, op, operands)
        pass

    def __next__(self):
        frame = inspect.stack()[1].frame
        self.tracer.trace_namespace(frame)
        ip = frame.f_lasti
        scout = Scout(self.tracer, ip, '__next__', [self])
        self.tracer.trace_arg_srcs(frame, self)
        if not scout.bool_value:
            raise StopIteration
        return scout
    pass


class BranchNavigator(object):
    def __init__(self, tracer, bools = None):
        super(BranchNavigator, self).__init__()
        self.tracer = tracer
        if bools != None:
            self.bools = bools
        else:
            self.bools = {}
            pass
        self.trace_log = []
        pass

    def _trace(self, ip):
        insn = self.bools[ip]

        if self.trace_log:
            up_stream_ip, v = self.trace_log[-1]
            up_stream = self.bools[up_stream_ip]
        else:
            up_stream = None
            pass
        insn.record_up_stream(up_stream)

        if isinstance(insn, InsnBool):
            insn.mark_new_enclosing_loop(self)
            pass

        self.trace_log.append((ip, insn.bool_value))
        pass

    def get_insn(self, ip):
        return self.bools[ip]

    def set_value(self, ip, v):
        insn = self.bools[ip]
        insn.bool_value = v
        pass

    def get_bool(self, scout):
        ip = scout.ip
        if ip not in self.bools:
            if scout.op == '?':
                insn = InsnBool(ip)
            else:
                insn = InsnIter(ip)
                pass
            self.bools[ip] = insn
            self.tracer._put_insn(insn)
        else:
            insn = self.bools[ip]
            insn.flip_value()
            pass

        self._trace(ip)
        return self.bools[ip].bool_value
    pass

class BranchNavigatorGuided(BranchNavigator):
    def __init__(self, tracer, bools, guided_values):
        super(BranchNavigatorGuided, self).__init__(tracer, bools)
        self.guided_values = guided_values
        self.value_idx = 0
        self.stop_guiding = False
        pass

    def _guide_value(self):
        v = self.guided_values[self.value_idx]
        self.value_idx += 1

        if self.value_idx >= len(self.guided_values):
            self.stop_guiding = True
            pass

        return v

    def get_bool(self, scout):
        if self.stop_guiding:
            return BranchNavigator.get_bool(self, scout)

        ip = scout.ip
        guided_ip, value = self._guide_value()
        if ip != guided_ip:
            self.stop_guiding = True
            return self.get_bool(scout)

        self.set_value(ip, value)

        self._trace(ip)
        return value
    pass

class EnclosingLoopTracer(object):
    class InsnMixin(object):
        def __init__(self, *args, **kws):
            super(EnclosingLoopTracer.InsnMixin, self).__init__(*args, **kws)
            self.loop_head_branch = None
            # All loop heads of enclosing loops
            self.enclosing_loop_heads = set()

            self.loop_tree_following = [None, None]
            pass

        def immediate_enclosing_loop_head(self, tracer):
            for h_ip in self.enclosing_loop_heads:
                head = tracer._get_insn(h_ip)
                if len(head.enclosing_loop_heads) + 1 == len(self.enclosing_loop_heads):
                    return h_ip
                pass
            return -1

        def mark_new_enclosing_loop(self, bnav):
            ip = self.ip

            # Handle enclosing loop
            for i, (ip_, v) in enumerate(reversed(bnav.trace_log)):
                if ip ==  ip_:
                    self.loop_head_branch = v
                    for inner_ip, inner_v in bnav.trace_log[len(bnav.trace_log) - i:]:
                        inner = bnav.get_insn(inner_ip)
                        inner.enclosing_loop_heads.add(ip)
                        pass
                    pass
                elif ip_ in self.enclosing_loop_heads:
                    # Revisit this instruction because the enclosing loop, not this loop.
                    break
                pass
            pass

        def is_loop_head(self):
            return self.loop_head_branch != None

        def loop_depth(self, tracer):
            return tracer._loop_head_depth(self.enclosing_loop_head)
        pass

    def __init__(self, *args, **kws):
        super(EnclosingLoopTracer, self).__init__(*args, **kws)
        pass

    def _first_ip(self):
        ips = [ip for ip in self.insns.keys() if ip >= 0]
        ips.sort()
        return ips[0]

    # The outer most lines of a function have a depth value 0, and
    # their enclosing_loop_head value will be -1.
    # The outer most loops have a depth value 1.
    # Every inner loops have a depath value increased by 1 nested.
    def _loop_head_depth(self, loop_head_ip):
        if loop_head_ip == -1:
            return 0
        head = self._get_insn(loop_head_ip)
        return len(head.enclosing_loop_heads)

    def _compute_IELH_for_bool(self, insn, to_visit):
        insn.enclosing_loop_head = insn.immediate_enclosing_loop_head(self)
        if insn.loop_head_branch != None:
            inner, sibling = insn.br[0], insn.br[1]
            if not insn.loop_head_branch:
                inner, sibling = sibling, inner
                pass
            to_visit.append((inner, insn.ip))
            to_visit.append((sibling, insn.immediate_enclosing_loop_head(self)))
            return
        to_visit.append((insn.br[0], insn.immediate_enclosing_loop_head(self)))
        to_visit.append((insn.br[1], insn.immediate_enclosing_loop_head(self)))
        pass

    def _compute_IELH_for_not_bool(self, insn, to_visit, elh):
        '''Update enclosing_loop_head of insn if the new elh encloses the old
one.

        '''
        if hasattr(insn, 'enclosing_loop_head') and \
           self._loop_head_depth(insn.enclosing_loop_head) <= self._loop_head_depth(elh):
            return
        insn.enclosing_loop_head = elh
        next_ip = insn.br[0]
        if next_ip >= 0:
            to_visit.append((next_ip, elh))
            pass
        pass

    def _compute_immediate_enclosing_loop(self):
        '''Compute immediate enclosing loop.

        An immediate enclosing loop of an instruction is a loop that
        enclosing the instruction.  An instruction may be enclosed by
        more than one loop.  The immediate enclosing loop is the most
        inner one.

        A loop is represented by a loop head, an InsnBool.

        '''
        to_visit = [(self._first_ip(), -1)]
        visited_bools = set()
        while len(to_visit):
            ip, enclosing_loop_head = to_visit.pop()
            if ip in visited_bools:
                continue

            insn = self._get_insn(ip)
            if isinstance(insn, InsnBool):
                visited_bools.add(ip)
                self._compute_IELH_for_bool(insn, to_visit)
            else:
                self._compute_IELH_for_not_bool(insn, to_visit,
                                                enclosing_loop_head)
                pass
            pass
        pass

    def _establish_loop_tree(self):
        if not len(self.branch_navi.bools):
            return

        for insn in self.branch_navi.bools.values():
            for up_stream_ip_v in insn.up_streams:
                if not up_stream_ip_v:
                    continue
                up_stream_ip, up_stream_value = up_stream_ip_v
                up_stream = self._get_insn(up_stream_ip)
                if up_stream.loop_depth(self) > insn.loop_depth(self):
                    continue
                fidx = 0 if up_stream_value else 1
                assert(up_stream.loop_tree_following[fidx] == None)
                up_stream.loop_tree_following[fidx] = insn.ip
                pass
            pass
        pass
    pass

class NamespaceTraceMixin(object):
    class InsnMixin(object):
        def __init__(self, *args, **kws):
            super(NamespaceTraceMixin.InsnMixin, self).__init__(*args, **kws)
            self.assign_locals = ({}, {})
            self.assign_globals = ({}, {})

            self.arg_srcs = []
            pass

        def _current_locals(self, bnav):
            if isinstance(self, InsnBool):
                assert(self.ip == bnav.trace_log[-1][0])
                if not bnav.trace_log[-1][1]:
                    return self.assign_locals[1]
                pass
            return self.assign_locals[0]

        def _current_globals(self, bnav):
            if isinstance(self, InsnBool):
                assert(self.ip == bnav.trace_log[-1][0])
                if not bnav.trace_log[-1][1]:
                    return self.assign_globals[1]
                pass
            return self.assign_globals[0]
        pass

    def __init__(self, *args, **kws):
        super(NamespaceTraceMixin, self).__init__(*args, **kws)
        self._reset_ns()
        pass

    def _reset_ns(self):
        self.saved_locals = {}
        self.saved_globals = {}
        pass

    def trace_namespace(self, frame):
        insn = self._get_insn(self.lasti)

        lns = frame.f_locals
        assigns = insn._current_locals(self.branch_navi)
        for k, v in self.saved_locals.items():
            if (k not in lns) or lns[k].ip == v.ip:
                continue
            assigns[k] = lns[k].ip
            pass
        for k in lns.keys():
            if k not in self.saved_locals:
                assigns[k] = lns[k].ip
                pass
            pass
        self.saved_locals = lns.copy()

        gns = frame.f_globals
        assigns = insn._current_globals(self.branch_navi)
        for k, v in self.saved_globals.items():
            if (k not in gns) or gns[k].ip == v.ip:
                continue
            print(k, gns[k].ip)
            assigns[k] = gns[k].ip
            pass
        for k in gns.keys():
            if k not in self.saved_globals:
                assigns[k] = gns[k].ip
                pass
            pass
        self.saved_globals = gns.copy()
        pass

    def _collect_src(self, ip, frame):
        src = set()
        lns = frame.f_locals
        for k, v in lns.items():
            if v.ip == ip:
                src.add(k)
                pass
            pass
        gns = frame.f_globals
        for k, v in gns.items():
            if v.ip == ip:
                src.add(k)
                pass
            pass
        return src

    def trace_arg_srcs(self, frame, *args, **kws):
        vars = [arg.ip for arg in args] + \
            [kws[k].ip for k in sorted(kws.keys())]
        srcs = [self._collect_src(ip, frame)
                for ip in vars]

        insn = self._get_insn(self.lasti)

        if not insn.arg_srcs:
            insn.arg_srcs = srcs
            return

        assert(len(srcs) == len(insn.arg_srcs))
        for i, src in enumerate(srcs):
            insn.arg_srcs[i] = insn.arg_srcs[i] & src
            pass
        pass
    pass

class Insn(NamespaceTraceMixin.InsnMixin):
    def __init__(self, ip, op):
        super(Insn, self).__init__()
        self.ip = ip
        self.op = op
        self.opvs = set()
        self.br = [-1, -1]
        pass

    def jump_to(self, ip):
        assert(self.br[0] == -1 or self.br[0] == ip)
        self.br[0] = ip
        pass
    pass

class InsnBool(Insn, EnclosingLoopTracer.InsnMixin):
    def __init__(self, ip, op = '?'):
        super(InsnBool, self).__init__(ip, op)

        self.bool_value = True
        # Keep the previous branches reaching this instruction.
        self.up_streams = set()
        pass

    def flip_value(self):
        self.bool_value = not self.bool_value
        pass

    def record_up_stream(self, up_stream):
        if up_stream:
            assert(isinstance(up_stream, InsnBool))
            self.up_streams.add((up_stream.ip, up_stream.bool_value))
        else:
            # indicate this bool is reachable from the entry of the
            # function.
            self.up_streams.add(None)
            pass
        pass

    def jump_to(self, ip):
        if self.bool_value:
            assert(self.br[0] == -1 or self.br[0] == ip)
            self.br[0] = ip
        else:
            assert(self.br[1] == -1 or self.br[1] == ip)
            self.br[1] = ip
            pass
        pass
    pass

class InsnIter(InsnBool):
    def __init__(self, ip, op = '__next__'):
        super(InsnIter, self).__init__(ip, op)
        pass
    pass

class Tracer(EnclosingLoopTracer, NamespaceTraceMixin):
    def __init__(self):
        super(Tracer, self).__init__()
        self.insns = {}
        self.lasti = -1
        self.op = ''
        self.branch_navi = BranchNavigator(self)
        self.consts = {}
        self.ip_consts = {}
        pass

    def _get_insn(self, ip):
        if ip < 0:
            if ip not in self.insns:
                return None
            return self.insns[ip]

        if (ip // 10 * 10) not in self.insns:
            return None
        insn = self.insns[ip // 10 * 10]
        if isinstance(insn, list):
            if len(insn) <= (ip % 10):
                return None
            insn = insn[ip % 10]
        else:
            assert(ip % 10 == 0)
            pass
        return insn

    # Convert IP of a Scout to the IP of sub-instructions.
    #
    # Some Python syntax may cause several actions with the same IP
    # value.  In other words, in the point of view of CodeDecom, they
    # are several instructions at the same location.  We convert IPs
    # of scouts (instructions) into sub-IPs.  So, all sub-instructions
    # at the same location get an unique location (IP) to distinguish
    # them.
    #
    # A sub-IP is about REAL IP times 10 adding an offset.  The first
    # sub-IP will be IP times 10.  The second sub-IP will be IP times
    # 10 plus 1.  The N-the sub-IP will be IP times 10 plus N-1.  So,
    # for every IP, it can have at most 10 sub-instructions.
    def _conv_sub_ip(self, scout):
        # Adjust IP for instructions at the same location.  Turn Insns
        # of the same location into a list.  Always append the new
        # Insn found at the tail.  Assume no the same operator appears
        # in the list more than once.
        if scout.ip < 0:
            return
        scout.ip *= 10
        ip = scout.ip

        if (self.lasti // 10 * 10) == ip:
            # More than one instructions at the same location.
            if isinstance(self.insns[ip], list):
                for insn in self.insns[ip]:
                    if insn.op == scout.op and conv_operands_scout_to_insn(scout) in insn.opvs:
                        # Assume that no operator appears in the list
                        # more than once.
                        scout.ip = insn.ip
                        return
                    pass
                scout.ip += len(self.insns[ip])
            else:
                if self.insns[ip].op == scout.op:
                    # Assume that no operator appears in the list more
                    # than once.
                    return
                scout.ip += 1
                pass

            last_insn = self._get_insn(self.lasti)
            if last_insn.op not in ('?', '__next__'):
                if last_insn.br[0] >= 0:
                    scout.ip = last_insn.br[0]
                    pass
                pass
            else:
                if last_insn.bool_value:
                    if last_insn.br[0] >= 0:
                        scout.ip = last_insn.br[0]
                        pass
                    pass
                else:
                    if last_insn.br[1] >= 0:
                        scout.ip = last_insn.br[1]
                    pass
                pass
            pass
        pass

    def _put_insn(self, insn):
        if insn.ip < 0:
            self.insns[insn.ip] = insn
            return

        unadj_ip = insn.ip // 10 * 10
        if unadj_ip in self.insns:
            if isinstance(self.insns[unadj_ip], list):
                assert((insn.ip % 10) == len(self.insns[unadj_ip]))
                self.insns[unadj_ip].append(insn)
            else:
                assert((insn.ip % 10) == 1)
                self.insns[unadj_ip] = [self.insns[unadj_ip], insn]
                pass
            pass
        else:
            assert(unadj_ip == insn.ip)
            self.insns[unadj_ip] = insn
            pass
        pass

    def get_const_scout(self, v):
        if v in self.consts:
            return self.consts[v]

        scout = Scout(self, -1000000 - len(self.consts), 'const')
        scout.value = v
        self.consts[v] = scout
        self.ip_consts[scout.ip] = v
        return scout

    def found_insn(self, scout):
        self._conv_sub_ip(scout)
        ip = scout.ip

        if scout.op == '?':
            self.do_bool(scout)
        elif scout.op == '__next__':
            self.do_bool(scout)
        elif not self._get_insn(ip):
            insn = Insn(ip, scout.op)
            self._put_insn(insn)
            pass

        insn = self._get_insn(ip)
        assert(insn.op == scout.op)
        v = conv_operands_scout_to_insn(scout)
        insn.opvs.add(v)

        if ip >= 0 and self.lasti >= 0:
            last_insn = self._get_insn(self.lasti)
            last_insn.jump_to(ip)
            pass
        if ip >= 0:
            self.lasti = ip
            pass
        pass

    def do_bool(self, scout):
        ip = scout.ip
        v = self.branch_navi.get_bool(scout)
        scout.bool_value = v
        pass

    def _plan_guided(self):
        '''Make a plan to guide the moch function run through a specific path
        of branches.

        Every branch instruction will go to one of two branches,
        depending on a condition.  When a condition is true, the
        branch will go to the first branch, otherwise, go to the
        second branch.  This algorithm make sure every branch in the
        function has been reached.

        A loop is one of two branches of a branch instruction that go
        back to the branch instrucion itself.  For every loop, it
        should be run through a least twice to collect data flows that
        flowing from the first round to the second and later rounds.

        '''
        if len(self.branch_navi.bools) == 0:
            return False

        to_visit = [b for ip, b in self.branch_navi.bools.items()
                   if b.br[0] < 0 or b.br[1] < 0]
        if len(to_visit) == 0:
            return False
        visiting = to_visit[0]

        guided_values = [(visiting.ip, visiting.br[0] < 0)]
        while len(visiting.up_streams):
            if None in visiting.up_streams:
                # The function entry can reach this branch.  It stops
                # here to let the function reach here from the entry.
                break
            ustream_ip, ustream_v = list(visiting.up_streams)[0]
            guided_values.append((ustream_ip, ustream_v))
            visiting = self._get_insn(ustream_ip)
            pass

        self.branch_navi = \
            BranchNavigatorGuided(self, self.branch_navi.bools,
                                  guided_values)

        return True

    def _plan_guided_loops(self):
        bools = self.branch_navi.bools
        if len(bools) == 0:
            return

        for insn in bools.values():
            if None in insn.up_streams:
                root_insn = insn
                break
            pass
        else:
            raise 'Unknown error - can not find the root of the loop tree'

        guided_values_list = [[(root_insn.ip, True)], [(root_insn.ip, False)]]

        def has_looped_twice():
            last_ip, last_v = guided_values[-1]
            last_insn = self._get_insn(last_ip)
            depth = last_insn.loop_depth(self)

            cnt = 0
            for ip, v in reversed(guided_values[:-1]):
                if ip == last_ip:
                    cnt += 1
                    if cnt == 2:
                        return True
                    continue
                insn = self._get_insn(ip)
                if insn.loop_depth(self) <= depth:
                    break
                pass
            return False

        while len(guided_values_list):
            guided_values = guided_values_list.pop()
            ip, value = guided_values[-1]
            insn = self._get_insn(ip)
            next_ip = insn.loop_tree_following[0 if value else 1]

            if not next_ip:
                if insn.enclosing_loop_head == -1:
                    if value != insn.loop_head_branch:
                        yield guided_values
                        continue
                    next_ip = ip
                    pass

            if not next_ip:
                next_ip = insn.enclosing_loop_head
                pass

            if insn.is_loop_head():
                if has_looped_twice():
                    if value == insn.loop_head_branch:
                        continue
                    continue
                pass

            guided_values_list.append(guided_values + [(next_ip, True)])
            guided_values.append((next_ip, False))
            guided_values_list.append(guided_values)
            pass
        return

    def _mock_function(self, func):
        '''Wrap a function.

        Create a new function from the code of the function passed in.
        All data, including constants and global variables, will be
        wrapped as actors to monitor operations on them.  This mock
        function syhould be called with actors as arguments.

        When a mock function is called, it will operate on arguments,
        constants, and global variables.  They are all actors.  So,
        all operations on actors will be monitored to analyze the
        behavior of the code.

        '''
        glob = {}
        for i, vname in enumerate(func.__code__.co_names):
            scout = Scout(self, -2000000 - i, 'global', [])
            self._get_insn(scout.ip).name = vname
            glob[vname] = scout
            pass

        c = func.__code__
        scout_consts = tuple([self.get_const_scout(const)
                              for const in c.co_consts])
        code = c.replace(co_consts = scout_consts)

        return func.__class__(code, glob, func.__name__)

    def trace(self, func):
        args = [Scout(self, -1 - i, 'arg', [])
                for i in range(func.__code__.co_argcount)]
        for i, arg in enumerate(args):
            self._get_insn(arg.ip).name = func.__code__.co_varnames[i]
            pass

        func = self._mock_function(func)

        self.lasti = -1
        self._reset_ns()
        r = func(*args)
        rscout = Scout(self, 1000000, 'return', [r])

        while self._plan_guided():
            self.lasti = -1
            self._reset_ns()
            r = func(*args)
            rscout = Scout(self, 1000000, 'return', [r])
            pass

        self._compute_immediate_enclosing_loop()

        self._establish_loop_tree()

        for guided_values in self._plan_guided_loops():
            self.branch_navi = \
                BranchNavigatorGuided(self, self.branch_navi.bools,
                                      guided_values)

            self.lasti = -1
            self._reset_ns()
            r = func(*args)
            rscout = Scout(self, 1000000, 'return', [r])
            pass
        pass

    def debug_show(self):
        ips = list(self.insns.keys())
        ips.sort()
        insns = [self.insns[ip] for ip in ips]

        # Expand embeded lists of Insns.
        i = 0
        while i < len(insns):
            insn = insns[i]
            if isinstance(insn, list):
                insns[i:i+1] = insn
                continue
            i += 1
            pass

        sps = lambda: '    ' * self._loop_head_depth(insn.enclosing_loop_head) if hasattr(insn, 'enclosing_loop_head') else ''

        for i, insn in enumerate(insns):
            ip = insn.ip

            if ip <= -2000000:
                print('%04d: %s %s' % (ip, insn.op, insn.name))
            elif ip <= -1000000:
                const_value = self.ip_consts[ip]
                print('%04d: %s %s' % (ip, insn.op, repr(const_value)))
            elif ip < 0:
                print('%04d: %s %d %s' % (ip, insn.op, -ip - 1, insn.name))
            elif insn.op == '?':
                print('%04d: %s? operands=%s\n        %sTrue:%d False:%d' % (ip, sps(), repr(insn.opvs), sps(), insn.br[0], insn.br[1]))
            elif insn.op == '__next__':
                print('%04d: %s__next__ operands=%s\n        %sHasData:%d Stop:%d' % (ip, sps(), repr(insn.opvs), sps(), insn.br[0], insn.br[1]))
            else:
                if i < len(insns) - 1:
                    next_ip = insns[i + 1].ip
                else:
                    next_ip = -1
                    pass
                if next_ip == insn.br[0]:
                    print('%04d: %s%s operands=%s' % (ip, sps(), insn.op, repr(insn.opvs)))
                else:
                    print('%04d: %s%s operands=%s\n        %sgoto %d' % (ip, sps(), insn.op, repr(insn.opvs), sps(), insn.br[0]))
                    pass
                pass

            if insn.assign_locals[0] and ip >= -1:
                print('        %slocals-0: %s' % (sps(),
                                                  ' '.join(['%s=%d' % (k, v)
                                                            for k, v in insn.assign_locals[0].items()])))
                pass
            if insn.assign_locals[1] and ip >= -1:
                print('        %slocals-1: %s' % (sps(),
                                                  ' '.join(['%s=%d' % (k, v)
                                                            for k, v in insn.assign_locals[1].items()])))
                pass
            if insn.assign_globals[0] and ip >= -1:
                print('        %sglobals-0: %s' % (sps(),
                                                   ' '.join(['%s=%d' % (k, v)
                                                             for k, v in insn.assign_globals[0].items()])))
                pass
            if insn.assign_globals[1] and ip >= -1:
                print('        %sglobals-1: %s' % (sps(),
                                                   ' '.join(['%s=%d' % (k, v)
                                                             for k, v in insn.assign_globals[1].items()])))
                pass

            if insn.arg_srcs:
                arg_names = ['op%d=%s' % (i, ','.join(sorted(src)))
                             for i, src in enumerate(insn.arg_srcs)
                             if src]
                if arg_names:
                    print('        %s%s' % (sps(), ' '.join(arg_names)))
                    pass
                pass

            i += 1
            pass
        pass
    pass

def bar(*a, **kws):
    pass

def test(a, b):
    # keyword arguments do not work.
    g = a
    c = a + b + bar(3) + foo
    d = 0
    for i in range(101):
        if c > 300:
            d = c * 6 + b
        elif c < 30:
            tiger()
            d = c * 3 + b * a
        elif c in (50, 70):
            d = 7 * c
        else:
            d = 2 * c * 2 + 5 / b / a
            pass
        c += 1
        g += 1
        pass
    return d + c

tracer = Tracer()
tracer.trace(test)
tracer.debug_show()
