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
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '<', [self, other])

    def __le__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '<=', [self, other])

    def __eq__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '==', [self, other])

    def __ne__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '!=', [self, other])

    def __gt__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '>', [self, other])

    def __ge__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '>=', [self, other])

    def __bool__(self):
        ip = inspect.stack()[1].frame.f_lasti
        scout = Scout(self.tracer, ip, '?', [self])
        return scout.bool_value

    def __add__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '+', [self, other])

    def __sub__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '-', [self, other])

    def __mul__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '*', [self, other])

    def __rmul__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '*', [other, self])

    def __floordiv__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '//', [self, other])

    def __truediv__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '/', [self, other])

    def __rtruediv__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '/', [other, self])

    def __and__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '&', [self, other])

    def __or__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '|', [self, other])

    def __xor__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '^', [self, other])

    def __call__(self, *args, **kws):
        ip = inspect.stack()[1].frame.f_lasti
        return Scout(self.tracer, ip, 'call', [self, args, kws])

    def __iter__(self):
        ip = inspect.stack()[1].frame.f_lasti
        return ScoutIter(self.tracer, ip, '__iter__', [self])
    pass

class ScoutIter(Scout):
    def __init__(self, tracer, ip, op, operands = None):
        super(ScoutIter, self).__init__(tracer, ip, op, operands)
        pass

    def __next__(self):
        ip = inspect.stack()[1].frame.f_lasti
        scout = Scout(self.tracer, ip, '__next__', [self])
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
            self.tracer.insns[ip] = insn
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

class Insn(object):
    def __init__(self, ip, op):
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

class InsnBool(Insn):
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

class Tracer(object):
    def __init__(self):
        self.insns = {}
        self.lasti = -1
        self.op = ''
        self.branch_navi = BranchNavigator(self)
        self.consts = {}
        self.ip_consts = {}
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
        ip = scout.ip
        if scout.op == '?':
            self.do_bool(scout)
        elif scout.op == '__next__':
            self.do_bool(scout)
        elif ip not in self.insns:
            self.insns[ip] = Insn(ip, scout.op)
            pass

        insn = self.insns[ip]
        assert(insn.op == scout.op)
        if scout.op == 'call':
            opnds = scout.operands
            v = (opnds[0].ip, tuple((a.ip for a in opnds[1])),
                 tuple(((k, v.ip) for k, v in opnds[2].items())))
        else:
            v = tuple([op.ip for op in scout.operands])
            pass
        insn.opvs.add(v)

        if ip >= 0 and self.lasti >= 0:
            last_insn = self.insns[self.lasti]
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

    def _enum_conds(self):
        if len(self.branch_navi.bools) == 0:
            return False

        unvisited = [b for ip, b in self.branch_navi.bools.items()
                     if b.br[0] < 0 or b.br[1] < 0]
        if len(unvisited) == 0:
            return False
        visiting = unvisited[0]

        guided_values = [(visiting.ip, visiting.br[0] < 0)]
        while len(visiting.up_streams):
            if None in visiting.up_streams:
                # The function entry can reach this branch.  It stops
                # here to let the function reach here from the entry.
                break
            ustream_ip, ustream_v = list(visiting.up_streams)[0]
            guided_values.append((ustream_ip, ustream_v))
            visiting = self.insns[ustream_ip]
            pass

        self.branch_navi = \
            BranchNavigatorGuided(self, self.branch_navi.bools,
                                  guided_values)

        return True

    def _mock_function(self, func):
        glob = {}
        for i, vname in enumerate(func.__code__.co_names):
            scout = Scout(self, -2000000 - i, 'global', [])
            self.insns[scout.ip].name = vname
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
            self.insns[arg.ip].name = func.__code__.co_varnames[i]
            pass

        func = self._mock_function(func)

        self.lasti = -1
        r = func(*args)
        rscout = Scout(self, 1000000, 'return', [r])

        while self._enum_conds():
            self.lasti = -1
            r = func(*args)
            rscout = Scout(self, 1000000, 'return', [r])
            pass
        pass

    def debug_show(self):
        ips = list(self.insns.keys())
        ips.sort()
        for i, ip in enumerate(ips):
            insn = self.insns[ip]

            if ip <= -2000000:
                print('%04d: %s %s' % (ip, insn.op, insn.name))
            elif ip <= -1000000:
                const_value = self.ip_consts[ip]
                print('%04d: %s %s' % (ip, insn.op, repr(const_value)))
            elif ip < 0:
                print('%04d: %s %d %s' % (ip, insn.op, -ip - 1, insn.name))
            elif insn.op == '?':
                print('%04d: ? operands=%s\n\tTrue:%d False:%d' % (ip, repr(insn.opvs), insn.br[0], insn.br[1]))
            elif insn.op == '__next__':
                print('%04d: __next__ operands=%s\n\tHasData:%d Stop:%d' % (ip, repr(insn.opvs), insn.br[0], insn.br[1]))
            else:
                if i < len(ips) - 1:
                    next_ip = ips[i + 1]
                else:
                    next_ip = -1
                    pass
                if next_ip == insn.br[0]:
                    print('%04d: %s operands=%s' % (ip, insn.op, repr(insn.opvs)))
                else:
                    print('%04d: %s operands=%s\n\tgoto %d' % (ip, insn.op, repr(insn.opvs), insn.br[0]))
                    pass
                pass
            pass
        pass
    pass

def bar(*a, **kws):
    pass

def test(a, b):
    # keyword arguments do not work.
    c = a + b + bar(3) + foo
    d = 0
    for i in range(101):
        if c > 300:
            d = c * 6 + b
        elif c < 30:
            tiger()
            d = c * 3 + b * a
        else:
            d = 2 * c * 2 + 5 / b / a
            pass
        c += 1
        pass
    return d + c

tracer = Tracer()
tracer.trace(test)
tracer.debug_show()
