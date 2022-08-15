from .scout import Tracer, Scout
import inspect
import operator
from functools import reduce

class RemoteHostTracer(Tracer):
    def __init__(self, *args, **kws):
        super(RemoteHostTracer, self).__init__(*args, **kws)

        self.reg_global('RemoteHost', RemoteHostTracer.RemoteHostConstructor)
        pass

    class RemoteHostConstructor(Scout):
        def __call__(self, *args, **kws):
            frame = inspect.stack()[1].frame
            self.tracer.trace_namespace(frame)
            ip = frame.f_lasti
            assert(args[0].op == 'const')
            scout = RemoteHostTracer.RemoteHost(args[0].value, self.tracer, ip, 'call', [self, args, kws])
            insn = self.tracer._get_insn(scout.ip)
            insn.tags.add('noop')
            self.tracer.trace_arg_srcs(frame, self, *args, **kws)
            return scout
        pass

    class RemoteHost(Scout):
        def __init__(self, hostname, *args, **kws):
            super(RemoteHostTracer.RemoteHost, self).__init__(*args, **kws)
            self.hostname = hostname
            pass

        def __enter__(self):
            frame = inspect.stack()[1].frame
            self.tracer.trace_namespace(frame)
            ip = frame.f_lasti
            scout = Scout(self.tracer, ip, '__enter__', [self])
            insn = self.tracer._get_insn(scout.ip)
            insn.tags.add(('RemoteHost:enter', self.hostname))
            self.tracer.trace_arg_srcs(frame, self)
            return scout

        def __exit__(self, exc_type, exc_value, tb):
            frame = inspect.stack()[1].frame
            self.tracer.trace_namespace(frame)
            ip = frame.f_lasti
            scout = Scout(self.tracer, ip, '__exit__', [self, exc_type, exc_value])
            insn = self.tracer._get_insn(scout.ip)
            insn.tags.add(('RemoteHost:exit', self.hostname))
            self.tracer.trace_arg_srcs(frame, self)
            return scout
        pass

    def find_remote_scopes(self):
        remotes = set()
        incompletes = []
        for path in self.paths_between(self.root_ip(),
                                       self.last_ip()):
            for ip in path:
                insn = self._get_insn(ip)
                for tag in insn.tags:
                    if isinstance(tag, tuple) and tag[0].startswith('RemoteHost:'):
                        hostname = tag[1]
                        if tag[0].endswith(':enter'):
                            incompletes.append((hostname, (ip, -1)))
                        else:
                            assert(incompletes[-1][0] == hostname)
                            _, (from_ip, _) = incompletes.pop()
                            remotes.add((hostname, (from_ip, ip)))
                            pass
                        pass
                    pass
                pass
            pass
        return remotes

    def find_range_vars(self, from_ip, end_ip):
        required_vars = set()
        generated_vars = set()
        for path in self.paths_between(from_ip, end_ip):
            required = set()
            generated = set()
            for ip in path:
                insn = self._get_insn(ip)
                opvars = reduce(operator.or_, insn.arg_srcs, set())
                required |= opvars - generated
                generated |= reduce(operator.or_,
                                    [set(assign.keys())
                                     for assign in insn.assign_locals + insn.assign_globals],
                                    set())
                pass
            required_vars |= required
            generated_vars |= generated
            pass
        return required_vars, generated_vars
    pass

