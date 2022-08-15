from CodeDecom.remotehost import RemoteHostTracer

def test_hosts(a, b):
    while a < b:
        a += 7
        with RemoteHost('DBFleet'):
            a += b * 2
            pass
        b *= a
        with RemoteHost('LogFleet'):
            c = b + 7
            pass
        pass
    return a + b

tracer = RemoteHostTracer()
tracer.trace(test_hosts)
tracer.debug_show()

print()

remotes = tracer.find_remote_scopes()

for host, (from_ip, end_ip) in sorted(remotes):
    args, gens = tracer.find_range_vars(from_ip, end_ip)
    print('Host', host, 'from', from_ip, 'to', end_ip,
          '\n    input:', args, '\n    output:', gens)
    pass
