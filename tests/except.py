from CodeDecom import scout

def test_exception(a, b):
    c = a
    while a < b:
        a += 7
        if a > b:
            a += b * 2
            pass
        pass
    return a + b

tracer = scout.Tracer()
tracer.trace(test_exception)
tracer.debug_show()
