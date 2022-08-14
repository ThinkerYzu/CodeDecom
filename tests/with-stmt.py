from CodeDecom import scout

def test_with(a, b):
    while a < b:
        a += 7
        with a:
            a += b * 2
            pass
        pass
    return a + b

tracer = scout.Tracer()
tracer.trace(test_with)
tracer.debug_show()
