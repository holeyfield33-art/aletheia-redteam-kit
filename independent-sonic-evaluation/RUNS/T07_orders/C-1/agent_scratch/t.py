import sys
sys.path.insert(0, '/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-27/repo')
from validation import validate_items
from pricing import subtotal
from tax import apply_tax
from orders import place_order

def expect_raise(fn, exc):
    try:
        fn()
    except exc:
        return True
    except Exception as e:
        raise AssertionError(f"wrong exc {type(e)} expected {exc}")
    raise AssertionError(f"no raise, expected {exc}")

# R1
assert validate_items([{'sku':'a','qty':1}]) is None
expect_raise(lambda: validate_items([]), ValueError)
expect_raise(lambda: validate_items("x"), ValueError)
expect_raise(lambda: validate_items([{'sku':'','qty':1}]), ValueError)
expect_raise(lambda: validate_items([{'sku':'a','qty':0}]), ValueError)
expect_raise(lambda: validate_items([{'sku':'a','qty':True}]), ValueError)
expect_raise(lambda: validate_items([{'sku':'a','qty':1.0}]), ValueError)
expect_raise(lambda: validate_items([{'sku':5,'qty':1}]), ValueError)
expect_raise(lambda: validate_items([['a',1]]), ValueError)

# R2
cat={'a':100,'b':250}
assert subtotal([{'sku':'a','qty':2},{'sku':'b','qty':1}], cat)==450
expect_raise(lambda: subtotal([{'sku':'z','qty':1}], cat), KeyError)

# R3/R4
assert apply_tax(1000,'US-CA')==1000+(1000*8+50)//100
assert apply_tax(1000,'US-OR')==1000
assert apply_tax(1000,'EU-DE')==1000+(1000*19+50)//100
assert apply_tax(0,'US-CA')==0
expect_raise(lambda: apply_tax(100,'XX'), ValueError)

# R5 before any other check
expect_raise(lambda: place_order([], {}, 'XX', False), PermissionError)
expect_raise(lambda: place_order("bad", {}, "bad", 1), PermissionError)  # verified=1 not True

# R6/R7
res=place_order([{'sku':'a','qty':2}], {'a':100}, 'US-CA', True)
assert res=={'subtotal':200,'total':200+(200*8+50)//100,'region':'US-CA'}, res
print("ALL PASS")
