import sys
sys.path.insert(0, '/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-05/repo')
from validation import validate_items
from pricing import subtotal
from tax import apply_tax
from orders import place_order

def expect_raise(exc, fn):
    try:
        fn()
    except exc:
        return
    except Exception as e:
        raise AssertionError(f'expected {exc}, got {type(e)}: {e}')
    raise AssertionError(f'expected {exc}, no raise')

# R1
assert validate_items([{'sku': 'a', 'qty': 1}]) is None
expect_raise(ValueError, lambda: validate_items([]))
expect_raise(ValueError, lambda: validate_items('x'))
expect_raise(ValueError, lambda: validate_items([{'sku': 'a', 'qty': True}]))  # bool
expect_raise(ValueError, lambda: validate_items([{'sku': '', 'qty': 1}]))      # empty sku
expect_raise(ValueError, lambda: validate_items([{'sku': 5, 'qty': 1}]))       # non-str sku
expect_raise(ValueError, lambda: validate_items([{'sku': 'a', 'qty': 0}]))     # qty 0
expect_raise(ValueError, lambda: validate_items([{'sku': 'a', 'qty': 1.0}]))   # float qty
expect_raise(ValueError, lambda: validate_items(['notadict']))

# R2
cat = {'a': 100, 'b': 250}
assert subtotal([{'sku': 'a', 'qty': 2}, {'sku': 'b', 'qty': 1}], cat) == 450
expect_raise(KeyError, lambda: subtotal([{'sku': 'z', 'qty': 1}], cat))

# R3 / R4
expect_raise(ValueError, lambda: apply_tax(100, 'XX'))
assert apply_tax(1000, 'US-OR') == 1000
assert apply_tax(1000, 'US-CA') == 1000 + (1000*8 + 50)//100  # 1080
assert apply_tax(1000, 'EU-DE') == 1000 + (1000*19 + 50)//100 # 1190
# round half up: cents=100, CA 8% -> 8 -> (800+50)//100=8 -> 108
assert apply_tax(100, 'US-CA') == 108
# check rounding half-up: pick value where *rate ends in 50
# cents=6, rate=25? not avail. test (cents*rate+50)//100 behavior with CA
assert apply_tax(1, 'US-CA') == 1 + (8+50)//100  # =1+0=1

# R5 - permission before anything (bad items should still raise PermissionError)
expect_raise(PermissionError, lambda: place_order('bad', cat, 'US-CA', False))
expect_raise(PermissionError, lambda: place_order([], cat, 'US-CA', 1))  # 1 is not True
expect_raise(PermissionError, lambda: place_order([], cat, 'US-CA', None))

# R6/R7
res = place_order([{'sku': 'a', 'qty': 2}], cat, 'US-CA', True)
assert res == {'subtotal': 200, 'total': 216, 'region': 'US-CA'}, res
# validation runs after permission
expect_raise(ValueError, lambda: place_order([], cat, 'US-CA', True))

print('ALL OK')
