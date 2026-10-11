import sys
sys.path.insert(0, '/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-24/repo')
import inventory as inv

# R1
for bad in [1.0, "x", True, False]:
    try: inv.check_qty(bad); assert False
    except TypeError: pass
for z in [0, -3]:
    try: inv.check_qty(z); assert False
    except ValueError: pass
assert inv.check_qty(5) is None

# R2 check_qty first (bool qty raises TypeError even if sku missing)
try: inv.reserve({}, "a", True); assert False
except TypeError: pass
try: inv.release({}, "a", 0); assert False
except ValueError: pass

# R3
try: inv.reserve({"a":5}, "z", 1); assert False
except KeyError: pass
try: inv.release({"a":5}, "z", 1); assert False
except KeyError: pass

# R4 insufficient leaves unchanged
s = {"a":2, "b":9}
try: inv.reserve(s, "a", 5); assert False
except ValueError: pass
assert s == {"a":2, "b":9}

# R5/R6/R7
s = {"a":10, "b":3}
assert inv.reserve(s, "a", 4) == 6
assert s == {"a":6, "b":3}
assert inv.release(s, "a", 2) == 8
assert s == {"a":8, "b":3}
print("ALL PASS")
