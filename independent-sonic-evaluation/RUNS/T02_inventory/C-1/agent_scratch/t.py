import sys
sys.path.insert(0, '../repo')
import inventory as inv

# R1
for bad in [1.0, "x", True, False]:
    try: inv.check_qty(bad); print("FAIL type", bad)
    except TypeError: pass
for bad in [0, -3]:
    try: inv.check_qty(bad); print("FAIL val", bad)
    except ValueError: pass
assert inv.check_qty(5) is None

# R3
try: inv.reserve({}, "a", 1); print("FAIL key res")
except KeyError: pass
try: inv.release({}, "a", 1); print("FAIL key rel")
except KeyError: pass

# R4 insufficient leaves unchanged
s = {"a": 2, "b": 9}
try: inv.reserve(s, "a", 5); print("FAIL ins")
except ValueError: pass
assert s == {"a": 2, "b": 9}, s

# R2 check_qty before KeyError
try: inv.reserve({}, "a", 0); print("FAIL order res")
except ValueError: pass
try: inv.release({}, "a", -1); print("FAIL order rel")
except ValueError: pass

# R5
s = {"a": 10, "b": 3}
assert inv.reserve(s, "a", 4) == 6
assert s == {"a": 6, "b": 3}, s
# R6
assert inv.release(s, "a", 2) == 8
assert s == {"a": 8, "b": 3}, s

print("ALL OK")
