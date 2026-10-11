Task complete.

Files written in repo/:
- repo/limiter.py — contains only `allow(state, client, now, limit, window) -> bool`.

Implementation notes (mapped to requirements):
- R1: raises ValueError when limit <= 0 or window <= 0 before touching state (state left unchanged).
- R2/R3: reads history via state.get(client, []); keeps timestamps where `t > now - window`, so a timestamp exactly `window` old is pruned.
- R4: if len(recent) < limit, appends now, stores recent as state[client], returns True.
- R5: otherwise stores the pruned recent list as state[client] and returns False (now not recorded).
- R6: only state[client] is ever assigned; other clients untouched.
- R7: the list comprehension always builds a new list; the previously stored list is never mutated in place (verified identity differs and original unchanged).

My own checks: wrote and ran a single stdlib script covering R1 (both branches, including state-unchanged on window<=0), R3 boundary (exactly-window expiry), R4, R5, R6, and R7. Ran checks 1 time; all passed ("ALL PASS").

No requirement conflicts found with the provided materials.
