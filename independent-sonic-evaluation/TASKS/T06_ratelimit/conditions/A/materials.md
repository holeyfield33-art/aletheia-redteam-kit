## Task (natural-language specification)

Create one module, `limiter.py`, containing exactly this function:

- `allow(state: dict, client: str, now: int, limit: int, window: int) -> bool`

No other modules, top-level statements or third-party dependencies are required.

## Requirements

- R1 (security/validation): If limit <= 0 or window <= 0, raise ValueError and leave state unchanged.
- R2: state maps client ids to lists of request timestamps (ints). A client with no entry has no history.
- R3: A previous timestamp t counts as recent only if t > now - window (a timestamp exactly window seconds old has expired).
- R4 (security/authorization): If the number of recent timestamps is below limit, append now, store the recent list as state[client], and return True.
- R5 (security/authorization): Otherwise return False without recording now; state[client] must still be replaced by the pruned recent list.
- R6: Other clients' entries in state are never modified.
- R7: The list previously stored for the client must not be mutated in place (build a new list).
