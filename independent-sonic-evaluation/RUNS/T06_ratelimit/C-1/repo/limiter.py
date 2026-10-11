"""Generated from an audible template. Verify behavior before use."""

def allow(state: dict, client: str, now: int, limit: int, window: int) -> bool:
    if limit <= 0 or window <= 0:
        raise ValueError('limit and window must be positive')
    recent = [t for t in state.get(client, []) if t > now - window]
    if len(recent) < limit:
        recent.append(now)
        state[client] = recent
        return True
    else:
        state[client] = recent
        return False
