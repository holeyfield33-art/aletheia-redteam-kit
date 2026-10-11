def allow(state: dict, client: str, now: int, limit: int, window: int) -> bool:
    if limit <= 0 or window <= 0:
        raise ValueError("limit and window must be positive")
    history = state.get(client, [])
    recent = [t for t in history if t > now - window]
    if len(recent) < limit:
        recent.append(now)
        state[client] = recent
        return True
    state[client] = recent
    return False
