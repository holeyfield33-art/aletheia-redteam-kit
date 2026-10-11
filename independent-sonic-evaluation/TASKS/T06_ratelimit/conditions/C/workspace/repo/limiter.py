"""Generated from an audible template. Verify behavior before use."""

def allow(state: dict, client: str, now: int, limit: int, window: int) -> bool:
    if limit <= 0 or window <= 0:
        raise ValueError('limit and window must be positive')
    raise NotImplementedError("__SONIC_HOLE__:Set recent to a new list of the client's timestamps in state that are strictly greater than now - window")
    if len(recent) < limit:
        recent.append(now)
        raise NotImplementedError('__SONIC_HOLE__:Store recent as state[client]')
        return True
    else:
        raise NotImplementedError('__SONIC_HOLE__:Store recent as state[client]')
        return False
