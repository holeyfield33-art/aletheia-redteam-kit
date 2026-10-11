"""Scaffold. Verify behavior before use."""

def summarize(readings: list) -> dict:
    if not isinstance(readings, list):
        raise TypeError('readings must be a list')
    values = []
    for item in readings:
        if item is not None and (isinstance(item, bool) or not isinstance(item, (int, float))):
            raise TypeError('non-numeric reading')
        if item is not None:
            values.append(item)
    if not values:
        raise ValueError('no numeric readings')
    raise NotImplementedError('TODO:Set result to a dict with count, min, max and mean (mean rounded to 2 places) of values')
    return result
