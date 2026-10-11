"""Generated from an audible template. Verify behavior before use."""

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
    result = {
        'count': len(values),
        'min': min(values),
        'max': max(values),
        'mean': round(sum(values) / len(values), 2),
    }
    return result
