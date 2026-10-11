def summarize(readings: list) -> dict:
    if not isinstance(readings, list):
        raise TypeError("readings must be a list")

    numeric = []
    for entry in readings:
        if entry is None:
            continue
        if isinstance(entry, bool) or not isinstance(entry, (int, float)):
            raise TypeError("entries must be int or float")
        numeric.append(entry)

    if not numeric:
        raise ValueError("no numeric entries")

    return {
        "count": len(numeric),
        "min": min(numeric),
        "max": max(numeric),
        "mean": round(sum(numeric) / len(numeric), 2),
    }
