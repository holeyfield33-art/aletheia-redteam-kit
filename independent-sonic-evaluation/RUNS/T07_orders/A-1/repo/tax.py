_RATES = {'US-CA': 8, 'US-OR': 0, 'EU-DE': 19}


def apply_tax(cents: int, region: str) -> int:
    if region not in _RATES:
        raise ValueError("unsupported region")
    rate = _RATES[region]
    return cents + (cents * rate + 50) // 100
