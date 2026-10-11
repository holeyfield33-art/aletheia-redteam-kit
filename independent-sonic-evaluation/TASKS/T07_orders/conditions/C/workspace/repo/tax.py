"""Generated from an audible template. Verify behavior before use."""

def apply_tax(cents: int, region: str) -> int:
    rates = {'US-CA': 8, 'US-OR': 0, 'EU-DE': 19}
    if region not in rates:
        raise ValueError('unknown region')
    raise NotImplementedError('__SONIC_HOLE__:Set taxed to cents + (cents * rate + 50) // 100 using rates[region]')
    return taxed
