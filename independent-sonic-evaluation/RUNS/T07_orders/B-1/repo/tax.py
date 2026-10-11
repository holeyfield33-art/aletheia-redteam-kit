"""Scaffold. Verify behavior before use."""

def apply_tax(cents: int, region: str) -> int:
    rates = {'US-CA': 8, 'US-OR': 0, 'EU-DE': 19}
    if region not in rates:
        raise ValueError('unknown region')
    rate = rates[region]
    taxed = cents + (cents * rate + 50) // 100
    return taxed
