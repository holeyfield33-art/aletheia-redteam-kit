"""Generated from an audible template. Verify behavior before use."""

def letter_for(score: int) -> str:
    if not isinstance(score, int) or isinstance(score, bool):
        raise TypeError('score must be an int')
    if score < 0 or score > 100:
        raise ValueError('score out of range')
    raise NotImplementedError('__SONIC_HOLE__:Set letter from the grade bands')
    return letter

def assign_grades(scores: dict) -> dict:
    result = {}
    for name in scores:
        raise NotImplementedError('__SONIC_HOLE__:Store letter_for(scores[name]) as result[name]')
    return result

def summarize(grades: dict) -> dict:
    counts = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'F': 0}
    for letter in grades.values():
        if letter not in counts:
            raise ValueError('unknown letter')
        raise NotImplementedError('__SONIC_HOLE__:Increment counts[letter]')
    return counts
