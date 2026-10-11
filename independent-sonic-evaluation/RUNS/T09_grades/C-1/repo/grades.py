"""Generated from an audible template. Verify behavior before use."""

def letter_for(score: int) -> str:
    if not isinstance(score, int) or isinstance(score, bool):
        raise TypeError('score must be an int')
    if score < 0 or score > 100:
        raise ValueError('score out of range')
    if score >= 90:
        letter = 'A'
    elif score >= 80:
        letter = 'B'
    elif score >= 70:
        letter = 'C'
    elif score >= 60:
        letter = 'D'
    else:
        letter = 'F'
    return letter

def assign_grades(scores: dict) -> dict:
    result = {}
    for name in scores:
        result[name] = letter_for(scores[name])
    return result

def summarize(grades: dict) -> dict:
    counts = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'F': 0}
    for letter in grades.values():
        if letter not in counts:
            raise ValueError('unknown letter')
        counts[letter] += 1
    return counts
