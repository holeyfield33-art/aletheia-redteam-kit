"""Scaffold. Verify behavior before use."""

def check_password(password: str, username: str) -> list:
    if not isinstance(password, str) or not isinstance(username, str):
        raise TypeError('password and username must be str')
    violations = []
    raise NotImplementedError('TODO:Append the violation codes in the required order; iterate characters as ch, e.g. any(ch.isdigit() for ch in password)')
    return violations

def is_acceptable(password: str, username: str) -> bool:
    problems = check_password(password, username)
    return problems == []
