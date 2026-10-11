def check_password(password: str, username: str) -> list:
    if not isinstance(password, str) or not isinstance(username, str):
        raise TypeError('password and username must be str')
    violations = []
    if len(password) < 12:
        violations.append('too_short')
    if not any(ch.isdigit() for ch in password):
        violations.append('no_digit')
    if not any(ch.isupper() for ch in password):
        violations.append('no_upper')
    if not any(ch.islower() for ch in password):
        violations.append('no_lower')
    if username != '' and username.lower() in password.lower():
        violations.append('contains_username')
    return violations

def is_acceptable(password: str, username: str) -> bool:
    problems = check_password(password, username)
    return problems == []
