"""Scaffold. Verify behavior before use."""
import hashlib
import hmac

def sign(username: str, expiry: int, secret: str) -> str:
    payload = f'{username}.{expiry}'
    mac = hmac.new(secret.encode(), payload.encode(), hashlib.sha256)
    signature = mac.hexdigest()
    return f'{payload}.{signature}'

def verify(token: str, secret: str, now: int) -> str:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('malformed token')
    username = parts[0]
    expiry_text = parts[1]
    provided = parts[2]
    if not username or not expiry_text.isdigit():
        raise ValueError('malformed token')
    expected_token = sign(username, int(expiry_text), secret)
    expected = expected_token.split('.')[2]
    if not hmac.compare_digest(provided, expected):
        raise PermissionError('bad signature')
    if now >= int(expiry_text):
        raise PermissionError('token expired')
    return username
