import hashlib
import hmac


def sign(username: str, expiry: int, secret: str) -> str:
    payload = f"{username}.{expiry}"
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{username}.{expiry}.{signature}"


def verify(token: str, secret: str, now: int) -> str:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    username, expiry, signature = parts
    if not username or not expiry.isdigit():
        raise ValueError("malformed token")

    expected = sign(username, int(expiry), secret).rsplit(".", 1)[1]
    if not hmac.compare_digest(expected, signature):
        raise PermissionError("bad signature")

    if now >= int(expiry):
        raise PermissionError("token expired")

    return username
