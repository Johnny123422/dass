import os
import secrets

class Config:
    # FIX: secret key random, lungime mare, din variabila de mediu
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///deskly_fixed.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # FIX #4B: cookie flags de securitate corecte
    SESSION_COOKIE_HTTPONLY = True       # nu poate fi accesat din JS
    SESSION_COOKIE_SECURE = False        # True in productie cu HTTPS
    SESSION_COOKIE_SAMESITE = "Lax"     # protectie CSRF
    PERMANENT_SESSION_LIFETIME = 3600   # 1 ora - expirare corecta

    # FIX: CSRF protection activata
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Rate limiting
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15
