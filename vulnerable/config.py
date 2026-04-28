import os

class Config:
    # VULNERABILITATE: secret key hard-coded si slaba
    SECRET_KEY = "secret123"
    SQLALCHEMY_DATABASE_URI = "sqlite:///deskly_vulnerable.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # VULNERABILITATE: SESSION_COOKIE_HTTPONLY = False (implicit nu e setat)
    SESSION_COOKIE_HTTPONLY = False
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = None
    PERMANENT_SESSION_LIFETIME = 86400 * 30  # 30 zile - expirare slaba
