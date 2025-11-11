import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
	SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
	SQLALCHEMY_DATABASE_URI = os.environ.get(
		"DATABASE_URL", f"sqlite:///{BASE_DIR / 'app.db'}"
	)
	SQLALCHEMY_TRACK_MODIFICATIONS = False
	MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 2 * 1024 * 1024))  # 2MB
	
	# Session configuration
	PERMANENT_SESSION_LIFETIME = int(os.environ.get("PERMANENT_SESSION_LIFETIME", 300))  # 5 minutes in seconds
	SESSION_COOKIE_SECURE = False  # Set to False for development, True for production
	SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookie
	SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
	SESSION_REFRESH_EACH_REQUEST = True  # Reset the session timeout on each request
