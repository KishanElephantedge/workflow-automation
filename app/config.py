from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 1440
    frontend_origin: str = "http://localhost:5173"

    # Cross-site cookie settings. Local dev (frontend and gateway both on localhost, plain
    # HTTP) is same-site, so "lax"/insecure works fine there. The real deployment has the
    # dashboard on a different registrable domain (vercel.app) than the gateway (onrender.com)
    # -- a genuinely cross-site request. SameSite=Lax cookies are excluded from cross-site
    # XHR/fetch entirely (only survive top-level navigation); SameSite=None requires Secure.
    # Set COOKIE_SAMESITE=none and COOKIE_SECURE=true in the deployed environment.
    cookie_samesite: str = "lax"
    cookie_secure: bool = False

    class Config:
        env_file = ".env"


settings = Settings()
