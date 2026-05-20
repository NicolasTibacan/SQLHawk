import os


class Settings:
    def __init__(self) -> None:
        self.api_database_url = os.getenv(
            "API_DATABASE_URL", "sqlite:///./data/sqlhawk.db"
        )
        self.jwt_secret_key = os.getenv("JWT_SECRET_KEY", "").strip()
        self.jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256").strip() or "HS256"
        self.access_token_expires_minutes = int(
            os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES", "60")
        )
        self.reports_dir = os.getenv("REPORTS_DIR", "./data/reports")
        self._validate()

    def _validate(self) -> None:
        if not self.jwt_secret_key or self.jwt_secret_key == "change-me":
            raise ValueError(
                "JWT_SECRET_KEY must be set to a strong random value (32+ chars)."
            )
        if len(self.jwt_secret_key) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters long.")


settings = Settings()
