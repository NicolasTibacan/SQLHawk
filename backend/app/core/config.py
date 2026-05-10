import os


class Settings:
    def __init__(self) -> None:
        self.api_database_url = os.getenv(
            "API_DATABASE_URL", "sqlite:///./data/sqlhawk.db"
        )
        self.jwt_secret_key = os.getenv("JWT_SECRET_KEY", "change-me")
        self.jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256")
        self.access_token_expires_minutes = int(
            os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES", "60")
        )
        self.reports_dir = os.getenv("REPORTS_DIR", "./data/reports")


settings = Settings()
