from pydantic import BaseModel, Field, field_validator


ALLOWED_DB_TYPES = {
    "postgres",
    "postgresql",
    "mysql",
    "mariadb",
    "workbench",
    "mysql-workbench",
    "mysql_workbench",
}


class TargetConnection(BaseModel):
    db_type: str = Field(..., examples=["postgres", "mysql", "workbench"])
    host: str = Field(..., min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=256)
    database: str = Field(..., min_length=1, max_length=128)
    ssl: bool = False

    @field_validator("db_type")
    @classmethod
    def validate_db_type(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in ALLOWED_DB_TYPES:
            raise ValueError("Unsupported db_type")
        return normalized

    @field_validator("host", "username", "database")
    @classmethod
    def strip_fields(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Field cannot be empty")
        return cleaned


class ScanRequest(BaseModel):
    target_name: str = Field(..., min_length=1, max_length=120)
    target: TargetConnection


class Finding(BaseModel):
    title: str
    description: str
    severity: str
    evidence: str | None = None
    recommendation: str


class Recommendation(BaseModel):
    title: str
    recommendation: str
    severity: str | None = None


class ScanResult(BaseModel):
    id: int
    target_name: str
    target_type: str
    status: str
    risk_score: float
    risk_level: str
    strength_score: float
    findings: list[Finding]
    recommendations: list[Recommendation]

    class Config:
        from_attributes = True


class ScanListItem(BaseModel):
    id: int
    target_name: str
    target_type: str
    risk_score: float
    risk_level: str
    started_at: str

    class Config:
        from_attributes = True
