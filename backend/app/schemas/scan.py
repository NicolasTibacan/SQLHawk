from pydantic import BaseModel, Field


class TargetConnection(BaseModel):
    db_type: str = Field(..., examples=["postgres", "mysql", "workbench"])
    host: str
    port: int | None = None
    username: str
    password: str
    database: str
    ssl: bool = False


class ScanRequest(BaseModel):
    target_name: str
    target: TargetConnection


class Finding(BaseModel):
    title: str
    description: str
    severity: str
    evidence: str | None = None
    recommendation: str


class ScanResult(BaseModel):
    id: int
    target_name: str
    target_type: str
    status: str
    risk_score: float
    risk_level: str
    strength_score: float
    findings: list[Finding]

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
