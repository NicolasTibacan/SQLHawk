from pydantic import BaseModel


class ReportPayload(BaseModel):
    scan_id: int
    target_name: str
    risk_score: float
    risk_level: str
    strength_score: float
    findings: list[dict]
    recommendations: list[dict]
    generated_at: str
