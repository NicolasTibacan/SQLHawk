from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ...models.scan import Scan
from ...models.user import User
from ...schemas.scan import ScanListItem, ScanRequest, ScanResult
from ...services.analyzer import run_scan
from ...services.report import ensure_report_pdf
from ..deps import get_current_user, get_db

router = APIRouter()


@router.post("/scans", response_model=ScanResult)
def create_scan(
    payload: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    try:
        result = run_scan(payload.target)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    scan = Scan(
        user_id=current_user.id,
        target_name=payload.target_name,
        target_type=result["target_type"],
        status="completed",
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        strength_score=result["strength_score"],
        findings=result["findings"],
        recommendations=result["recommendations"],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        pdf_path = ensure_report_pdf(scan)
        scan.report_pdf_path = pdf_path
        db.add(scan)
        db.commit()
        db.refresh(scan)
    except Exception:
        pass
    return scan


@router.get("/scans", response_model=list[ScanListItem])
def list_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Scan]:
    return (
        db.query(Scan)
        .filter(Scan.user_id == current_user.id)
        .order_by(Scan.started_at.desc())
        .all()
    )


@router.get("/scans/{scan_id}", response_model=ScanResult)
def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    return scan
