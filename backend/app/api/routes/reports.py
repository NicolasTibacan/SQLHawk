from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy.orm import Session

from ...models.scan import Scan
from ...models.user import User
from ...services.report import build_report_payload, ensure_report_pdf, render_report_html
from ..deps import get_current_user, get_db

router = APIRouter()


@router.get("/reports/{scan_id}")
def get_report(
    scan_id: int,
    format: str = Query("json", pattern="^(json|html|pdf)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
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

    if format == "html":
        html = render_report_html(scan)
        return HTMLResponse(content=html)

    if format == "pdf":
        pdf_path = scan.report_pdf_path
        if not pdf_path or not Path(pdf_path).exists():
            pdf_path = ensure_report_pdf(scan)
            scan.report_pdf_path = pdf_path
            db.add(scan)
            db.commit()
            db.refresh(scan)
        filename = f"sqlhawk-report-{scan.id}.pdf"
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=filename,
        )

    return build_report_payload(scan)
