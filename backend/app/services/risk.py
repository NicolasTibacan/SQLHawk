SEVERITY_SCORE = {
    "low": 1.0,
    "medium": 2.5,
    "high": 4.0,
    "critical": 6.0,
}


def score_findings(findings: list[dict]) -> tuple[float, str, float]:
    total = 0.0
    for finding in findings:
        severity = str(finding.get("severity", "low")).lower()
        total += SEVERITY_SCORE.get(severity, 1.0)

    score = min(10.0, total)
    if score >= 9.0:
        level = "critical"
    elif score >= 7.0:
        level = "high"
    elif score >= 4.0:
        level = "medium"
    else:
        level = "low"

    strength = max(0.0, 100.0 - score * 10.0)
    return score, level, strength
