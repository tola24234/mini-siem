def calculate_risk_score(detection_result):

    attack_type = detection_result.get("attack_type", "")

    score = 30   # base risk

    if "Bruteforce" in attack_type or "SSH" in attack_type:
        score += 40

    severity = "LOW"

    if score >= 70:
        severity = "HIGH"
    elif score >= 50:
        severity = "MEDIUM"

    return {
        "risk_score": score,
        "severity": severity
    }

