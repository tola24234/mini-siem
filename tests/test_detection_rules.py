import engine.detection_rules as detection_rules
from engine.risk_scoring import calculate_risk_score


def test_bruteforce_detection_triggers_at_threshold(monkeypatch):
    detection_rules.failed_attempts.clear()
    monkeypatch.setattr(detection_rules.time, "time", lambda: 1_000)
    log_line = "sshd: Failed password for root from 203.0.113.9 port 22 ssh2"

    assert detection_rules.detect_bruteforce(log_line) is None
    assert detection_rules.detect_bruteforce(log_line) is None
    result = detection_rules.detect_bruteforce(log_line)

    assert result["source_ip"] == "203.0.113.9"
    assert result["attack_type"] == "SSH Brute Force Attempt"
    assert result["mitre_id"] == "T1110"
    assert detection_rules.failed_attempts["203.0.113.9"] == []


def test_bruteforce_detector_ignores_non_authentication_event():
    detection_rules.failed_attempts.clear()

    assert detection_rules.detect_bruteforce("sshd: Accepted password for analyst") is None
    assert detection_rules.failed_attempts == {}


def test_risk_scoring_assigns_high_severity_to_ssh_detection():
    risk = calculate_risk_score({"attack_type": "SSH Brute Force Attempt"})

    assert risk == {"risk_score": 70, "severity": "HIGH"}


def test_risk_scoring_assigns_low_severity_to_unknown_detection():
    risk = calculate_risk_score({"attack_type": "Unknown"})

    assert risk == {"risk_score": 30, "severity": "LOW"}
