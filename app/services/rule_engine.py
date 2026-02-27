class RuleEngine:
    def __init__(self):
        self.rules = [
            {
                "name": "SSH Brute Force",
                "pattern": "Failed password",
                "threshold": 5,
                "severity": "HIGH"
            }
        ]

    def evaluate(self, logs):
        alerts = []

        for rule in self.rules:
            count = sum(rule["pattern"] in log for log in logs)

            if count >= rule["threshold"]:
                alerts.append({
                    "rule": rule["name"],
                    "severity": rule["severity"],
                    "count": count
                })

        return alerts
