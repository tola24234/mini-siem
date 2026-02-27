class SOCMemoryEngine:

    def __init__(self):
        self.memory = {}

    # -------------------------------------------------
    # Store event intelligence
    # -------------------------------------------------
    def add_event(self, ip, attack_type):

        if ip not in self.memory:
            self.memory[ip] = {
                "events": 0,
                "attack_types": set()
            }

        self.memory[ip]["events"] += 1
        self.memory[ip]["attack_types"].add(attack_type)

    # -------------------------------------------------
    # Anomaly scoring
    # -------------------------------------------------
    def anomaly_score(self, ip):

        if ip not in self.memory:
            return 0

        event_count = self.memory[ip]["events"]

        # Simple heuristic scoring
        if event_count > 20:
            return 90
        elif event_count > 10:
            return 70
        elif event_count > 5:
            return 50

        return 20
soc_memory_engine = SOCMemoryEngine()
