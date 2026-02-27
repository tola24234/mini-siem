def create_alert(alert_data):
    print("\n🚨 SECURITY ALERT DETECTED!")
    print("Type:", alert_data["type"])
    print("IP:", alert_data["ip"])
    print("Attempts:", alert_data["attempts"])
    print("Severity:", alert_data["severity"])
    print("MITRE:", alert_data["mitre_technique"])
    print("-" * 40)
