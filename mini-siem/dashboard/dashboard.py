from analyzer.log_analyzer import analyze_logs

def show_dashboard():
    print("=== MINI SIEM DASHBOARD ===")

    results = analyze_logs()

    if not results:
        print("No suspicious activity detected.")
        return

    for ip, data in results.items():
        print(f"{ip} -> {data['count']} failed attempts")
        print("  🚨 ALERT GENERATED")
        print("  MITRE ATT&CK:")
        print(f"    Tactic: {data['mitre']['tactic']}")
        print(f"    Technique: {data['mitre']['technique_id']} - {data['mitre']['technique_name']}")
        print(f"    Sub-technique: {data['mitre']['sub_technique']}")
        print()

if __name__ == "__main__":
    show_dashboard()
