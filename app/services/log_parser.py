def parse_log_file(filepath):
    logs = []
    try:
        with open(filepath, "r") as file:
            for line in file:
                logs.append(line.strip())
    except Exception as e:
        print("Error reading log file:", e)

    return logs
