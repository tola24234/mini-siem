from flask import Flask, request, jsonify
import datetime

app = Flask(__name__)

LOG_FILE = "logs/remote_logs.log"

@app.route('/ingest', methods=['POST'])
def ingest_log():
    data = request.json
    
    log_entry = {
        "timestamp": str(datetime.datetime.now()),
        "source": data.get("source"),
        "event": data.get("event"),
        "ip": data.get("ip")
    }

    with open(LOG_FILE, "a") as f:
        f.write(str(log_entry) + "\n")

    return jsonify({"status": "log received"}), 200

if __name__ == "__main__":
    app.run(port=5001)
