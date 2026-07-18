import requests


def get_ip_info(ip):
    """
    Lookup IP geolocation using ip-api.com
    """

    # Skip localhost addresses
    if ip in ["127.0.0.1", "::1", "localhost"]:
        return {
            "country": "Local Machine",
            "city": "Localhost",
            "isp": "Loopback",
            "latitude": 0,
            "longitude": 0
        }

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=3
        )

        data = response.json()

        if data.get("status") == "success":
            return {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "latitude": data.get("lat", 0),
                "longitude": data.get("lon", 0),
            }

    except Exception as e:
        print("Geo lookup error:", e)

    return {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "latitude": 0,
        "longitude": 0,
    }
