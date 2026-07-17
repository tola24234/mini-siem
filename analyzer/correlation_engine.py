import re


def correlate_events(log_file):

    alerts = []

    failed_login_ips = set()
    sudo_users = set()


    try:

        with open(log_file, "r", errors="ignore") as file:

            for line in file:


                # Collect failed SSH login sources
                if "Failed password" in line:

                    ip_match = re.search(
                        r"from (\d+\.\d+\.\d+\.\d+)",
                        line
                    )

                    if ip_match:
                        failed_login_ips.add(
                            ip_match.group(1)
                        )


                # Detect sudo activity
                if "sudo" in line:

                    user_match = re.search(
                        r"user=(\w+)",
                        line
                    )

                    if user_match:
                        sudo_users.add(
                            user_match.group(1)
                        )


        # Correlation rule:
        # Failed login + privilege activity

        if failed_login_ips and sudo_users:

            for ip in failed_login_ips:

                alerts.append(
                    "[CORRELATION ALERT] "
                    f"Possible account compromise from {ip}"
                )


    except FileNotFoundError:

        alerts.append(
            f"[ERROR] Log file not found: {log_file}"
        )


    return alerts
