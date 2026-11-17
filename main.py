
import ipaddress
import json



def load_firewall_log():
    lines = []
    blank_lines = 0

    with open("firewall.log", "r") as file:
        for line in file:
            cleaned_line = line.strip()

            if cleaned_line == "":
                blank_lines += 1
                continue

            lines.append(cleaned_line)

    return lines, blank_lines



def parse_firewall_line(line):
    parts = line.split()

    if len(parts) < 8:
        return None

    try:
        firewall_event = {
            "action": parts[2],
            "src": parts[3].split("=", 1)[1],
            "dst": parts[4].split("=", 1)[1],
            "proto": parts[5].split("=", 1)[1],
            "port": parts[6].split("=", 1)[1],
            "bytes": parts[7].split("=", 1)[1]
        }

        if firewall_event["action"] not in ["ALLOWED", "BLOCKED"]:
            return None

        ipaddress.ip_address(firewall_event["src"])
        ipaddress.ip_address(firewall_event["dst"])

        port = int(firewall_event["port"])
        if port < 1 or port > 65535:
            return None

        if int(firewall_event["bytes"]) < 0:
            return None

        return firewall_event

    except (IndexError, ValueError):
        return None



def load_authentication_log():
    lines = []
    blank_lines = 0

    with open("authentication.log", "r") as file:
        for line in file:
            cleaned_line = line.strip()

            if cleaned_line == "":
                blank_lines += 1
                continue

            lines.append(cleaned_line)

    return lines, blank_lines




def parse_authentication_line(line):
    parts = line.split()

    if len(parts) < 7:
        return None

    try:
        auth_event = {
            "timestamp": parts[0] + " " + parts[1],
            "event": parts[2],
            "user": parts[3].split("=", 1)[1],
            "src": parts[4].split("=", 1)[1],
            "host": parts[5].split("=", 1)[1],
            "method": parts[6].split("=", 1)[1]
        }

        ipaddress.ip_address(auth_event["src"])

        return auth_event

    except (IndexError, ValueError):
        return None




def analyse_firewall(firewall_events):
    allowed = 0
    blocked = 0
    unique_ips = set()
    blocked_ips = {}
    port_counts = {}

    for event in firewall_events:

        if event["action"] == "ALLOWED":
            allowed += 1

        elif event["action"] == "BLOCKED":
            blocked += 1

        unique_ips.add(event["src"])

        if event["action"] == "BLOCKED":
            ip = event["src"]
            blocked_ips[ip] = blocked_ips.get(ip, 0) + 1

        port = event["port"]
        port_counts[port] = port_counts.get(port, 0) + 1

    top_blocked_ips = sorted(
        blocked_ips.items(),
        key=lambda item: item[1],
        reverse=True
    )[:5]

    top_ports = sorted(
        port_counts.items(),
        key=lambda item: item[1],
        reverse=True
    )[:5]

    return {
        "allowed": allowed,
        "blocked": blocked,
        "unique_ips": len(unique_ips),
        "top_blocked_ips": top_blocked_ips,
        "top_ports": top_ports
    }




def analyse_authentication(auth_events):
    success = 0
    failed = 0
    locked = 0
    logout = 0
    unknown = 0

    failed_ips = {}
    failed_users = {}

    for event in auth_events:

        if event["event"] == "LOGIN_SUCCESS":
            success += 1

        elif event["event"] == "LOGIN_FAILED":
            failed += 1

            ip = event["src"]
            user = event["user"]

            failed_ips[ip] = failed_ips.get(ip, 0) + 1
            failed_users[user] = failed_users.get(user, 0) + 1

        elif event["event"] == "ACCOUNT_LOCKED":
            locked += 1

        elif event["event"] == "LOGOUT":
            logout += 1

        else:
            unknown += 1

    top_failed_ips = sorted(
        failed_ips.items(),
        key=lambda item: item[1],
        reverse=True
    )[:5]

    top_failed_users = sorted(
        failed_users.items(),
        key=lambda item: item[1],
        reverse=True
    )[:5]

    return {
        "success": success,
        "failed": failed,
        "locked": locked,
        "logout": logout,
        "unknown": unknown,
        "top_failed_ips": top_failed_ips,
        "top_failed_users": top_failed_users
    }




def generate_report(report_data):
    try:
        with open("investigation_report.json", "w") as file:
            json.dump(report_data, file, indent=4)

        print("\nJSON report saved as investigation_report.json")

    except OSError as error:
        print("\nCould not save the JSON report:", error)



def main():
    print("Security Log Investigation Tool")
    print("=" * 40)

    try:
        # Load firewall log
        firewall_lines, firewall_blank_lines = load_firewall_log()

        # Parse firewall events
        firewall_events = []
        firewall_malformed = 0

        for line in firewall_lines:
            event = parse_firewall_line(line)

            if event is None:
                firewall_malformed += 1
            else:
                firewall_events.append(event)

        # Analyse firewall events
        firewall_results = analyse_firewall(firewall_events)

        print("\nFIREWALL LOG ANALYSIS")
        print("Non-blank lines:", len(firewall_lines))
        print("Blank lines:", firewall_blank_lines)
        print("Valid events:", len(firewall_events))
        print("Malformed lines:", firewall_malformed)

        print("Allowed events:", firewall_results["allowed"])
        print("Blocked events:", firewall_results["blocked"])
        print("Unique source IPs:", firewall_results["unique_ips"])

        print("\nTop 5 blocked IPs:")
        for ip, count in firewall_results["top_blocked_ips"]:
            print(ip, "-", count)

        print("\nTop 5 targeted ports:")
        for port, count in firewall_results["top_ports"]:
            print(port, "-", count)

        # Load authentication log
        auth_lines, auth_blank_lines = load_authentication_log()

        # Parse authentication events
        valid_auth_events = []
        auth_malformed = 0

        for line in auth_lines:
            event = parse_authentication_line(line)

            if event is None:
                auth_malformed += 1
            else:
                valid_auth_events.append(event)

        # Analyse authentication events
        auth_results = analyse_authentication(valid_auth_events)

        print("\nAUTHENTICATION LOG ANALYSIS")
        print("Non-blank lines:", len(auth_lines))
        print("Blank lines:", auth_blank_lines)
        print("Valid events:", len(valid_auth_events))
        print("Malformed lines:", auth_malformed)

        print("\nAuthentication event counts:")
        print("Successful logins:", auth_results["success"])
        print("Failed logins:", auth_results["failed"])
        print("Account locks:", auth_results["locked"])
        print("Logouts:", auth_results["logout"])
        print("Unknown events:", auth_results["unknown"])

        print("\nTop 5 failed-login IPs:")
        for ip, count in auth_results["top_failed_ips"]:
            print(ip, "-", count)

        print("\nTop 5 targeted usernames:")
        for user, count in auth_results["top_failed_users"]:
            print(user, "-", count)

        # Create security observations
        observations = []

        if auth_results["top_failed_ips"]:
            ip, count = auth_results["top_failed_ips"][0]
            observations.append(
                f"The highest number of failed logins came from "
                f"{ip}, with {count} attempts. This activity should "
                f"be investigated."
            )

        if auth_results["top_failed_users"]:
            user, count = auth_results["top_failed_users"][0]
            observations.append(
                f"The most frequently targeted username was "
                f"{user}, with {count} failed login attempts."
            )

        if firewall_results["top_blocked_ips"]:
            ip, count = firewall_results["top_blocked_ips"][0]
            observations.append(
                f"The highest number of blocked firewall events "
                f"came from {ip}, with {count} events."
            )

        # Combine results for the JSON report
        report_data = {
            "firewall": {
                "non_blank_lines": len(firewall_lines),
                "blank_lines": firewall_blank_lines,
                "valid_events": len(firewall_events),
                "malformed_lines": firewall_malformed,
                "allowed": firewall_results["allowed"],
                "blocked": firewall_results["blocked"],
                "unique_source_ips": firewall_results["unique_ips"],
                "top_blocked_ips": firewall_results["top_blocked_ips"],
                "top_targeted_ports": firewall_results["top_ports"]
            },

            "authentication": {
                "non_blank_lines": len(auth_lines),
                "blank_lines": auth_blank_lines,
                "valid_events": len(valid_auth_events),
                "malformed_lines": auth_malformed,
                "successful_logins": auth_results["success"],
                "failed_logins": auth_results["failed"],
                "account_locks": auth_results["locked"],
                "logouts": auth_results["logout"],
                "unknown_events": auth_results["unknown"],
                "top_failed_login_ips": auth_results["top_failed_ips"],
                "top_targeted_usernames": auth_results["top_failed_users"]
            },

            "security_observations": observations
        }

    
        generate_report(report_data)

    except FileNotFoundError as error:
        print("\nERROR: A required log file could not be found.")
        print("Check that firewall.log and authentication.log")
        print("are in the same folder as main.py.")
        print("Details:", error)

    except PermissionError as error:
        print("\nERROR: Permission denied when accessing a file.")
        print("Details:", error)


if __name__ == "__main__":
    main()
