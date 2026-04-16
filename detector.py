import csv
from datetime import datetime

# Threshold settings
ODD_HOURS_START = 0
ODD_HOURS_END = 6
MAX_LOGIN_GAP_MINUTES = 30

# Risk scoring
RISK_SCORES = {
    "High": 50,
    "Medium": 30,
    "Low": 10
}

user_logins = {}

def parse_time(time_str):
    return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")

def check_anomalies(logs):
    alerts = []

    for log in logs:
        user = log['user']
        ip = log['ip']
        location = log['location']
        time = parse_time(log['timestamp'])

        if user not in user_logins:
            user_logins[user] = []

        history = user_logins[user]

        # Rule 1: Odd hour login
        if ODD_HOURS_START <= time.hour <= ODD_HOURS_END:
            alerts.append((user, "Odd hour login", "Medium"))

        # Rule 2: Multiple locations quickly
        for prev in history:
            time_diff = (time - prev['time']).total_seconds() / 60
            if prev['location'] != location and time_diff < MAX_LOGIN_GAP_MINUTES:
                alerts.append((user, "Multiple locations in short time", "High"))

        # Rule 3: Rapid logins
        recent_logins = [
            h for h in history
            if (time - h['time']).total_seconds() / 60 < 10
        ]
        if len(recent_logins) >= 3:
            alerts.append((user, "Multiple rapid logins", "Low"))

        history.append({
            "time": time,
            "location": location,
            "ip": ip
        })

    return alerts


def load_logs(file):
    logs = []
    with open(file, mode='r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            logs.append(row)
    return logs


if __name__ == "__main__":
    print("="*40)
    print("     SOC ALERT REPORT")
    print("="*40)

    logs = load_logs("logs.csv")
    alerts = check_anomalies(logs)

    # Aggregate alerts
    filtered_alerts = {}

    for user, issue, severity in alerts:
        if user not in filtered_alerts:
            filtered_alerts[user] = {}

        if issue not in filtered_alerts[user]:
            filtered_alerts[user][issue] = severity

    print("\n--- ALERTS ---\n")

    user_summary = {}
    user_risk = {}

    for user, issues in filtered_alerts.items():
        user_summary[user] = {"Low": 0, "Medium": 0, "High": 0}
        user_risk[user] = 0

        for issue, severity in issues.items():
            print(f"User: {user} | Issue: {issue} | Severity: {severity}")
            user_summary[user][severity] += 1
            user_risk[user] += RISK_SCORES[severity]

    total_alerts = sum(len(issues) for issues in filtered_alerts.values())
    print(f"\nTotal Unique Alerts: {total_alerts}\n")

    print("--- SUMMARY ---\n")
    for user, counts in user_summary.items():
        print(f"{user} → High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']}")

    print("\n--- RISK SCORES ---\n")

    sorted_users = sorted(user_risk.items(), key=lambda x: x[1], reverse=True)

    for user, score in sorted_users:
        if score >= 70:
            level = "CRITICAL 🔴"
        elif score >= 40:
            level = "HIGH 🟠"
        elif score >= 20:
            level = "MEDIUM 🟡"
        else:
            level = "LOW 🟢"

        print(f"{user} → Risk Score: {score} ({level})")

    top_user = sorted_users[0][0]

    print("\n--- TOP THREAT USER ---\n")
    print(f"Most Suspicious User: {top_user} (Score: {user_risk[top_user]})")

    # Save report
    with open("alerts_report.txt", "w") as f:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"Report Generated At: {current_time}\n\n")

        f.write("--- ALERTS ---\n\n")
        for user, issues in filtered_alerts.items():
            for issue, severity in issues.items():
                f.write(f"User: {user} | Issue: {issue} | Severity: {severity}\n")

        f.write(f"\nTotal Unique Alerts: {total_alerts}\n\n")

        f.write("--- SUMMARY ---\n\n")
        for user, counts in user_summary.items():
            f.write(f"{user} → High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']}\n")

        f.write("\n--- RISK SCORES ---\n\n")
        for user, score in sorted_users:
            f.write(f"{user} → Risk Score: {score}\n")

        f.write(f"\nMost Suspicious User: {top_user} (Score: {user_risk[top_user]})\n")

    print("\nReport saved as alerts_report.txt\n")