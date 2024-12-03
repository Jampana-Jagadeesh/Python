import re
import csv
from collections import Counter, defaultdict

FAILED_LOGIN_THRESHOLD = 10  # Configurable threshold for failed login attempts

# Functions
def parse_log_files(file_path):
    """Parses the log file and extracts relevant data."""
    ip_pattern = r"(\d{1,3}(?:\.\d{1,3}){3})"  # Match IP addresses
    endpoint_pattern = r'"[A-Z]+ (.*?) HTTP'  # Match endpoints (URLs)
    failed_login_pattern = r'401|Invalid credentials'  # Match failed logins (status code or message)

    requests_by_ip = Counter()
    endpoint_access = Counter()
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as log_file:
        for line in log_file:
            ip_match = re.search(ip_pattern, line)
            endpoint_match = re.search(endpoint_pattern, line)
            failed_login_match = re.search(failed_login_pattern, line)

            if ip_match:
                ip_address = ip_match.group(1)
                requests_by_ip[ip_address] += 1

            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access[endpoint] += 1

            if failed_login_match and ip_match:
                failed_logins[ip_address] += 1

    return requests_by_ip, endpoint_access, failed_logins


def save_results_to_csv(requests_by_ip, most_accessed_endpoint, suspicious_activity, output_file):
    with open(output_file, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in requests_by_ip.items():
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    log_file_path = input("Enter the path to the log file: ")
    output_file = "log_analysis_results.csv"

    print("Analyzing log file...")
    requests_by_ip, endpoint_access, failed_logins = parse_log_files(log_file_path)

    # Most accessed endpoint
    most_accessed_endpoint = endpoint_access.most_common(1)[0] if endpoint_access else ("N/A", 0)

    # Suspicious activity
    suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

    # Display results
    print("\nRequests per IP:")
    for ip, count in requests_by_ip.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count} failed login attempts")

    # Save to CSV
    save_results_to_csv(requests_by_ip, most_accessed_endpoint, suspicious_activity, output_file)
    print(f"\nResults saved to {output_file}")


if __name__ == "__main__":
    main()
