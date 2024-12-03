# Overview
The Log Analysis Tool is a Python script designed to parse and analyze server log files. It provides insights such as:

1. The number of requests made by each IP address.
2. The most frequently accessed endpoint.
3. Detection of suspicious activities like brute force login attempts.

# Features
1. Count Requests per IP Address

Extracts all IP addresses from the log file.
Calculates the number of requests made by each IP.
Outputs the results sorted in descending order.
Identify the Most Frequently Accessed Endpoint

2. Extracts and counts endpoint requests.
Identifies the endpoint with the highest number of accesses.
Detect Suspicious Activity

3. Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10).
Detects failed login attempts based on HTTP status code 401 or specific failure messages.
Save Results to CSV

4. Outputs results into a CSV file (log_analysis_results.csv) with the following sections:
Requests per IP
Most Accessed Endpoint
Suspicious Activity

# Input Requirements

Example.log

# Usage
Run the script: python log_analyzer.py
Provide the path to the log file when prompted:
Enter the path to the log file: example.log

The script will:
Analyze the log file.
Display results in the terminal.

Save the analysis to log_analysis_results.csv.

# Output

CSV File (log_analysis_results.csv)

