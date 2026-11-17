





# Security log investigation tool

This project is developed for Scripting For Cybersecurity

This is a python based security log investigation that anlayses firewalla and authentication logs to identify potentially suspicoious activity.

The programm processes log files, validate entries, Calculates security statistics and generates a structured JSON investigation report.


How to Run

1. ensure python is installed 

2. make sure main.py, firewall.log and authentication.log are in the same project folder.

3. Open a termainl in that folder.

4 Run:

Pythom main.py

The results will be displayed in the terminal and saved to investigation_report.Json.



























COMP H2702 – Scripting for Cybersecurity
Project Dataset (Student Version)

All data in this package is SYNTHETIC and created for teaching purposes.
No real production, personal, or malicious data is included.

Files:
1. firewall.log
   Format: timestamp action src=<IP> dst=<IP> proto=<TCP/UDP> port=<port> bytes=<count>
2. authentication.log
   Format: timestamp event user=<name> src=<IP> host=<hostname> method=<method>
3. suspicious_ips.txt
   Short list of IP addresses for investigation/enrichment exercises.

Some malformed lines are intentionally included. Your script should handle unexpected or incomplete data.
Public-looking IPs use documentation-only ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
Students should not scan or contact these addresses. They are data values only.
