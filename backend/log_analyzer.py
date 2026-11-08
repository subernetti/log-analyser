import re
from collections import Counter

# An IP with at least this many failed requests is marked as suspicious.
FAILED_REQUESTS_THRESHOLD = 5
# 401 Unauthorized, 403 Forbidden, 404 Not Found: typical for login guessing and scanning.
FAILED_STATUS_CODES = {401, 403, 404}
# Amount of IPs shown at the "Top IPs" table
TOP_IPS_LIMIT = 5

# Nginx "combined" format, e.g.:
# 192.168.1.10 - - [08/Nov/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 5320 "-" "Mozilla/5.0"
# Nginx's default "main" format is the same, plus one extra field at the end: "$http_x_forwarded_for".
LOG_LINE_PATTERN = re.compile(
    r"^(?P<ip>\S+) "  # client IP address
    r"\S+ \S+ "  # identity and user name (usually "- -")
    r"\[[^\]]+\] "  # date and time in square brackets
    r'"\S+ (?P<path>\S+) [^"]*" '  # request line: method, path, protocol
    r"(?P<status_code>\d{3}) "  # HTTP status code
    r"\S+ "  # response size in bytes (or "-")
    r'"[^"]*" "[^"]*"'  # referrer and user agent
    r'( "[^"]*")?$'  # optional X-Forwarded-For field ("main" format only)
)


def parse_log_line(line: str) -> dict | None:
    """Parse one log line into a dict with ip, status_code and path, or return None if it is malformed."""
    match = LOG_LINE_PATTERN.match(line.strip())
    if match is None:
        return None
    return {
        "ip": match.group("ip"),
        "status_code": int(match.group("status_code")),
        "path": match.group("path"),
    }


def parse_log_file(content: str) -> list[dict]:
    """Parse every line of the log file and skip the malformed ones."""
    entries = []
    for line in content.splitlines():
        entry = parse_log_line(line)
        if entry is not None:
            entries.append(entry)
    return entries


def calculate_error_rate(entries: list[dict]) -> float:
    """Return the percentage of 4xx and 5xx responses, rounded to 1 decimal."""
    if not entries:
        return 0.0
    error_count = 0
    for entry in entries:
        if entry["status_code"] >= 400:
            error_count += 1
    return round(error_count / len(entries) * 100, 1)


def count_requests_per_ip(entries: list[dict]) -> Counter:
    """Count how many requests each IP address made."""
    return Counter(entry["ip"] for entry in entries)


def count_failed_requests_per_ip(entries: list[dict]) -> Counter:
    """Count how many 401/403/404 responses each IP address received."""
    failed_counts = Counter()
    for entry in entries:
        if entry["status_code"] in FAILED_STATUS_CODES:
            failed_counts[entry["ip"]] += 1
    return failed_counts


def find_suspicious_ips(entries: list[dict]) -> list[dict]:
    """Return the IPs whose failed request count reaches the threshold, most failures first."""
    suspicious_ips = []
    for ip, failed_requests in count_failed_requests_per_ip(entries).most_common():
        if failed_requests >= FAILED_REQUESTS_THRESHOLD:
            suspicious_ips.append({"ip": ip, "failed_requests": failed_requests})
    return suspicious_ips


def analyze_entries(entries: list[dict]) -> dict:
    """Compute all statistics for the parsed log entries."""
    requests_per_ip = count_requests_per_ip(entries)
    top_ips = []
    for ip, request_count in requests_per_ip.most_common(TOP_IPS_LIMIT):
        top_ips.append({"ip": ip, "requests": request_count})
    return {
        "total_requests": len(entries),
        "unique_ips": len(requests_per_ip),
        "error_rate": calculate_error_rate(entries),
        "top_ips": top_ips,
        "suspicious_ips": find_suspicious_ips(entries),
    }
