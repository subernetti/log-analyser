from log_analyzer import analyze_entries, calculate_error_rate, parse_log_file, parse_log_line

VALID_LINE = (
    '192.168.1.10 - - [08/Nov/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" '
    '200 5320 "-" "Mozilla/5.0"'
)
# Nginx's default "main" format: the same line plus an X-Forwarded-For field at the end.
MAIN_FORMAT_LINE = VALID_LINE + ' "-"'
FAILED_LOGIN_LINE = (
    '203.0.113.77 - - [08/Nov/2026:10:16:01 +0000] "POST /login HTTP/1.1" '
    '401 128 "-" "python-requests/2.31"'
)


def test_valid_line_is_parsed_correctly() -> None:
    entry = parse_log_line(VALID_LINE)
    assert entry == {"ip": "192.168.1.10", "status_code": 200, "path": "/index.html"}


def test_main_format_line_with_extra_field_is_parsed() -> None:
    entry = parse_log_line(MAIN_FORMAT_LINE)
    assert entry == {"ip": "192.168.1.10", "status_code": 200, "path": "/index.html"}


def test_malformed_line_returns_none() -> None:
    assert parse_log_line("this is not an nginx log line") is None


def test_suspicious_ip_is_detected() -> None:
    # 5 failed logins (exactly the threshold) from one IP, plus one normal request.
    log_lines = [FAILED_LOGIN_LINE] * 5 + [VALID_LINE]
    analysis = analyze_entries(parse_log_file("\n".join(log_lines)))
    assert analysis["suspicious_ips"] == [{"ip": "203.0.113.77", "failed_requests": 5}]


def test_ip_below_threshold_is_not_suspicious() -> None:
    # 4 failed logins: one less than the threshold.
    log_lines = [FAILED_LOGIN_LINE] * 4 + [VALID_LINE]
    analysis = analyze_entries(parse_log_file("\n".join(log_lines)))
    assert analysis["suspicious_ips"] == []


def test_error_rate_is_calculated_correctly() -> None:
    # 1 error (401) out of 2 requests = 50%.
    entries = parse_log_file(VALID_LINE + "\n" + FAILED_LOGIN_LINE)
    assert calculate_error_rate(entries) == 50.0


def test_error_rate_of_empty_list_is_zero() -> None:
    # Without this check, we would divide by zero.
    assert calculate_error_rate([]) == 0.0
