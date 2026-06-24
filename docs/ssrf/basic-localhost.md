# SOC Playbook — SSRF Against Localhost (Basic)

## Scenario
Web application stock check feature is vulnerable to SSRF. Attacker uses it to reach the admin interface on `http://localhost/admin` and deletes user `carlos`.

## Attack Flow
1. User supplies URL to stock check endpoint.
2. Backend fetches `http://localhost/admin`.
3. Attacker supplies `http://localhost/admin/delete?username=carlos`.
4. Admin action executes server-side.

## Indicators to Alert On
- Outbound HTTP requests from web tier to `127.0.0.1`, `localhost`, `[::1]`.
- Request parameters containing `localhost`, `127.0.0.1`, `0.0.0.0`.
- Requests to `/admin`, `/admin/delete`, or other sensitive paths from non-admin sources.
- New user deletion events triggered by the web application account.

## Detection Queries (Example Patterns)
```
# Network / proxy logs
destination_ip = "127.0.0.1" AND src_service = "web-app"

# Application logs
request_url CONTAINS "localhost/admin"

# Database audit logs
DELETE FROM users WHERE username = "carlos"
  AND source = "web_app_account"
```

## Response Steps
1. Confirm SSRF is not a false positive (check referrer, request body, response codes).
2. Block the attacking session / source IP at WAF or load balancer.
3. Review application access logs for further SSRF payloads.
4. Check for additional impacted admin actions beyond user deletion.
5. Notify incident response if data exfiltration or privilege escalation is suspected.

## Tuning Guidance
- Whitelist allowed domains in the SSRF inspection rule.
- Exclude internal health-check IPs if present to reduce false positives.
- Enrich with asset inventory: `localhost` from the web tier is high risk; from a health-check job may be low risk.

## Linked Writeup
- `security-writeups/portswigger-ssrf-lab01.md`
