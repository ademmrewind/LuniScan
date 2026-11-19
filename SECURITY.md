# Security policy

LuniScan is a local, single-operator tool for approved laboratory networks. Keep published ports on loopback and run one backend process with one worker. The API has no login and assumes trusted local users. Use the explicit allowlist and authorize every service before starting a check.

Report suspected vulnerabilities privately through GitHub Security Advisories when the repository owner enables private reporting. If that channel is unavailable, request a private contact channel from the maintainer without posting technical details publicly. Include the version, affected workflow, expected behavior, and a minimal reproduction using a disposable local environment. Remove credentials, private IP addresses, and database records from attachments.

The backend rejects cross-origin browser mutations and has no cross-origin access policy enabled. API bodies are limited to 16 KiB. The documented launch commands disable raw access logs so search terms are excluded from standard logging. Scan lifecycle logs still record job IDs and outcomes. SQLite and generated reports can contain internal network inventory. Store and share their files accordingly.
