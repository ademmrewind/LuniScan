# Contributing

Use the Windows or Docker setup in [README.md](README.md). Keep changes scoped, preserve the API contract, and update tests when user-visible behavior changes.

- Run Pytest, Ruff, Python compilation, TypeScript checking, and the Vite build before opening a pull request.
- Run the Edge integration suite for browser workflows. It uses an isolated SQLite database and a loopback TCP listener.
- Use synthetic test fixtures or real local loopback observations. Remove private addresses, credentials, and internal inventory from screenshots or logs.
- Keep network operations within the documented approved scope and limits. Preserve explicit operator approval.

Include the reason for the change, the verification commands you ran, and any work you could not verify.
