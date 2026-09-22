# Security Policy

## Supported Versions

Only the latest release receives security fixes.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| older   | :x:                |

## Reporting a Vulnerability

Please **do not** open a public issue for security problems.

Report vulnerabilities privately via GitHub's
[private vulnerability reporting](../../security/advisories/new)
("Security" tab → "Report a vulnerability").

Please include:

- affected version and Checkmk version,
- a description of the issue and its impact,
- steps to reproduce or a proof of concept.

You can expect an initial response within 14 days. If the report is
accepted, a fix is released as a new version and the advisory is published
with credit to the reporter (unless you prefer to stay anonymous).

## Handling of Keystore Passwords

The keystore password configured in Checkmk is written in cleartext to
`keystore.cfg` on the monitored host, because `keytool` needs it at runtime.

- Check the file's permissions after deployment (via the Agent Bakery or
  manually) and restrict it to `root` (`chown root:root`, `chmod 600`).
- The agent plugin passes the password to `keytool` through an environment
  variable (`-storepass:env`), never as a command-line argument, so it is not
  visible in the process list.
