# Security policy

## Reporting a vulnerability
Please report security problems privately, not in a public issue. Use GitHub's private reporting: open the repository's **Security** tab and choose **Report a vulnerability**.

Useful details:
- what the problem is and its impact, for example a crafted DNS or WHOIS response that leads to command execution or leaks the webhook URL
- steps or a test domain that reproduce it
- your OS, `bash --version` and `curl --version`

This is a personal project maintained in spare time, so responses and fixes are best effort, with no guaranteed timeline. Reports are still welcome and will be taken seriously.

## Supported versions
Only the latest release and `main` receive fixes.

## Scope
In scope: the script and its CI workflow.

Out of scope: the security posture of domains the script reports on. A FAIL result on someone else's domain is for them to fix, not a vulnerability in this project.
