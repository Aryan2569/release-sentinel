# Security Policy

## Supported Versions

Release Sentinel is currently in active development. Only the latest minor release line receives security updates.

| Version | Supported          |
| :------ | :----------------- |
| 0.5.x   | :white_check_mark: |
| < 0.5.0 | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Vulnerabilities are reported through GitHub Private Vulnerability Reporting. If you believe you have discovered a vulnerability in Release Sentinel:

1. **GitHub Private Vulnerability Reporting**: Use the **Security** tab on the repository and select **Report a vulnerability**.
2. **Details to include**:
   - A description of the issue and potential security impact.
   - Minimal reproduction steps or proof-of-concept.
   - Any suggested mitigations.

### Response Timeline

Response, triage, and patch delivery are best effort; this is a solo-maintained alpha. When vulnerabilities are confirmed, we coordinate responsible disclosure and release patches promptly.

## Security Principles

Release Sentinel adheres to strict security and safety principles:
- **Safe Static Inspection**: Release Sentinel analyzes npm tarballs statically in memory and never executes package code or lifecycle scripts.
- **Isolated Tarball Handling**: Tarballs are extracted purely in memory with path traversal protection, compression ratio checks, and hard size limits.
- **Fail-Closed Live Architecture**: When unexpected registry errors, budget limits, or network failures occur, Release Sentinel fails closed to prevent compromised packages from slipping through uninspected.
