# Security Policy

## Supported Versions

Release Sentinel is currently in active development. Only the latest minor release line receives security updates.

| Version | Supported          |
| :------ | :----------------- |
| 0.5.x   | :white_check_mark: |
| < 0.5.0 | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you believe you have discovered a vulnerability in Release Sentinel:

1. **GitHub Private Vulnerability Reporting**: Use the **Security** tab on the repository and select **Report a vulnerability**.
2. **Email**: If GitHub reporting is unavailable, email `security@release-sentinel.dev` with:
   - A description of the issue and potential security impact.
   - Minimal reproduction steps or proof-of-concept.
   - Any suggested mitigations.

### Response Timeline

- **Initial Response**: Within 48 hours acknowledging receipt.
- **Triage & Assessment**: Within 7 business days with confirmation of validity and severity.
- **Fix & Advisory**: We coordinate coordinated disclosure and release patches promptly.

## Security Principles

Release Sentinel adheres to strict security and safety principles:
- **Safe Static Inspection**: Release Sentinel analyzes npm tarballs statically in memory and never executes package code or lifecycle scripts.
- **Isolated Tarball Handling**: Tarballs are extracted purely in memory with path traversal protection, compression ratio checks, and hard size limits.
- **Fail-Closed Live Architecture**: When unexpected registry errors, budget limits, or network failures occur, Release Sentinel fails closed to prevent compromised packages from slipping through uninspected.
