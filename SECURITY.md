# Security Policy

## Supported versions

Zarpa is pre-alpha. Only the latest commit on `main` receives security fixes until 1.0.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:
https://github.com/SW3T0/zarpa/security/advisories/new

Please include a description, affected component, reproduction steps and impact. You will get an
acknowledgement within 7 days and a status update within 30 days. We credit reporters unless asked not to.

## Scope

In scope: the protocol, pairing and encryption, the daemon and its local API, shell extensions, the
CLI and MCP server (including agent permission bypasses), and release artifacts.
Out of scope: attacks requiring prior full control of a paired device, and denial of service from
physically present LAN attackers.
