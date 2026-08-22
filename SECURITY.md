# Security Policy

## Supported versions

Security fixes are applied to the latest version on the `main` branch and to the latest published release when applicable.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| `main` | Yes |
| Older releases | Best effort |

## Reporting a vulnerability

Please do **not** disclose suspected security vulnerabilities in a public issue, discussion, pull request, or social-media post.

Use GitHub's **Private Vulnerability Reporting** for this repository from the **Security** tab and choose **Report a vulnerability**. Include enough information to reproduce and assess the issue, such as:

- affected version or commit;
- affected endpoint, component, or configuration;
- reproduction steps or a minimal proof of concept;
- expected and observed behavior;
- potential impact;
- any suggested mitigation, if known.

If Private Vulnerability Reporting is temporarily unavailable, open a public issue that contains **no vulnerability details** and only asks the maintainer to provide a private reporting channel.

## Security expectations

G-Hotspot is intended to be self-hosted. Deployments should follow these minimum safeguards:

- terminate public traffic with HTTPS;
- do not expose the application port directly when a reverse proxy is used;
- enable `TRUST_PROXY` only when `TRUSTED_PROXY_CIDRS` contains the exact proxy IP addresses or CIDRs that connect directly to G-Hotspot;
- keep the encryption master key separate from database backups for higher-assurance deployments;
- restrict filesystem access to `.env`, database files, signing material, and encryption keys;
- keep Node.js and the host operating system supported and patched;
- review GitHub security alerts and update dependencies and Actions promptly.

## Scope notes

A security report is especially useful when it affects authentication or authorization, setup access, secret handling, encryption, session security, captive-portal identity boundaries, command or path injection, request forgery, or sensitive-data exposure.

Please avoid testing against systems you do not own or have explicit permission to assess.
