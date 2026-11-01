---
name: Bug report
about: Report a reproducible problem with proxy-firewall.
title: "[Bug] "
labels: ""
assignees: ""
---

<!-- Report suspected vulnerabilities privately to anar.k.jafarov@gmail.com. -->

## Problem

Describe what failed and how it affects your deployment.

## Steps to reproduce

1.
2.
3.

## Expected and actual behavior

Explain what you expected and what happened instead.

## Environment

- Version (from `VERSION`), image tag or commit:
- OS and architecture:
- Go version, if building from source:
- Deployment method (systemd, Docker, Compose or direct binary):
- Relevant features (TLS, Redis, MaxMind, admin interface):

## Configuration and logs

Include only the settings and log excerpts needed to reproduce the problem.
Remove passwords, credentials, license keys, private keys and sensitive addresses.
For systemd installations, logs are in `/etc/proxy-firewall/log/proxy-firewall.log`.

```text
Paste sanitized configuration and logs here.
```

## Checks

- [ ] I searched existing issues for the same problem.
- [ ] I removed secrets and private deployment data from this report.
