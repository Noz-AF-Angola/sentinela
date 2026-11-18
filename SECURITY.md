# Security policy

Sentinela controls a security component, so bugs in it can matter. Thanks for taking the time to report them.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
<https://github.com/Noz-AF-Angola/sentinela/security/advisories/new>

Include what you can: the version (`sentinela version`), the configuration mode (local or proxy auth, cscli mode), steps to reproduce and what an attacker gains. You will get an answer within a week. Once a fix is released, the advisory is published with credit to you unless you prefer otherwise.

## Supported versions

Only the latest minor release gets security fixes while the project is at 0.x.

## Scope

In scope: authentication and session bypass, CSRF, XSS, command or argument injection into cscli, trust of forged proxy headers, information leaks across users.

Out of scope: problems that need an already compromised admin account or host, deployments that ignore the README (publishing Sentinela or the LAPI on the internet without protection, trusting `0.0.0.0/0`), and denial of service through a flood of requests that a reverse proxy should rate-limit.

The threat model is described in the README, section "Security and threat model".
