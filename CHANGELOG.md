# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

## [0.1.2] - 2026-11-18

### Fixed

- The login still failed over plain HTTP after 0.1.1: the page layout also carried a `<meta name="referrer" content="no-referrer">` tag, which overrides the response header. It is now `same-origin` as well, and a test checks both.

## [0.1.1] - 2026-11-18

### Fixed

- Login and every form failed with "cross-origin request detected" when the UI was served over plain HTTP (for example on a VPN address). The `Referrer-Policy: no-referrer` header made browsers send `Origin: null`, and without `Sec-Fetch-Site` (only sent over HTTPS) the cross-origin check rejected the request. The policy is now `same-origin`, so other sites still receive no referrer.

## [0.1.0] - 2026-11-18

First public release.

### Added

- Decisions: list active decisions (optionally including the community blocklist), add a ban or captcha on an IP or range, delete one decision, unblock every decision for an IP.
- Alerts: list with filters (IP, scenario, origin, period, active decision) and an alert page with source, decisions, context and events.
- AppSec: requests analysed and blocked per engine, rules that matched, and recent AppSec / virtual-patching alerts, read from the Prometheus endpoint.
- Hub: browse collections, scenarios, parsers, postoverflows, contexts, AppSec configs and AppSec rules; install, upgrade and remove items; update the index; reload CrowdSec.
- Allowlists: create, delete, add and remove entries with expiration and comment; list installed whitelist parsers.
- Bouncers and machines pages.
- Authentication: users file with bcrypt and optional TOTP, `admin`/`viewer` roles, read-only mode, or proxy mode behind Authelia / oauth2-proxy.
- cscli access through a local command (`sudo`) or the Docker Engine API (socket proxy).
- Demo mode with fake data.
- Docker image (distroless, non-root), Compose, Traefik and systemd examples.
