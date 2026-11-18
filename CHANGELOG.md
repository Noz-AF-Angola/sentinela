# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

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
