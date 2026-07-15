# Changelog

## 1.1.0 - 2026-07-15

### Added

- Five-step discovery-to-validation workflow with live readiness indicators.
- Triage dashboard, quick views, risk/recent/occurrence/endpoint sorting, and evidence-score bars.
- Comparison-readiness guidance and one-click transitions from a candidate to identity capture or the test matrix.
- Caido request/response context-menu integration that analyzes and focuses the selected request in the assistant.
- Exact CSRF/XSRF substitution for repeated query/form fields and nested JSON arrays or keys containing dots.
- An 8 MiB editor preview limit with a clear fallback to the complete message in Caido HTTP History.
- Coverage reporting and downloadable build artifacts in the GitHub validation workflow.
- Repository-specific Ed25519 release signing with a committed public verification key.

### Fixed

- Request/response correlation now requires the same observed object value instead of a matching field name alone.
- Authentication, telemetry, and pagination context no longer changes a candidate fingerprint.
- Invalid owner controls stop before a cross-identity request is sent.
- HTTP 401 cross responses count as authentication failures in bounded batches.
- Clear and rescan operations drain old workers before deleting stored candidates.
- Queue overflow can be retried by the recent-History monitor.
- Passive pause, resume, cancel, project-change, and active-comparison states no longer overwrite each other.
- Cookie identity headers preserve semicolon-separated cookie semantics.
- Duplicate identity profiles are rejected.
- Stale message loads and refreshes no longer overwrite a newer frontend selection.
- CSV exports protect formula-like values after leading whitespace, and download URLs are revoked safely.
- Malformed settings lists and review states are validated at the backend boundary.

### Changed

- Upgraded the build stack to Node.js 22, pnpm 11, Caido SDK 0.57.1, Vue 3.5, TypeScript 6, and Vitest 4.
- Expanded the backend suite from 13 to 20 tests.
- Refreshed GitHub Actions and added dependency audit plus downloadable CI artifacts.

## 1.0.1

- Restored readable text and controls in Caido's dark theme.

## 1.0.0

- Initial Caido release.
