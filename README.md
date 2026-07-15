# IDOR / BOLA Assistant for Caido

IDOR / BOLA Assistant is an evidence-driven access-control workbench for Caido. It passively inspects scoped HTTP History and live responses for object references, keeps distinct observations per endpoint, and supports explicit owner-versus-target comparisons using captured test identities.

Passive discovery never sends requests. Active comparisons are initiated only from the UI, accept `GET` and `HEAD` requests only, require both generated requests to remain in Caido Scope, and stop at a configurable request budget. State-changing requests are prepared as Replay sessions and are never sent automatically.

Candidates and automated comparisons are review leads, not vulnerability verdicts. Always validate object ownership, authorization rules, and impact manually.

## Features

- Detects object references in paths, query/form fields, JSON, GraphQL, XML, multipart bodies, cookies, allowlisted headers, and bounded response bodies.
- Presents a five-step Discover → Capture → Assign → Compare → Validate workflow with readiness guidance and triage metrics.
- Provides quick review/high/untested/suspicious views, multiple sort modes, evidence-score bars, and responsive accessible controls.
- Adds **Analyze with IDOR BOLA Assistant** to Caido request/response context menus and focuses a detected candidate directly.
- Separates object references from authentication context, pagination, telemetry, and weak generic identifiers.
- Keeps low-evidence signals under **Suppressed** and promotes repeated distinct evidence when appropriate.
- Stores masked values and hashes in candidate metadata and exports instead of copying raw object identifiers into those records.
- Captures multiple in-memory identity profiles from selected Caido requests, including supported authentication headers and session-bound CSRF/XSRF substitutions.
- Associates each candidate with up to 20 distinct observations and lets reviewers explicitly assign an owner identity.
- Runs one controlled owner-versus-target comparison or a bounded sequential read-only batch.
- Validates the owner control first and skips the cross-identity request when the owner session is redirected, denied, rate limited, blocked, or otherwise unusable.
- Compares status, content type, authentication barriers, redirects, normalized JSON/XML/HTML, object identity, and owner-baseline stability.
- Stops batches on request-budget exhaustion, rate limiting, repeated authentication/session failures, cancellation, or scope violations.
- Creates owner and cross-identity Replay sessions for mutation requests without sending either request.
- Supports review states, reversible endpoint/host rules, filtered JSON/CSV metadata exports, and redacted Caido Findings after manual confirmation.
- Persists candidates, observations, review states, rules, and settings per Caido project. Authentication profiles remain memory-only.
- Applies captured CSRF/XSRF values to the exact repeated query/form occurrence or nested JSON path, including arrays and dotted keys.
- Caps embedded request/response previews at 8 MiB while leaving complete messages available in Caido HTTP History.

## Requirements and build

- Node.js 22 or newer.
- pnpm 11.
- A current Caido release compatible with SDK `0.57.x`.

```bash
pnpm install
pnpm typecheck
pnpm test:coverage
pnpm lint
pnpm knip
pnpm audit --audit-level high
pnpm build
```

The loadable package is created at:

```text
dist/plugin_package.zip
```

## Install

1. Build the plugin or obtain `plugin_package.zip` from a trusted release.
2. Open Caido's plugin installation screen and load the ZIP package.
3. Add only authorized targets to Caido Scope.
4. Open **IDOR BOLA Assistant** from the sidebar.

## Recommended workflow

1. Proxy normal traffic from dedicated test accounts. Passive discovery populates **Candidates** without sending traffic.
2. Review active and suppressed candidates. The displayed URL and reference values are redacted.
3. Focus a useful candidate and note one of its Caido Request IDs.
4. Open **Identities**, capture that request as a named owner profile, and repeat with a trusted request from each target test identity.
5. Open **Test matrix**, select an observation, and assign its real owner profile. Never infer ownership from a similar username or role label.
6. Choose a distinct target profile or **Anonymous**.
7. For `GET`/`HEAD`, run a single comparison first. Select multiple read-only candidates only after confirming the owner assignments.
8. For mutation methods, use **Prepare mutation in Replay**, review side effects, and decide manually whether either Replay request is safe to send.
9. Review the source, owner-control, and cross-identity messages. Similar responses alone are not treated as suspicious unless object-identity evidence is preserved.
10. Mark the workflow status. Use **Confirm & publish Finding** only after manual validation.

## Safety and data boundaries

- The scanner uses only identifiers already observed in traffic. It does not increment, enumerate, brute-force, or synthesize adjacent IDs.
- Scope-only mode is enabled by default and enforced again before active requests are sent or Replay sessions are created.
- Active comparisons never accept mutation methods.
- Owner and target profiles with the same authentication fingerprint are rejected.
- Identity profiles are kept in backend memory and are cleared when the active Caido project changes or the plugin unloads.
- Authentication values are not exposed as profile fields, written to candidate tables, copied into exports, or embedded in Finding descriptions. The evidence viewer and each Finding can still reference existing Caido HTTP messages, which remain governed by the Caido project's own data handling.
- Candidate rules contain selectors and reasons only; they do not contain HTTP messages or raw identifier values.
- Binary and oversized bodies are skipped or bounded according to Settings.
- A successful cross-identity response is not sufficient by itself. Authentication failures, redirects, WAF responses, rate limiting, unstable controls, and missing ownership evidence remain protected or inconclusive.

## Tabs

- **Candidates** — filters, review states, masked reference evidence, source/control/cross messages, metadata export, and Finding publication.
- **Candidates** also includes a live triage dashboard, workflow progress, quick views, sorting, and direct actions into identity capture or the test matrix.
- **Identities** — capture and remove memory-only profiles.
- **Test matrix** — assign owners, run explicit read-only comparisons, stop a batch, or prepare mutations in Replay.
- **Rules** — add or remove host/endpoint `IGNORE` and `ALLOW` rules.
- **Settings** — body/history bounds, candidate limits, active request budget, delay, custom reference names, ignored paths, and volatile response fields.

## الاستخدام السريع بالعربية

1. ابنِ الإضافة باستخدام `pnpm install && pnpm build` ثم حمّل `dist/plugin_package.zip` داخل Caido.
2. أضف الأهداف المصرّح بها فقط إلى **Caido Scope**.
3. مرّر ترافيك حسابات الاختبار؛ التحليل السلبي لا يرسل أي طلبات.
4. اختر Candidate مناسبًا، ثم التقط Request موثوقًا لكل حساب من تبويب **Identities**.
5. من **Test matrix** عيّن الحساب المالك الحقيقي لكل Observation، واختر حسابًا آخر أو Anonymous.
6. المقارنة الآلية تعمل فقط مع `GET/HEAD` وضمن ميزانية الطلبات المحددة. طلبات التعديل تُجهّز داخل Replay ولا تُرسل تلقائيًا.
7. الأداة تستخدم IDs شوهدت بالفعل فقط؛ لا تعمل enumeration أو brute force.
8. راجع رسائل المصدر والمالك والحساب الآخر يدويًا، ثم انشر Finding فقط بعد التأكد من الملكية والأثر.
9. بيانات المصادقة تبقى في الذاكرة الخلفية ولا تظهر في الواجهة أو التصدير أو Findings.

## License

MIT. See [LICENSE](LICENSE).
