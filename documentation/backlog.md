# WP Bouncer backlog

Owner: product-manager. Last updated 2026-10-23, against released version 1.1.1.
Minimum supported: PHP 7.4, WordPress 5.8. Distribution: GitHub releases (not wp.org), so wp.org review does not gate a release, but the wp.org plugin guidelines (GPL, no tracking, escaped output, no remote calls without disclosure) are still the quality bar.

## Owner decisions (2026-10-23)

1. **PHPStan:** target level 6 in WPB-1 (both `phpstan.neon.dist` and `phpstan-php74.neon`). Level 7+ revisited later.
2. **Privacy (WPB-3b):** approved for 1.2.0. Block-log retention of up to 365 days stays as it is.
3. **Rule categories:** the four proposed categories are confirmed (Block lists; Login and accounts; Scanners and floods; Attack payloads and hardening). No category-level switches: every rule stays independently switchable.
4. **Audit scope:** WPB-3 assesses signing release zips (decision as an ADR) and adds a `SECURITY.md` with a disclosure contact.
5. **Release split:** superseded 2026-10-24: everything planned for 1.2.0 ships together, including WPB-2, WPB-4, WPB-6 and WPB-7.
6. **Integration suite:** landed (tests/Integration, 407 tests). WPB-2, WPB-4 and WPB-3b must include integration tests.

7. **Security decisions (2026-10-23, from the WPB-3 blue-team review):**
   - **Release signing (SB-07/ADR 002): deferred.** Not in 1.1.2 or 1.2.0; revisit later. Workflow hardening that doesn't need signing (SB-08/SB-10) can still be proposed separately.
   - **Header IP source with no trusted proxies (SB-01 part 2): change behaviour on upgrade.** Fall back to REMOTE_ADDR and show a site-wide admin notice explaining why; never accept loopback/private addresses from a header.
   - **Privacy erase (WPB-3b): keep block-log rows** (legitimate interest), with URI and reason redacted. No `user_id` column in the block log; no IP-based export to requesters.
   - **Multisite (SB-14): restrict server-wide actions** (geo URL import, `.htaccess` writes, the PHP probe, custom regexes) to the network admin (`manage_network_options`) on multisite.
   - **SECURITY.md: GitHub private vulnerability reporting only**, no email contact. The owner enables it in the repository settings.
   - **Red team re-run** in fix-list format (no attack descriptions) to replace the incomplete pass-1 report.

## How this is prioritised

Method: **RICE** (Reach x Impact x Confidence / Effort), with one override: **security and data-loss work jumps the queue** (severity order: security > data loss > crash/white screen > broken feature > cosmetic).

- Reach: 1-10, share of installs/admins touched per release.
- Impact: 0.25 minimal, 0.5 low, 1 medium, 2 high, 3 massive.
- Confidence: how sure we are of Reach and Impact.
- Effort in weeks of team time: S = 0.5, M = 1.5, L = 4.

| ID | Item | Reach | Impact | Conf. | Effort | RICE |
|---|---|---|---|---|---|---|
| WPB-3 | Security audit | 10 | 3 | 70% | 4 (L) | 5.3 |
| WPB-1 | phpcs / PHPStan clean | 3 | 1 | 90% | 1.5 (M) | 1.8 |
| WPB-4 | Dashboard widget | 6 | 0.5 | 70% | 1.5 (M) | 1.4 |
| WPB-2 | Rules UI redesign | 8 | 1 | 60% | 4 (L) | 1.2 |

RICE alone says audit, lint, widget, UI. **Proposed order of work: WPB-1, WPB-3, WPB-4, WPB-2.** The one deviation from RICE is that lint goes first. It is small, it is a mechanical rewrite of 45 files that would otherwise collide with every other change, and the audit should read the final, formatted code. The phpcs `WordPress.Security.*` sniffs (escaping, nonces, input sanitising) also give the audit a free first pass. The UI redesign is last because it is the largest and least certain item, but its **design phase (architect, docs only) starts immediately** and runs alongside WPB-1 and WPB-3, so it is ready when the developer is free. The widget goes before the UI because it is smaller, independent, and reuses the same design work on statuses.

## Release plan (semver)

| Release | Contents | Why this number |
|---|---|---|
| **1.1.2** (patch) | Not released (owner decision 2026-10-24); its work is on the release branch and ships in 1.2.0 | |
| **1.2.0** (minor) | WPB-5 minimums (PHP 8.3, WordPress 7.0) first, then the remaining WPB-3 fixes, WPB-4 widget, WPB-2 Rules UI, WPB-3b privacy hooks, WPB-6 version warnings, WPB-7 PHP settings checks | New backwards-compatible features, no breaking change to settings keys, hooks or the `wp_bouncer_rules` filter. Everything ships together so it goes through one full test and audit cycle (owner decision 2026-10-24). |
| **Hotfix 1.1.x** (out of band) | Any Critical or High audit finding | Do not wait for 1.1.2 or 1.2.0. Triage first, patch, tag. |

Every release: bump `wp-bouncer.php` header and `Plugin::VERSION`, `readme.txt` Stable tag plus its Changelog and Upgrade Notice, and `documentation/CHANGELOG.md` together. Final security-red delta audit on the diff since the last tag before tagging (release workflow step 3).

- 1.1.2 changelog: **Fixed/Security** entries for each audit fix (reference severity, not exploit detail, until users have had time to update). **Changed** (internal): "Code now passes the WordPress coding standard; lint is enforced in CI". readme.txt: Stable tag, changelog, and an Upgrade Notice if any security fix is included.
- 1.2.0 changelog: **Added** (dashboard widget, privacy exporter/eraser if approved), **Changed** (Rules tab is grouped into categories; no settings are lost or reset). readme.txt: update the description of the Rules tab and add a Dashboard widget line; screenshots are outdated after the UI change, so refresh them.

## Cross-cutting dependency: integration test suite

A separate effort is adding MySQL/MariaDB e2e runs and a WordPress integration suite (`WP_UnitTestCase`; `.github/workflows/tests.yml` has an `integration` placeholder). Until it lands, the e2e suite (SQLite plus the MySQL/MariaDB matrix already in `tests.yml`) is the only check on WordPress-facing behaviour. Policy:

- WPB-1 does not need it (behaviour must not change; unit plus e2e suffice).
- WPB-3 regression tests for admin handlers (capability, nonce, redirects) are much better as integration tests.
- WPB-2 and WPB-4 must ship with integration tests. If the suite has not landed when development starts, the work may proceed, but it does not leave the "tester" step until integration tests exist for it.

---

# Now

## WPB-1: Code passes phpcs and PHPStan
- **Type:** chore
- **Priority:** P2 overall, but sequenced first (enabler, see above)
- **Effort:** M. 216 errors and 45 warnings in 45 files; 72 are auto-fixable with phpcbf, so about 140 need manual fixes or justified ignores.
- **Risk:** Low to medium. Mass reformatting can hide an accidental behaviour change (for example Yoda or strict-comparison rewrites, escaping that alters output). Mitigation: do the phpcbf pass as its own change with no manual edits mixed in, run the full unit and e2e suites on it, then do manual fixes in small batches. Review the diff with whitespace ignored.
- **Dependencies:** none. Should merge before WPB-3 starts and before WPB-2/WPB-4 code is written, to avoid conflicts.

**User story.** As a maintainer, I want the plugin source to pass the WordPress coding standard and static analysis in CI, so that new code is held to the same bar automatically and reviewers and the security audit can spend their time on logic instead of style and missing escaping.

**Acceptance criteria**
1. `make lint` reports 0 errors and 0 warnings on `wp-bouncer/`.
2. Every remaining `phpcs:ignore`, `phpcs:disable` or ruleset exclusion has a same-line reason (`-- why`). Blanket `phpcs:ignoreFile` is not used. The count of ignores is listed in the pull request so reviewers can see it did not balloon.
3. Ignores on `WordPress.Security.*` and `WordPress.DB.*` sniffs are reviewed individually by code-reviewer and each states why the value is safe.
4. `.github/workflows/tests.yml`: the `lint` job no longer has `continue-on-error: true`, and a deliberately introduced violation makes the job fail (verify once on a throwaway branch). The heading comment "Non-blocking" is updated.
5. `make analyse` still passes at the agreed level, in both configurations (`phpstan.neon.dist` and `phpstan-php74.neon`).
6. No behaviour change: `make test` and `make e2e` (and `make check` against the built zip) pass with no test edited to make them pass. Any test edit is explained in the PR.
7. PHP 7.4 and WordPress 5.8 compatibility intact (phpcs `testVersion 7.4-` and `minimum_supported_wp_version 5.8` stay as configured; no `%i` placeholders, no PHP 8 syntax).
8. Translation readiness not regressed: `WordPress.WP.I18n` clean for text domain `wp-bouncer`, and every string with placeholders keeps its `translators:` comment.
9. `documentation/developer-guide.md` and `CLAUDE.md` state that lint is blocking (docs-writer).

**Open question for the owner: should "passes PHPStan" mean a higher level?** It passes at level 5 today and is already blocking in CI (also run as PHP 7.4). My recommendation: **target level 6 in this item, and decide on 7 later; do not go to 8 or 9 now.**
- Level 6 adds missing type hints and generics in PHPDoc. For this codebase that mostly means adding array-shape annotations to the settings arrays and `$wpdb` results. It is cheap, documents the settings structure (which the UI redesign and widget will lean on), and creates no runtime changes.
- Level 7 reports possibly-wrong union types; level 8 checks calls on nullable values; levels 9 and 10 treat `mixed` strictly. The WordPress boundaries (`$_POST`, `get_option()`, `apply_filters()` from third-party code, and the `treatPhpDocTypesAsCertain: false` setting that exists on purpose) would produce many findings that are fixed with casts or suppressions rather than real bugs. Poor return.
- Before committing, spend a half-day spike running level 6 and 7 and recording the error counts. If level 6 is under about 50 errors, include it in 1.1.2; if it is larger, make raising the level a separate chore item for 1.2.0. Do not use a baseline file to hide errors unless the owner agrees (question below).
- Other owner decisions: (a) should `make check` also run lint and analyse? (b) should phpcs also cover `tests/`? (currently `wp-bouncer/` only, which matches what ships).

## WPB-3: Full security audit and assessment
- **Type:** chore (assessment), with bugs/features spawned from its findings
- **Priority:** P1. Security work goes to the front of the queue by policy; it starts as soon as WPB-1 has merged, because the audit should run on the formatted code.
- **Effort:** L (assessment plus triage), plus remediation sized per finding
- **Risk:** Medium. The firewall runs on every request, so a fix to IP resolution or the WAF can lock out real users or open a bypass; mitigate with monitor-mode notes in the changelog and tests that pin both the block and the allow case. A finding in a released version is a disclosure risk: keep details in `documentation/security/` (not published in release notes) until the fix is out.
- **Dependencies:** WPB-1 merged. Integration suite for regression tests on WordPress-facing handlers (use unit/e2e meanwhile). Feeds into WPB-2 and WPB-4 via a delta audit.

**User story.** As a site admin who is trusting this plugin to protect my site, I want it independently reviewed from both the attacker's and the defender's side, so that the firewall itself is not the weakest point on my site and any weaknesses are fixed before I rely on it.

**Scope (in)**
1. **Admin surface:** every `admin_post_*` and `wp_ajax_*` handler in `src/Admin/AdminController.php` (capability, nonce, input validation, redirect and message handling, `$_REQUEST` use, state changes via GET such as the Dashboard "Block" link), the list tables, and the admin views (output escaping, stored XSS from attacker-controlled log fields such as URI, User-Agent, reason, referrer).
2. **REST/AJAX:** the plugin registers no REST routes today (confirm). AJAX is the geo import step. Also review how the firewall treats other plugins' REST and AJAX endpoints (the user-enumeration rule).
3. **Firewall bypasses:** IP spoofing via `X-Forwarded-For`, `CF-Connecting-IP` and other headers (`IpResolver`, trusted proxies, the "no proxies listed" case, IPv6 and IPv4-mapped forms, CIDR edge cases); allowlist and loopback handling; rule-order and early-exit bypasses; path normalisation (encoded slashes, double encoding, case, `//`, trailing dots, `PATH_INFO`); method override; `WP_BOUNCER_DISABLE` handling.
4. **WAF evasion:** encoding and case tricks, nested array keys, values over the 8 KB cap, JSON and multipart bodies, parameter names, cookies and headers (not inspected by design: document as accepted risk or change), ReDoS in the WAF and User-Agent regexes (user-supplied regexes included), and `excluded_params` abuse.
5. **Login protection:** lockout counter evasion and abuse (lock out a victim's IP by spoofing, username-ban lockout used for denial of service), `generic_errors`, the `authenticate` filter paths.
6. **Update channel integrity:** `Update\Updater` and `ReleaseManifest`: SHA-256 verification (where the hash and the zip are both fetched from the same origin, so a compromised release controls both: assess signing), URL pinning to the repository, downgrade, redirect and TLS handling, `update.json` parsing, tag-to-release workflow and GitHub Actions permissions in `release.yml`.
7. **File writes:** the `uploads/.htaccess` block (`UploadsGuard`, `insert_with_markers`), the probe script written to uploads (race, predictable name, cleanup), the cron safety check, symlink and permission issues, behaviour on multisite upload dirs, and the deletion of the uploads file on uninstall.
8. **Geo import:** CSV/gz upload and URL download (SSRF via the admin-supplied URL and DNS rebinding, zip/gzip bomb, disk and time exhaustion, temp-file handling and cleanup, malformed rows), and the DB-IP default URL.
9. **CSV export injection:** `AdminController::csv_safe()` coverage of every exported column (only some columns pass through it, but check all of them, including leading whitespace/newline tricks and non-ASCII look-alikes), and Content-Disposition handling.
10. **SQL:** every `$wpdb` use, including interpolated table and column names in `BlockLog`, `TrafficLog`, `GeoDatabase`; sorting parameters; LIKE escaping.
11. **Data exposure and privacy:** the block log and traffic log store visitor IPs, User-Agents, URLs and referrers (redaction is implemented for the traffic log; check the block log's `uri` and `reason` fields, which `BlockLog` truncates but does not redact). Retention up to 365 days (block log) and 7 days (traffic). The plugin registers **no WordPress personal-data exporter or eraser** and adds no privacy-policy text. Review under GDPR/UK GDPR expectations (see WPB-3b).
12. **Denial of service by design:** log flooding (per IP+rule de-dup, but spoofed IPs), transient and `wp_options` bloat from counters, the rate-limit and 404 counters used against a victim IP, the traffic log write per request.
13. **Alerts:** header injection, mail flooding limits, information in alert emails.
14. **Uninstall and multisite:** what is left behind, whether per-site tables and options are cleaned on network uninstall (`uninstall.php`), network activation behaviour.
15. **Supply chain and packaging:** the zip contents, no dev files, `composer.json` dev-only, GitHub Actions secrets and permissions.

**Out of scope:** WordPress core, the web server and the host, third-party plugins' own flaws (only how this plugin interacts with them), and load/penetration testing against any live or production site. All dynamic testing is against local or throwaway test sites only (CLAUDE.md). Do not test on a site where `plugins/wp-bouncer` is a symlink to the repo and then run an update or uninstall.

**Leads from reading the code (unverified, for the auditors to confirm or discard; not findings):**
- `handle_block_ip` accepts a GET link (nonce-protected) and reads `$_REQUEST['back']` without sanitising.
- `handle_geo_import` fetches an admin-supplied URL with `download_url()`; check SSRF protections and size limits.
- The `wpb_msg` query parameter is printed in an admin notice (escaped), but a crafted link can show an arbitrary message to an admin (content spoofing).
- CSV `csv_safe()` is applied via `array_map` to all cells; confirm the numeric `user_id`/`status` columns and a cell beginning with a space or newline.
- Update verification: the hash is published next to the zip it protects.

**Method.** security-blue first (threat model and trust boundaries, written to `documentation/security/threat-model.md`), then security-red against that model (read-only, `documentation/security/audit-<date>.md`), run in parallel where independent. Then triage (product-manager), then fixes (debugger or developer), then code-reviewer, then security-red retest of each fix.

**Deliverables** (all under `documentation/security/`)
- `threat-model.md`: assets, actors, trust boundaries, data flows, assumptions (for example "the admin is trusted").
- `audit-<date>.md`: every finding with ID, severity, affected file and function, proof of concept (local only), recommended fix, status.
- `risk-register.md`: accepted risks and their rationale (for example "cookies and headers are not inspected by the WAF").
- A triaged list of remediation items in this backlog, one per finding, with severity.
- Regression tests: one test per fixed finding, which fails on the old code and passes on the new.
- A summary suitable for the changelog (severity counts, no exploit detail).

**Severity policy for releases** (CVSS-style judgement by security-red, confirmed by product-manager)
- **Critical or High** (remote unauthenticated compromise or bypass of a core protection; any admin-privilege escalation; update-channel compromise; data loss): fix immediately, hotfix release outside the plan, and block all other releases until fixed.
- **Medium** (needs an authenticated admin or unusual configuration; partial bypass; privacy exposure): blocks the next release unless the owner signs a written waiver in the risk register with a mitigation and a target version.
- **Low / Informational:** does not block; goes to the backlog, ordered by RICE.
- Anything that causes a security regression test to fail blocks the release.

**Acceptance criteria**
1. Threat model, audit report and risk register exist in `documentation/security/` and cover every scope item above (each item marked reviewed, with "no findings" stated explicitly where that is the result).
2. Each finding has a severity, a status (fixed / accepted with rationale / won't fix with rationale), and an owner.
3. All Critical and High findings are fixed and retested. All Medium findings are fixed or carry a signed waiver.
4. Each fixed finding has a regression test (unit, e2e, or integration), and the whole suite passes (`make check`).
5. The IP-spoofing review includes tests proving that a forged forwarded-for header does not change the detected IP when the request does not come from a trusted proxy, and that the "no trusted proxies listed" case is covered by the admin warning.
6. The audit states explicitly the privacy position (what personal data is stored, for how long, how it can be exported or erased) and the owner's decision on WPB-3b.
7. The update-channel assessment states whether a compromised GitHub release could silently install malicious code, and recommends signing or another control (decision recorded as an ADR in `documentation/adr/`).
8. A delta audit of WPB-2 and WPB-4 is done before 1.2.0 is tagged.

**Timing relative to the others.** Run it **after WPB-1 and before the UI and widget work is merged, then run a short delta audit on the 1.2.0 diff.** Reasoning: auditing before lint means findings reference code that is about to be rewritten, and the lint pass adds escaping fixes the audit would otherwise re-report. Auditing only after the UI and widget would delay security fixes for existing, released code by weeks, which breaks the "security jumps the queue" rule. The UI and widget code is new and mostly admin-side output, which a delta audit covers well. security-blue can start its threat model while lint is in progress (it reads design, not diffs).

### WPB-3b: Personal-data exporter, eraser and privacy-policy text (spawned from WPB-3 item 11)
- **Type:** feature
- **Priority:** P2. Becomes P1 if the audit rates the privacy exposure Medium or above.
- **Effort:** M
- **Risk:** Medium (erasing log rows is data deletion: confirm the owner wants the activity log to be erasable; matching an email to an IP is not possible, since logs store IPs and the logged-in `user_id` only for traffic).
- **Dependencies:** WPB-3 decision. Integration tests (WordPress privacy tools are only realistically testable there).
- **Release:** 1.2.0 if approved.

**User story.** As a site admin subject to GDPR, I want the plugin to take part in WordPress's Export/Erase Personal Data tools and to suggest privacy-policy text, so that I can answer a visitor's data request without editing database tables by hand.

**Acceptance criteria (draft, pending owner answers)**
1. A registered exporter (`wp_privacy_personal_data_exporters`) returns, for a requested user, the traffic-log rows whose `user_id` matches, paginated.
2. A registered eraser (`wp_privacy_personal_data_erasers`) removes or anonymises those rows and reports items removed/retained.
3. `wp_add_privacy_policy_content()` text describes what is logged and the retention periods, reflecting the current settings' wording where practical.
4. Tests prove export and erase on a user with rows and a user without.
5. No change to the schema unless the owner chooses IP-based requests (see questions).

## WPB-2 and WPB-4 follow in "Next" below.

---

# Next

## WPB-4: Dashboard widget with recent-block statistics
- **Type:** feature
- **Priority:** P3. RICE 1.4. Nice-to-have visibility: an admin sees activity without opening the Bouncer screen.
- **Effort:** M
- **Risk:** Low to medium. It runs on every wp-admin home view, so a slow query or an uncached aggregate on a big log slows the dashboard of every admin. Mitigated by caching (below).
- **Dependencies:** none hard. Needs small additions to `BlockLog` (a time-bounded count for the "previous period" comparison, a recent-rows helper). Integration tests required once the suite lands. Benefits from WPB-1 (no style churn) and the WPB-3 delta audit (output escaping of attacker-controlled log fields).
- **Release:** 1.2.0

**User story.** As a site admin, I want a "WP Bouncer" box on the WordPress Dashboard showing what was blocked recently, so that I can see at a glance whether my site is under attack and jump to the Activity Log without opening the plugin.

**Proposed content (in priority order; the owner may trim)**
1. Status line: Enforcing / Monitor mode / Switched off (emergency constant) and the number of rules that are on out of the total.
2. Blocked in the last 24 hours and the last 7 days, each with a trend against the previous equal period (arrow plus the number and a text word, not colour alone).
3. Top 3 rules (7 days), each linking to the Activity Log filtered by rule.
4. Top 3 IPs and top 3 countries (7 days), IPs linking to the Activity Log filtered by IP. Countries shown only when a geo database is loaded.
5. The last 5 blocks (time ago, IP, rule).
6. A "View Activity Log" link, and "Settings" link.
7. **Active lockouts and bans:** note a design limit. Lockouts and bans live in transients named `wpb_<md5>` and cannot be listed or counted. Use "lockouts in the last 24 hours" from the log (action `lockout`), which the Dashboard tab already counts for 7 days. A true live count needs a new index of active bans (data-engineer decision), which I recommend against for the first version.

**Who can see it.** Users with `manage_options`, the same as `AdminController::CAPABILITY` (the plugin has no other capability). The widget is not registered for anyone else, so it does not render or query. Question for the owner on multisite below.

**Performance requirements.** Aggregates are cached in a transient (name starting `wpb_`, so the existing uninstall cleanup removes it) for about 5 minutes, and the cache is cleared when the log is cleared or an IP is blocked. A cache hit makes zero queries against the log table. A miss makes a small fixed number of indexed queries (the `created_at` column is indexed). The widget never calls remote services. The recent-blocks list is limited to 5 rows and the 'top' lists to 3. Without a persistent object cache the transient is one `wp_options` row, which is acceptable. Architect to decide whether to render the content lazily by AJAX so a slow query never delays the dashboard page itself; recommend yes only if measured to be needed.

**Acceptance criteria**
1. The widget appears on the Dashboard (`wp-admin/index.php`) for an administrator and not for editors, authors or any user without `manage_options`. A test checks both.
2. It shows: status, blocked counts for 24 hours and 7 days with trend, top rules, top IPs, top countries, the last 5 blocks and a link to the Activity Log, with correct numbers against a seeded log table.
3. Email alerts (action `alert`) are excluded from all counts, consistent with the Dashboard tab.
4. Counts match the plugin's own Dashboard tab for the same period (same definition of "blocked": action `blocked` only; `monitored` and `lockout` shown separately).
5. **Monitor mode:** the widget shows a clear "Monitor mode: requests are logged, not blocked" line, and the headline numbers are labelled "Would have been blocked" using the `monitored` action, so the numbers cannot be mistaken for real blocks.
6. **Switched off** (`WP_BOUNCER_DISABLE`): shows "WP Bouncer is switched off in wp-config.php" and still shows historical numbers, labelled as such; no notices are duplicated.
7. **Empty states:** a fresh install or empty log shows a friendly "Nothing blocked yet" message rather than zeros in tables; a missing geo database hides countries with a pointer to Tools; the traffic log being off does not matter to this widget.
8. **Performance:** with the cache warm the widget runs no queries on `bouncer_log`; with it cold it runs no more than the documented number of queries; both are asserted in a test. The cached value expires and refreshes. A log with 1 million rows does not slow the dashboard visibly (documented measurement on a MySQL test site, not a production one).
9. **Escaping and privacy:** all values (IPs, rule names, reasons) are escaped; the widget never shows full URLs, User-Agents or referrers (only IP, rule, time). It is visible only to administrators, who can already see the log.
10. **Accessibility:** headings and lists are semantic; any chart or sparkline has a text alternative; trends are readable without colour; the box can be collapsed, moved and hidden through WordPress's own Screen Options (standard dashboard behaviour); links have visible focus.
11. **Compatibility:** works on PHP 7.4 and WordPress 5.8, on MySQL, MariaDB and SQLite; no new database table; no new settings. No JavaScript is required (works with it disabled).
12. **Translation ready:** all strings use the `wp-bouncer` text domain; numbers use `number_format_i18n`; times use the site's time zone.
13. Uninstall leaves no widget transient behind (verify against the existing `uninstall.php` cleanup of `wpb_` transients).
14. Integration test covers capability, rendering and cache invalidation once the integration suite exists; unit tests cover the stat-building logic in a pure class.

## WPB-2: Redesign the Rules UI into categories
- **Type:** feature (UX redesign, no new protection)
- **Priority:** P3. RICE 1.2; the lowest score but the one the owner cares about for scale. Rules have grown from the original set to 11, and a third-party extension point is wanted.
- **Effort:** L
- **Risk:** Medium to high for a UI change. The main trap: the Rules tab is a single form and `Settings::apply_form()` replaces only the keys the tab owns, so **splitting rules into several forms or panels that post `tab=rules` separately would reset every rule not on the submitted panel** (unticked checkboxes are absent from POST). Also the Dashboard tab toggles rules through a different handler (`handle_toggle_rule`). A mistake here silently disables protections.
- **Dependencies:** **architect designs first, before any developer work** (design to `documentation/architecture/rules-ui.md`, with security-blue input on settings handling and data-engineer only if storage changes, which it should not). Integration tests required for the save paths once the suite lands. WPB-1 merged first. Delta audit before release.
- **Release:** 1.2.0

**Flag for the architect (design before build).** I am not specifying the layout; I am specifying the constraints and the decisions the architect must make and record in an ADR:
1. Layout choice among: accordion/sections on one page, sub-tabs, or a card grid with an overview. Whatever is chosen must satisfy the criteria below.
2. How a category is declared by a rule, for built-in and third-party rules (see criterion 11).
3. Whether Country blocking (settings live on the Countries tab) is shown inside its category as a status-and-link card.
4. Whether the Dashboard tab's "Rules" table (a separate on/off list) is kept, merged into the new overview, or reduced to a link. Avoid two UIs that can disagree.

**User story.** As a site admin, I want the rules grouped into clear categories with a status for each, so that I can find a rule quickly, see what is on and off at a glance, and the screen stays usable as more rules are added.

**Proposed categories (for the owner to confirm or rename)**

| Category | Rules | What the admin is deciding |
|---|---|---|
| Block lists (who is refused) | `ip_blocklist`, `country` (settings on the Countries tab), `user_agent` | Which visitors never get in |
| Login and accounts | `login_lockout`, `xmlrpc`, `user_enumeration` | Protecting sign-in and usernames |
| Scanners and floods | `sensitive_files`, `not_found`, `rate_limit` | Temporary bans for probing and too many requests |
| Attack payloads and hardening | `waf`, `uploads_php` | Malicious request content and script uploads |

Reasoning: the first group is "static" rules the admin curates; the second is the login surface (and XML-RPC is mostly a login attack vector); the third is the three rules that place a time-limited ban on the IP (documented that way in architecture.md); the fourth is content inspection and file hardening. Four groups of 2-3 rules scale to about 5 groups of 3-4 without a redesign. A rule with no category falls into "Other".

**Current state (verified in the code)**
- The Rules tab (`views/rules.php`) is one `<form>` with tab key `rules`; every panel is a `<section id="rule-<rule_id>">` with a switch named `wp_bouncer[rules][<id>][enabled]`. The uploads panel's Test now / Write it now buttons use separate forms attached by the `form=` attribute.
- Existing anchors: `#rule-<rule_id>` for each panel on the Rules tab (stable, keep them); `#wpb-alerts` on the General tab (used by the alert email's "settings_url" in `AlertNotifier`). No other screen currently links to a `#rule-*` anchor; notices refer to "Rules -> No PHP in uploads" in text only. Preserving these ids is cheap and protects any bookmarks or external links.
- `AdminController::rule_labels()` is a hard-coded list of the built-in rules; a third-party rule added through `wp_bouncer_rules` has no label, no settings, no switch, and appears in the log only under its id (`rule_title()` falls back to the id). Settings are allow-listed in `Settings::sanitize()`, so a third-party rule cannot save settings through this form today.
- The Dashboard tab has a table of rules with Turn on/off buttons (separate POST handler, no JavaScript).

**Acceptance criteria**
1. **Grouping:** the Rules tab shows the rules under the confirmed categories, each category with a heading and a one-line description. Every built-in rule (all 11, including `country`) appears in exactly one category.
2. **Independent switches (original core requirement):** every rule keeps its own on/off switch, and turning one rule on or off never changes another rule. There is no category-level switch that turns several rules at once (or, if the owner wants one, it is a separate explicit story).
3. **Status overview:** each category shows "N of M rules on" and each rule shows an on/off badge, readable without colour and without opening the panel. Rules needing set-up (country without a geo database, rate limiting off by default, uploads protection broken) show a warning status with a link to the fix, reusing the conditions already used for the admin notices.
4. **Saving keeps working per tab:** saving the Rules tab changes only the rules fields; General, Countries and Traffic settings are unchanged (existing `TAB_FIELDS` behaviour). Saving with one category collapsed, hidden or on another sub-tab must not alter the rules in it: all rule inputs are submitted every time, or the tab ownership is split in `TAB_FIELDS` with tests. Test: save, then compare the full settings array before and after for untouched rules.
5. **Settings data unchanged:** the option structure `wp_bouncer_settings['rules'][<id>]` is unchanged; no migration; existing installs see the same values after upgrade. Downgrade to 1.1.x loses nothing.
6. **No-JavaScript fallback:** with JavaScript disabled, every category and rule is visible and every setting can be changed and saved (JS may only enhance, for example collapse/expand, jump links, filter). The Dashboard tab toggles still work.
7. **Deep links:** `#rule-<id>` anchors continue to work and, if panels are collapsed or on sub-tabs, load with the target rule's category open and the rule scrolled into view and focus-able. A category anchor (for example `#wpb-cat-<slug>`) works the same way. Notices and other screens that point to a rule link to its anchor, for example the uploads warnings (currently text-only). Hash changes while on the page (clicking a link) also open the section.
8. **Accessibility (WCAG 2.1 AA target):** all controls reachable and operable by keyboard in a logical order; collapsible sections use real buttons with `aria-expanded` and `aria-controls` (or native `<details>`); headings follow a proper hierarchy; the switch keeps its programmatic name (rule title, not just "Enabled" - currently every switch reads only "Enabled", which is ambiguous to a screen-reader user: fix); status uses text as well as colour; visible focus; state changes (saved, expanded) announced; the screen is usable at 200% zoom and in WordPress admin high-contrast and RTL.
9. **Scales:** adding a twelfth rule (a test fixture) in an existing category requires no layout change, and a long list of rules is still scannable (within a category, panels are collapsed by default except for rules needing attention or the one targeted by the URL; the architect decides the default).
10. **Dashboard consistency:** the Dashboard tab and the Rules tab agree on rule state and on category names; one source of truth for labels, descriptions and categories (replace the duplicated lists).
11. **Extension point:** a rule registered through `wp_bouncer_rules` can declare its category without breaking compatibility. The architect chooses the mechanism; constraints: do not add a method to `RuleInterface` (that would break existing third-party rules); an unknown or missing category goes to an "Other" (or "Add-ons") category; unknown rules at least appear in the overview with their id and enabled state so the admin can see them. Document it in `documentation/adding-a-rule.md` and `rules.md`. Whether third-party rules can have a switch and settings stored by the plugin is a scope question for the owner (below); the minimum is category and title for display.
12. **Built-in rule declaration:** adding a built-in rule requires declaring its category in one place; a test fails if a rule in `Settings::defaults()` has no category.
13. **Translation:** category names, descriptions and status text are translatable, with translator comments for strings with placeholders; the existing sentences with inline number inputs keep working in translated form.
14. **Self-lockout guard and sanitising unchanged:** the "these settings would have blocked you" guard and `Settings::sanitize()` behave exactly as before (existing unit tests untouched and passing).
15. **Responsive:** usable on a narrow admin screen (WordPress mobile breakpoint).
16. **Docs and screenshots:** `rules.md`, `README.md` (the Using it table), `readme.txt` description/FAQ/screenshots updated (docs-writer).
17. **Tests:** unit tests for the category registry and status calculation (pure PHP); e2e tests that save a category's settings and confirm the other rules are unchanged, that anchors resolve, and that the page works without JavaScript; integration tests (once available) for the save handler and capability checks.

---

## WPB-5: Raise minimum versions to PHP 8.3 and WordPress 7.0
- **Type:** chore (breaking for old environments)
- **Priority:** P1 for 1.2.0 (owner decision 2026-10-24)
- **Effort:** M
- **Risk:** Medium. Sites below the new minimums stop receiving updates and stay on 1.1.1 (1.1.2 is not released, owner decision 2026-10-24).
- **Dependencies:** none. Do this first in 1.2.0, before other 1.2.0 work, so new code can use PHP 8.3 features.
- **Release:** 1.2.0

**User story.** As the maintainer, I want WP Bouncer to require PHP 8.3+ and WordPress 7.0+, so that the plugin only runs on versions that still get security fixes and the test matrix stays small.

**Acceptance criteria**
- `Requires PHP: 8.3` and `Requires at least: 7.0` in the plugin header and readme.txt; `update.json` (scripts/build-manifest.php) carries the same `requires` and `requires_php`.
- A site below either minimum is not offered 1.2.0 by the updater; it keeps its current version and the Plugins screen says why. Test this in e2e with a manifest that requires newer versions.
- Activating on an unsupported environment fails cleanly with a message, never a fatal error (the main plugin file stays parseable by old PHP, or WordPress's own header check blocks it first).
- phpcs.xml.dist `testVersion` / `minimum_wp_version`, phpstan-php74.neon (replace with a PHP 8.3 config), CI matrix (unit PHP 8.3–8.5; integration and e2e WordPress 7.0, latest, nightly; drop PHP 7.4–8.2 and WordPress 5.8–6.x), composer.json `require.php`.
- Remove compatibility code that only existed for old versions (for example the pre-6.5 users-sitemap 404 workaround if WordPress 7.0 handles it, `%i` restriction notes) and update CLAUDE.md "Minimum versions".
- Changelog **Changed** entry and readme Upgrade Notice telling admins on older PHP or WordPress to upgrade their stack first.

## WPB-6: Warn about unsupported PHP and database versions
- **Type:** feature
- **Priority:** P2
- **Effort:** S–M
- **Risk:** Low. Read-only checks; the risk is stale end-of-life data giving wrong warnings.
- **Dependencies:** WPB-5 (the plugin's own minimums define the floor).
- **Release:** 1.2.0 (owner decision 2026-10-24: one release, one test cycle)

**User story.** As a site admin, I want WP Bouncer to tell me when my server runs a PHP, MySQL or MariaDB version that no longer gets security fixes, so that I know to ask my host to upgrade.

**Acceptance criteria**
- Detects the PHP version (`PHP_VERSION`) and the database server and version (`$wpdb->db_server_info()` / `db_version()`, handling MariaDB's `5.5.5-10.x` style prefix and managed-database version strings).
- Compares against an end-of-life table kept in one pure-PHP class (for example `Environment\SupportPolicy`) with branch → security-support end date, for PHP, MySQL and MariaDB. Warnings are date-based, so a version starts warning on its end date without a plugin release. Dates are verified against php.net, the MySQL lifecycle policy and mariadb.org at implementation time and on every release (add to the release checklist).
- Three states: supported; ending within 90 days (notice); past end of life (warning). Unknown versions (for example a newer branch not in the table, or an unparseable string) show no warning.
- Shown on the plugin Dashboard tab and added to WordPress Site Health (`site_status_tests`) rather than as a site-wide nag; a site-wide admin notice only for past-EOL, dismissible per user for 30 days.
- Visible only to `manage_options` (network admin on multisite). No external requests: the data ships with the plugin.
- Unit tests for parsing and every state; integration test for the Site Health entries.

## WPB-7: Check PHP settings with security implications
- **Type:** feature
- **Priority:** P2
- **Effort:** M
- **Risk:** Low. Read-only; false alarms are the main risk, so each check states why it matters and how to fix it.
- **Dependencies:** shares the reporting surface with WPB-6 (Dashboard tab and Site Health).
- **Release:** 1.2.0, with WPB-6

**User story.** As a site admin, I want WP Bouncer to flag PHP settings that weaken my site's security, so that I can fix them or ask my host to.

**Acceptance criteria**
- Read-only: the plugin never changes PHP or server settings; it reports the current value, why it matters and the recommended value.
- Initial checks (product-manager and security-blue to confirm the list and severities):
  - `display_errors` on in production (leaks paths and data) — warning.
  - `expose_php` on (version in headers) — info.
  - `allow_url_include` on — critical.
  - `allow_url_fopen` on — info only (WordPress and many plugins need it).
  - `session.use_strict_mode`, `session.cookie_httponly`, `session.cookie_secure` (on HTTPS sites), `session.cookie_samesite` — info, since WordPress itself doesn't use PHP sessions but other plugins may.
  - `open_basedir` unset — info.
  - `disable_functions` not restricting `exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen` — info.
  - `file_uploads`, `upload_max_filesize`, `post_max_size`, `max_input_vars` — info, shown for context.
  - Related WordPress settings: `WP_DEBUG_DISPLAY` on, `WP_DEBUG_LOG` writing to the default web-reachable `wp-content/debug.log`, `DISALLOW_FILE_EDIT` off, `FORCE_SSL_ADMIN` off on HTTPS sites — owner to confirm whether these belong here or in a separate "WordPress hardening" check.
- Each check is a small pure class behind one interface, so checks are unit-testable and a later release can add more; extension filter `wp_bouncer_environment_checks`.
- Results on the Dashboard tab and in Site Health, grouped by severity; no site-wide notice for info items.
- Visible only to `manage_options` (network admin on multisite). Values that could be sensitive (paths in `open_basedir`) are shown only to that capability and never logged.

# Later

(Nothing is queued here yet. Candidates that came out of this planning, not yet requested by the owner:)

- **Raise PHPStan level** beyond what WPB-1 reaches (if WPB-1 stops at 6, level 7).
- **Live count of active bans** (needs an index of bans; see WPB-4).
- **Update-channel signing** (if the audit recommends it; likely a separate L item with an ADR).
- **Per-category quick actions** (for example "monitor this category only") if the owner wants a category-level control after WPB-2.
- **Network (multisite) dashboard widget and network-wide settings**, if the owner wants multisite super-admin visibility.

---

# Triage log

- **2026-10-24: flaky update checks in e2e on WordPress 5.8 / PHP 7.4 (not fixed, by owner decision).** On CI the Updates section of `tests/e2e/run.sh` passed in one run and failed five checks in the next ("tampered zip is refused", "Update now succeeds", "...new version installed", "...no update offered now", "auto-update switched on"). Likely cause, unconfirmed: the mock release files are served by the site's own single-worker PHP built-in server, so WordPress downloading from itself can stall. Moot once WPB-5 drops WordPress 5.8; if it reappears on supported versions, try `PHP_CLI_SERVER_WORKERS>1` or a separate mock server on a standard port.
- **2026-10-24: 1.1.2 not released (owner decision).** Its fixes ship in 1.2.0. Sites below PHP 8.3 / WordPress 7.0 stay on 1.1.1.

No open bugs are recorded. Audit findings will be added here as individual items with severity, using the order security > data loss > crash > broken feature > cosmetic.

---

# Open questions for the owner

1. **PHPStan target level (WPB-1).** Recommendation: level 6 now (after a half-day spike), no higher yet. Do you want that, or keep level 5? May the work use a baseline file for leftovers, or must the code be clean without one?
2. **Lint scope (WPB-1).** Should `make check` include lint and analyse, and should phpcs also cover `tests/`?
3. **Audit and disclosure (WPB-3).** Who receives findings, and is there a security contact or `SECURITY.md` for outside reporters? Do you want findings kept private until the fix ships (my recommendation)?
4. **Release ordering (WPB-3).** Confirm: 1.1.2 = lint plus audit fixes, with Critical/High findings as an immediate hotfix?
5. **Update signing (WPB-3).** The update check compares the zip with a SHA-256 published in the same release. If a compromised GitHub account could change both, do you want signing (for example a detached signature verified against a key bundled in the plugin) assessed as part of the audit? That is a bigger change and needs a key-management decision.
6. **Privacy (WPB-3b).** Do you want the exporter/eraser and policy text? The logs hold IPs, so a request is by IP or email: should the eraser handle IP-based requests (needs a UI for entering an IP) as well as logged-in users (traffic log `user_id` only)? Should the activity log be erasable per IP? Is the 365-day maximum retention for the block log acceptable, or should it be capped (the traffic log is capped at 7 days)?
7. **Categories (WPB-2).** Are the four proposed categories right (names, membership)? In particular: is XML-RPC under "Login and accounts" and `not_found` under "Scanners and floods" what you expect?
8. **Third-party rules (WPB-2).** Is the extension point only "a category and title so the rule appears in the overview", or should the plugin also give third-party rules an on/off switch and stored settings? The second is a larger design with security implications (the settings allow-list) and I recommend deferring it.
9. **Category-level switches (WPB-2).** The brief says each rule stays independently on/off. Confirm that you do not want an "all on / all off" per category.
10. **Dashboard tab (WPB-2).** Keep the Dashboard tab's rule table, or replace it with the new overview? Keeping both risks them drifting apart.
11. **Widget (WPB-4).** Which stats are must-haves? My default is the list above. Should the widget show IPs (visible to admins only; the log already does)? Should it appear on the multisite network dashboard, and is the plugin meant to be network-activated (tables are per-site, so each site's dashboard would show its own data)?
12. **Widget refresh (WPB-4).** Is a cache of up to 5 minutes acceptable (numbers lag slightly), or do you want live numbers?
13. **1.2.0 scope.** If the UI redesign is not ready when the widget is, may the widget ship alone as 1.2.0 and the UI follow as 1.3.0? *(Answered 2026-10-24: no split; all of it ships as 1.2.0.)*
14. **Integration suite timing.** Should WPB-2 and WPB-4 wait for it, or may development start and tests follow? I have written the acceptance criteria assuming they do not leave the tester step without integration tests.

### Owner decisions on the security-fix plan (2026-10-24)

The owner accepted the architect's recommendations on all seven questions in
`documentation/architecture/security-fixes.md`:

1. While the header-IP fallback is active, bans and lockouts are logged but not enforced.
2. Add the opt-in constant `WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS` (off by default; loopback never allowed).
3. Waivers W-1 and W-2 are signed. RT-01 (unsigned updates) stays open by the signing deferral and does not block releases.
4. Automatic bans and lockouts are capped at 24 hours.
5. The WAF inspects JSON request bodies in 1.2.0, on by default.
6. On multisite, sub-site admins may still upload geo CSV files; only URL import is restricted to network admins.
7. 1.1.3 ships as its own patch release.

Release order: 1.1.2 (S1, S2, S3, WPB-1), then 1.1.3 (S8, S4, S5, S6, S7, S9),
then 1.2.0 (S10 to S14, then WPB-4, then WPB-2).

### Owner decisions on minimum versions and environment checks (2026-10-24)

- 1.2.0 supports only PHP 8.3+ and WordPress 7.0+ (WPB-5). 1.1.2 is not released; its fixes ship in 1.2.0.
- Add warnings for unsupported PHP, MySQL and MariaDB versions (WPB-6) and checks for PHP settings with security implications (WPB-7).
- WPB-6 and WPB-7 move into 1.2.0 so the whole release goes through one test and audit cycle.
- Skipping 1.1.2 is acceptable: the owner's sites all run current PHP and WordPress, so none are left on 1.1.1.
- WPB-7 includes WordPress-level checks (owner, 2026-10-24): `DISALLOW_FILE_EDIT` off and a web-readable debug log as warnings; `WP_DEBUG_DISPLAY` on the Dashboard tab only; `FORCE_SSL_ADMIN` left to core's HTTPS test. Other WordPress hardening checks go to a later item. See documentation/architecture/env-checks-and-widget.md.
- WPB-4 widget (owner, 2026-10-24, may revisit): all seven proposed items; IPs shown (admins only); per-site widget, nothing on the network dashboard; 5-minute cache. See documentation/architecture/env-checks-and-widget.md.
