# WP Bouncer backlog

Owner: product-manager. Last updated 2026-10-26, against released version 1.2.0.
Minimum supported: PHP 8.3, WordPress 7.0. Distribution: GitHub releases (not wp.org), so wp.org review does not gate a release, but the wp.org plugin guidelines (GPL, no tracking, escaped output, no remote calls without disclosure) are still the quality bar.

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

## Owner decisions (2026-10-24, UI items)

1. **WPB-9:** on very wide screens the Rules tab splits into **three columns** (cap at 3). The category (rule type) headings are **1.3 times** their current size.
2. **WPB-10b (column resizing):** widths are remembered **per browser** (`localStorage`, not user meta). It moves from 1.3.0 to **1.2.1**, alongside WPB-8, WPB-9 and WPB-10a. The owner chose to ship new JS in a patch release. The Activity Log and the Traffic tab keep **separate** widths, stored **per column** (keyed by table + column name).
3. **WPB-11 (threat map):** the owner accepted all proposed defaults. Colour scale is **logarithmic**. The map **follows the table's filters and date range**, using the **last 30 days** when no date filter is set. **Centroid dots only** (no tinted country shapes). A "threat" is a row with a **blocking action**; allowlisted, monitor-only and alert rows are not counted. A map asset of **up to about 100 KB** is acceptable. The panel is **open by default**, and its open/closed state is **remembered per browser** (`localStorage`).

## How this is prioritised

Method: **RICE** (Reach x Impact x Confidence / Effort), with one override: **security and data-loss work jumps the queue** (severity order: security > data loss > crash/white screen > broken feature > cosmetic).

- Reach: 1-10, share of installs/admins touched per release.
- Impact: 0.25 minimal, 0.5 low, 1 medium, 2 high, 3 massive.
- Confidence: how sure we are of Reach and Impact.
- Effort in weeks of team time: S = 0.5, M = 1.5, L = 4.

| ID | Item | Priority | Basis |
|---|---|---|---|
| WPB-8 | S13 audit gap (WP-CLI and direct option saves) | P1 | Security override: jumps the queue. Small, so it goes first in 1.2.1. |
| WPB-9 | Rules tab: category blocks in columns, larger headings | P3 | RICE: Reach 8 x Impact 0.25 x Confidence 0.8 / Effort 0.5 = 3.2. Cosmetic, UI-only, so it ranks below all security and functional work. |
| WPB-10a | Activity Log and Traffic tab: long Request / User-Agent values overlap the next column (bug) | P2 | Severity: cosmetic, top of its class (values are unreadable, though still reachable via the title tooltip). RICE: Reach 6 x Impact 0.5 x Confidence 0.5 / Effort 0.5 = 3.0, with low confidence until reproduced. Ranked above WPB-9 because it hides data rather than just looking plain. |
| WPB-10b | Resizable columns (drag) on Activity Log and Traffic tab | P3 | RICE: Reach 5 x Impact 0.5 x Confidence 0.8 / Effort 1.5 = 1.3. Owner-requested convenience; the bug fix removes most of the pain first. |
| WPB-12 | Detect settings changes made while the plugin wasn't loaded | P2 | Security detection gap (WPB8-RT-02). Not yet RICE-scored; target 1.2.2 or 1.3.0. |
| WPB-13 | Track admin logins (log every admin login, alert on a new location) | P2 | RICE: Reach 7 x Impact 1 x Confidence 0.5 / Effort 1.5 = 2.3. Security detection feature, not a bug, so no override. Ranks above WPB-11 (0.75) and is built first (owner decision). Confidence is low until the open questions are answered. |
| WPB-11 | Activity Log: threat hotspot map by country | P3 | RICE: Reach 6 x Impact 1 x Confidence 0.5 / Effort 4 = 0.75. Owner-requested, new capability with an asset-licence and accessibility cost (hence the low confidence and L effort). Ranks last: nothing is broken without it, and it needs a new minor release. |

No other open items are scored. "Later" items are unscored candidates.

## Release plan (semver)

| Release | Status | Contents | Why this number |
|---|---|---|---|
| **1.2.0** (minor) | Released 2026-10-24 (tag v1.2.0, commit 072805e) | See "Done" | New backwards-compatible features, plus the 1.1.2 and 1.1.3 work, which was never released separately. |
| **1.2.1** (patch) | Ready to tag 2026-10-24 (WPB-8, WPB-9, WPB-10a, WPB-10b) | WPB-8, WPB-9 | WPB-8 is a security fix to existing behaviour; WPB-9 is a presentation-only change. No new settings keys or breaking change in either. |
| **1.2.1** (patch), addition | Proposed | WPB-10a | CSS-only bug fix (no new JS, settings or storage). Goes with WPB-8 and WPB-9; if 1.2.1 is cut early for WPB-8, it moves to 1.2.2. |
| **1.2.1** (patch), addition | Owner decision 2026-10-24 | WPB-10b | New JS and a new capability would normally be a minor bump; the owner chose to ship it in the patch release. It is backwards compatible, with no settings keys or storage change (browser `localStorage` only). If 1.2.1 is cut early for WPB-8, it moves to 1.2.2. |
| **1.3.0** (minor) | Proposed | WPB-13 (built first), then WPB-11 | WPB-13: new logged event type, new alert setting and possibly per-user seen-history storage. WPB-11: new user-facing capability (map, new JS and bundled map asset, one cache transient, no schema change). Both backwards compatible, so a minor bump. |
| **Hotfix** (out of band) | As needed | Any Critical or High finding | Do not wait for a planned release. Triage first, patch, tag. |

Every release: bump `wp-bouncer.php` header and `Plugin::VERSION`, `readme.txt` Stable tag plus its Changelog and Upgrade Notice, and `documentation/CHANGELOG.md` together. Final security-red delta audit on the diff since the last tag before tagging.

---

# Done

- WPB-1: Code passes phpcs and PHPStan. Shipped in 1.2.0.
- WPB-2: Rules UI redesign into categories. Shipped in 1.2.0.
- WPB-3: Full security audit and fixes S1 to S14. Shipped in 1.2.0.
- WPB-3b: Personal-data exporter, eraser and privacy-policy text. Shipped in 1.2.0.
- WPB-4: Dashboard widget with recent-block statistics. Shipped in 1.2.0.
- WPB-5: Raise minimum versions to PHP 8.3 and WordPress 7.0. Shipped in 1.2.0.
- WPB-6: Warn about unsupported PHP and database versions. Shipped in 1.2.0.
- WPB-7: Check PHP settings with security implications. Shipped in 1.2.0.

Accepted open risk: RT-01 (unsigned updates), because release signing (SB-07 / ADR 002) is deferred by owner decision.

---

# Now

## WPB-8: Audit settings changes made outside the admin UI (S13 gap)
- **Type:** bug (security, incomplete control)
- **Status:** done, awaiting release in 1.2.1.
- **Priority:** P1. Security work jumps the queue. Not Critical or High: it needs an already-privileged actor, and the logging is a detection control, not a protection. So it goes in the next patch release, not a hotfix.
- **Effort:** S
- **Risk:** Low to medium. Option hooks fire on every update of the option, including our own saves, so a naive hook would log twice. Hooks must not slow the firewall path (register them only where settings are written, not at `plugins_loaded` priority 1 on every front-end request if avoidable).
- **Dependencies:** S13 (`SettingsDiff`, `AdminController::save()`); see `documentation/architecture/security-fixes.md` section S13.
- **Release:** 1.2.1

**User story.** As a site admin, I want changes to WP Bouncer settings to be logged and alerted whichever way they are made (admin screen, WP-CLI or code calling `update_option()`), so that someone weakening my firewall without using the UI cannot do it unseen.

**Acceptance criteria**
1. Changing `wp_bouncer_settings` with `wp option update`, `wp eval` or a direct `update_option()` creates the same `alert` log row (rule `settings`, changed keys, actor) as a UI save. When there is no logged-in user, the actor is shown as CLI or "unknown", never blank.
2. A risky change (mode, a rule turned off, allowlist, trusted proxies, IP source) queues the `firewall_changes` alert and fires `wp_bouncer_settings_changed`, as for UI saves.
3. A UI save produces exactly one log row and one alert (no double logging).
4. Saving with no change produces no row.
5. Values are never written to the log, only key paths (unchanged from S13).
6. Works on multisite (per-site option) and on MySQL, MariaDB and SQLite.
7. Integration tests cover a CLI-style `update_option()` save, a UI save (one row) and a no-change save. No measurable cost on requests that do not write the option.
8. Changelog **Security** entry (severity only, no exploit detail) and readme Upgrade Notice.

---

# Next

## WPB-9: Rules tab: category blocks in columns, with larger headings
- **Status:** done, awaiting release in 1.2.1. Owner confirmed the layout on 2026-10-24 with the 1.2.1-dev test package ("looks a lot better").
- **Type:** feature (UI-only; follow-up to WPB-2)
- **Priority:** P3 (low). Cosmetic and presentation-only; ranked by RICE in the table above. It never displaces WPB-8.
- **Effort:** S
- **Risk:** Low. No PHP logic, settings or storage change. Watch points: the sticky save bar and the in-page category navigation (`.wpb-cat-nav`, anchors with `scroll-margin-top`) must keep working in a multi-column layout; an expanded rule's settings panel makes one block much taller than its neighbours; long translated headings must wrap, not overflow.
- **Dependencies:** WPB-2 (shipped in 1.2.0). Touches `wp-bouncer/assets/admin.css` and at most the wrapper markup in `wp-bouncer/src/Admin/views/rules.php`.
- **Release:** 1.2.1 (patch: presentation only, no new settings keys, no upgrade step). Not worth its own release; if 1.2.1 is cut early for WPB-8, WPB-9 moves to 1.2.2 rather than delaying the security fix.

**Current state (1.2.0).** `partials/rule-category.php` renders each category as a `<section class="wpb-card wpb-category">` labelled by its `<h2>`, followed by a description, an "N of M on" summary and one `rule-row.php` per rule (`role="group"` labelled by the rule's `<h3>`, switch plus an expandable settings `<details>`). `rules.php` outputs the sections one after another inside `.wpb-rules-form`, and `admin.css` has no grid or column rules for them, so every block is a full-width row in a single column. The category `<h2>` uses the default WP admin h2 size; there is no size rule for it beyond `margin-bottom: 2px`. Rule titles (`.wpb-rule-text h3`) are `1.05em`.

**User story.** As a site admin, I want the rule categories on the Rules tab laid out side by side in columns, with a slightly larger heading on each block, so that I can see more of my switches without scrolling and find a category at a glance.

**Acceptance criteria**
1. At desktop admin widths (above the WP admin breakpoint of 782px) the category blocks are laid out in a responsive grid of two columns, rising to **three columns on very wide screens and never more than three** (owner decision 2026-10-24), using CSS only (grid with `auto-fit`/`minmax` and a cap of three, or equivalent). The column count adapts to the width of the content area, including when the WP admin menu is folded or expanded.
2. At 782px and below (WP mobile admin), and in any container too narrow for two usable columns, the blocks fall back to a single column with no horizontal scrolling.
3. Each category (rule type) heading is **1.3 times** its current computed size (owner decision 2026-10-24), and stays in keeping with WP admin typography: same font family and weight, relative units (`em`/`rem`, for example `1.3em` on the h2 relative to its current size), no custom font. The rule titles inside a block remain visibly smaller than the category heading, so the hierarchy is category > rule.
4. Switch behaviour is unchanged: every rule remains independently switchable, each switch toggles and saves as before, and expanding a rule's settings works. The saved `wp_bouncer_settings` value is byte-identical to 1.2.0 for the same form input (verified by an automated test; no new fields, names or keys).
5. Keyboard order stays logical: Tab moves through the blocks in DOM order, matching the visual reading order (row by row in a left-to-right locale). CSS must not use `order`, or grid placement, that reorders blocks against the DOM. The jump links in `.wpb-cat-nav` still focus the right block.
6. Screen-reader grouping is kept: each category is still a labelled region (`section` with `aria-labelledby` pointing at its heading) and each rule is still a labelled group. Heading levels (h2 category, h3 rule) are unchanged. If markup changes to a fieldset/legend, the accessible name and role must be no worse than today (checked with a screen reader or an accessibility-tree test).
7. Visible focus, forced-colors support and the 200% zoom / 400% reflow behaviour (WCAG 1.4.10) are not regressed; a block taller than its neighbours (settings panel open) does not overlap or clip adjacent blocks.
8. RTL: the grid mirrors correctly (use logical properties, as the existing CSS does). Long translated headings wrap within their block.
9. The sticky save bar is still reachable and does not cover the last row of blocks.
10. No new JavaScript, no new requests and no change to the PHP rule logic or firewall path. Works on multisite unchanged.
11. Tests: the existing `RulesTabTest` markup assertions still pass (or are updated only for any wrapper element added); a manual or e2e screenshot check at desktop width and at 782px or below is recorded in the PR.
12. Changelog **Changed** entry ("Rules tab: categories shown in columns on wide screens"). No readme.txt Upgrade Notice needed; update screenshots in `readme.txt`/docs if they show the Rules tab.

**Open questions for the owner (not guessed):** none.

(Closed 2026-10-24: column cap on very wide screens is three, and headings are 1.3 times their current size; see criteria 1 and 3.)

## WPB-10: Activity Log and Traffic tab: fix column overlap, then make columns resizable
Owner request (verbatim): "On the activity page the Request and User-Agent fields are fixed width and when the Request or User-Agent is a longer string then the string visually is printed on top of the next field. The column width in the activity log should be adjustable to fix this. The same adjustable column width should be applied to the traffic tab. When I say adjustable I mean the user should be able to click and drag the column wider or narrower."

Split into two deliverables so the fix does not wait for the feature.

**Current state (1.2.0).** Request and User-Agent cells (`LogListTable::column_request()` and `column_user_agent()`) are wrapped in `.wpb-trunc`: `display: inline-block; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap` (180px at 782px and below), with the full value in a `title` attribute. `admin.css` fixes widths only for `.column-created_at` (150px), `.column-country` (80px) and `.column-action` (90px); Request, User-Agent and the rest are auto width. There is no `table-layout: fixed` and no per-column rule for them. `admin.js` is enqueued on all plugin admin screens and has no table code. **The Traffic tab (`TrafficListTable`) uses the same `.wpb-trunc` for Request, Client (user-agent line) and Referrer, with no width rules at all, so it is exposed to the same defect.** From the code alone the 320px clip should already prevent text from running over a neighbour, so the exact trigger is not understood (candidates: an inline-block `<code>` with `vertical-align: bottom` in a narrow auto-layout cell, a theme or browser-specific rendering, or a screen width where the table is wider than the content area). It must be reproduced first (browser, width, locale, sample string) before the fix is designed.

### WPB-10a: Long Request / User-Agent values overlap the next column (bug)
- **Status:** fixed, awaiting release in 1.2.1. Owner reproduced it in Firefox on macOS and confirmed the fix on 2026-10-24 with the 1.2.1-dev test package. Cause: `.wpb-trunc` had a fixed 320px cap wider than the cell; it is now block-level and capped at 100% of the cell, with `overflow: hidden` on the long-text cells (CSS only, plus a regression test in `tests/Integration/Admin/ListTableTruncationTest.php`).
- **Type:** bug
- **Severity:** cosmetic (lowest class), upper end: data is visually corrupted and hard to read, but nothing is lost, the full value is in the `title`, and there is no security or data impact. Not a hotfix.
- **Priority:** P2. See the table above.
- **Effort:** S
- **Risk:** Low. CSS only, scoped to the two list tables. Watch points: do not break the existing `.wpb-trunc` use elsewhere; Screen Options column hiding; mobile card layout.
- **Dependencies:** none. Repro first. Touches `wp-bouncer/assets/admin.css`, maybe `LogListTable.php` / `TrafficListTable.php` markup.
- **Release:** 1.2.1 (patch, with WPB-8 and WPB-9).

**User story.** As a site admin, I want long Request and User-Agent values to stay inside their own column, so that I can read every row of the Activity Log and Traffic tab without text running over the next field.

**Acceptance criteria**
1. With very long unbroken strings (URL with 500+ characters, a 400-character User-Agent, no spaces) on desktop widths, no cell's text paints over or under a neighbouring cell, on both the Activity Log and the Traffic tab (Request, User-Agent/Client, Referrer).
2. Overflowing values are clipped with an ellipsis (or wrapped; the developer picks one and uses it on both tables) and the full value remains reachable through the `title` and by widening (after WPB-10b). Table width never exceeds its container (no new horizontal page scroll).
3. Behaviour is the same whether or not the user ever resizes columns, and for RTL.
4. Short values, the other columns and Screen Options column hiding look unchanged; at 782px and below the WP collapsed layout still works with no overlap.
5. No JS, PHP logic or storage change; no effect on the firewall path.
6. Tests: markup assertions that the long-value cells keep the clipping class, plus a fixture-driven e2e or recorded manual screenshot at desktop and 782px for both tables.
7. Changelog **Fixed** entry. No readme Upgrade Notice.

### WPB-10b: Drag-to-resize columns on Activity Log and Traffic tab (feature)
- **Status:** done, awaiting release in 1.2.1. Owner tested the resizing in a browser on 2026-10-24 ("works well").
- **Type:** feature
- **Priority:** P3. See the table above.
- **Effort:** M
- **Risk:** Medium (the largest risk in the UI backlog). Pointer and keyboard handling must not break WP's sortable header links or Screen Options; layout switches to `table-layout: fixed` once widths are set; widths saved against the wrong set of visible columns would look broken. Shipping new JS in a patch release (owner decision) adds an extra test and audit cycle to 1.2.1.
- **Dependencies:** WPB-10a first (shared CSS and clipping). Touches `wp-bouncer/assets/admin.js`, `admin.css`, and the two list-table classes (header markup).
- **Release:** 1.2.1 (owner decision 2026-10-24: new JS in a patch release, chosen by the owner; originally proposed for 1.3.0).

**User story.** As a site admin, I want to click and drag the edge of a column header to make that column wider or narrower on the Activity Log and the Traffic tab, so that I can read long URLs and user agents the way I need to.

**Acceptance criteria**
1. Each resizable column header has a drag handle on its trailing edge (right in LTR, left in RTL), with a pointer cursor of `col-resize` and a hit area of at least 24px wide that does not cover the header's sort link. Pressing the handle never triggers a sort; clicking the header text still sorts as in 1.2.0, and sorting still works with the handle present (pointer events, `stopPropagation`, handle not inside the `<a>`).
2. Dragging changes the column's width live; neighbours do not overlap. A minimum width applies per column (proposed 60px; narrow columns such as Country and Action may use a smaller minimum), and the table never exceeds its container.
3. Keyboard: the handle is focusable (`role="separator"`, `aria-orientation="vertical"`, `aria-valuenow`/`aria-valuemin`/`aria-valuemax`, an accessible name such as "Resize Request column" translated via `__()`). Left/Right arrows change the width by 10px (Shift: 50px), Home/End jump to minimum/maximum, Esc or the reset control restores the default. Width changes are announced politely (`aria-live` or updated `aria-valuenow`). Visible focus style and forced-colors support.
4. Persistence (owner decision 2026-10-24): widths are remembered **per browser** in `localStorage`, not in user meta, so no PHP, no database change and no new request. Each width is stored **per column**, keyed by table + column name (for example `wpb_cols:log:request`), so the Activity Log and the Traffic tab keep **separate** widths even for columns with the same name.
5. Reset: a "Reset column widths" control on each of the two screens (and double-click on a handle resets that column) returns to the default widths and clears the stored value for that table only.
6. Screen Options: hiding or showing a column does not break the layout, and stored widths for hidden columns are kept but not applied. Unknown or stale stored values are ignored safely.
7. Mobile: at 782px and below, where WP collapses list tables, resizing is off (no handles, no stored widths applied) and the WPB-10a clipping still holds.
8. RTL: handles sit at the correct edge, drag direction is mirrored, and widths are stored as sizes, not left/right offsets.
9. No effect on the firewall path or any front-end request. Vanilla JS only (no jQuery dependency, no libraries), no new external requests, small (target under about 4 KB unminified added), loaded only on the Activity Log and Traffic screens (not on every plugin admin page; the current single `admin.js` is enqueued on all of them, so this needs a separate script or a screen check). Works on multisite unchanged.
10. Nothing leaves the browser (`localStorage` only), so the privacy-policy text needs no change; `uninstall.php` and the privacy eraser need no step for it. Stored values are validated (numeric, clamped to min and max) before use.
11. Tests: unit/integration assertions for the header markup (handle element, ARIA attributes, script enqueued only on these screens, absent from other tabs); an e2e or documented manual check covering drag, keyboard resize, sort click, reset, column hide, reload persistence, RTL and 782px.
12. Changelog **Added** entry; readme.txt Changelog and screenshots updated.

**Open questions for the owner (not guessed):**
- None. WPB-10a was reproduced and its fix confirmed by the owner (Firefox on macOS, 2026-10-24).

(Closed 2026-10-24: persistence is per-browser `localStorage`; ships in 1.2.1; the two tables keep separate widths, stored per column.)

## WPB-12: Detect settings changes made while the plugin wasn't loaded
- **Type:** feature (security detection, follow-up to WPB-8)
- **Priority:** P2. Not yet RICE-scored, so it sits outside the table's ranking until it is.
- **Target:** 1.2.2 or 1.3.0. Not in 1.2.1.
- **Source:** WPB8-RT-02 (the WPB-8 review). The finding is not in `documentation/security/` in this repository, so its text is not checked here.
- **Effort:** not yet sized.

**Gap.** WPB-8 audits settings writes only while WP Bouncer is loaded. A change made while the plugin isn't loaded (for example `wp --skip-plugins`), or by editing the database directly, is not logged (see the 1.2.1 Known limits in `documentation/CHANGELOG.md`).

**Proposed approach.** After each audited write, store a fingerprint of the settings. In daily maintenance and on `admin_init`, compare the current settings with the stored fingerprint and log any difference. The fingerprint and the comparison are for the developer to design; no acceptance criteria are set yet.

---

## WPB-13: Track admin logins
- **Type:** feature (security detection)
- **Priority:** P2. See the table above (RICE 2.3).
- **Effort:** M (provisional; depends on where the seen-history lives).
- **Risk:** Medium. (1) Log flooding: application-password logins can occur on every REST or XML-RPC call. (2) New personal data (IP and country per admin login) and a per-user seen-history, so privacy text, retention, export and erase must be reviewed. (3) False-positive alerts for admins on mobile or VPN networks. (4) The log write budget and firewall speed: nothing may be added to the `plugins_loaded` priority-1 path.
- **Dependencies:** `AlertNotifier` (admin-created alert, around lines 170-230 and 750-800, which already writes `ACTION_ALERT` rows through `BlockLogInterface`); `Plugin::register_login_hooks()` (`wp_login`, `application_password_did_authenticate`); geolocation (`documentation/geolocation.md`); the Activity Log filters; the existing alert settings. Built before WPB-11 (both touch the Activity Log; WPB-11 counts only blocking actions, so login rows must not distort the map).
- **Release:** 1.3.0 (owner decision 2026-10-26: alongside WPB-11, built first).

**User story.** As a site admin, I want every successful administrator login recorded in the Activity Log, and an email when an admin signs in from a place not seen for that user recently, so that a stolen admin password or application password is noticed quickly.

**Owner decisions (2026-10-26)**
1. "Admin" means users with the administrator role or the `manage_options` capability, plus network super admins (same scope as the existing admin-created alert).
2. Logins are recorded as rows in the existing Activity Log (user, IP, country, time, method: interactive password, or application password over REST or XML-RPC) and are filterable there. No new table and no new screen.
3. An email alert is sent only when an admin logs in from an IP range or country not seen for that user recently, not on every login. It is part of the existing alert settings and can be switched off.
4. Target 1.3.0, alongside WPB-11, built before WPB-11.
5. (Owner, 2026-10-26, on security-blue SB13 advice) A "new location" is a country **or** IP range (IPv4 /24, IPv6 /64) not seen for that user in the history window. Country plus range, not country only.
6. (Owner, 2026-10-26) The personal-data eraser removes that user's login rows from the Activity Log immediately, as well as their stored login history. Rows are not left to expire.
7. (Owner, 2026-10-26) A separate "Record admin logins" setting, default on. Turning it off also stops the new-location alert. Answers open question 8.

**Acceptance criteria**
1. A successful interactive login (`wp_login`) by an admin creates one Activity Log row with the user, IP, country (empty if unknown), time and method "interactive password".
2. A successful application-password authentication (`application_password_did_authenticate`) by an admin creates a row with method "application password" and the transport (REST or XML-RPC) where it can be told apart.
3. Logins by non-admin users create no row. A user who gains or loses admin status is treated by their role at login time.
4. Multisite (revised 2026-10-26 after WPB13-RT-01): a site admin's login, wherever on the network it happens, is recorded and assessed on every site where that user is an admin. A super admin's login is recorded on the site where it happened. Behaviour is unchanged on single sites.
5. Failed logins and lockouts are unchanged, and no existing row type or count changes. Login rows are not counted as threats (WPB-11 and the dashboard widget exclude them).
6. The Activity Log action filter can select login rows alone, and the row renders with an accessible, translated label that does not rely on colour.
7. An email alert is queued when an admin's login comes from a location (per the architect's definition) not seen for that user in the "recent" window, and not otherwise. The first-ever login after the feature is installed does not alert (no history to compare); this is verified by a test.
8. The alert setting sits with the existing alert settings, defaults to on, and switching it off stops the email while login rows are still recorded. Whether row recording itself can be switched off is an open question below.
9. The email names the user, IP, country, time and method, and contains no password, token or application-password value. Logged values are escaped on output.
10. Login recording adds no work to the `plugins_loaded` priority-1 firewall path and no extra database query on requests that are not logins.
11. A login must never fail or be delayed because logging or alerting failed (errors are swallowed and reported to the debug log only).
12. Works on MySQL, MariaDB and SQLite; SQL uses `$wpdb->prepare()`. No schema change unless the architect decides otherwise (then `Installer::DB_VERSION` and the upgrade path are covered).
13. Privacy: the personal-data exporter and eraser, privacy-policy text and `uninstall.php` cover any new stored data (the log rows and any seen-history).
14. Tests: unit tests for the pure-PHP "seen before" decision (same range, new range, new country, first login, expired history); integration tests for both hooks, non-admin users, the alert setting off, multisite super admin, and the flood limit once decided; an e2e or recorded manual check of the filter and the email.
15. Docs: `documentation/CHANGELOG.md` and `readme.txt` Changelog **Added** entry, rules/alerts documentation, and an Upgrade Notice if the new alert defaults to on for existing sites.

**Open questions for the architect and security-blue (not decided here)**
1. "Recently": how long is the seen-history window (for example 30 or 90 days), and does it slide or expire?
2. "IP range": IPv4 /24 and IPv6 /64, or another grouping, or ASN? Is country alone enough when geolocation is installed? What happens with no geo database, and with shared or proxy addresses (trusted proxies, IP source setting)?
3. Where does per-user seen-history live (user meta, an option, derived from past log rows)? Consider size per user, multisite scope, cost of lookup at login, and survival of log pruning (the log keeps up to 365 days).
4. Privacy and retention: are login rows kept as long as other log rows (up to 365 days)? Does the eraser remove or redact them? Does the log's lack of a `user_id` column (owner decision 2026-10-23) force a new column or storing the login name in an existing field? Is the privacy-policy text updated?
5. Flooding: an application password can authenticate on every REST or XML-RPC request. Should such rows be deduplicated or rate-limited (for example one per user, IP and method per window), and how is that shown so the log stays truthful?
6. Log write budget: how does this share the existing log write budget and flood protection with block rows, so that a login burst cannot crowd out blocking rows (or the reverse)?
7. Alert noise and abuse: alert throttling per user, behaviour when the alert queue is already full, and whether an attacker who already holds valid credentials can use the history (for example by logging in once from a chosen range) to hide later logins.
8. Is a switch to turn off login recording (not only the alert) wanted for privacy-sensitive sites? Owner decision 2 does not say.
9. Which `ACTION_*` value or rule key do login rows use, and does that change how existing filters, exports, the dashboard widget and WPB-11 count rows?

---

## WPB-11: Activity Log: threat hotspot map by country
Owner request (verbatim): "Add a map to the activity log showing the hotspots for where threats are coming from. The dots should highlight the country where the threat is coming from and get more and more bright red the more attacks are seen from that country. The mouseover for the threat dots should give the country name and abbreviation, as well the total number of detected threats."

- **Type:** feature
- **Priority:** P3. See the table above.
- **Effort:** L (map asset sourcing and licence check, aggregate query and cache, SVG/JS rendering, accessibility alternative, tests).
- **Risk:** Medium. (1) Asset licence: the map data must be GPL-compatible (Natural Earth is public domain; verify any simplified SVG derived from it and record the source in `documentation/`). (2) Zip size: a world SVG or centroid table adds tens of KB; the owner accepts up to about 100 KB uncompressed (centroids plus a simplified base map) and the zip size change is reported in the release notes. (3) Aggregate cost on a large `bouncer_log`: must be cached and never run on the front end. (4) Accessibility: colour alone fails WCAG 1.4.1, so a text alternative is required. (5) Data quality: rows with an empty country (no geo database installed, or private/unresolvable IPs) cannot be plotted.
- **Dependencies:** Geolocation (`documentation/geolocation.md`); the stored `bouncer_log.country` 2-letter column; `Countries::name()`; the `LogListTable` screen; the transient-caching approach of `DashboardWidget` (`FLOOD_ROWS` = 100000, 1-hour TTL on very large logs). Shares the Activity Log screen and script-loading rules with WPB-10b, so build after WPB-10a and WPB-10b. No schema change expected; the developer and data-engineer confirm with `EXPLAIN` whether an index on `country` is needed.
- **Release:** 1.3.0 (minor: new capability, new JS and bundled asset, one transient; backwards compatible).

**User story.** As a site admin, I want a map on the Activity Log that shows which countries threats come from, with brighter red for countries that attack more, so that I can see at a glance where attacks originate and decide whether to block a country.

**Acceptance criteria** (all defaults decided by the owner on 2026-10-24)
1. Placement: the map appears on the Activity Log screen above the table, in a collapsible panel that is **open by default**. The open/closed state is **remembered per browser** in `localStorage` (no PHP, no request). The panel has a heading and does not push the table's filters out of view on first load.
2. One dot per country with at least one detected threat in the selected window, placed at the country's centroid on a world map that ships inside the plugin. **Dots only**: countries are not tinted or filled. Countries with no threats show no dot. Dots for very small or adjacent countries must stay distinguishable (a minimum dot size, and no dot hidden under another without a way to reach it by keyboard).
3. Colour intensity runs from a light tint to bright red as the country's count rises, on a **logarithmic scale** normalised between the smallest and the largest count in view (so one dominant country does not wash out the rest). With a single country, or all counts equal, the dot uses the brightest red.
4. Tooltip on mouse hover and on keyboard focus (each dot is focusable, in a logical order, for example by descending count), showing the country name (from `Countries::name()`), the ISO 3166-1 alpha-2 code, and the total number of detected threats for the window. Esc dismisses it; it is also reachable by touch tap. Tooltip text is escaped and translated (`__()` / `_n()`).
5. A visible legend explains the scale: a light-to-red gradient with the lowest and highest counts labelled, and the scale type named as logarithmic.
6. Non-colour alternative (WCAG 1.4.1): a "Top countries" table or list under or beside the map, with country name, code and count, sorted by count descending, showing the top 10 with a "show all" control. Dot size or a label may also vary, but the table is the required alternative. The map itself has an accessible name and a short description; decorative map shapes are hidden from assistive technology.
7. Scope of the data: the map **follows the table's current date range and filters**, including country and action. With **no date filter it uses the last 30 days**, and the active window is stated next to the map. A "threat" is a row with a **blocking action**; allowlisted, monitor-only and alert rows are not counted. The exact action values are mapped in the design and listed in the help text.
8. Empty log: a helpful empty state (for example "No threats recorded in this period yet") with no broken map. No geo database: a notice explains that country data needs the geolocation database, with a link to the geolocation settings, and the map is not drawn. Partial data: rows with an empty or unknown country are counted separately and shown as "Unknown location: N threats" next to the map, never as a dot and never dropped silently.
9. Performance: the per-country aggregate (`COUNT(*) ... GROUP BY country` over the window) is computed only in wp-admin when the Activity Log is shown, never on a front-end or firewall request. The result is cached in a transient keyed by the window and filters, using the `DashboardWidget` pattern (short TTL, 1 hour when the window holds more than `FLOOD_ROWS` rows), and the query uses `$wpdb->prepare()`, works on MySQL, MariaDB and SQLite, and is checked with `EXPLAIN` on a large fixture. A manual "refresh" is optional.
10. Privacy: only aggregated per-country counts are sent to the browser. No IPs, URIs, user agents or per-row data are included in the map markup or its JSON, so no new personal data is exposed and the privacy-policy text needs no change. The data is passed with `wp_localize_script`/inline JSON, escaped, and capped at about 250 countries.
11. No external requests: no tile servers, CDN map libraries, web fonts or remote images. The map asset, script and CSS ship in the zip, are loaded only on the Activity Log screen (not on other plugin pages or the front end), and need no jQuery. The map asset is **up to about 100 KB** uncompressed (owner-approved ceiling). Its source and GPL-compatible licence are recorded in `documentation/` and in `readme.txt` credits. The zip size change is measured and noted in the PR.
12. Responsive: at 782px and below, and narrow containers, the map scales to the container width with no horizontal page scroll; the top-countries table remains usable and dots keep a touch target of at least 24px or fall back to the table. Works at 200% zoom and 400% reflow (WCAG 1.4.10).
13. RTL: the layout, legend and panel controls mirror correctly (use logical properties). The map itself is not mirrored (geography is fixed); the legend direction follows the page direction.
14. Accessibility details: legend and dot colours meet 3:1 non-text contrast against the map background (WCAG 1.4.11); visible focus ring on dots; forced-colors mode shows dots and the table; reduced motion respected (no animation required).
15. No effect on the firewall path: nothing is added to the `plugins_loaded` priority-1 request path, and no new hook runs on front-end requests. Multisite: shows the current site's log only, unchanged permissions (same capability as the Activity Log).
16. Translation ready: all strings in the `wp-bouncer` text domain; country names come from `Countries::name()`.
17. Tests: unit tests for the pure-PHP aggregation and scale/bucketing (empty, one country, one dominant country, unknown-country row); integration tests for the query on MySQL/MariaDB, the cache and flood TTL, the empty-state and no-geo-database states, and that the script is enqueued only on the Activity Log screen; an e2e or recorded manual check of hover and keyboard focus tooltips, legend, table, RTL and 782px.
18. Docs and release: `documentation/CHANGELOG.md` and `readme.txt` Changelog **Added** entry, `documentation/geolocation.md` updated, readme.txt credits for the map data, screenshots updated, and the asset licence noted. No readme Upgrade Notice needed (no behaviour change for existing sites).

**Open questions for the owner (not guessed):** none.

(Closed 2026-10-24: log scale; follows filters and date range, 30 days by default; centroid dots only; blocking actions only; asset up to about 100 KB; panel open by default and remembered per browser.)

---

# Later

(Nothing is queued here yet. Candidates that came out of this planning, not yet requested by the owner:)

- **Raise PHPStan level** beyond what WPB-1 reached (level 7).
- **Live count of active bans** (needs an index of bans; see the dashboard widget design).
- **Screen Options column toggles on the Log and Traffic tabs** (found during WPB-10b). None are shown today (see `documentation/architecture/column-resize.md` §3). Unscored. The WPB-10b resize code already skips hidden columns, so it would work once they exist.
- **Update-channel signing** (SB-07 / ADR 002, deferred; likely a separate L item).
- **Per-category quick actions** (for example "monitor this category only") if the owner wants a category-level control.
- **Network (multisite) dashboard widget and network-wide settings**, if the owner wants multisite super-admin visibility.

---

# Triage log

- **2026-10-24: flaky update checks in e2e on WordPress 5.8 / PHP 7.4. Closed.** WordPress 5.8 and PHP 7.4 have been unsupported since WPB-5 shipped in 1.2.0, so the case no longer applies. If it reappears on supported versions, try `PHP_CLI_SERVER_WORKERS>1` or a separate mock server on a standard port.
- **2026-10-24: 1.1.2 and 1.1.3 not released (owner decision).** Their fixes shipped in 1.2.0. Sites below PHP 8.3 / WordPress 7.0 stay on 1.1.1.
- **2026-10-24: S13 audit gap.** Accepted for 1.2.0, tracked as WPB-8 for 1.2.1.
- **2026-10-24: Rules tab layout request.** Owner asked for columnar category blocks and larger headings. Triaged as cosmetic (lowest severity), tracked as WPB-9 for 1.2.1.
- **2026-10-24: Activity Log / Traffic column overlap and resizable columns.** Owner reported long Request and User-Agent text printing over the next field and asked for drag-resizable columns on both tabs. Triaged the overlap as a cosmetic bug (WPB-10a, P2, 1.2.1, needs a repro because the code already clips with an ellipsis) and the Traffic tab as having the same exposure; the resize request is a feature (WPB-10b, P3, 1.3.0).
- **2026-10-24: Threat hotspot map request.** Owner asked for a map on the Activity Log with dots per country, brighter red for more attacks, and a hover tooltip with name, code and total. Triaged as a feature (not a bug, no severity class), tracked as WPB-11, P3, effort L, target 1.3.0. Constraints recorded: no remote calls (map ships in the zip, GPL-compatible source), aggregate cached and admin-only, aggregated counts only (no new personal data), non-colour alternative required.
- **2026-10-24: Owner decisions on WPB-9, WPB-10b and WPB-11.** WPB-9 caps at three columns on very wide screens and category headings are 1.3 times their current size. WPB-10b moves from 1.3.0 to 1.2.1 (owner chose new JS in a patch release), with per-browser `localStorage` widths, separate per table, keyed per column. WPB-11 accepted all proposed defaults (log scale, follows filters with 30-day default, centroid dots, blocking actions only, asset up to about 100 KB, panel open by default and remembered per browser). See "Owner decisions (2026-10-24, UI items)".
- **2026-10-26: Admin login tracking request.** Owner asked to record admin logins and alert on new locations. Triaged as a security detection feature (no severity class), tracked as WPB-13, P2, effort M, target 1.3.0, built before WPB-11. Owner decisions recorded in the story; seen-history, "recently", "IP range", retention and flood questions are open for the architect and security-blue.

No other open bugs are recorded.

---

# Open questions for the owner

All earlier questions were answered by later decisions; see the "Owner decisions" sections. Open:

1. **Lint scope.** Should `make check` also run lint and analyse, and should phpcs cover `tests/` (today `wp-bouncer/` only)? No recorded decision found.
2. **WPB-9 layout details.** Decided: three-column cap and 1.3 times heading size. Nothing open.
3. **WPB-10a column overlap.** Fixed and confirmed by the owner (Firefox on macOS, 2026-10-24). Resizing questions (persistence, release, shared or separate widths) are decided. Nothing open.
4. **WPB-11 threat map.** All six questions decided by the owner on 2026-10-24. Nothing open.

### Owner decisions on the security-fix plan (2026-10-24)

The owner accepted the architect's recommendations on all seven questions in
`documentation/architecture/security-fixes.md`:

1. While the header-IP fallback is active, bans and lockouts are logged but not enforced.
2. Add the opt-in constant `WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS` (off by default; loopback never allowed).
3. Waivers W-1 and W-2 are signed. RT-01 (unsigned updates) stays open by the signing deferral and does not block releases.
4. Automatic bans and lockouts are capped at 24 hours.
5. The WAF inspects JSON request bodies in 1.2.0, on by default.
6. On multisite, sub-site admins may still upload geo CSV files; only URL import is restricted to network admins.
7. 1.1.3 ships as its own patch release. (Superseded: 1.1.2 and 1.1.3 were never released; the work shipped in 1.2.0.)

Release order: 1.1.2 (S1, S2, S3, WPB-1), then 1.1.3 (S8, S4, S5, S6, S7, S9),
then 1.2.0 (S10 to S14, then WPB-4, then WPB-2). (Superseded: all shipped together in 1.2.0.)

### Owner decisions on minimum versions and environment checks (2026-10-24)

- 1.2.0 supports only PHP 8.3+ and WordPress 7.0+ (WPB-5). 1.1.2 is not released; its fixes ship in 1.2.0.
- Add warnings for unsupported PHP, MySQL and MariaDB versions (WPB-6) and checks for PHP settings with security implications (WPB-7).
- WPB-6 and WPB-7 move into 1.2.0 so the whole release goes through one test and audit cycle.
- Skipping 1.1.2 is acceptable: the owner's sites all run current PHP and WordPress, so none are left on 1.1.1.
- WPB-7 includes WordPress-level checks (owner, 2026-10-24): `DISALLOW_FILE_EDIT` off and a web-readable debug log as warnings; `WP_DEBUG_DISPLAY` on the Dashboard tab only; `FORCE_SSL_ADMIN` left to core's HTTPS test. Other WordPress hardening checks go to a later item. See documentation/architecture/env-checks-and-widget.md.
- WPB-4 widget (owner, 2026-10-24, may revisit): all seven proposed items; IPs shown (admins only); per-site widget, nothing on the network dashboard; 5-minute cache. See documentation/architecture/env-checks-and-widget.md.
