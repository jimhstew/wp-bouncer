# 1.2.0 design: environment checks (WPB-6, WPB-7) and dashboard widget (WPB-4)

Author: architect, 2026-10-24. Inputs: backlog WPB-4/6/7 and owner decisions, `security/env-checks.md`
(SB-E1..E16), `architecture/security-fixes.md` §5–7. Minimums are now **PHP 8.3 / WordPress 7.0** (WPB-5),
so new code may use enums, `readonly` classes, `match` and `str_starts_with()`. That supersedes WPB-4 AC11's
"PHP 7.4 / WP 5.8" (the MySQL, MariaDB and SQLite parts of AC11 still apply).

## 1. WPB-6 + WPB-7: environment checks

### 1.1 Classes (`WPBouncer\Environment\`)
| Class | Layer | Responsibility |
|---|---|---|
| `Severity` (enum: `critical`, `warning`, `notice`, `info`, `ok`, `unknown`) | pure | Ordering and grouping. `notice` = "ending within 90 days". |
| `CheckResult` (readonly) | pure | `id, group (versions\|php\|wordpress), severity, title, value, why, fix, private (bool), dashboard_only (bool)`. `value` is a **safe summary** ("On", "set (3 paths)", "inside web root: yes"), never a raw path (SB-E10). |
| `CheckInterface` | pure | `id(): string`, `run( EnvironmentInterface $env ): CheckResult`. |
| `EnvironmentInterface` | pure | `php_version(): string`, `db_server_info(): string`, `sapi(): string`, `ini( string $name ): string\|false`, `constant( string $name ): mixed` (null if undefined), `is_https(): bool`, `inside_web_root( string $path ): ?bool`. |
| `RuntimeEnvironment` | WP adapter | Implements it from `PHP_VERSION`, `$wpdb->db_server_info()` (no SQL, SB-E9), `PHP_SAPI`, `ini_get()`, `defined()/constant()`, `is_ssl()`/home URL scheme; `inside_web_root()` compares `realpath()` of the path's directory with `realpath( ABSPATH )` and returns only the bool. |
| `IniValue` | pure | `flag( string\|false $raw ): ?bool` (On/1/true/yes/stdout/stderr → true; Off/0/''/false/no → false; anything else or `false` → null = unknown), `bytes()`, `int()` (SB-E13). |
| `VersionParser` | pure | `php( string ): ?string` → `"8.3"`; `database( string $server_info ): ?array{product: 'mysql'\|'mariadb', branch: string}`. Strips `5.5.5-`, detects `MariaDB`, takes `major.minor`; distro suffixes (`-0ubuntu…`, `-log`) ignored; Aurora/Azure/TiDB/SQLite/unparseable → null. |
| `SupportPolicy` | pure | See 1.2. |
| `Checks\PhpVersionCheck`, `Checks\DatabaseVersionCheck` | pure | WPB-6, using parser + policy + injected `Clock` (the existing test `FrozenClock` double). |
| `Checks\IniFlagCheck` | pure | Data-driven, one instance per boolean directive: `( id, directive, bad_when (bool), severity, why, fix, ?only_if callable )`. Covers `allow_url_include`, `display_errors`, `display_startup_errors` (warning only if `display_errors` also on), `log_errors`, `expose_php`, `allow_url_fopen`, `session.*`, `zend.assertions`, `cgi.fix_pathinfo` (only for `fpm-fcgi`/`cgi-fcgi`). |
| `Checks\ErrorLogLocationCheck`, `OpenBasedirCheck`, `DisableFunctionsCheck`, `AutoPrependCheck`, `UploadLimitsCheck` | pure | Path/list checks; `DisableFunctionsCheck` lists only the missing exec-family names. Path values marked `private`. |
| `Checks\FileEditCheck`, `DebugLogCheck`, `DebugDisplayCheck` | pure | WordPress constants. `DebugDisplayCheck` is `dashboard_only` (core owns it in Site Health, SB-E5). |
| `EnvironmentReport` | pure | `__construct( CheckInterface[] $builtins )`, `run( EnvironmentInterface, array $extra ): Report`. Runs each check in `try/catch (\Throwable)`; a non-`CheckResult` return or exception gives an `unknown` row "Check failed" with the check id (no message text). Enforces the ID rules (1.3). `Report` exposes `by_severity()`, `by_group()`, `issue_count()`, `check_count()`. |
| `EnvironmentAdmin` | WP adapter | Registers hooks, `can_view()`, memoises one `Report` per request, Dashboard partial, notice, dismiss handler. **Does not touch `AdminController.php`.** |
| `SiteHealth` | WP adapter | `site_status_tests` and `debug_information` callbacks (1.4). |

`Plugin::register()` gains one line: `( new EnvironmentAdmin( $this ) )->register()` inside `is_admin() || wp_doing_cron()`.
Nothing is constructed at `plugins_loaded` or on the firewall path (SB-E9).

### 1.2 SupportPolicy data shape
```php
final class SupportPolicy {
    public const VERIFIED_ON = 'YYYY-MM-DD';          // bumped every release (SB-E14)
    public const ENDING_DAYS = 90;
    public const STALE_DAYS  = 365;
    // product => branch => ['security_until' => 'YYYY-MM-DD' (UTC, inclusive), 'lts' => bool]
    private const BRANCHES = ['php' => [...], 'mysql' => [...], 'mariadb' => [...]];
    public function status( string $product, string $branch, int $now ): Severity; // ok|notice|critical|unknown
    public function security_until( string $product, string $branch ): ?string;
    public function is_stale( int $now ): bool;
}
```
- Missing branch → `unknown`. MySQL Innovation (9.x) and MariaDB short-term releases are listed individually
  with their end date or left out (→ unknown); never "supported" without an entry.
- Past EOL → `critical` (Site Health `critical`, matching core's meaning of "no security fixes"); the Dashboard
  tab labels it "Warning: no longer receives security fixes" (WPB-6's "warning" state). Ending → `notice`.
- Stale guard (SB-E12): if `is_stale()`, a result that would be `ok` becomes `unknown` ("bundled policy may be
  out of date; update WP Bouncer"); `notice`/`critical` are still reported.
- Dates are verified by the developer at implementation against php.net, Oracle's lifecycle policy and
  mariadb.org; month-only sources use the last day with a comment. Release checklist item added (docs-writer).

### 1.3 `wp_bouncer_environment_checks` filter contract
```php
/** @param CheckInterface[] $checks Built-in checks first. @return CheckInterface[] */
$checks = apply_filters( 'wp_bouncer_environment_checks', $builtins );
```
- Applied lazily, once per request, only when a report is rendered (never at load time).
- A non-array return falls back to the built-ins. Items that are not `CheckInterface` are dropped.
- Removing a built-in is allowed (hosts may hide checks they cannot change).
- IDs: `^[a-z0-9_]{3,64}$`; `wpb_` is reserved for classes in `WPBouncer\Environment\Checks\`; duplicates
  are dropped (first wins), so a third-party check cannot shadow a built-in (SB-E16).
- Third-party results are escaped like built-ins; `why`/`fix` go through `wp_kses_post()`, everything else
  `esc_html()`. A third-party check's `private` flag is respected; values are never logged.
- Third-party checks do not raise the site-wide notice (only built-in PHP/DB EOL does).

### 1.4 Where results render
- **Dashboard tab:** new partial `views/partials/environment.php`, included from `views/dashboard.php` when
  `can_view()`. Grouped by severity (critical, warning, notice, then a collapsed `<details>` for info/ok/
  unknown). The header line reads "N issues found in the M checks WP Bouncer runs" or "No issues found in the
  M checks WP Bouncer runs"; never "secure", no score (SB-E11). EOL rows add "Some hosts and distributions
  backport security fixes; check with your host."
- **Site Health direct tests** (`site_status_tests['direct']`, SB-E4), badge `WP Bouncer` / blue:
  `wp_bouncer_php_eol`, `wp_bouncer_db_eol`, `wp_bouncer_php_settings` (aggregate: worst of the ini checks),
  `wp_bouncer_wp_hardening` (`DISALLOW_FILE_EDIT`, debug log location). Mapping: critical → `critical`,
  warning/notice → `recommended`, else `good` (unknown says "not in WP Bouncer's bundled policy"). Wording says
  "by WP Bouncer's bundled support policy" and doesn't restate core's `php_version`/`sql_server` verdicts
  (SB-E5). Callbacks don't read the current user (core's scheduled check runs them with no user).
  `dashboard_only` results are excluded.
- **Site Health Info:** `debug_information['wp-bouncer-environment']`, one field per check (summary value).
  `open_basedir`, `disable_functions`, `auto_prepend_file`, `error_log` fields have `'private' => true`.
- **Site-wide notice:** only past-EOL PHP or DB. Hooked on `admin_notices` (single site) or
  `network_admin_notices` (multisite) after `can_view()`. It uses only `PhpVersionCheck` and
  `DatabaseVersionCheck` (no full report, no SQL) with a static memo. Shows the version, e.g. "PHP 8.2 no longer
  receives security fixes", plus a Dismiss link and a link to Site Health. Not shown on the plugin's own
  Dashboard tab (the section already says it).
- Never on the front end, in REST, admin-ajax, `wp_localize_script` or HTML comments (SB-E2).

### 1.5 Caching, capability, multisite, dismiss
- **Caching:** none persisted. One `Report` per request, held in `EnvironmentAdmin` (SB-E3, SB-E9). The checks
  are `ini_get()` and constant reads (microseconds).
- **Capability:** `EnvironmentAdmin::can_view(): bool` = `current_user_can( 'wpb_manage_firewall' )` (S12's
  meta cap: `manage_network_options` on multisite, `manage_options` otherwise). Checked server-side in the
  partial, the notice and the dismiss handler (SB-E1).
- **Multisite:** sub-site admins never see the section or the notice. Super admins see the section on any
  site's Dashboard tab (they hold the network capability) and the notice in the network admin only. Site
  Health is already super-admin only (`view_site_health_checks`).
- **Dismiss:** `admin-post.php?action=wp_bouncer_env_dismiss` with `check_admin_referer( 'wp_bouncer_env_dismiss' )`
  + `can_view()` (403 otherwise), then `wp_safe_redirect( wp_get_referer() ?: admin_url() )`. Stores user meta
  `wpb_env_notice_dismissed` = `[ 'at' => time(), 'state' => 'php:8.2|mariadb:10.6' ]`; nothing from the
  request is stored (SB-E8). The notice is hidden while `state` matches and `at` is under 30 days old; a new EOL
  state shows it again. `uninstall.php` deletes the meta for all users (`delete_metadata( 'user', 0, key, '', true )`),
  once per network because user meta is global.

### 1.6 Test plan
- **Unit:** `VersionParserTest` table (PHP `8.3.12-1ubuntu`, `8.4.0RC1`; `5.5.5-10.6.18-MariaDB-0ubuntu`,
  `10.11.6-MariaDB-log`, `11.4.2-MariaDB`; MySQL `8.0.36-0ubuntu`, `8.4.2`, `9.1.0`; Aurora, SQLite, garbage →
  null). `SupportPolicyTest`: every state, UTC boundary days (`security_until` inclusive, day 90 and 91), stale
  guard. `SupportPolicyFreshnessTest`: `VERIFIED_ON` no more than 6 months before the top `CHANGELOG.md` release
  date (today if undated) (SB-E14). `IniValueTest` table. One test per check against a `FakeEnvironment`
  (`tests/Support`). `EnvironmentReportTest`: throwing check, wrong return type, invalid/duplicate/`wpb_`-shadowing
  IDs, non-array filter return.
- **Integration:** our four test IDs exist in `site_status_tests` and return valid arrays with
  `wp_set_current_user( 0 )`; `debug_information` private flags; Dashboard tab section shown to an admin, not an
  editor; multisite: hidden from a sub-site admin (tab and notice), shown to a super admin; dismiss without nonce
  → 403, with nonce stores server time and ignores a posted `at`; notice returns when the state changes or after
  30 days (frozen clock); rendered HTML contains neither `ABSPATH` nor `WP_CONTENT_DIR`; no `wpb_`/`wp_bouncer_`
  option or transient is written by a render; a third-party check returning `<script>` is escaped.
- **E2E (`run.sh`, SQLite):** Dashboard tab shows the section (DB row "Unknown"), Site Health status page lists the
  WP Bouncer tests, front page HTML contains no environment strings.

## 2. WPB-4: dashboard widget

### 2.1 Classes
- `Admin\WidgetStats` (pure): `build( WidgetStatsSource $src, Clock $clock, string $mode, bool $disabled, bool $geo ): array`.
  Returns `{ status, headline_action, h24, h24_prev, d7, d7_prev, trend24, trend7 (up|down|same|new), secondary
  (monitored/lockout/blocked counts), rate_limited (bool), top_rules, top_ips, top_countries (null without geo),
  recent, empty (bool) }`.
- `Log\WidgetStatsSource` interface, implemented by `BlockLog` (additive; `BlockLogInterface` unchanged):
  - `period_counts( string $since14, string $since7, string $since24, string $since48 ): array<action, {h24,h24_prev,d7,d14}>`
    — one query: `SUM(CASE WHEN created_at >= %s THEN 1 ELSE 0 END)` columns, `WHERE created_at >= %s AND action IN
    ('blocked','monitored','lockout','suppressed') GROUP BY action`. Portable to MySQL, MariaDB and SQLite.
  - `top()` gains optional `?string $action = null` (backwards compatible).
  - `recent( int $limit, array $actions ): array` selecting only `created_at, ip, rule, action`, `ORDER BY created_at DESC, id DESC`.
- `Admin\DashboardWidget` (WP adapter): `wp_dashboard_setup` → `if ( current_user_can( AdminController::CAPABILITY ) )
  wp_add_dashboard_widget( 'wp_bouncer_dashboard', … )`; the render callback checks again. Status (mode, disabled,
  rules on/total) is computed live from settings, so it is never stale.

### 2.2 Queries and caching
- Cold: `period_counts` (1) + top rules (1) + top IPs (1) + top countries (1, skipped without geo) + recent (1) =
  **at most 5 queries**, all bounded by the indexed `created_at`. Warm: **0 queries** on `bouncer_log`.
- Transient `wpb_widget_stats` (swept by the existing `wpb_` uninstall cleanup), TTL 300 s, filterable via
  `wp_bouncer_widget_cache_ttl` (clamped to 60–3600). It holds only the aggregate array.
- Invalidation: `delete_transient()` on new action `wp_bouncer_log_cleared` (fired in `handle_clear_log`) and on
  `wp_bouncer_settings_changed` (S13; block-IP goes through `save()`), plus after `purge_older_than()` in the daily cron.
- Data-engineer: confirm the `CASE` aggregate on SQLite and measure on 1M rows (MySQL test site). If a 14-day scan
  during a flood is slow, consider an `(action, created_at)` index under `DB_VERSION` 3 rather than AJAX.
- No lazy AJAX: the cache keeps the miss rare and AC11 requires no JavaScript. Revisit only if measured.

### 2.3 Content rules
- Monitor mode: headline action `monitored`, labelled "Would have been blocked", plus "Monitor mode: requests are
  logged, not blocked". Disabled: "WP Bouncer is switched off in wp-config.php", numbers labelled "Before it was
  switched off". Alerts are excluded everywhere (AC3).
- If any `suppressed` row is in the window: "Logging was rate-limited during a flood; numbers are a lower bound"
  (answers security-fixes §7 RT-23 note).
- Empty log: "Nothing blocked yet". Geo missing: countries hidden, with a link to Tools.
- Trend: arrow + number + word ("up 12 from the previous 24 hours"), `number_format_i18n()`, `_n()`; times via
  `human_time_diff()`; absolute times in the site time zone.

### 2.4 Escaping (attacker-controlled fields)
- `ip`, `rule` and `country` come from requests or third-party rules. Each is escaped at output with `esc_html()`.
  Rule names go through `AdminController::rule_title()` (unknown ids shown escaped). Countries must match
  `^[A-Z]{2}$`, otherwise "Unknown".
- Links: `esc_url( AdminController::url( 'log', [ 'rule' => rawurlencode( $rule ) ] ) )`. `add_query_arg()` does
  not encode values. IP links are built only when `IpUtils::is_valid()`, using a new exact `ip` log filter
  (`log_filters_from_request` / `BlockLog::where()`; validated with `IpUtils::is_valid`), not `s=`.
- Never shows URI, User-Agent, referrer or reason (AC9). Nothing goes into `wp_localize_script`.

### 2.5 Capability and multisite
`manage_options` only (matches `AdminController::CAPABILITY`). Per site: each site's dashboard shows its own
tables and transient. Not registered on the network dashboard (`wp_network_dashboard_setup`), since there is no
network-wide data.

### 2.6 Test plan
- **Unit `WidgetStatsTest`** (fake source, `FrozenClock`): trends up/down/same/new (previous 0), monitor and
  disabled labels, empty state, `rate_limited`, countries null without geo, top lists limited to 3, recent to 5.
- **Integration:** widget registered for an admin and not for an editor or author (`$wp_meta_boxes`); seeded log
  gives exact numbers that equal the Dashboard tab's helpers for the same period; alerts excluded; cold ≤5 and warm
  0 queries on the table (`SAVEQUERIES`, filtered by table name); the cache is cleared by clear-log and block-IP
  and refreshes after the TTL; `<script>` in `rule` and a malformed `ip` render escaped and unlinked;
  uninstall leaves no `wpb_widget_stats`; multisite: site 2's widget shows site 2's data.
- **E2E:** `curl` of `wp-admin/index.php` as admin (no JS) contains the widget and "Nothing blocked yet" on a fresh
  site, then counts after `run.sh` triggers blocks.
- **Measurement:** tester documents cold-render time on a 1M-row MySQL test site (never production).

### 2.7 Open widget questions (backlog Q11, Q12): recommendations
- Must-haves: all seven items, in the order listed; trim recent blocks first if space is tight.
- Show IPs: yes (admins only, the log already shows them).
- Network dashboard: no; per-site widget on each site. Network activation is supported as today.
- Refresh: a 5-minute cache is acceptable; live numbers are one click away in the Activity Log.

## 3. 1.2.0 order
1. **S8** (in progress; owns `AdminController.php`).
2. **WPB-5** bump (headers, readme, phpcs/phpstan configs, CI matrix; devops + developer). Small; lands right after
   S8 so later slices may use 8.3 syntax.
3. **S4, S5, S6, S7, S9** (former 1.1.3), then **S10–S14** + WAF JSON, as in security-fixes §4/§5.
4. **WPB-3b** = S14's privacy tools plus its integration tests and policy text; no separate branch.
5. **WPB-4**, then **WPB-6/7**, then **WPB-2**.

`AdminController.php` lock (one branch at a time), in order: S8 → S5 (`notices()`, geo import) → S6
(`action_label`) → S10 (`handle_unlock_ip`) → S12 (`guard`) → S13 (`save()`) → WPB-4 (two-line window: the `ip`
log filter and `wp_bouncer_log_cleared`) → WPB-2 (slices 2–4). S4, S7, S9, S11, S14 and **WPB-6/7 do not edit it**.

Parallel at any time (new files): `WidgetStats`, all of `Environment\*` including `SupportPolicy` date research,
`RuleCatalog`/`RuleStatus`, `SettingsDiff`, `FetchContext`. WPB-6/7 needs S12 (the `wpb_manage_firewall` cap)
merged first. Other shared files: `views/dashboard.php` (S8 links, WPB-6/7 one include, WPB-2 rewrite: WPB-6/7
merges before WPB-2 and WPB-2 keeps the include), `Plugin.php` (one-line registrations; trivial rebases),
`BlockLog.php` (S4 `normalize`, WPB-4 read helpers, `ip` filter: no overlap), `uninstall.php` (S9 restructure
first; WPB-6 adds the user-meta delete inside `wp_bouncer_uninstall()` outside the per-site loop).

## 4. Security-blue recommendations (SB-E1..E16)
| ID | Decision |
|---|---|
| E1 | Adopted: `can_view()` via S12's `wpb_manage_firewall`, checked server-side everywhere. Super admins also see it on per-site tabs, since they hold the network cap. |
| E2 | Adopted: Dashboard tab and Site Health only; no REST, AJAX or localized data. |
| E3 | Adopted: nothing persisted except the dismiss meta (state ids, no values); no logging. |
| E4 | Adopted: direct tests only, prefixed ids, user-independent callbacks, private Info fields. |
| E5 | Adopted: own wording/ids; `WP_DEBUG_DISPLAY` and HTTPS left to core in Site Health. |
| E6 | Adopted: bundled data, no HTTP or loopback probes. |
| E7 | Adopted: `esc_html`/`esc_attr` everywhere, `wp_kses_post` for why/fix, `try/catch (\Throwable)` + type check. |
| E8 | Adopted: admin-post + `check_admin_referer` + cap; server `time()`; state-bound dismissal. |
| E9 | Adopted: lazy, per-request memo; the notice reads only `PHP_VERSION` and `db_server_info()`. |
| E10 | Adopted: safe summaries only; `open_basedir` shown as "set (N paths)", never the paths. |
| E11 | Adopted: "No issues found in the N checks…"; unknown ≠ warning; backport sentence. |
| E12 | Adopted: `VERIFIED_ON` + 12-month stale guard with injected clock. |
| E13 | Adopted: `IniValue` normaliser; unparseable → unknown; `display_errors` runtime-value note in `why`. |
| E14 | Adopted: release checklist item + freshness unit test against the changelog date. |
| E15 | Declined for 1.2.0: needs loopback requests (contradicts E6); goes to the later "WordPress hardening" item. |
| E16 | Adopted: ID pattern, reserved `wpb_` prefix, first-wins de-duplication. |
| §3 table | Adopted as the WPB-7 list and severities; `allow_url_include` 8.4 deprecation and `enable_dl` checked at implementation. |

## 5. Owner questions
1. **WordPress-level checks in WPB-7** (backlog open point). Recommendation: include `DISALLOW_FILE_EDIT` (warning) and
   debug-log location (warning) now, `WP_DEBUG_DISPLAY` on the Dashboard tab only, and drop `FORCE_SSL_ADMIN`. The rest
   goes to a later "WordPress hardening" item.
2. **Widget scope (backlog Q11/Q12).** Recommendation: all seven items, IPs shown, per-site widgets only (none on the
   network dashboard), and a 5-minute cache.
