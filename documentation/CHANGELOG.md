# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.3.0] - 2026-10-30

### Added

- **Settings changed outside WP Bouncer are detected (WPB-12).** After each change made with WP Bouncer loaded, the plugin keeps a keyed fingerprint of its settings. A daily check, and a check on admin page loads for users who can manage WP Bouncer (at most once an hour per site), compares the settings with it. A difference, such as a change made with `wp --skip-plugins` or directly in the database, adds one Activity Log row: rule "settings", "Changed outside WP Bouncer", actor unknown, with the time it was found (not the time it was made) and the setting paths that changed, never their values. The row also queues the `firewall_changes` email, which follows the alert switch. The email is sent even with alerts off when the alert, mode or admin-email settings changed, or when the fingerprint can't be trusted. The settings found are then taken as the new baseline, so the same change is reported once. Nothing is reverted or blocked. The first check after the update records the baseline silently. Each site is checked on its own, and uninstalling removes the fingerprint.
- **Developer hook and filter for settings drift (WPB-12).** `wp_bouncer_settings_drift` fires after each reported drift, with the paths, the kind, the trigger and whether the row was written, so you can send it off the server. `wp_bouncer_settings_drift_check` can skip the admin and cron checks. See the developer guide.
- **Administrator logins are recorded (WPB-13).** Each successful login by an administrator (the administrator role, `manage_options`, or a network super admin) adds one Activity Log row with action "Admin login", the user, IP, country, time and method: interactive password, application password (REST), application password (XML-RPC), or password (XML-RPC). Filter the log by action to see only these. Application-password and XML-RPC logins are recorded once per user, range and method each hour.
- **Email alert for a login from a new location (WPB-13).** An administrator who logs in from an IP range (IPv4 /24, IPv6 /64) or a country not seen for that account in the last 90 days gets one email. The first login after the update starts the history without an email. Each administrator gets at most 3 of these emails an hour, and the site at most 10 an hour; further logins are still recorded, and one "throttled" notice is sent per hour. The window can be changed with the `wp_bouncer_admin_login_window_days` filter.
- **Settings for admin logins (WPB-13).** "Record administrator logins in the Activity Log" (`alerts.record_admin_logins`) and "an administrator logs in from a new location" (`alerts.admin_login_location`) are on the General tab, both on by default, including on upgraded sites. Switching either one off sends a risky-change alert.
- **Privacy (WPB-13).** The WordPress Export and Erase Personal Data tools cover each administrator's login history and login rows ("Site security: administrator logins"). Erasing deletes the rows and resets the history, so the next login from any location is treated as new and alerts. The privacy policy suggestion describes the login record.
- **Developer hooks (WPB-13).** `wp_bouncer_admin_login_recorded`, `wp_bouncer_admin_login_alert`, `wp_bouncer_admin_login_is_admin`, `wp_bouncer_admin_login_window_days`, `wp_bouncer_admin_login_defer`, `wp_bouncer_record_admin_login` and `wp_bouncer_log_login_budget_per_minute`. See the developer guide.
- **Threat map on the Activity Log (WPB-11).** A world map shows where blocked requests and lockouts came from, by country, with a **Top countries** table beside it. Monitor-only matches, alerts and admin logins are not counted. The map follows the date range, rule, action and country filters, and ignores the search box and the IP filter (the panel says so). Without dates it covers the last 30 days. Countries are taken from the stored country of each row; rows with no known country count as unknown location. Codes that have no place on the map (such as Tor exit nodes) are listed in the table. The map is drawn from a bundled SVG, `world.svg` (64,277 bytes), with no network request. The panel can be hidden, and that choice is remembered in the browser. The plugin zip is about 397 KB, up from 313,771 bytes in 1.2.0.
- **Blocked countries are marked in the Top countries lists.** On the Activity Log and the Dashboard, a country the country rule refuses shows a "Blocked" badge ("Blocked at login" when the rule covers login pages only, "Would be blocked" in monitor mode). The badge uses the same test as the firewall, including allow-list mode.
- **From and To date filters on the Activity Log (WPB-11).** Two date fields (`log_from`, `log_to`) limit the table, its paging and the CSV export to whole days in the site's time zone. A range that ends before it starts is ignored, and a range longer than 365 days is cut to 365. Without dates the table is unchanged.
- **Activity Log index (WPB-11, database schema version 4).** The log table gets an index on action, time and country, which keeps the map fast on large logs. Upgrading adds it: it took 1.7 seconds on MariaDB with a million rows, and longer on larger logs.

### Changed

- The Dashboard and dashboard widget counts of threats, the 14-day chart and the top rules, IPs and countries now leave out login rows, as they already left out alerts.
- Uninstalling WP Bouncer removes each site's administrator login history.
- The Dashboard tab no longer lists the rules with on/off buttons. Rules are switched on and off on the Rules tab.

### Known limits

- Settings changes made while WP Bouncer isn't loaded are detected, but not as they happen (WPB-12). Limits, in plain words:
  - Detection only. WP Bouncer never reverts a change.
  - Someone who can read `wp-config.php` or run code on the server can defeat the check.
  - The check relies on real security keys (salts) in `wp-config.php`. If they are missing or still the placeholder, WordPress uses values stored in the database, and the check gives no extra protection.
  - Someone with database write access, but not `wp-config.php`, can't forge a matching record. They can delete the record and the baseline marker, though, so the next check starts over silently.
  - Restoring an older settings-and-fingerprint pair is not detected. This includes an old backup of both, which hides a later admin-email change.
  - Once the fingerprint is broken, the attacker chooses the recipients: the addresses are in the database. Ship the `wp_bouncer_settings_drift` action off the server.
  - Removing WP Bouncer from `active_plugins` is not detected.
  - Detection can take up to a day: the daily cron, or the next admin page load (at most hourly). Under `DISABLE_WP_CRON` with no admin visits, it can take longer.
  - Changes made before the first baseline (after the update from 1.2.1) are not seen, and a change reverted between two checks is never seen.
  - With a persistent object cache, a direct database edit is seen only once the cached settings expire.
  - A legitimate restore, import, staging copy or salt rotation is reported as drift, once.

## [1.2.1] - 2026-10-24

### Security

- **Settings changes are audited whichever way they are made (WPB-8).** Changes to WP Bouncer's settings are now logged in the Activity Log and alerted, whether they are made on the admin screen, with WP-CLI, or by code calling `update_option()`. The actor is shown as `login #ID (context)`, or as `cli` or `unknown` when no one is signed in. Settings-change alert emails have their own limit of 10 an hour. After that, one "throttled" notice is sent, so they can't crowd out other critical alerts. Changes that could silence alerts (switching the firewall mode, turning off any alert, or changing alert recipients) are always emailed, up to 50 an hour per site. On multisite, alerts name the site where the change happened.
- **Turning off any alert is now treated as a risky change.** In 1.2.0, switching off the new-administrator or plugin-change alerts was logged but not emailed. It now sends a firewall-change alert, as switching off the other alerts already did.

### Changed

- **Rules tab layout (WPB-9).** The rule categories sit side by side, in up to three columns on wide screens, and in one column on narrow screens and on mobile. Category headings are a little larger. Presentation only: no settings change, and the save bar stays put.

### Fixed

- **Activity Log and Traffic tab (WPB-10a).** Long Request, User-Agent, Client and Referrer values no longer spill over the next column. They are cut off with an ellipsis at the edge of their own column, and the full value is shown on hover.

### Added

- **Resizable columns (WPB-10b).** On the Activity Log and the Traffic tab, drag the edge of a column heading to make that column wider or narrower. The keyboard works too: Tab to the edge, then use the arrow keys (Home and End jump to the smallest and largest width, Escape resets). Double-click an edge, or press **Reset column widths**, to go back to the default widths. Widths are remembered in this browser only, kept separately for each table. Resizing is off at 782px and below, where WordPress shows the tables in its narrow layout.

### Development

- JavaScript unit tests use Node's built-in test runner (`make test-js`), and CI runs them.
- The integration suite makes no live HTTP requests (outbound calls are answered locally) and its real-DDL tests drop and recreate tables far less often. It takes about 13 seconds, down from 31 seconds. No coverage was removed.
- The end-to-end suite batches its WP-CLI calls, reads the database directly, and runs the test server with OPcache on. It takes about 58 seconds, down from 116 seconds. No coverage was removed.

### Known limits

- Settings changed while WP Bouncer isn't loaded, for example with `wp --skip-plugins`, or by editing the database directly, are not logged.

## [1.2.0] - 2026-10-24

Folds in the work planned for the never-released 1.1.2 and 1.1.3 releases. Sites on PHP below 8.3 aren't offered 1.2.0 automatically. Sites on WordPress below 7.0 may be (see the upgrade notes).

### Upgrade notes

- **Minimum versions are now PHP 8.3 and WordPress 7.0.** Upgrade PHP and WordPress first. Sites on PHP below 8.3 aren't offered 1.2.0 automatically. Sites running 1.1.x on WordPress below 7.0 may still receive it through automatic updates, because the 1.1.x updater doesn't enforce the WordPress requirement (core only checks the PHP one). On such a site 1.2.0 doesn't start the firewall: it shows an admin notice, emails the site administrator (and the network administrator on multisite) once that the firewall is OFF until WordPress is updated to 7.0 or newer, and keeps checking for updates. Updating WordPress turns the firewall back on.
- **Database upgrade (schema version 3).** On the first request after the update, the plugin creates `{prefix}bouncer_counters` (login attempt counters) and runs dbDelta on `{prefix}bouncer_traffic`, which adds an index on `user_id` with ALTER TABLE. On a large traffic table that can take a while, so update on a quiet day on busy sites, and take a backup first. Only one request runs the upgrade at a time. If the tables can't be created (for example, the database user lacks the privilege), admins see a notice and the upgrade is retried every 10 minutes.
- **Data cleanup of older rows.** Rows written by earlier versions are redacted: secret query values in URLs in the Activity Log and Traffic log, and in traffic referrers, become `[removed]`. A lockout reason that names an account which doesn't exist now reads "(last: unknown username)". The first slice runs during the upgrade request; the rest runs from cron, a minute later, in 20-second slices, until it is done. Rows are not deleted, and the removed text can't be recovered.
- **Bans last at most 24 hours.** Automatic bans and lockouts placed after the update last at most 1,440 minutes. Stored settings above that are read as 1,440. Bans placed before the update keep their original expiry, except temporary IPv6 bans, which reset (see IPv6 under Security).
- **Bans are suspended in IP-fallback mode.** While a forwarding header is set as the IP source with no trusted proxies listed, bans and lockouts are logged but not enforced. Fix the IP setup (see the notice on each admin screen).
- **Log write budget.** Block-log writes are limited site-wide to 120 ordinary rows a minute and 30 lockout or uploads-block rows a minute. Events over the limit are counted in one "suppressed" summary row. Worst case is about 173,000 ordinary rows a day, plus up to 43,000 priority rows. Blocking is never affected, and alert rows aren't limited.
- **WAF cost.** Large values (over 8 KB) add about 2.5 to 5 ms per request.
- **WAF JSON inspection is new and on by default.** After updating, check the Activity Log for `WAF JSON` entries. A webhook or integration that posts large JSON without a login cookie may be refused. Raise `wp_bouncer_waf_json_max_bytes` or `wp_bouncer_waf_json_max_fields` in a mu-plugin, or untick **Also inspect JSON request bodies** on the Rules tab.
- **Logins from another site.** Headless front ends and apps on another domain that log in to WordPress must add their origin with the `wp_bouncer_login_allowed_origins` filter, from a plugin or mu-plugin. This check needs the login lockout rule on.
- **Multisite.** Network-activate WP Bouncer. Per-site activation can strip the uploads protection. On a network, only network admins can change the uploads `.htaccess` setting, run URL geo imports and the uploads test or sync, or add regex User-Agent patterns.
- **Settings.** Nothing is removed or reset. New settings get their defaults. Email alerts for firewall changes (`firewall_changes`) are on by default.
- **Downgrading to 1.1.x** keeps working. Uninstalling 1.1.x doesn't drop `{prefix}bouncer_counters`; drop it by hand if you need to.

### Security

- **Forwarded IP addresses.** A forwarding header (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` and similar) is ignored unless the request comes from a listed trusted proxy. With no trusted proxies listed, the connection address is used and an admin notice explains the fix. While that fallback is active, bans and lockouts are suspended; failed logins are still logged, and the WAF, User-Agent, blocklist and sensitive-file checks still apply.
- Header values that are private, loopback, link-local, carrier-grade NAT, unique-local (IPv6) or unspecified are refused. The opt-in constant `WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS` accepts private (not loopback) values from a trusted proxy, for intranet sites.
- Loopback requests (127.0.0.1 and ::1) are exempt only when they carry no forwarding header. Loopback and trusted-proxy addresses are never banned.
- Trusted proxy and allowlist entries wider than /8 (IPv4) or /16 (IPv6) are ignored and dropped on save, with a message naming them.
- **Cross-site logins are refused.** A login attempt that the browser says another site started (or a sibling subdomain, unless its origin is this site's or on the allowed list) is refused before the password is checked. This covers wp-login.php, xmlrpc.php, WooCommerce and custom login forms. Refused attempts aren't counted, and a forged header gains nothing. Monitor mode doesn't refuse.
- REST requests that send application-password (Basic) credentials from another site are refused the same way.
- **Cross-site probes and 404s.** A probe or 404 caused by another site's page is counted separately. It needs 5 probes (`wp_bouncer_cross_site_probe_limit`) or five times the 404 limit (`wp_bouncer_cross_site_404_multiplier`). Then it only refuses that visitor's requests from other sites, never the whole site.
- **Login attempts are counted before the password check**, so a burst of parallel guesses can't all get through. Application-password attempts on REST and XML-RPC are counted the same way. Login counters are kept in `{prefix}bouncer_counters`, unless an object cache is enabled with `wp_bouncer_atomic_object_cache`.
- **IPv6 counts are per /64** (`WP_BOUNCER_IPV6_PREFIX`, 48 to 128, default 64; 128 means per address). This covers login counting, the rate limit, sensitive-file and 404 counters and bans, and the Activity Log's de-duplication. Attempts from one /48 are limited to 8 times the per-/64 limit (`wp_bouncer_ipv6_wide_multiplier`, login only). Unlock an IP clears every key for its /64, and the old per-address keys too. Temporary IPv6 bans placed before the update reset, because their keys are now per /64.
- Update packages must come from the exact expected GitHub release URL.
- **WAF fails closed.** If the regex engine errors on a built-in signature, the request is refused. Values up to 64 KB are scanned in overlapping 8 KB windows, plus the last 8 KB of longer values.
- XML-RPC `system.multicall` is detected by reading `methodName` with PHP's own XML parser. `/xmlrpc.php/extra` and `/wp-login.php/extra` paths are recognised.
- **User enumeration.** For logged-out visitors, `?author=N` with N above 0 and `?author_name=` count as scans. The oEmbed response no longer includes the author name or URL. With generic errors on, the lost-password error is generic too, though WordPress can still reveal whether an account exists (a known limitation).
- **Uploads.** `<?=` is detected as PHP code (with a relaxed rule for compressed media, to avoid false alarms). The `.htaccess` block is removed only after two failed checks in a row, not after one server error. Leftover self-test files are swept daily.
- **Privacy.** Secret query values are removed from URLs in the Activity Log and Traffic log. Lockout reasons don't store usernames of accounts that don't exist. Alert rows don't carry email addresses. If WP-Cron isn't running, the log purge still runs from admin visits.
- **Country lookup.** A country header is read only from a listed trusted proxy. Server variables (such as `GEOIP_COUNTRY_CODE`) are read directly and never as request headers. If the header can't be trusted and no geo database is loaded, country blocking is paused and an admin notice says so.
- **Geo URL import.** Only https downloads from the vendor hosts (`download.db-ip.com`, `download.ip2location.com`) are allowed, and each redirect is checked. Downloads and unpacked CSVs are size-capped (1 GB by default, `wp_bouncer_geo_max_bytes`).
- **Multisite capability.** The `wpb_manage_firewall` capability is held by network admins on multisite and by administrators on a single site. Sub-site admins can still upload geo CSV files, within the size cap.
- **Admin hardening.** Block-IP links use a nonce per address and accept one address. Admin notices show fixed text only, never free text from the URL. CSV export neutralises more spreadsheet formula triggers. Switching on the IP blocklist, country or User-Agent rule runs the self-lockout guard.
- Uninstall and network deactivation clean up every site on a multisite network.
- Critical alerts (a new administrator account, and WP Bouncer being deactivated) have their own limit of 20 an hour, so a flood of other alerts can't push them out.

### Changed

- Minimum PHP 8.3 and WordPress 7.0. Compatibility code for older versions is removed. CI runs unit tests on PHP 8.3 to 8.5, and integration and end-to-end tests on WordPress 7.0, latest and nightly (nightly is allowed to fail), on MySQL and MariaDB.
- Automatic bans and lockouts are capped at 24 hours (see the upgrade notes).
- **Rules tab in categories.** The rules are grouped into Block lists (`block-lists`), Login and accounts (`login-accounts`), Scanners and floods (`scanners-floods`), and Attack payloads and hardening (`payloads-hardening`). Rules from other plugins go under Other (`other`). Each rule shows On or Off, and a flag: **Needs attention** when it is on but not fully working, or **Before switching on** when it is off and needs setting up (rate limiting, and country blocking before a geo database is loaded). The Dashboard's rules overview uses the same groups and status, and the notices read the same status.
- **A sensitive-file probe no longer bans on its own.** The first probe is refused. A second probe within 10 minutes that another site's page didn't cause bans the IP from every page for the ban length. Probes caused by another site are counted separately (see Security). A ban length of 0 still refuses only the probe.
- **Loopback is narrower.** A same-host proxy that forwards a header is no longer exempt. Counting and banning still skip loopback addresses.
- **Settings audit.** Saving settings writes one `alert` row to the Activity Log. It names the changed settings and the user, never the values. Changes that weaken the firewall (mode, allowlist, trusted proxies, IP source, geo source or header, alert recipients, the XML-RPC mode, a rule switched off, the firewall-change alert itself, or a shorter Activity Log or Traffic log retention, which makes the daily purge erase older rows) also send a `firewall_changes` email. Clearing the Activity Log is audited and emailed too.
- The update-source filters `wp_bouncer_update_manifest_url` and `wp_bouncer_update_package_prefix` are honoured only when `WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS` is `true` in wp-config.php. Forks and testers must add the constant.
- Saving settings that would block you is refused when your address is shared (behind a proxy, CDN or the fallback). The save points you to the IP setup instead of allowlisting the shared address.
- Release pipeline hardened for maintainers: publishing is separate from the build, actions and downloads are pinned, the zip is reproducible, and the downloaded checksum is verified.
- CI blocks on phpcs (WordPress Coding Standards) and PHPStan level 6. Code is cleaned up to the coding standard; no change in behaviour.

### Added

- **Email alert `firewall_changes`** (on by default): the risky settings changes above, a daily reminder while `WP_BOUNCER_DISABLE` is set, and the Activity Log being cleared.
- **Environment checks**, on the Dashboard tab and in Site Health:
  - PHP and database (MySQL, MariaDB) versions against their security support end dates. A warning starts 90 days before the end date, and a critical notice follows the end date. Unknown versions get no warning.
  - PHP settings with security effects: `allow_url_include`, `display_errors`, `display_startup_errors`, `log_errors`, error log location, `expose_php`, `zend.assertions`, `cgi.fix_pathinfo`, session cookie and strict-mode settings, `open_basedir`, `disable_functions`, `auto_prepend_file`, and upload limits (for context).
  - WordPress settings: `DISALLOW_FILE_EDIT`, a web-readable debug log, and `WP_DEBUG_DISPLAY`.
  - Filter `wp_bouncer_environment_checks` to add or remove checks.
- **Privacy tools.** WordPress's Export and Erase Personal Data tools include a traffic-log exporter and eraser, and a block-log eraser. The block log keeps its rows and times, but the URL and reason of rows that name the account are cleared. A privacy-policy text is added to the policy guide. Exports and erasure are by user account only, not by IP address.
- **Multisite alerts.** On a network, the network admin email gets firewall alerts too.
- **Constants:** `WP_BOUNCER_IPV6_PREFIX`, `WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS`, `WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS`.
- **Filters:** `wp_bouncer_settings_changed` (action), `wp_bouncer_geo_import_hosts`, `wp_bouncer_geo_import_allow_http`, `wp_bouncer_log_budget_per_minute`, `wp_bouncer_log_priority_budget_per_minute`, `wp_bouncer_atomic_object_cache`, `wp_bouncer_ipv6_wide_multiplier`, `wp_bouncer_cross_site_404_multiplier`, `wp_bouncer_cross_site_probe_limit`, `wp_bouncer_environment_checks`, `wp_bouncer_geo_max_bytes`, `wp_bouncer_login_allowed_origins`, `wp_bouncer_waf_json_max_bytes`, `wp_bouncer_waf_json_max_fields`, `wp_bouncer_widget_cache_ttl`, `wp_bouncer_rule_info`. Signatures are in the [developer guide](developer-guide.md#hooks-filters-and-constants).
- Integration tests (`make integration`) against MySQL and MariaDB, in single-site and multisite.
- End-to-end suite can run against MySQL or MariaDB and a chosen WordPress version.
- **WAF JSON body inspection** (`inspect_json`, on by default, also on existing sites; checkbox on the Rules tab). JSON request bodies are checked with the same signatures as form fields. A body counts as JSON when its Content-Type says so, the way WordPress reads it (`application/json`, any `+json` type, `+oembed`, and lists such as `text/plain, application/json`). A body that isn't declared as JSON, and isn't multipart, is also treated as JSON if its first non-blank byte is `{`, `[` or `"`, because many plugins decode the raw body whatever its type says.
  - Checked: visitors who aren't logged in, and logged-in users who can't edit posts.
  - Not checked: users who can edit posts. A cookie session counts only with a nonce (`X-WP-Nonce` or `_wpnonce`): a valid REST nonce on REST requests, and on other requests any nonce, as long as the request doesn't come from another site. Application-password credentials count only on REST or XML-RPC requests. Administrators aren't inspected by the WAF at all.
  - Fails closed: a body the plugin can't check gets a 403 when it is over the size limit, nested more than 512 levels, holds more than 5,000 fields (values and containers), or would need too much memory to decode (estimated against `memory_limit`). The size limit is 1 MB for anonymous visitors and 8 MB for logged-in users, each capped by `post_max_size`. Invalid JSON gets no WAF verdict, because WordPress refuses it.
  - WAF verdicts block the request and never ban the IP.
  - Filters: `wp_bouncer_waf_json_max_bytes( $max, $logged_in )` and `wp_bouncer_waf_json_max_fields( $max )`.
  - Known limitation: plugins that receive large signed JSON webhooks without a cookie may need the byte or field limit raised.
- **Dashboard widget** (WPB-4). A WP Bouncer box on the WordPress Dashboard, for users with `manage_options`. It is per site: each site's Dashboard shows its own log, and the network Dashboard has none. It shows blocks in the last 24 hours and the last 7 days, each with a trend against the period before, and the top three rules, IP addresses and countries for the last 7 days (countries only when a geo database is loaded), and the latest five blocks. The status line says whether the firewall is enforcing, in monitor mode or switched off. The numbers are cached for 5 minutes, or for an hour while the log is flooded (more than 100,000 rows in 14 days). Filter `wp_bouncer_widget_cache_ttl` sets the cache length in seconds (60 to 3600). The cache is cleared when settings change, when the Activity Log is cleared and after the daily purge.
- **Activity Log: Block /64.** For an IPv6 row, this blocks its whole /64 network, which matches how the firewall counts that client.
- **Action `wp_bouncer_log_cleared`**, fired after the Activity Log is emptied.
- **Filter `wp_bouncer_rule_info`** describes rules from other plugins for the Rules and Dashboard tabs: their category and title. Built-in rules ignore it. See [adding-a-rule.md](adding-a-rule.md).

### Fixed

- Network uninstall and network deactivation now cover every site, not just the current one.
- Regex errors in User-Agent patterns are recorded instead of silently ignored. More than 100 patterns are ignored.
- A single server error while checking uploads no longer removes the uploads block.
- Rule switches have accessible names. Screen readers announced only "Enabled" for every rule, and the Traffic switch had the same problem.

## [1.1.1] - 2026-10-20

### Added
- **Sensitive-file probes** rule (`sensitive_files`). Refuses requests for files that leak secrets if they exist: `.env`, `.git/` and other version-control data, `.htpasswd`, wp-config backups, PHP file backups, database dumps, site backup archives, log files, phpinfo pages, database admin tools, known web shells, PHP in uploads, the PHPUnit `eval-stdin.php` exploit and project manifests. A file that exists is served by the web server before WordPress runs, so a probe that reaches WordPress is a guess, and the IP is banned from the whole site for 60 minutes (configurable; 0 refuses only the probe). Extra path fragments can be added. `/.well-known/` is never treated as a probe.
- **404 flood** rule (`not_found`). Bans an IP for 60 minutes after more than 20 "not found" pages in 60 seconds (all configurable). Missing images, CSS, JS, fonts and media don't count, nor do logged-in administrators or, by default, search engine crawlers.
- **No PHP in uploads** (`uploads_php`):
  - Keeps a `# BEGIN WP Bouncer` block in `wp-content/uploads/.htaccess` that refuses to run scripts there (Apache 2.2/2.4, LiteSpeed). It uses access rules only, not `php_flag`, which breaks PHP-FPM servers. Other content in the file is left alone. The block is removed when the setting is turned off, while `WP_BOUNCER_DISABLE` is on, and on deactivation and uninstall.
  - Refuses uploads through WordPress (media library, REST API, sideloads) whose names have a script extension anywhere (`photo.php.jpg`), that are server config files (`.htaccess`, `.user.ini`), or that contain `<?php`.
  - **Test now** button: puts a tiny script in uploads, requests it, deletes it, and reports whether the server ran it. The equivalent nginx rule is shown for servers that ignore `.htaccess`.
  - Safety check: after the block is written, a one-off cron job fetches a text file from uploads. If the server answers with an error (a host whose `AllowOverride` doesn't allow access rules would fail every upload, images included), the block is removed again and the admin screens say why.
- **Email alerts** (`alerts` settings, General tab). Emails when an account is created as, promoted to or given the administrator role (or made a multisite super admin), and when a plugin is installed, activated, deactivated or deleted, including WP Bouncer itself being deactivated. Plugin updates are optional (off by default). Each email says who did it, from which IP and country, and when. Changes in one request arrive as one email; at most 20 emails are sent per hour. Recipients default to the site's admin email. A **Send a test email** button. Alerts keep working while `WP_BOUNCER_DISABLE` is on.
- **Traffic log** (Traffic tab, `traffic` settings), off by default. Records every request that reaches WordPress in a new table `{prefix}bouncer_traffic`: time, IP, client type, method, URL, response code, referrer, User-Agent and logged-in user. Written on `shutdown`, so the final status is recorded, including the 403 of requests the firewall blocked. Client types (`Traffic\ClientClassifier`): browser, mobile browser, search engine, bot or crawler, uptime monitor, feed reader, WordPress, script or tool, attack tool, no User-Agent, other. Secret query parameters (`key`, `pwd`, `password`, `token`, `access_token`, `_wpnonce`, anything containing `pass`, `token` or `secret`, …) are replaced with `[removed]` in URLs and referrers. Retention 1 to 7 days (default 7), purged by an hourly cron job (`wp_bouncer_traffic_purge`). Options to skip WP-Cron and Heartbeat requests (on by default) and logged-in administrators. Filters by client, response class and IP, search, CSV export, and Block IP from any row. Summary of the last 24 hours: requests, distinct IPs, 4xx responses, top client types.
- Activity Log action `alert` (purple badge) and rule filter "Email alerts". Alerts are not counted in the Dashboard's block statistics.
- Tools → Unlock IP also lifts sensitive-file and 404-flood bans.

### Changed
- Database schema version 2 (the traffic table). Sites updating from 1.1.0 get it, and the hourly purge job, on the first request after the update.
- The three new rules and alerts are on by default, including on sites updating from 1.1.0. On update the uploads `.htaccess` block is written on the first request.
- End-to-end tests run PHP's built-in server with a router (as Apache with WordPress's rewrite rules) and pretty permalinks, and capture outgoing mail.

## [1.1.0] - 2026-10-20

### Added
- Updates from GitHub releases through WordPress's normal plugin updater. New versions show on the Plugins screen and on Dashboard → Updates with **Update now** and **View details**, and the plugin can be set to **Enable auto-updates** like any other. WP-CLI `wp plugin update` works too.
- Each update zip is checked against the SHA-256 published with the release, and must come from this repository's releases, before WordPress installs it.
- `Update URI` header, so WordPress never takes updates for this plugin from WordPress.org.
- Updates card on the Tools tab: installed and latest version, and a **Check for updates now** button.
- `WP_BOUNCER_DISABLE_UPDATES` constant to switch update checks off.
- Release workflow: pushing a `vX.Y.Z` tag runs the tests, builds the zip and `update.json`, and publishes the GitHub release.

## [1.0.1] - 2026-10-20

### Fixed
- Importing a full geo database from the Tools tab, by upload or URL, returned HTTP 500. The whole file (about 710,000 ranges) was loaded in one request, which takes from 20 seconds to a few minutes and ran past the host's PHP time limit. The import now runs in steps of about 5 seconds, driven by the Tools tab with a progress bar (`Geo\GeoImport`, `CsvImporter::prepare()` / `import_chunk()`).

- The emergency switch `WP_BOUNCER_DISABLE` didn't lift login lockouts: the firewall stopped, but the login check still refused a locked-out IP. It now turns off every blocking hook and leaves only the admin screens. A red notice is shown on every admin screen while it's on.

### Changed
- Repository split so that only the plugin is uploaded: `wp-bouncer/` (the plugin), `tests/`, `documentation/`. Some hosts' malware scanners flagged the test files, which contain attack payloads on purpose.
- `make` builds `builds/wp-bouncer-<version>.zip`, and refuses to ship any test or tooling files. `make check` runs the end-to-end suite against the installed zip, and CI does the same.
- `MemoryStore` moved from the plugin to `tests/Support`, since only the tests use it.

### Added
- Stop button for a running import. Ranges loaded so far are kept and marked "incomplete".
- "Continue import" button when JavaScript is unavailable.
- Files are checked before the current data is replaced, so a wrong file or a URL that returns an error page leaves the old data in place.
- Clear messages for uploads over `upload_max_filesize` or `post_max_size`. The Tools tab shows the server's upload limit.
- `wp_bouncer_geo_step_seconds` filter.
- End-to-end tests for the Tools-screen import, which now runs under a 30-second PHP limit.

## [1.0.0] - 2026-10-19

### Added
- Firewall core running on `plugins_loaded`, with enforce and monitor modes, an allowlist and loopback exemption.
- Rules: IP blocklist, User-Agent filter, country blocking, XML-RPC blocking, login lockout, rate limiting, WAF (SQLi/XSS/traversal/code injection), user enumeration.
- Local geolocation: DB-IP Lite / IP2Location LITE CSV import (file or URL, gzip supported), or a CDN/web-server country header.
- Admin UI: Dashboard with per-rule switches and stats, General, Rules, Countries (searchable picker grouped by continent), Activity Log (filter, search, CSV export, block IP), Tools (geo import, unlock IP).
- Guard against admins blocking themselves when saving settings.
- `wp_bouncer_rules` filter and `WP_BOUNCER_DISABLE` constant.
- PHPUnit unit suite, PHPStan config, WPCS config, end-to-end smoke test, GitHub Actions CI.
