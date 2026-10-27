# Rules reference

All rules live in `wp-bouncer/src/Rules/`, except `uploads_php`, which lives in `wp-bouncer/src/Hardening/` because it works through the web server and the upload handler rather than the request firewall. Settings are stored under `wp_bouncer_settings['rules'][<id>]`, and every rule has an `enabled` flag.

Evaluation order: `ip_blocklist`, `sensitive_files`, `not_found`, `login_lockout`, `rate_limit`, `user_agent`, `xmlrpc`, `user_enumeration`, `country`, `waf`. The first rule that refuses a request wins.

Administrators (users with `manage_options`) are never inspected by the WAF, the rate limiter, the sensitive-file rule or the 404 counter. Allowlisted IPs skip every rule. A loopback IP (127.0.0.1 or ::1) skips every rule only when the request carries no forwarding header, so a same-host proxy's requests are inspected like any other. Loopback and trusted-proxy addresses are never banned.

While the IP detection fallback is active (a forwarding header is configured but no trusted proxies are listed), bans and lockouts are suspended and failed logins are only logged. The WAF, User-Agent, blocklist and sensitive-file checks still apply. Outside the fallback, requests that carry a forwarding header from an unlisted private address (for example a local proxy you haven't listed) are not banned either; unlisted public addresses can be. Behind a CDN, list all of its published ranges under Trusted proxies.

Email alerts aren't a rule; they are described at the end.

## Categories and status

The Rules tab groups the rules into four categories. Each has a permanent slug, which appears in page anchors and in the `wp_bouncer_rule_info` filter. Slugs never change; only the display names may.

| Category (display name) | Slug | Rules |
|---|---|---|
| Block lists | `block-lists` | `ip_blocklist`, `country` (a status card; its settings are on the Countries tab), `user_agent` |
| Login and accounts | `login-accounts` | `login_lockout`, `xmlrpc`, `user_enumeration` |
| Scanners and floods | `scanners-floods` | `sensitive_files`, `not_found`, `rate_limit` |
| Attack payloads and hardening | `payloads-hardening` | `waf`, `uploads_php` |
| Other | `other` | Rules added by other plugins with no known category (see [adding-a-rule.md](adding-a-rule.md)) |

Each rule has one state, **On** or **Off**, which is its saved switch. A flag can add a line of text beside it:

- **Needs attention** (counted in the category's "needs attention" total): the rule is on but isn't fully working. Country blocking shows this when no geo database is loaded, when the country header can't be trusted (the rule is then paused), when block mode has no countries chosen (unless "block unknown" is on), or when allow mode has none (so the rule isn't applied). The uploads rule shows it when the server broke uploads and the block was removed, when the block couldn't be written, or when the last **Test now** found that scripts still run.
- **Before switching on** (a neutral hint, not counted): the rule is off and needs setting up first. Rate limiting shows this, because without a persistent object cache every counted request writes to the database. Country blocking shows it while the rule is off and no geo database is loaded.

Some of these reasons also appear as a notice across WP Bouncer's screens. The Rules tab, the Dashboard tab, the notices and the Dashboard widget all use one status calculation, so they agree. Categories and status are display only: they never change how the firewall decides.

---

## `ip_blocklist`: IP blocklist
**Default:** on (empty list) · **Status:** 403

| Setting | Type | Notes |
|---|---|---|
| `ips` | string[] | IPv4/IPv6 addresses or CIDR ranges. Invalid entries are dropped on save. |

Adding IPs: Rules tab, the "Block IP" row action in the Activity Log, or the "Block" button on the Dashboard's Top IPs.

## `user_agent`: User-Agent filter
**Default:** on · **Status:** 403

| Setting | Type | Notes |
|---|---|---|
| `block_empty` | bool | Refuse requests with no User-Agent. Real browsers always send one. |
| `patterns` | string[] | Plain text matches anywhere, ignoring case. `/regex/flags` is a PCRE pattern, and invalid regexes are dropped on save. |

The default patterns are well-known attack tools only. Generic clients such as `curl`, `python-requests` and `Go-http-client` aren't listed, because uptime monitors and integrations use them. Add them yourself if you want.

## `country`: Country blocking
**Default:** off · **Status:** 403 · Needs a geo source, see [geolocation.md](geolocation.md)

| Setting | Type | Notes |
|---|---|---|
| `mode` | `block` \| `allow` | `allow` refuses every country *not* listed. An `allow` list with no countries counts as off, so the whole world can't be locked out. |
| `countries` | string[] | ISO 3166-1 alpha-2 codes, plus `T1` (Tor, Cloudflare header only), `EU`, `AP`. |
| `block_unknown` | bool | Refuse IPs the database can't place. Leave this off unless you really mean it, because new or reassigned ranges are often missing. |
| `scope` | `site` \| `login` | `login` covers wp-login.php, xmlrpc.php and /wp-admin/ only, so visitors can still read the site. |

## `xmlrpc`: XML-RPC blocking
**Default:** on, `block_all` · **Status:** 403

| Setting | Type | Notes |
|---|---|---|
| `mode` | `block_all` \| `block_abuse` | `block_abuse` keeps XML-RPC working for apps but refuses `system.multicall`, `pingback.ping` and `pingback.extensions.getPingbacks`. |

While the rule is on, the plugin also removes the `X-Pingback` header and the RSD link. In `block_all` mode it also sets `xmlrpc_enabled` to false and empties the method list. Use `block_abuse` if you rely on the WordPress mobile apps, Jetpack or a desktop blogging client.

## `login_lockout`: Login lockout
**Default:** on · **Status:** 403 with Retry-After

| Setting | Type | Default | Notes |
|---|---|---|---|
| `max_attempts` | int 1–100 | 5 | Failures allowed in the window. |
| `window_minutes` | int 1–1440 | 15 | Fixed window from the first failure. |
| `lockout_minutes` | int 1–1440 | 60 | Capped at 24 hours. Values stored above 1440 are read as 1440. |
| `banned_usernames` | string[] | admin, administrator, root, test | Trying one locks the IP out immediately. **Remove any name a real account uses.** |
| `generic_errors` | bool | true | "Unknown username" and "wrong password" become the same message. |

The protection works at two levels:
1. `LoginLockoutRule` refuses **POSTs** to wp-login.php and any request to xmlrpc.php from a locked-out IP before WordPress authenticates. The login page itself still displays.
2. The `authenticate` filter (priority 999) refuses locked-out IPs on *every* login path, including REST application passwords and custom login forms.

Failed-login counts are kept per IPv4 address, or per IPv6 /64 network (`WP_BOUNCER_IPV6_PREFIX` sets the width). The rate limit, sensitive-file and 404 rules use the same key, so one /64 is one client for all of them. Each attempt is counted before the password is checked, so parallel guesses can't all pass. Attempts from one IPv6 /48 are capped at 8 times the per-/64 limit (`wp_bouncer_ipv6_wide_multiplier`).

**Cross-site logins are refused.** A login attempt that the browser says another site started (`Sec-Fetch-Site` cross-site or same-site, or an `Origin` that isn't this site's or on `wp_bouncer_login_allowed_origins`) is refused before the password check, on wp-login.php, xmlrpc.php and custom forms alike. REST requests with application-password credentials from another site are refused too. Refused attempts aren't counted. This needs this rule switched on, and monitor mode only logs. Headless front ends and apps on another origin need that origin added with `wp_bouncer_login_allowed_origins` (see the [developer guide](developer-guide.md#hooks-filters-and-constants)).

Lift a lockout early under Tools → Unlock an IP.

## `rate_limit`: Rate limiting
**Default:** off · **Status:** 429 with Retry-After

| Setting | Type | Default |
|---|---|---|
| `max_requests` | int 10–100000 | 240 |
| `window_seconds` | int 1–3600 | 60 |
| `ban_minutes` | int 1–1440 | 10 |

Only requests that reach PHP are counted, per IPv4 address or IPv6 /64 network. Static files served by the web server aren't. **Without a persistent object cache** (Redis or Memcached), every counted request writes a transient to `wp_options`, so only enable this on busy sites that have one. Don't set limits so low that a page load (one HTML request plus AJAX calls) trips them. Sites behind a CDN must configure the client IP source first, otherwise every visitor shares the CDN's IP. While the IP detection fallback is active (see the first paragraph), rate limiting is effectively off.

## `waf`: Web application firewall
**Default:** on, all categories · **Status:** 403

| Setting | Type | Notes |
|---|---|---|
| `sqli` | bool | UNION SELECT, `' OR '1'='1` tautologies, SLEEP/BENCHMARK, `information_schema`, `INTO OUTFILE`, stacked DROP/TRUNCATE. |
| `xss` | bool | `<script`, `javascript:`, `on*=` event handlers inside tags, iframe/object/embed/base/meta tags, `document.cookie`. |
| `traversal` | bool | `../../`, `/etc/passwd`, `../wp-config.php`, `php://` and similar stream wrappers. Also checked in the URL path. |
| `code_injection` | bool | `<?php`, `eval(`/`assert(`/`shell_exec(`/`base64_decode(`, `${jndi:`, `; wget http://…`. |
| `excluded_params` | string[] | Top-level parameter names that are never inspected. |
| `inspect_json` | bool | Default on. Also scan JSON request bodies. See below. |

Scope: parameter names and values in the query string and POST body (nested arrays included), and JSON request bodies (below). Values up to 64 KB are scanned in overlapping 8 KB windows, and the last 8 KB of longer values are scanned too. Each value is checked as-is and after one extra round of URL decoding, which catches double encoding. Cookies and headers aren't inspected. If a built-in signature can't be checked (the regex engine fails), the request is refused.

**JSON request bodies** (`inspect_json`). A body counts as JSON when its `Content-Type` says so, the way WordPress reads it: `application/json`, any `+json` type, `+oembed`, and lists such as `text/plain, application/json`. A body that isn't declared as JSON, and isn't multipart, is also treated as JSON when its first non-blank byte is `{`, `[` or `"`, because many plugins decode the raw body whatever its type says.

- **Checked:** visitors who aren't logged in, and logged-in users who can't edit posts.
- **Not checked:** users who can edit posts. A cookie session counts only with a valid REST nonce (`X-WP-Nonce`, or `_wpnonce`). Application-password credentials count only on REST or XML-RPC requests, so a Basic header on a front-end or admin-ajax path gets no exemption. Administrators aren't inspected by the WAF at all.
- **Scanned like form fields:** each leaf is checked as `key=value` and each container's key on its own, with the same signatures and the same windows as above.
- **Fails closed:** a body the plugin can't check gets a 403 when it is over the size limit, nested more than 512 levels, holds more than 5,000 fields (values and containers together), or would need too much memory to decode (estimated against `memory_limit`). The size limit is 1 MB for anonymous visitors and 8 MB for logged-in users, each capped by `post_max_size`. Invalid JSON gets no WAF verdict, because WordPress refuses it.
- **Never a ban:** WAF verdicts block the request and never ban the IP.
- **Filters:** `wp_bouncer_waf_json_max_bytes( $max, $logged_in )` receives the default (already capped by `post_max_size`) and can change it. `wp_bouncer_waf_json_max_fields( $max )` changes the field limit (default 5,000). Both are in the [developer guide](developer-guide.md#hooks-filters-and-constants).
- **Known limitation:** a plugin that receives large signed JSON webhooks without a cookie may need the size or field limit raised.

Cost: scanning is per request, and large values (over 8 KB) add about 2.5 to 5 ms.

**False positives:** the signatures are tuned to leave normal prose alone. Phrases like "select a union rep", "I <3 the online =" and "edit wp-config.php" are all in the test suite as must-pass. A site whose visitors legitimately submit code, such as a programming Q&A form, should add that form's field name to `excluded_params`. Start new installs in monitor mode and check the log.

Signatures are in `WafRule::SIGNATURES`. Each one has a short name that appears in the log reason.

## `user_enumeration`: User enumeration
**Default:** on · **Status:** 403

| Setting | Type | Notes |
|---|---|---|
| `block_author_scan` | bool | `?author=<number>` and `?author_name=` for logged-out visitors (outside wp-admin). Pretty author URLs such as `/author/jane/` still work. |
| `block_rest_users` | bool | `/wp-json/wp/v2/users…` and `?rest_route=/wp/v2/users…` for logged-out visitors. |

The users sitemap (`/wp-sitemap-users-1.xml`) is answered with a 404 while the rule is on. For logged-out visitors, the oEmbed response leaves out the author's name and URL. With `generic_errors` on (login lockout rule), the lost-password error is made generic, but WordPress still adds its own message after it, so the lost-password form can still reveal whether an account exists (a known limitation).

## `sensitive_files`: Sensitive-file probes
**Default:** on · **Status:** 403 · `src/Rules/SensitiveFileRule.php`

| Setting | Type | Notes |
|---|---|---|
| `ban_minutes` | int 0–1440 | How long the IP is then refused on every page. Default 60, capped at 24 hours. `0` refuses only the probe itself. |
| `extra_paths` | string[] | More path fragments to treat as probes, matched anywhere in the lowercased path, e.g. `/old-admin/`. |

Matched against the decoded, lowercased path (never the query string). The groups, each named in the log reason, are in `SensitiveFileRule::PATTERNS`: environment files (`/.env`, `/.env.production`), version-control data (`/.git/`, `/.svn/`…), server config files (`.htpasswd`, `.htaccess`, `.user.ini`, `.DS_Store`…), hidden config folders (`/.aws/`, `/.ssh/`…), wp-config copies (`wp-config.php.bak`, `wp-config.old`…), PHP file backups (`*.php.bak`, `*.php~`, `*.php.swp`…), database dumps (`*.sql`, `*.sql.gz`, `*.sqlite`), site backup archives at the top level (`/backup.zip`, `/wordpress.tar.gz`…), log files (`debug.log`, `error_log`), phpinfo pages, database admin tools (`adminer*.php`, `/phpmyadmin/`), known web shells (`wso.php`, `c99.php`…), PHP in uploads, the PHPUnit `eval-stdin.php` exploit, project manifests at the top level (`composer.json`, `package.json`, `docker-compose.yml`) and `/server-status`.

Never treated as probes: `/.well-known/…`, `/wp-config.php`, `/wp-config-sample.php`, and the uploads self-test script.

Why a probe is enough to refuse: a file that exists is served by the web server before WordPress runs, so a request that reaches WordPress is for a file that isn't there. No real visitor asks for `/.git/config`. The first probe is refused. A second probe within 10 minutes (`BAN_WINDOW`) from the same visitor's own browsing bans the IP for `ban_minutes`, because one probe can be a misfired link or a stray request. Probes whose `Sec-Fetch-Site` says another site's page caused them are counted in their own bucket: they need `cross_site_probes` probes, and then only that visitor's requests from other sites are refused, never the whole site. A real image, script or style load of a matching file doesn't count toward a ban (it is still refused). The keys are `sf_probe:<ip>` and `sf_ban:<ip>` in the counter store, `sf_probe_x:<ip>` and `sf_xban:<ip>` for probes and bans caused by another site, where `<ip>` is the counter subject (the IPv4 address, or the IPv6 /64 network); **Tools → Unlock an IP** clears `sf_ban:` and `sf_xban:`.

## `not_found`: 404 flood
**Default:** on · **Status:** 403 · `src/Rules/NotFoundFloodRule.php`

| Setting | Type | Notes |
|---|---|---|
| `max_404` | int 3–10000 | "Not found" pages allowed per window. Default 20. |
| `window_seconds` | int 10–3600 | Default 60. |
| `ban_minutes` | int 1–1440 | Default 60, capped at 24 hours. |
| `ignore_crawlers` | bool | Don't count User-Agents of major search engines (Google, Bing, DuckDuckGo, Baidu, Yandex, Apple, Yahoo, Petal, Seznam, Qwant). User-Agents can be faked, so this trades a little protection for not banning crawlers that revisit removed pages. Default on. |

Two halves. `Plugin::track_not_found()` runs on `template_redirect` at priority 999, after other plugins have had their chance to turn the 404 into a redirect or a page; if `is_404()`, it calls `NotFoundFloodRule::record()`. Going over the limit places a ban (logged with action `lockout`), and `inspect()` refuses the IP from its next request.

Not counted: missing static files (images, CSS, JS, source maps, fonts, audio/video, PDF), so a page with a broken image never bans its reader; logged-in administrators; allowlisted IPs. `.txt`, `.json`, `.xml` and `.php` do count, because scanners ask for plugin `readme.txt` files and config files. REST API "no route" errors aren't page 404s and don't count.

404s caused by another site's page (`Sec-Fetch-Site` cross-site, or a subresource request from another origin) have their own counter, `nf_count_x:<ip>`, with the limit times `cross_site_multiplier` (default 5; filter `wp_bouncer_cross_site_404_multiplier`). Going over it refuses only that visitor's requests from other sites (`nf_xban:<ip>`), never the whole site. Keys: `nf_count:<ip>` and `nf_ban:<ip>`, where `<ip>` is the counter subject (the IPv4 address, or the IPv6 /64 network).

## `uploads_php`: No PHP in uploads
**Default:** on · `src/Hardening/UploadsGuard.php` (WordPress side) and `src/Hardening/UploadsPolicy.php` (pure, unit-tested)

| Setting | Type | Notes |
|---|---|---|
| `htaccess` | bool | Keep a `# BEGIN WP Bouncer` … `# END WP Bouncer` block in `wp-content/uploads/.htaccess`. |
| `check_uploads` | bool | Refuse uploads that are scripts in disguise. |

**The `.htaccess` block** is a `<FilesMatch>` on script extensions (`php`, `php0`–`php9`, `phtml`, `pht`, `phar`, `phps`, `pgif`, `shtml`, `cgi`, `pl`, `py`, `asp`, `aspx`, `jsp`) with `Require all denied`, plus `Order`/`Deny` for Apache 2.2. It deliberately doesn't use `php_flag engine off`, which gives a 500 error on servers running PHP-FPM. It is written with WordPress's `insert_with_markers()`, so anything else in the file stays. A fingerprint of the wanted state is kept in option `wp_bouncer_uploads_htaccess`; on each `init` the plugin compares it and only touches the file when something changed (after a failed write it retries once an hour, and the Bouncer screens show a warning). The block is removed when either setting turns it off, while `WP_BOUNCER_DISABLE` is on, on deactivation, and on uninstall. If nothing else was in the file, the file is deleted.

**Safety check.** `Require` and `Deny` are only allowed in `.htaccess` when the host's `AllowOverride` permits them; on a host that doesn't, every file in uploads, images included, would get a 500 error while the block is there. So after writing the block the plugin schedules a one-off cron job (`wp_bouncer_uploads_check`) that puts a small text file in uploads and fetches it. If the server answers with a 5xx error twice in a row, at least 5 minutes apart within an hour (one error is not enough, and a success resets the count), the block is removed, the state is marked `broken` so it isn't written again, an `alert` entry is logged, and the Bouncer screens show an error. **Test now** runs the same check first. **Write it now** on the Rules tab tries again once the host is fixed. A check that can't reach the site at all changes nothing.

nginx ignores `.htaccess`. The Rules tab shows the equivalent rule:

```nginx
location ~* ^/wp-content/uploads/.*\.(php[0-9]?|phtml|pht|phar|phps|pgif|shtml|cgi|pl|py|asp|aspx|jsp)$ {
    deny all;
}
```

**Test now** (`UploadsGuard::probe()`) writes `wp-content/uploads/wp-bouncer-test-<random>.php`, requests it over HTTP from the site itself, deletes it, and stores the result in option `wp_bouncer_uploads_probe`. Protected means a 401/403, or the script's source coming back as text. Not protected means the script ran. If the safety check found the block breaking uploads, the result is "not protected, block removed". Anything else (404, 500, a timeout, a redirect) is reported as "could not tell".

**Upload checks** hook `wp_handle_upload_prefilter` and `wp_handle_sideload_prefilter`, which cover the media library, the REST API (`/wp/v2/media`), `media_handle_sideload()` and WP-CLI `wp media import`. A file is refused if any part of its name after the first dot is a script extension (`photo.php.jpg`, since some servers run any file with `.php` in its name), if it is a server config file (`.htaccess`, `.user.ini`, `php.ini`, `web.config`, `.htpasswd`), or if its first 50 MB contain `<?php` in any case, or a `<?=` that opens PHP code (compressed media files get a relaxed test for `<?=`, to avoid false alarms). Refusals are logged with rule `uploads_php`. Plugins that write files themselves, without WordPress's upload functions, aren't covered; the `.htaccess` block is what protects against those.

---

## Email alerts
**Default:** on · General tab · `src/Alerts/AlertNotifier.php` (hooks) and `src/Alerts/AlertFormatter.php` (pure, unit-tested) · Settings in `wp_bouncer_settings['alerts']`

| Setting | Type | Notes |
|---|---|---|
| `enabled` | bool | Master switch. |
| `recipients` | string[] | Up to 10 valid addresses. Empty means the site's admin email. |
| `new_admin` | bool | An account is created as, promoted to or given the administrator role (any role with `manage_options`), or made a multisite super admin. Hooks: `user_register`, `set_user_role`, `add_user_role`, `granted_super_admin`. |
| `plugin_changes` | bool | A plugin is installed (`upgrader_process_complete`, action `install`), activated, deactivated or deleted (`activated_plugin`, `deactivated_plugin`, `deleted_plugin`). WP Bouncer itself being deactivated says so in the subject. |
| `plugin_updates` | bool | A plugin is updated. Off by default, since updates are routine and auto-updates already email the admin. |
| `record_admin_logins` | bool | Default on. Every successful login by an administrator is written to the Activity Log as action `login`, rule `admin_login` (see "Administrator logins" below). Off stops the rows, the location history and the new-location email. Does not depend on `enabled`. |
| `admin_login_location` | bool | Default on. Email when an administrator logs in from an IP range or country not seen for that account in the history window. Needs `enabled` and `record_admin_logins`. |
| `firewall_changes` | bool | Default on. Settings that weaken the firewall are saved (mode, allowlist, trusted proxies, IP source, geo source or header, alert recipients, XML-RPC mode, a rule switched off, a shorter Activity Log or Traffic log retention), the Activity Log is cleared, or `WP_BOUNCER_DISABLE` is set (one reminder a day, sent from cron or an admin request). Every settings save also writes one `alert` row naming the changed settings, not their values. Recipients include the network admin on multisite. |

Events are queued during the request and sent as one `wp_mail()` on `shutdown`, so "install and activate" is one email. Creating an administrator fires several hooks; they are merged into one line per user. Each email gives what happened, when, who was logged in (or "no logged-in user" for WP-CLI, cron or code), and the IP, country and User-Agent. Names are stripped of control characters, so a crafted username can't add mail headers. At most 20 emails go out per hour (transient `wpb_alert_count`), not counting administrator-login emails, which have their own limits (10 per site an hour, 3 per administrator; see "Administrator logins" below). Every event is also written to the Activity Log with rule `alerts` and action `alert`, which the Dashboard's statistics leave out. Alerts keep working while `WP_BOUNCER_DISABLE` is on, because they never refuse anyone.

### Administrator logins

**Default:** on (both settings) · `src/AdminLogins/` (recorder, history, policy; pure parts unit-tested) · Settings in `wp_bouncer_settings['alerts']`

- **Recording.** A successful login by a user with the administrator role or `manage_options`, or a network super admin, writes one Activity Log row: action `login`, rule `admin_login`, with the user, IP, country and method in the reason. Methods: interactive password, interactive password + two-factor, application password (REST), application password (XML-RPC), and password (XML-RPC). Login rows are not counted as threats on the Dashboard or in the dashboard widget.
- **Once per hour for app passwords and XML-RPC.** Application-password and XML-RPC logins are recorded once per user, range and method each hour (per network for site admins), so a script that calls the REST API on every request writes one row, not thousands. A login from a new range is always recorded.
- **New location.** The plugin keeps, per administrator and site, the IP ranges (IPv4 /24, IPv6 /64) and countries seen in the last 90 days, in user meta. A login from a range or country not in that history sends one email, and the row says "new location". The first login after the feature starts the history without an email. A history that has fully expired alerts on the next login. With no geo database, only the range is compared. A login whose IP can't be trusted (see the IP source setting) is recorded with a note, and no history or email is kept for it.
- **Limits.** 3 new-location emails per administrator and hour, and 10 per site and hour. Over the limit, the row says "alert throttled" and one "Admin login alerts throttled" notice is written to the Activity Log per hour.
- **Two-factor.** With the Two Factor plugin, the login is recorded after the second factor passes; a password step alone writes nothing. Other two-factor plugins that finish login after `wp_login` should use the `wp_bouncer_admin_login_defer` and `wp_bouncer_record_admin_login` hooks (see the [developer guide](developer-guide.md)). Until they do, those logins are not recorded.
- **Not recorded.** Logins that set the login cookie without `wp_login` (magic links, User Switching) and logins by other roles. Attackers who use a range the administrator already uses are not flagged by the email; the row is the record.
- **Multisite.** A site administrator's login is recorded and checked on each site where they are an administrator (up to 100 sites). A super admin's login is recorded on the site where it happened.
- **Filtering.** In the Activity Log, choose **Admin login** in the action filter. Rule filter: **Admin logins**.

**Send a test email** (General tab) sends a sample and reports WordPress's mail error if sending fails.

---

## Traffic log
**Default:** off · Traffic tab · `src/Traffic/` · Settings in `wp_bouncer_settings['traffic']`

| Setting | Type | Notes |
|---|---|---|
| `enabled` | bool | Record requests. |
| `retention_days` | int 1–7 | Rows older than this are deleted by the hourly cron job `wp_bouncer_traffic_purge`. Default 7. The purge never keeps anything longer than 7 days, whatever is stored. |
| `skip_background` | bool | Don't record `/wp-cron.php` or admin-ajax Heartbeat requests. Default on. |
| `skip_admins` | bool | Don't record logged-in administrators. Default off. |

`TrafficRecorder` writes one row on `shutdown` at priority 100, after everything else, so `http_response_code()` is final. Blocked requests are included: the block page ends with `exit`, and PHP still runs shutdown hooks. WP-CLI is never recorded. A failure to write (for example, the table is missing) is silent and never breaks the page.

Columns of `{prefix}bouncer_traffic`: `created_at` (UTC), `ip`, `method`, `uri` (up to 2048 characters), `referrer` (2048), `user_agent` (512), `client`, `status` (0 if unknown), `user_id` (0 for visitors). Indexed on time, IP, client, status and user.

**Client type** (`ClientClassifier::classify()`, pure) is read from the User-Agent, first match wins: attack tool (sqlmap, WPScan, Nikto…), search engine (Googlebot, Bingbot…), uptime monitor, feed reader, bot or crawler (anything saying bot, crawl or spider; SEO and AI crawlers; link previews), WordPress (its own loopback and pingback requests), script or tool (curl, wget, Python, Go, Java…), then mobile browser or browser for `Mozilla/…`, "no User-Agent" for an empty one, and "other". The User-Agent is whatever the client claims, so the type is a reading aid, not proof.

**Secrets in URLs** (`TrafficEntry::redact_url()`, pure): the values of `key`, `pwd`, `pass`, `password`, `token`, `access_token`, `refresh_token`, `id_token`, `auth`, `code`, `secret`, `client_secret`, `api_key`, `signature`, `nonce`, `_wpnonce`, `session`, `sid`, `otp`, `jwt`, and any parameter whose name contains `pass`, `token` or `secret`, become `[removed]`, in both the URL and the referrer. That covers WordPress's password-reset links (`wp-login.php?action=rp&key=…`).

What isn't recorded: files the web server serves itself (images, CSS, JS, and any file that exists), since those never reach WordPress.
